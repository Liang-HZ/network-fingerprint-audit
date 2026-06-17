#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import datetime as dt
import functools
import html
import http.server
import ipaddress
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request


PROJECT_ROOT = pathlib.Path(__file__).resolve().parent
DEFAULT_REPORTS_DIR = PROJECT_ROOT / "reports"
BROWSER_PROBE_TEMPLATE = PROJECT_ROOT / "browser_probe.html"

CN_DNS_HINTS = {
    "114.114.114.114",
    "114.114.115.115",
    "223.5.5.5",
    "223.6.6.6",
    "180.76.76.76",
    "119.29.29.29",
}

CLASH_CONFIG_CANDIDATES = [
    pathlib.Path.home()
    / "Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/clash-verge.yaml",
    pathlib.Path.home()
    / "Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/config.yaml",
    pathlib.Path.home()
    / ".config/clash-verge/clash-verge.yaml",
    pathlib.Path.home() / ".config/clash.meta/config.yaml",
]

PROXY_CLIENT_SIGNATURES = [
    {
        "name": "Clash/Mihomo",
        "process_keywords": ("clash", "mihomo"),
        "config_paths": tuple(CLASH_CONFIG_CANDIDATES),
    },
    {
        "name": "Surge",
        "process_keywords": ("surge",),
        "config_paths": (
            pathlib.Path.home() / "Library/Application Support/Surge",
            pathlib.Path.home() / "Library/Mobile Documents/iCloud~com~nssurge~inc~surge/Documents",
            pathlib.Path.home() / "AppData/Roaming/Surge",
        ),
    },
    {
        "name": "sing-box",
        "process_keywords": ("sing-box", "sfm", "sfi"),
        "config_paths": (
            pathlib.Path.home() / ".config/sing-box",
            pathlib.Path.home() / "Library/Application Support/io.nekohasekai.sfavt",
            pathlib.Path.home() / "AppData/Roaming/sing-box",
            pathlib.Path.home() / "AppData/Local/sing-box",
        ),
    },
    {
        "name": "V2Ray/v2rayN",
        "process_keywords": ("v2rayx", "v2rayu", "v2ray"),
        "config_paths": (
            pathlib.Path.home() / "Library/Application Support/V2RayX",
            pathlib.Path.home() / "Library/Application Support/V2RayU",
            pathlib.Path.home() / ".config/v2ray",
            pathlib.Path.home() / "AppData/Roaming/v2rayN",
            pathlib.Path.home() / "AppData/Roaming/v2ray",
        ),
    },
    {
        "name": "Shadowsocks",
        "process_keywords": ("shadowsocks", "ss-local"),
        "config_paths": (
            pathlib.Path.home() / "Library/Application Support/ShadowsocksX-NG",
            pathlib.Path.home() / ".ShadowsocksX-NG",
            pathlib.Path.home() / "AppData/Roaming/Shadowsocks",
        ),
    },
    {
        "name": "Outline",
        "process_keywords": ("outline",),
        "config_paths": (
            pathlib.Path.home() / "Library/Application Support/Outline",
            pathlib.Path.home() / "AppData/Roaming/Outline",
        ),
    },
    {
        "name": "Hiddify",
        "process_keywords": ("hiddify",),
        "config_paths": (
            pathlib.Path.home() / "Library/Application Support/Hiddify",
            pathlib.Path.home() / "AppData/Roaming/Hiddify",
        ),
    },
]

MACOS_BROWSER_CANDIDATES = [
    pathlib.Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
    pathlib.Path("/Applications/Chromium.app/Contents/MacOS/Chromium"),
    pathlib.Path("/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"),
]


def run_command(*args: str, timeout: int = 5) -> dict[str, object]:
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return {
            "cmd": list(args),
            "code": completed.returncode,
            "stdout": completed.stdout.strip(),
            "stderr": completed.stderr.strip(),
        }
    except FileNotFoundError:
        return {"cmd": list(args), "code": None, "stdout": "", "stderr": "command not found"}
    except subprocess.TimeoutExpired:
        return {"cmd": list(args), "code": None, "stdout": "", "stderr": "timeout"}


def skipped_command_result(*args: str, reason: str) -> dict[str, object]:
    return {"cmd": list(args), "code": None, "stdout": "", "stderr": reason}


def redact_user_path(path: pathlib.Path | str) -> str:
    raw = str(path)
    home = str(pathlib.Path.home())
    if raw == home:
        return "~"
    if raw.startswith(home + os.sep):
        return "~" + raw[len(home) :]
    return raw


def fetch_json(url: str, timeout: int = 5) -> dict[str, object] | None:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            payload = response.read().decode("utf-8", errors="replace")
        return json.loads(payload)
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError, OSError):
        return None


def fetch_text(url: str, timeout: int = 5) -> str | None:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return response.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError):
        return None


def parse_cloudflare_trace(raw: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in raw.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key:
            parsed[key] = value.strip()
    return parsed


def fetch_proxycheck(ip: str, timeout: int = 5) -> dict[str, object] | None:
    if not ip:
        return None
    encoded_ip = urllib.parse.quote(ip, safe="")
    payload = fetch_json(
        f"https://proxycheck.io/v2/{encoded_ip}?vpn=1&asn=1&risk=1",
        timeout=timeout,
    )
    if not isinstance(payload, dict) or payload.get("status") != "ok":
        return None
    result = payload.get(ip)
    return result if isinstance(result, dict) else None


def parse_key_value_block(text: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        parsed[key.strip()] = value.strip()
    return parsed


def command_stdout(result: dict[str, object]) -> str:
    return str(result.get("stdout", "")).strip()


def command_failed(result: dict[str, object]) -> bool:
    return result.get("code") != 0


def command_failure_notes(
    raw_command_status: dict[str, dict[str, object]],
    required_keys: tuple[str, ...],
) -> list[str]:
    notes: list[str] = []
    for key in required_keys:
        result = raw_command_status[key]
        if not command_failed(result):
            continue
        cmd = " ".join(str(part) for part in result.get("cmd", []))
        stderr = command_stdout({"stdout": result.get("stderr", "")})
        code = result.get("code")
        reason = stderr or f"exit code {code}"
        notes.append(f"{key}: {cmd} failed ({reason})")
    return notes


def parse_proxy_settings(raw: str) -> dict[str, object]:
    settings: dict[str, object] = {}
    for line in raw.splitlines():
        match = re.match(r"^\s*([A-Za-z0-9]+)\s*:\s*(.+?)\s*$", line)
        if match:
            settings[match.group(1)] = match.group(2)
    return settings


def parse_dns_nameservers(raw: str) -> list[str]:
    nameservers: list[str] = []
    for line in raw.splitlines():
        match = re.search(r"nameserver\[\d+\]\s*:\s*(.+)$", line)
        if match:
            nameserver = match.group(1).strip()
            if nameserver not in nameservers:
                nameservers.append(nameserver)
    return nameservers


def parse_default_route(raw: str) -> dict[str, str]:
    return parse_key_value_block(raw)


def parse_enabled_network_services(raw: str) -> list[str]:
    services: list[str] = []
    for line in raw.splitlines():
        service = line.strip()
        if not service or service.startswith("An asterisk"):
            continue
        if service.startswith("*"):
            continue
        services.append(service)
    return services


def parse_network_service_order(raw: str) -> list[dict[str, object]]:
    services: list[dict[str, object]] = []
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("An asterisk"):
            continue
        service_match = re.match(r"^\(\d+\)\s+(.+)$", stripped)
        if service_match:
            name = service_match.group(1).strip()
            enabled = True
            if name.startswith("*"):
                enabled = False
                name = name[1:].strip()
            services.append({"service": name, "enabled": enabled})
            continue
        device_match = re.match(r"^\(Hardware Port:\s*(.+?),\s*Device:\s*(.+?)\)$", stripped)
        if device_match and services:
            services[-1]["hardware_port"] = device_match.group(1).strip()
            services[-1]["device"] = device_match.group(2).strip()
    return services


def choose_active_network_service(
    default_interface: str | None,
    service_order: list[dict[str, object]],
    enabled_services: list[str],
) -> dict[str, str | None]:
    if default_interface:
        for item in service_order:
            if str(item.get("device") or "") == default_interface and item.get("enabled", True):
                return {
                    "service": str(item.get("service") or ""),
                    "interface": default_interface,
                    "source": "default-route",
                }

    if "Wi-Fi" in enabled_services:
        return {
            "service": "Wi-Fi",
            "interface": default_interface or None,
            "source": "heuristic-wifi",
        }

    if enabled_services:
        return {
            "service": enabled_services[0],
            "interface": default_interface or None,
            "source": "heuristic-enabled-service",
        }

    for item in service_order:
        if item.get("enabled", True) and item.get("service"):
            return {
                "service": str(item.get("service") or ""),
                "interface": str(item.get("device") or default_interface or ""),
                "source": "heuristic-service-order",
            }

    return {"service": None, "interface": default_interface or None, "source": "unavailable"}


def parse_split_tunnel_routes(raw: str) -> list[dict[str, str]]:
    routes: list[dict[str, str]] = []
    for line in raw.splitlines():
        if not line or line.startswith("Routing tables") or line.startswith("Internet:"):
            continue
        if line.startswith("Destination") or line.startswith("default"):
            continue
        if "utun" not in line:
            continue
        columns = line.split()
        if len(columns) >= 4:
            routes.append(
                {
                    "destination": columns[0],
                    "gateway": columns[1],
                    "netif": columns[3],
                }
            )
    return routes


def parse_listener_summary(tcp_raw: str, udp_raw: str) -> dict[str, bool]:
    summary = {
        "tcp_127_0_0_1_53": False,
        "udp_127_0_0_1_53": False,
        "tcp_127_0_0_1_7890": False,
    }
    for line in tcp_raw.splitlines():
        if ("127.0.0.1.53" in line or "127.0.0.1:53" in line) and "LISTEN" in line:
            summary["tcp_127_0_0_1_53"] = True
        if ("127.0.0.1.7890" in line or "127.0.0.1:7890" in line) and "LISTEN" in line:
            summary["tcp_127_0_0_1_7890"] = True
    for line in udp_raw.splitlines():
        if "127.0.0.1.53" in line or "127.0.0.1:53" in line:
            summary["udp_127_0_0_1_53"] = True
    return summary


def parse_windows_ipconfig_dns(raw: str) -> list[str]:
    nameservers: list[str] = []
    collecting_dns = False
    for line in raw.splitlines():
        if "DNS Servers" in line and ":" in line:
            collecting_dns = True
            value = line.split(":", 1)[1].strip()
        elif collecting_dns and line.startswith(" " * 20):
            value = line.strip()
        else:
            collecting_dns = False
            value = ""
        if not value:
            continue
        try:
            ipaddress.ip_address(value)
        except ValueError:
            continue
        if value not in nameservers:
            nameservers.append(value)
    return nameservers


def parse_defaults_array(raw: str) -> list[str]:
    values: list[str] = []
    for line in raw.splitlines():
        line = line.strip().strip(",")
        if line in {"(", ")"} or not line:
            continue
        values.append(line.strip('"'))
    return values


def load_json_file(path: pathlib.Path) -> dict[str, object] | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def extract_browser_languages(base_dir: pathlib.Path, browser_name: str) -> dict[str, object]:
    result: dict[str, object] = {"browser": browser_name, "profiles": [], "last_used": None}
    local_state = load_json_file(base_dir / "Local State")
    if local_state:
        profile_info = local_state.get("profile", {})
        if isinstance(profile_info, dict):
            result["last_used"] = profile_info.get("last_used")

    for candidate in sorted(base_dir.glob("*/Preferences")):
        profile_name = candidate.parent.name
        payload = load_json_file(candidate)
        if not payload:
            continue
        intl = payload.get("intl", {})
        accept_languages = None
        if isinstance(intl, dict):
            accept_languages = intl.get("accept_languages") or intl.get("_accept_languages")
        if accept_languages:
            result["profiles"].append(
                {"profile": profile_name, "accept_languages": str(accept_languages)}
            )
    return result


def sanitize_clash_excerpt(path: pathlib.Path) -> dict[str, object] | None:
    if not path.exists():
        return None

    interesting = (
        "mode:",
        "mixed-port:",
        "port:",
        "socks-port:",
        "allow-lan:",
        "ipv6:",
        "dns:",
        "tun:",
        "enable:",
        "listen:",
        "enhanced-mode:",
        "respect-rules:",
        "nameserver:",
        "fallback:",
        "dns-hijack:",
        "stack:",
        "auto-route:",
        "strict-route:",
        "auto-detect-interface:",
    )

    excerpt: list[str] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith("proxies:") or stripped.startswith("proxy-groups:"):
                break
            if any(stripped.startswith(key) for key in interesting):
                excerpt.append(line.rstrip())
    except OSError:
        return None

    if not excerpt:
        return None
    return {"path": redact_user_path(path), "excerpt": excerpt}


def process_display_name(command: str) -> str:
    if "\\" in command or re.match(r"^[A-Za-z]:", command):
        name = pathlib.PureWindowsPath(command).name
    else:
        name = pathlib.Path(command).name
    if name.lower().endswith(".exe"):
        name = name[:-4]
    if name.endswith(".app"):
        return name[:-4]
    return name or command


def parse_process_command(line: str) -> str:
    windows_exe = re.match(r"^([A-Za-z]:\\.*?\.exe)(?:\s|$)", line, re.IGNORECASE)
    if windows_exe:
        return windows_exe.group(1)
    return line.split(None, 1)[0]


def parse_process_display_names(raw: str, keywords: tuple[str, ...]) -> list[str]:
    matches: list[str] = []
    lowered_keywords = tuple(keyword.lower() for keyword in keywords)
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        lowered = stripped.lower()
        if not any(keyword in lowered for keyword in lowered_keywords):
            continue
        command = parse_process_command(stripped)
        display = process_display_name(command)
        if display not in matches:
            matches.append(display)
    return matches


def detect_proxy_clients(process_raw: str) -> list[dict[str, object]]:
    clients: list[dict[str, object]] = []
    for signature in PROXY_CLIENT_SIGNATURES:
        name = str(signature["name"])
        processes = parse_process_display_names(
            process_raw,
            tuple(str(item) for item in signature["process_keywords"]),
        )
        existing_paths: list[str] = []
        configs: list[dict[str, object]] = []
        for raw_path in signature["config_paths"]:
            path = pathlib.Path(raw_path)
            if not path.exists():
                continue
            existing_paths.append(redact_user_path(path))
            excerpt = sanitize_clash_excerpt(path) if path.is_file() else None
            if excerpt:
                configs.append(excerpt)
        if processes or existing_paths:
            clients.append(
                {
                    "name": name,
                    "processes": processes,
                    "paths": existing_paths,
                    "configs": configs,
                }
            )
    return clients


def get_case_insensitive(mapping: object, key: str) -> str | None:
    if not isinstance(mapping, dict):
        return None
    target = key.lower()
    for current_key, value in mapping.items():
        if str(current_key).lower() == target:
            return str(value)
    return None


def truthy_external_flag(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value or "").strip().lower() in {"1", "true", "yes", "y"}


def candidate_address_scope(address: str) -> str:
    if not address:
        return "unknown"
    if address.endswith(".local"):
        return "mdns"
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return "hostname"
    if parsed.is_private or parsed.is_loopback or parsed.is_link_local:
        return "private"
    return "public"


def locale_signals_include_chinese(locale_data: dict[str, object]) -> bool:
    for key in ("lang", "lc_all", "apple_locale"):
        value = str(locale_data.get(key) or "").strip().lower()
        if value.startswith("zh"):
            return True

    apple_languages = locale_data.get("apple_languages") or []
    if isinstance(apple_languages, list):
        for item in apple_languages:
            if str(item).strip().lower().startswith("zh"):
                return True
    return False


def first_language_tag(value: str | None) -> str | None:
    if not value:
        return None
    first = value.split(",", 1)[0].strip()
    return first or None


def public_ip_candidates(public_ip: dict[str, object]) -> list[str]:
    candidates: list[str] = []

    def add(value: object) -> None:
        ip = str(value or "").strip()
        if ip and ip not in candidates:
            candidates.append(ip)

    for source_name in ("ipapi_is", "ipinfo", "ifconfig"):
        source = public_ip.get(source_name)
        if isinstance(source, dict):
            add(source.get("ip"))

    cloudflare_trace = public_ip.get("cloudflare_trace_parsed")
    if isinstance(cloudflare_trace, dict):
        add(cloudflare_trace.get("ip"))

    return candidates


def nested_mapping(source: object, key: str) -> dict[str, object]:
    if not isinstance(source, dict):
        return {}
    value = source.get(key)
    return value if isinstance(value, dict) else {}


def public_ip_summary(public_ip: dict[str, object]) -> dict[str, object]:
    ipapi = public_ip.get("ipapi_is") if isinstance(public_ip.get("ipapi_is"), dict) else {}
    ipinfo = public_ip.get("ipinfo") if isinstance(public_ip.get("ipinfo"), dict) else {}
    ifconfig = public_ip.get("ifconfig") if isinstance(public_ip.get("ifconfig"), dict) else {}
    proxycheck = (
        public_ip.get("proxycheck") if isinstance(public_ip.get("proxycheck"), dict) else {}
    )
    ipapi_asn = nested_mapping(ipapi, "asn")
    ipapi_location = nested_mapping(ipapi, "location")

    return {
        "ip": ipapi.get("ip") or ipinfo.get("ip") or ifconfig.get("ip"),
        "observed_ips": public_ip.get("observed_ips", []),
        "asn_org": ipapi_asn.get("org") or ipinfo.get("org") or ifconfig.get("asn_org"),
        "city": ipapi_location.get("city") or ipinfo.get("city") or ifconfig.get("city"),
        "region": ipapi_location.get("state")
        or ipinfo.get("region")
        or ifconfig.get("region_name"),
        "country": ipapi_location.get("country_code")
        or ipinfo.get("country")
        or ifconfig.get("country_iso"),
        "timezone": ipapi_location.get("timezone")
        or ipinfo.get("timezone")
        or ifconfig.get("time_zone"),
        "ipapi_flags": {
            key: ipapi.get(key)
            for key in ("is_datacenter", "is_proxy", "is_vpn", "is_tor", "is_abuser")
        },
        "proxycheck_flags": {
            key: proxycheck.get(key)
            for key in ("proxy", "type", "risk")
        },
    }


def choose_browser_probe_language(
    browser_languages: list[dict[str, object]],
    apple_languages: list[str],
) -> str | None:
    for browser in browser_languages:
        last_used = str(browser.get("last_used") or "")
        profiles = browser.get("profiles", [])
        if not isinstance(profiles, list):
            continue
        for profile in profiles:
            if not isinstance(profile, dict):
                continue
            if str(profile.get("profile") or "") == last_used:
                return first_language_tag(str(profile.get("accept_languages") or ""))

    for browser in browser_languages:
        profiles = browser.get("profiles", [])
        if not isinstance(profiles, list):
            continue
        for profile in profiles:
            if not isinstance(profile, dict):
                continue
            first = first_language_tag(str(profile.get("accept_languages") or ""))
            if first:
                return first

    for language in apple_languages:
        if language:
            return str(language)
    return None


def windows_env_path(name: str) -> pathlib.Path | None:
    value = os.environ.get(name)
    if not value:
        return None
    return pathlib.Path(value)


def browser_binary_candidates() -> list[pathlib.Path]:
    if sys.platform == "win32":
        candidates: list[pathlib.Path] = []
        for base in (
            windows_env_path("PROGRAMFILES"),
            windows_env_path("PROGRAMFILES(X86)"),
            windows_env_path("LOCALAPPDATA"),
        ):
            if not base:
                continue
            candidates.extend(
                [
                    base / "Google/Chrome/Application/chrome.exe",
                    base / "Chromium/Application/chrome.exe",
                    base / "Microsoft/Edge/Application/msedge.exe",
                ]
            )
        return candidates
    return MACOS_BROWSER_CANDIDATES


def browser_profile_roots() -> list[tuple[str, pathlib.Path]]:
    if sys.platform == "win32":
        local_appdata = windows_env_path("LOCALAPPDATA")
        if not local_appdata:
            return []
        return [
            ("Chrome", local_appdata / "Google/Chrome/User Data"),
            ("Chromium", local_appdata / "Chromium/User Data"),
            ("Microsoft Edge", local_appdata / "Microsoft/Edge/User Data"),
        ]
    return [
        ("Chrome", pathlib.Path.home() / "Library/Application Support/Google/Chrome"),
        ("Chromium", pathlib.Path.home() / "Library/Application Support/Chromium"),
        ("Microsoft Edge", pathlib.Path.home() / "Library/Application Support/Microsoft Edge"),
    ]


def find_browser_binary(explicit_path: str | None = None) -> str | None:
    if explicit_path:
        candidate = pathlib.Path(explicit_path).expanduser()
        if candidate.exists() and os.access(candidate, os.X_OK):
            return str(candidate)
        return None
    for candidate in browser_binary_candidates():
        if candidate.exists() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


class QuietSimpleHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        return


def start_probe_server(directory: pathlib.Path) -> tuple[http.server.ThreadingHTTPServer, threading.Thread]:
    handler = functools.partial(QuietSimpleHTTPRequestHandler, directory=str(directory))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def extract_probe_payload(dom: str) -> tuple[str | None, str | None, dict[str, object] | None]:
    status_match = re.search(r'data-probe-status="([^"]+)"', dom)
    error_match = re.search(r'data-probe-error="([^"]*)"', dom)
    payload_match = re.search(r'data-probe-result="([^"]+)"', dom)

    status = status_match.group(1) if status_match else None
    error = error_match.group(1) if error_match else None
    if not payload_match:
        return status, error, None

    payload = payload_match.group(1)
    try:
        decoded = base64.b64decode(payload).decode("utf-8")
        return status, error, json.loads(decoded)
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return status, error, None


def run_browser_probe(
    browser_languages: list[dict[str, object]],
    apple_languages: list[str],
    *,
    skip_browser_probe: bool,
    browser_path: str | None,
) -> dict[str, object]:
    if skip_browser_probe:
        return {"status": "skipped", "reason": "Browser probe was skipped by configuration."}

    if not BROWSER_PROBE_TEMPLATE.exists():
        return {"status": "unavailable", "reason": f"Missing template: {BROWSER_PROBE_TEMPLATE}"}

    browser_binary = find_browser_binary(browser_path)
    if not browser_binary:
        return {"status": "unavailable", "reason": "No supported browser binary was found."}

    language_hint = choose_browser_probe_language(browser_languages, apple_languages)
    template = BROWSER_PROBE_TEMPLATE.read_text(encoding="utf-8")

    with tempfile.TemporaryDirectory(prefix="network-audit-") as temp_dir_raw:
        temp_dir = pathlib.Path(temp_dir_raw)
        probe_file = temp_dir / "browser_probe.html"
        profile_dir = temp_dir / "browser-profile"
        probe_file.write_text(template, encoding="utf-8")
        profile_dir.mkdir(parents=True, exist_ok=True)

        server, thread = start_probe_server(temp_dir)
        probe_url = f"http://127.0.0.1:{server.server_port}/browser_probe.html"

        cmd = [
            browser_binary,
            "--headless=new",
            "--disable-gpu",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-extensions",
            "--metrics-recording-only",
            "--mute-audio",
            f"--user-data-dir={profile_dir}",
            "--virtual-time-budget=12000",
            "--dump-dom",
        ]
        if language_hint:
            cmd.append(f"--lang={language_hint}")
        cmd.append(probe_url)

        timeout_note = None
        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=25,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            completed = subprocess.CompletedProcess(
                args=cmd,
                returncode=124,
                stdout=exc.stdout.decode("utf-8", errors="replace")
                if isinstance(exc.stdout, bytes)
                else (exc.stdout or ""),
                stderr=exc.stderr.decode("utf-8", errors="replace")
                if isinstance(exc.stderr, bytes)
                else (exc.stderr or ""),
            )
            timeout_note = "Chrome headless did not exit cleanly, but the script captured partial DOM output before termination."

        server.shutdown()
        server.server_close()
        thread.join(timeout=1)

    page_status, page_error, payload = extract_probe_payload(completed.stdout)
    if payload is None:
        return {
            "status": "error",
            "browser_path": browser_binary,
            "language_hint": language_hint,
            "probe_url": probe_url,
            "exit_code": completed.returncode,
            "stderr_excerpt": completed.stderr.strip()[:1200],
            "reason": "Could not parse browser probe payload.",
        }

    return {
        "status": "ok" if page_status == "done" else "error",
        "browser_path": browser_binary,
        "language_hint": language_hint,
        "probe_url": probe_url,
        "exit_code": completed.returncode,
        "page_status": page_status,
        "page_error": page_error,
        "stderr_excerpt": completed.stderr.strip()[:1200],
        "result": payload,
        "note": "The browser probe uses a temporary headless Chrome/Chromium profile to test browser-side WebRTC and request headers."
        + (f" {timeout_note}" if timeout_note else ""),
    }


def make_findings(data: dict[str, object]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []

    collection_errors = data.get("collection_errors", [])
    if isinstance(collection_errors, list) and collection_errors:
        findings.append(
            {
                "severity": "high",
                "title": "Required data collection failed",
                "detail": "; ".join(str(item) for item in collection_errors[:6]),
            }
        )

    public_ip = data.get("public_ip", {})
    if isinstance(public_ip, dict):
        ipapi = public_ip.get("ipapi_is") or {}
        proxycheck = public_ip.get("proxycheck") or {}
        external_flags: list[str] = []

        if isinstance(ipapi, dict):
            for flag_name, label in (
                ("is_datacenter", "datacenter"),
                ("is_proxy", "proxy"),
                ("is_vpn", "vpn"),
                ("is_tor", "tor"),
                ("is_abuser", "abuser"),
            ):
                if truthy_external_flag(ipapi.get(flag_name)):
                    external_flags.append(f"ipapi.is:{label}")
            asn = ipapi.get("asn") or {}
            if isinstance(asn, dict) and str(asn.get("type") or "").lower() == "hosting":
                external_flags.append("ipapi.is:asn_type=hosting")

        if isinstance(proxycheck, dict):
            if truthy_external_flag(proxycheck.get("proxy")):
                external_flags.append(f"proxycheck:proxy={proxycheck.get('type') or 'yes'}")
            risk = proxycheck.get("risk")
            if isinstance(risk, (int, float)) and risk >= 60:
                external_flags.append(f"proxycheck:risk={risk}")

        if external_flags:
            findings.append(
                {
                    "severity": "high",
                    "title": "External IP intelligence flags egress risk",
                    "detail": "; ".join(external_flags),
                }
            )

        ipinfo = public_ip.get("ipinfo") or {}
        ifconfig = public_ip.get("ifconfig") or {}
        org = str(ipinfo.get("org") or ifconfig.get("asn_org") or "")
        hostname = str(ipinfo.get("hostname") or ifconfig.get("hostname") or "")
        if not external_flags and (
            any(keyword in org.lower() for keyword in ("cloud", "hosting", "dmit", "vps"))
            or any(keyword in hostname.lower() for keyword in ("host-", "cloud", "vps"))
        ):
            findings.append(
                {
                    "severity": "high",
                    "title": "Datacenter egress detected",
                    "detail": f"Public egress appears to be a hosting ASN/hostname: {org or hostname}.",
                }
            )

    dns = data.get("dns", {})
    if isinstance(dns, dict):
        nameservers = dns.get("nameservers", [])
        if isinstance(nameservers, list) and any(ns in CN_DNS_HINTS for ns in nameservers):
            findings.append(
                {
                    "severity": "medium",
                    "title": "System DNS points to China-oriented public resolvers",
                    "detail": "At least one configured nameserver matches a common mainland public DNS.",
                }
            )

    env = data.get("locale", {})
    if isinstance(env, dict) and locale_signals_include_chinese(env):
        lang = str(env.get("lang") or "")
        lc_all = str(env.get("lc_all") or "")
        apple_languages = env.get("apple_languages") or []
        apple_locale = str(env.get("apple_locale") or "")
        findings.append(
            {
                "severity": "medium",
                "title": "Local language signals include Chinese",
                "detail": f"LANG={lang or 'unset'}; LC_ALL={lc_all or 'unset'}; AppleLanguages={apple_languages}; AppleLocale={apple_locale or 'unset'}.",
            }
        )

    browsers = data.get("browser_languages", [])
    if isinstance(browsers, list):
        for browser in browsers:
            if not isinstance(browser, dict):
                continue
            last_used = browser.get("last_used")
            for profile in browser.get("profiles", []):
                if not isinstance(profile, dict):
                    continue
                accept_languages = str(profile.get("accept_languages") or "")
                profile_name = str(profile.get("profile") or "")
                if "zh-CN" in accept_languages or accept_languages.startswith("zh"):
                    severity = "high" if last_used and profile_name == last_used else "medium"
                    findings.append(
                        {
                            "severity": severity,
                            "title": f"{browser.get('browser')} profile exposes Chinese Accept-Language",
                            "detail": f"{profile_name}: {accept_languages}",
                        }
                    )

    proxy = data.get("proxy", {})
    if isinstance(proxy, dict) and proxy.get("ProxyAutoDiscoveryEnable") == "1":
        findings.append(
            {
                "severity": "low",
                "title": "WPAD auto proxy discovery is enabled",
                "detail": "Auto proxy discovery adds another proxy-selection path for some apps.",
            }
        )

    proxy_clients = data.get("proxy_clients", [])
    if isinstance(proxy_clients, list) and proxy_clients:
        names = [
            str(client.get("name"))
            for client in proxy_clients
            if isinstance(client, dict) and client.get("name")
        ]
        if names:
            findings.append(
                {
                    "severity": "info",
                    "title": "Proxy client signatures detected",
                    "detail": ", ".join(names),
                }
            )

    clash = data.get("clash", {})
    listeners = data.get("listeners", {})
    if isinstance(clash, dict) and isinstance(listeners, dict):
        excerpts = clash.get("configs") or []
        text = "\n".join(
            "\n".join(config.get("excerpt", [])) for config in excerpts if isinstance(config, dict)
        )
        if "dns-hijack:" in text and listeners.get("tcp_127_0_0_1_53"):
            findings.append(
                {
                    "severity": "info",
                    "title": "Local DNS interception appears active",
                    "detail": "Clash/Mihomo is listening on 127.0.0.1:53 with dns-hijack enabled.",
                }
            )

    browser_probe = data.get("browser_probe", {})
    if isinstance(browser_probe, dict) and browser_probe.get("status") == "ok":
        probe_result = browser_probe.get("result", {})
        if isinstance(probe_result, dict):
            header_echo = probe_result.get("headerEcho", {})
            if isinstance(header_echo, dict):
                accept_language = get_case_insensitive(header_echo.get("headers"), "Accept-Language")
                if accept_language and (
                    "zh-CN" in accept_language or accept_language.lower().startswith("zh")
                ):
                    findings.append(
                        {
                            "severity": "medium",
                            "title": "Browser probe sent Chinese Accept-Language",
                            "detail": f"Echo endpoint saw: {accept_language}",
                        }
                    )

            webrtc = probe_result.get("webrtc", {})
            if isinstance(webrtc, dict):
                candidates = webrtc.get("candidates", [])
                if isinstance(candidates, list):
                    srflx_addresses: set[str] = set()
                    host_private: set[str] = set()
                    mdns_hosts: set[str] = set()
                    for candidate in candidates:
                        if not isinstance(candidate, dict):
                            continue
                        address = str(candidate.get("address") or "")
                        candidate_type = str(candidate.get("candidateType") or "")
                        scope = candidate_address_scope(address)
                        if candidate_type == "host" and scope == "private":
                            host_private.add(address)
                        if candidate_type == "host" and scope == "mdns":
                            mdns_hosts.add(address)
                        if candidate_type == "srflx" and scope == "public":
                            srflx_addresses.add(address)

                    if host_private:
                        findings.append(
                            {
                                "severity": "medium",
                                "title": "Browser WebRTC exposes private host candidates",
                                "detail": "Private host ICE addresses were visible in the browser probe.",
                            }
                        )
                    if mdns_hosts:
                        findings.append(
                            {
                                "severity": "info",
                                "title": "Browser WebRTC local addresses are obfuscated with mDNS",
                                "detail": "Host candidates used `.local` mDNS names instead of raw private IPs.",
                            }
                        )

                    public_ip_value = str(
                        ((data.get("public_ip") or {}).get("ipinfo") or {}).get("ip") or ""
                    )
                    if srflx_addresses and public_ip_value and public_ip_value not in srflx_addresses:
                        findings.append(
                            {
                                "severity": "medium",
                                "title": "Browser WebRTC public candidate differs from HTTP egress IP",
                                "detail": f"HTTP egress={public_ip_value}; WebRTC srflx={', '.join(sorted(srflx_addresses))}",
                            }
                        )

    return findings


def build_recommendations(data: dict[str, object]) -> list[dict[str, str]]:
    recommendations: list[dict[str, str]] = []
    findings = data.get("findings", [])
    finding_titles = {
        str(item.get("title"))
        for item in findings
        if isinstance(item, dict) and item.get("title")
    }

    if (
        "External IP intelligence flags egress risk" in finding_titles
        or "Datacenter egress detected" in finding_titles
    ):
        recommendations.append(
            {
                "priority": "P1",
                "area": "Egress Reputation",
                "action": "If your usage policy requires a lower-friction baseline, test from a long-lived, low-abuse consumer-like egress and avoid frequent IP hopping.",
                "why": "Hosting ASNs are more likely to trigger trust checks than stable end-user networks.",
            }
        )

    if "System DNS points to China-oriented public resolvers" in finding_titles:
        recommendations.append(
            {
                "priority": "P1",
                "area": "DNS Consistency",
                "action": "Reset the active network adapter DNS to Automatic or point it to your local proxy-managed DNS path so it does not advertise mainland public resolvers.",
                "why": "Even when DNS is intercepted later, mismatched resolver settings are an avoidable inconsistency.",
            }
        )

    if "Local language signals include Chinese" in finding_titles:
        recommendations.append(
            {
                "priority": "P2",
                "area": "System Locale",
                "action": "Keep terminal locale, system language order, and timezone internally consistent for the environment you want to test.",
                "why": "Mixed locale signals create an inconsistent device fingerprint across CLI, IDE, and browser contexts.",
            }
        )

    if any("profile exposes Chinese Accept-Language" in title for title in finding_titles):
        recommendations.append(
            {
                "priority": "P2",
                "area": "Browser Profile Hygiene",
                "action": "Use a dedicated browser profile for audits and keep its Accept-Language list aligned with the profile you actually intend to use.",
                "why": "Stored Chrome profile language settings can leak even when system locale looks cleaner.",
            }
        )

    if "Browser WebRTC exposes private host candidates" in finding_titles:
        recommendations.append(
            {
                "priority": "P2",
                "area": "WebRTC Exposure",
                "action": "Verify WebRTC local IP obfuscation is enabled in the browser you actually use and retest until host candidates no longer reveal raw private IPs.",
                "why": "Browser-side WebRTC is one of the few paths that can expose local addressing independently of HTTP proxying.",
            }
        )

    if "WPAD auto proxy discovery is enabled" in finding_titles:
        recommendations.append(
            {
                "priority": "P3",
                "area": "Proxy Determinism",
                "action": "Disable Auto Proxy Discovery on the active network service unless you explicitly rely on WPAD.",
                "why": "It introduces another proxy selection path that can make app behavior less predictable.",
            }
        )

    if not recommendations:
        recommendations.append(
            {
                "priority": "P3",
                "area": "Baseline",
                "action": "Keep rerunning the audit after every proxy, DNS, browser-profile, or locale change and compare the generated JSON reports.",
                "why": "The tool is most useful when you can diff the environment before and after a change.",
            }
        )

    return recommendations


def collect_public_ip(skip_network: bool) -> dict[str, object]:
    public_ip: dict[str, object] = {}
    if skip_network:
        return public_ip
    public_ip["ipapi_is"] = fetch_json("https://api.ipapi.is/json") or {}
    public_ip["ipinfo"] = fetch_json("https://ipinfo.io/json") or {}
    public_ip["ifconfig"] = fetch_json("https://ifconfig.co/json") or {}
    cloudflare_trace = fetch_text("https://www.cloudflare.com/cdn-cgi/trace") or ""
    public_ip["cloudflare_trace"] = cloudflare_trace
    public_ip["cloudflare_trace_parsed"] = parse_cloudflare_trace(cloudflare_trace)
    candidates = public_ip_candidates(public_ip)
    public_ip["observed_ips"] = candidates
    public_ip["proxycheck"] = fetch_proxycheck(candidates[0]) if candidates else {}
    return public_ip


def collect_macos_data(
    *,
    skip_network: bool,
    skip_browser_probe: bool,
    browser_path: str | None,
) -> dict[str, object]:
    now = dt.datetime.now().astimezone()

    proxy_raw = run_command("scutil", "--proxy")
    dns_raw = run_command("scutil", "--dns")
    route_raw = run_command("route", "-n", "get", "default")
    routes_raw = run_command("netstat", "-rn", "-f", "inet")
    tcp_raw = run_command("netstat", "-anv", "-p", "tcp")
    udp_raw = run_command("netstat", "-anv", "-p", "udp")
    network_service_order_raw = run_command("networksetup", "-listnetworkserviceorder")
    network_services_raw = run_command("networksetup", "-listallnetworkservices")
    apple_languages_raw = run_command("defaults", "read", "-g", "AppleLanguages")
    apple_locale_raw = run_command("defaults", "read", "-g", "AppleLocale")
    nwi_raw = run_command("scutil", "--nwi")
    process_raw = run_command("ps", "-axo", "comm=")

    default_route = parse_default_route(str(route_raw.get("stdout", "")))
    active_network = choose_active_network_service(
        default_route.get("interface"),
        parse_network_service_order(str(network_service_order_raw.get("stdout", ""))),
        parse_enabled_network_services(str(network_services_raw.get("stdout", ""))),
    )
    active_service = str(active_network.get("service") or "")

    def run_networksetup_for_service(flag: str) -> dict[str, object]:
        if not active_service:
            return skipped_command_result(
                "networksetup",
                flag,
                "<active-network-service>",
                reason="could not determine an active macOS network service",
            )
        return run_command("networksetup", flag, active_service)

    wifi_dns_raw = run_networksetup_for_service("-getdnsservers")
    wifi_webproxy_raw = run_networksetup_for_service("-getwebproxy")
    wifi_secureproxy_raw = run_networksetup_for_service("-getsecurewebproxy")
    wifi_socks_raw = run_networksetup_for_service("-getsocksfirewallproxy")
    wifi_autoproxy_raw = run_networksetup_for_service("-getautoproxyurl")
    wifi_discovery_raw = run_networksetup_for_service("-getproxyautodiscovery")

    public_ip = collect_public_ip(skip_network)

    clash_configs = [
        config
        for config in (sanitize_clash_excerpt(path) for path in CLASH_CONFIG_CANDIDATES)
        if config is not None
    ]
    proxy_clients = detect_proxy_clients(str(process_raw.get("stdout", "")))

    browser_languages: list[dict[str, object]] = []
    for browser_name, base_path in browser_profile_roots():
        if base_path.exists():
            browser_languages.append(extract_browser_languages(base_path, browser_name))

    apple_languages = parse_defaults_array(str(apple_languages_raw.get("stdout", "")))
    browser_probe = run_browser_probe(
        browser_languages,
        apple_languages,
        skip_browser_probe=skip_browser_probe or skip_network,
        browser_path=browser_path,
    )
    if skip_network and browser_probe.get("status") == "skipped":
        browser_probe["reason"] = "Browser probe was skipped because --skip-network was set."

    data: dict[str, object] = {
        "generated_at": now.isoformat(),
        "host": {
            "platform": sys.platform,
            "project_root": PROJECT_ROOT.name,
        },
        "public_ip": public_ip,
        "proxy": parse_proxy_settings(str(proxy_raw.get("stdout", ""))),
        "dns": {
            "nameservers": parse_dns_nameservers(str(dns_raw.get("stdout", ""))),
            "wifi_dns_raw": str(wifi_dns_raw.get("stdout", "")),
            "nwi": str(nwi_raw.get("stdout", "")),
        },
        "route": {
            "default": default_route,
            "split_tunnel_routes": parse_split_tunnel_routes(str(routes_raw.get("stdout", ""))),
        },
        "active_network": active_network,
        "listeners": parse_listener_summary(
            str(tcp_raw.get("stdout", "")),
            str(udp_raw.get("stdout", "")),
        ),
        "locale": {
            "lang": os.environ.get("LANG"),
            "lc_all": "",
            "tz": os.environ.get("TZ"),
            "apple_languages": apple_languages,
            "apple_locale": str(apple_locale_raw.get("stdout", "")),
            "timestamp": now.strftime("%Y-%m-%d %H:%M:%S %Z %z"),
        },
        "browser_languages": browser_languages,
        "browser_probe": browser_probe,
        "networksetup": {
            "service": active_service,
            "web_proxy": parse_key_value_block(str(wifi_webproxy_raw.get("stdout", ""))),
            "secure_web_proxy": parse_key_value_block(str(wifi_secureproxy_raw.get("stdout", ""))),
            "socks_proxy": parse_key_value_block(str(wifi_socks_raw.get("stdout", ""))),
            "auto_proxy_url": parse_key_value_block(str(wifi_autoproxy_raw.get("stdout", ""))),
            "auto_proxy_discovery": str(wifi_discovery_raw.get("stdout", "")),
        },
        "clash": {"configs": clash_configs},
        "proxy_clients": proxy_clients,
        "raw_command_status": {
            "proxy": proxy_raw,
            "dns": dns_raw,
            "route": route_raw,
            "routes": routes_raw,
            "tcp": tcp_raw,
            "udp": udp_raw,
            "network_service_order": network_service_order_raw,
            "network_services": network_services_raw,
            "processes": process_raw,
        },
    }
    data["findings"] = make_findings(data)
    data["recommendations"] = build_recommendations(data)
    return data


def parse_windows_proxy_registry(raw: str) -> dict[str, object]:
    settings: dict[str, object] = {}
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or "REG_" not in stripped:
            continue
        parts = stripped.split(None, 2)
        if len(parts) == 3:
            settings[parts[0]] = parts[2].strip()
    return settings


def collect_windows_data(
    *,
    skip_network: bool,
    skip_browser_probe: bool,
    browser_path: str | None,
) -> dict[str, object]:
    now = dt.datetime.now().astimezone()

    ipconfig_raw = run_command("ipconfig", "/all", timeout=10)
    route_raw = run_command("route", "print", timeout=10)
    tcp_raw = run_command("netstat", "-ano", "-p", "tcp", timeout=10)
    udp_raw = run_command("netstat", "-ano", "-p", "udp", timeout=10)
    winhttp_proxy_raw = run_command("netsh", "winhttp", "show", "proxy", timeout=10)
    user_proxy_raw = run_command(
        "reg",
        "query",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        timeout=10,
    )
    interface_raw = run_command(
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty InterfaceAlias",
        timeout=10,
    )
    process_raw = run_command(
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-Process | ForEach-Object { if ($_.Path) { $_.Path } else { $_.ProcessName } }",
        timeout=10,
    )
    culture_raw = run_command(
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-Culture | Select-Object -ExpandProperty Name",
        timeout=10,
    )
    system_locale_raw = run_command(
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-WinSystemLocale | Select-Object -ExpandProperty Name",
        timeout=10,
    )
    timezone_raw = run_command("tzutil", "/g", timeout=10)

    public_ip = collect_public_ip(skip_network)
    browser_languages: list[dict[str, object]] = []
    for browser_name, base_path in browser_profile_roots():
        if base_path.exists():
            browser_languages.append(extract_browser_languages(base_path, browser_name))

    browser_probe = run_browser_probe(
        browser_languages,
        [],
        skip_browser_probe=skip_browser_probe or skip_network,
        browser_path=browser_path,
    )
    if skip_network and browser_probe.get("status") == "skipped":
        browser_probe["reason"] = "Browser probe was skipped because --skip-network was set."

    raw_command_status = {
        "ipconfig": ipconfig_raw,
        "route": route_raw,
        "tcp": tcp_raw,
        "udp": udp_raw,
        "winhttp_proxy": winhttp_proxy_raw,
        "user_proxy": user_proxy_raw,
        "interface": interface_raw,
        "processes": process_raw,
        "culture": culture_raw,
        "system_locale": system_locale_raw,
        "timezone": timezone_raw,
    }
    collection_errors = command_failure_notes(
        raw_command_status,
        (
            "ipconfig",
            "route",
            "tcp",
            "udp",
            "winhttp_proxy",
            "user_proxy",
            "interface",
            "processes",
            "culture",
            "system_locale",
            "timezone",
        ),
    )

    windows_proxy = parse_windows_proxy_registry(command_stdout(user_proxy_raw))
    active_interface = command_stdout(interface_raw)
    proxy_clients = detect_proxy_clients(command_stdout(process_raw))

    data: dict[str, object] = {
        "generated_at": now.isoformat(),
        "host": {
            "platform": sys.platform,
            "project_root": PROJECT_ROOT.name,
        },
        "public_ip": public_ip,
        "collection_errors": collection_errors,
        "proxy": windows_proxy,
        "dns": {
            "nameservers": parse_windows_ipconfig_dns(command_stdout(ipconfig_raw)),
            "wifi_dns_raw": command_stdout(ipconfig_raw),
            "nwi": "",
        },
        "route": {
            "default": {"interface": active_interface},
            "split_tunnel_routes": [],
        },
        "active_network": {
            "service": "Windows",
            "interface": active_interface,
            "source": "Get-NetRoute",
        },
        "listeners": parse_listener_summary(
            str(tcp_raw.get("stdout", "")),
            str(udp_raw.get("stdout", "")),
        ),
        "locale": {
            "lang": command_stdout(culture_raw),
            "lc_all": "",
            "tz": command_stdout(timezone_raw),
            "apple_languages": [],
            "apple_locale": command_stdout(system_locale_raw),
            "timestamp": now.strftime("%Y-%m-%d %H:%M:%S %Z %z"),
        },
        "browser_languages": browser_languages,
        "browser_probe": browser_probe,
        "networksetup": {
            "service": "Windows",
            "web_proxy": windows_proxy,
            "secure_web_proxy": windows_proxy,
            "socks_proxy": windows_proxy,
            "auto_proxy_url": {"AutoConfigURL": windows_proxy.get("AutoConfigURL", "")},
            "auto_proxy_discovery": command_stdout(winhttp_proxy_raw),
        },
        "clash": {"configs": []},
        "proxy_clients": proxy_clients,
        "raw_command_status": raw_command_status,
    }
    data["findings"] = make_findings(data)
    data["recommendations"] = build_recommendations(data)
    return data


def collect_data(
    *,
    skip_network: bool,
    skip_browser_probe: bool,
    browser_path: str | None,
) -> dict[str, object]:
    if sys.platform == "darwin":
        return collect_macos_data(
            skip_network=skip_network,
            skip_browser_probe=skip_browser_probe,
            browser_path=browser_path,
        )
    if sys.platform == "win32":
        return collect_windows_data(
            skip_network=skip_network,
            skip_browser_probe=skip_browser_probe,
            browser_path=browser_path,
        )
    raise RuntimeError("This tool currently supports macOS and Windows only.")


def severity_label(level: str) -> str:
    return {
        "high": "高风险",
        "medium": "中风险",
        "low": "低风险",
        "info": "信息",
    }.get(level, level)


def probe_status_label(status: str | None) -> str:
    return {
        "ok": "成功",
        "error": "失败",
        "skipped": "已跳过",
        "unavailable": "不可用",
    }.get(status or "", status or "未知")


def browser_probe_result_label(status: str, candidates: list[object]) -> str:
    if status == "skipped":
        return "未检测"
    if status == "unavailable":
        return "浏览器不可用"
    if status == "error":
        return "检测失败"
    if status != "ok":
        return "未知"

    counts = browser_webrtc_candidate_counts(candidates)
    if counts["private"]:
        return "发现本机内网 IP 泄露"
    if counts["mdns"]:
        return "未发现本机内网 IP 泄露"
    if counts["public"]:
        return "未发现本机内网 IP 泄露"
    return "未看到 WebRTC 暴露地址"


def browser_webrtc_candidate_counts(candidates: list[object]) -> dict[str, int]:
    private_count = 0
    public_count = 0
    mdns_count = 0
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        candidate_type = str(candidate.get("candidateType") or "")
        scope = candidate_address_scope(str(candidate.get("address") or ""))
        if candidate_type == "host" and scope == "private":
            private_count += 1
        elif scope == "public":
            public_count += 1
        elif candidate_type == "host" and scope == "mdns":
            mdns_count += 1

    return {"private": private_count, "public": public_count, "mdns": mdns_count}


def browser_probe_result_detail(status: str, candidates: list[object]) -> str:
    if status != "ok":
        return ""
    counts = browser_webrtc_candidate_counts(candidates)
    if counts["private"]:
        return f"WebRTC 返回了 {counts['private']} 个本机内网地址，目标网站可能看到你的局域网地址。"
    if counts["mdns"]:
        return "浏览器只暴露了匿名 .local 地址，没有直接暴露本机内网 IP。"
    if counts["public"]:
        return "WebRTC 只返回了公网候选，没有看到本机内网地址。"
    return "没有采集到可展示的 WebRTC 地址。"


def browser_probe_problem_note(browser_probe: dict[str, object]) -> str:
    status = str(browser_probe.get("status") or "")
    if status == "ok":
        return ""
    reason = localize_browser_probe_reason(str(browser_probe.get("reason") or ""))
    page_error = str(browser_probe.get("page_error") or "")
    stderr = str(browser_probe.get("stderr_excerpt") or "")
    return reason or page_error or stderr[:240]


def format_value(value: object) -> str:
    if value in (None, ""):
        return "未知"
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def localize_finding(item: dict[str, object]) -> tuple[str, str]:
    title = str(item.get("title") or "")
    detail = str(item.get("detail") or "")

    if title == "Datacenter egress detected":
        return (
            "出口为数据中心/机房网络",
            detail.replace(
                "Public egress appears to be a hosting ASN/hostname: ",
                "公网出口 ASN / 主机名显示为托管网络：",
            ),
        )
    if title == "External IP intelligence flags egress risk":
        return ("外部 IP 情报标记出口风险", detail.replace("; ", "；"))
    if title == "System DNS points to China-oriented public resolvers":
        return ("系统 DNS 指向中国公共解析器", "系统当前配置的解析器里包含常见中国公共 DNS。")
    if title == "Local language signals include Chinese":
        return ("本机语言信号包含中文", detail.replace("; ", "；"))
    match = re.match(r"^(?P<browser>.+) profile exposes Chinese Accept-Language$", title)
    if match:
        return (f"{match.group('browser')} 配置文件暴露中文 Accept-Language", f"检测到 {detail}。")
    if title == "WPAD auto proxy discovery is enabled":
        return ("系统开启了 WPAD 自动代理发现", "自动代理发现会为部分应用增加额外的代理选择路径。")
    if title == "Proxy client signatures detected":
        return ("检测到代理客户端线索", f"本机存在这些代理客户端进程或配置路径：{detail}。")
    if title == "Local DNS interception appears active":
        return ("本地 DNS 劫持看起来是生效的", "Clash/Mihomo 正在监听 127.0.0.1:53，并启用了 DNS 劫持。")
    if title == "Browser probe sent Chinese Accept-Language":
        return ("浏览器探针实际发出了中文语言头", detail.replace("Echo endpoint saw: ", "回显站点看到的 Accept-Language 为："))
    if title == "Browser WebRTC exposes private host candidates":
        return ("WebRTC 暴露了本机内网 IP", "目标网站可能通过浏览器看到你的局域网地址。")
    if title == "Browser WebRTC local addresses are obfuscated with mDNS":
        return ("未发现 WebRTC 内网 IP 泄露", "浏览器只显示匿名 `.local` 地址，没有直接暴露本机内网 IP。")
    if title == "Browser WebRTC public candidate differs from HTTP egress IP":
        return (
            "浏览器 WebRTC 公网候选与 HTTP 出口不一致",
            detail.replace("HTTP egress=", "HTTP 出口=").replace("; WebRTC srflx=", "；WebRTC srflx="),
        )
    return (title, detail)


def localize_recommendation(item: dict[str, object]) -> tuple[str, str, str, str]:
    priority = str(item.get("priority") or "P3")
    area = str(item.get("area") or "")
    mapping = {
        "Egress Reputation": (
            "出口信誉",
            "如果你的目标是做低干扰基线测试，优先使用长期稳定、低滥用记录的消费级出口，避免频繁切换 IP。",
            "托管 ASN 比稳定终端网络更容易触发额外信任校验。",
        ),
        "DNS Consistency": (
            "DNS 一致性",
            "把当前网络服务的 DNS 恢复为自动，或明确指向本地代理管理的 DNS 路径，不要保留中国公共 DNS。",
            "即使后续还有 DNS 劫持，系统层配置不一致本身也是一个可避免的信号。",
        ),
        "System Locale": (
            "系统语言/区域",
            "让终端语言、系统语言顺序和时区保持一致，不要出现混合区域设定。",
            "CLI、IDE 和浏览器看到的语言/区域如果不一致，会形成更杂乱的设备指纹。",
        ),
        "Browser Profile Hygiene": (
            "浏览器配置文件",
            "为审计和日常使用分开浏览器 profile，并确保实际使用的 profile 的 Accept-Language 符合预期。",
            "Chrome profile 自己保存的语言设置会单独暴露，不会被系统语言完全覆盖。",
        ),
        "WebRTC Exposure": (
            "WebRTC 暴露面",
            "确认你真正使用的浏览器已经开启本地 IP 混淆，再重新跑探针，直到 host 候选不再暴露原始私网地址。",
            "WebRTC 是少数可能绕开普通 HTTP 代理语义、单独暴露本地网络信息的路径。",
        ),
        "Proxy Determinism": (
            "代理确定性",
            "如果你并不依赖 WPAD，就把 Auto Proxy Discovery 关掉，减少代理选择的不确定性。",
            "多一条自动代理发现路径，就多一层“某些应用走法不一致”的风险。",
        ),
        "Baseline": (
            "基线对比",
            "每次调整代理、DNS、浏览器 profile 或语言设置后，重新跑一次审计，并对比 JSON 报告差异。",
            "这个工具最有价值的场景，是让你看见改动前后到底少了哪些信号。",
        ),
    }
    localized = mapping.get(area, (area, str(item.get("action") or ""), str(item.get("why") or "")))
    return (priority, localized[0], localized[1], localized[2])


def localize_browser_probe_reason(text: str | None) -> str:
    if not text:
        return ""
    mapping = {
        "Browser probe was skipped by configuration.": "本次未运行浏览器侧检测。",
        "Browser probe was skipped because --skip-network was set.": "由于传入了 --skip-network，本次未运行浏览器侧检测。",
        "No supported browser binary was found.": "未找到可用的 Chrome / Chromium / Edge 浏览器可执行文件。",
        "Could not parse browser probe payload.": "无法解析浏览器探针返回的数据。",
    }
    return mapping.get(text, text)


def localize_browser_probe_note(text: str | None) -> str:
    if not text:
        return ""
    translated = text.replace(
        "The browser probe uses a temporary headless Chrome/Chromium profile to test browser-side WebRTC and request headers.",
        "浏览器探针会启动一个临时的 headless Chrome/Chromium profile，用来测试浏览器侧的 WebRTC 与请求头暴露。",
    )
    translated = translated.replace(
        "Chrome headless did not exit cleanly, but the script captured partial DOM output before termination.",
        "Chrome headless 没有优雅退出，但脚本已经在终止前拿到了完整页面结果。",
    )
    return translated


def render_markdown(data: dict[str, object]) -> str:
    host = data.get("host", {})
    lines = [
        "# 网络环境指纹审计报告",
        "",
        f"- 生成时间：{data.get('generated_at')}",
        f"- 平台：{host.get('platform')}",
        f"- 项目：{host.get('project_root')}",
        "",
        "## 主要发现",
        "",
    ]

    findings = data.get("findings", [])
    if isinstance(findings, list) and findings:
        for item in findings:
            if not isinstance(item, dict):
                continue
            title, detail = localize_finding(item)
            lines.append(f"- [{severity_label(str(item.get('severity') or 'info'))}] {title}：{detail}")
    else:
        lines.append("- 当前没有发现明显的高信号不一致项。")

    recommendations = data.get("recommendations", [])
    if isinstance(recommendations, list) and recommendations:
        lines.extend(["", "## 修复建议", ""])
        for item in recommendations:
            if not isinstance(item, dict):
                continue
            priority, area, action, why = localize_recommendation(item)
            lines.append(f"- [{priority}] {area}：{action} 原因：{why}")

    public_ip = data.get("public_ip", {})
    if isinstance(public_ip, dict):
        summary = public_ip_summary(public_ip)
        lines.extend(
            [
                "",
                "## 公网出口",
                "",
                f"- IP：{summary.get('ip') or '未知'}",
                f"- 观测到的 IP：{', '.join(summary.get('observed_ips', [])) or '未知'}",
                f"- ASN / 组织：{summary.get('asn_org') or '未知'}",
                f"- 位置：{summary.get('city') or '未知'}，{summary.get('region') or ''} {summary.get('country') or ''}".strip(),
                f"- 时区：{summary.get('timezone') or '未知'}",
                f"- ipapi.is 风险：{summary.get('ipapi_flags')}",
                f"- proxycheck 风险：{summary.get('proxycheck_flags')}",
            ]
        )

    dns = data.get("dns", {})
    if isinstance(dns, dict):
        lines.extend(
            [
                "",
                "## DNS 信号",
                "",
                f"- `scutil --dns` 解析器：{', '.join(dns.get('nameservers', [])) or '无'}",
                f"- 当前网络服务 DNS：{dns.get('wifi_dns_raw') or '未知'}",
                f"- NWI 摘要：`{str(dns.get('nwi', '')).replace(chr(10), ' | ')}`",
            ]
        )

    locale = data.get("locale", {})
    if isinstance(locale, dict):
        lines.extend(
            [
                "",
                "## 语言与区域",
                "",
                f"- LANG：{locale.get('lang') or '未设置'}",
                f"- LC_ALL：{locale.get('lc_all') or '未设置'}",
                f"- AppleLanguages：{locale.get('apple_languages') or []}",
                f"- AppleLocale：{locale.get('apple_locale') or '未知'}",
                f"- 本地时间：{locale.get('timestamp') or '未知'}",
            ]
        )

    active_network = data.get("active_network", {})
    if isinstance(active_network, dict):
        lines.extend(
            [
                "",
                "## 当前活跃网络服务",
                "",
                f"- 服务名：{active_network.get('service') or '未知'}",
                f"- 接口：{active_network.get('interface') or '未知'}",
                f"- 识别来源：{active_network.get('source') or '未知'}",
            ]
        )

    browsers = data.get("browser_languages", [])
    if isinstance(browsers, list):
        lines.extend(["", "## 浏览器配置语言", ""])
        for browser in browsers:
            if not isinstance(browser, dict):
                continue
            lines.append(f"- {browser.get('browser')}，最近使用 profile：{browser.get('last_used') or '未知'}")
            for profile in browser.get("profiles", []):
                if not isinstance(profile, dict):
                    continue
                lines.append(f"  - {profile.get('profile')}：{profile.get('accept_languages')}")

    browser_probe = data.get("browser_probe", {})
    if isinstance(browser_probe, dict):
        lines.extend(["", "## 浏览器侧探针", ""])
        probe_result = browser_probe.get("result", {})
        candidates: list[object] = []
        if isinstance(probe_result, dict):
            webrtc_data = probe_result.get("webrtc", {})
            if isinstance(webrtc_data, dict) and isinstance(webrtc_data.get("candidates"), list):
                candidates = webrtc_data["candidates"]
        browser_status = str(browser_probe.get("status") or "")
        lines.append(f"- WebRTC 结论：{browser_probe_result_label(browser_status, candidates)}")
        if browser_status == "ok":
            detail = browser_probe_result_detail(browser_status, candidates)
            if detail:
                lines.append(f"- 说明：{detail}")
        else:
            note = browser_probe_problem_note(browser_probe)
            if note:
                lines.append(f"- 检测说明：{note}")

        if isinstance(probe_result, dict):
            navigator_info = probe_result.get("navigator", {})
            header_echo = probe_result.get("headerEcho", {})
            webrtc = probe_result.get("webrtc", {})

            if isinstance(navigator_info, dict):
                lines.append(f"- `navigator.language`：{navigator_info.get('language')}")
                lines.append(f"- `navigator.languages`：{navigator_info.get('languages')}")
                lines.append(f"- 浏览器 User-Agent：{navigator_info.get('userAgent')}")
                lines.append(f"- 浏览器时区：{navigator_info.get('timezone')}")

            if isinstance(header_echo, dict):
                lines.append(f"- 回显 URL：{header_echo.get('url')}")
                lines.append(f"- 回显站点看到的出口 IP：{header_echo.get('origin')}")
                accept_language = get_case_insensitive(header_echo.get("headers"), "Accept-Language")
                user_agent = get_case_insensitive(header_echo.get("headers"), "User-Agent")
                lines.append(f"- 回显 Accept-Language：{accept_language or '缺失'}")
                lines.append(f"- 回显 User-Agent：{user_agent or '缺失'}")

            if isinstance(webrtc, dict):
                candidates = webrtc.get("candidates", [])
                lines.append(f"- WebRTC 是否可用：{webrtc.get('supported')}")
                lines.append(f"- WebRTC 地址数量：{len(candidates) if isinstance(candidates, list) else 0}")
                if isinstance(candidates, list):
                    for candidate in candidates:
                        if not isinstance(candidate, dict):
                            continue
                        lines.append(
                            f"  - {candidate.get('candidateType')} | {candidate.get('protocol')} | {candidate.get('address')}:{candidate.get('port')}"
                        )

    networksetup = data.get("networksetup", {})
    if isinstance(networksetup, dict):
        lines.extend(
            [
                "",
                "## 代理设置",
                "",
                f"- Web 代理：{networksetup.get('web_proxy')}",
                f"- HTTPS 代理：{networksetup.get('secure_web_proxy')}",
                f"- SOCKS 代理：{networksetup.get('socks_proxy')}",
                f"- 自动代理 URL：{networksetup.get('auto_proxy_url')}",
                f"- 自动代理发现：{networksetup.get('auto_proxy_discovery')}",
            ]
        )

    proxy_clients = data.get("proxy_clients", [])
    if isinstance(proxy_clients, list):
        lines.extend(["", "## 代理客户端识别", ""])
        if proxy_clients:
            for client in proxy_clients:
                if not isinstance(client, dict):
                    continue
                lines.append(f"- {client.get('name')}")
                processes = client.get("processes", [])
                if isinstance(processes, list) and processes:
                    lines.append(f"  - 进程：{', '.join(str(item) for item in processes)}")
                paths = client.get("paths", [])
                if isinstance(paths, list) and paths:
                    lines.append(f"  - 路径：{', '.join(str(item) for item in paths)}")
                configs = client.get("configs", [])
                if isinstance(configs, list):
                    for config in configs:
                        if not isinstance(config, dict):
                            continue
                        lines.append(f"  - 配置摘要：{config.get('path')}")
                        for excerpt in config.get("excerpt", []):
                            lines.append(f"    - `{excerpt}`")
        else:
            lines.append("- 未发现已知代理客户端进程或配置路径。")

    return "\n".join(lines) + "\n"


def render_html_legacy(data: dict[str, object]) -> str:
    findings = [item for item in data.get("findings", []) if isinstance(item, dict)]
    recommendations = [item for item in data.get("recommendations", []) if isinstance(item, dict)]
    high_count = sum(1 for item in findings if item.get("severity") == "high")
    medium_count = sum(1 for item in findings if item.get("severity") == "medium")
    low_count = sum(1 for item in findings if item.get("severity") == "low")
    info_count = sum(1 for item in findings if item.get("severity") == "info")
    total_findings = len(findings)

    public_ip = data.get("public_ip", {}) if isinstance(data.get("public_ip"), dict) else {}
    public_summary = public_ip_summary(public_ip)

    browser_probe = data.get("browser_probe", {}) if isinstance(data.get("browser_probe"), dict) else {}
    probe_result = browser_probe.get("result", {}) if isinstance(browser_probe.get("result"), dict) else {}
    navigator_info = probe_result.get("navigator", {}) if isinstance(probe_result.get("navigator"), dict) else {}
    header_echo = probe_result.get("headerEcho", {}) if isinstance(probe_result.get("headerEcho"), dict) else {}
    webrtc = probe_result.get("webrtc", {}) if isinstance(probe_result.get("webrtc"), dict) else {}

    def esc(value: object) -> str:
        return html.escape(format_value(value))

    accept_language = get_case_insensitive(header_echo.get("headers"), "Accept-Language")
    user_agent = get_case_insensitive(header_echo.get("headers"), "User-Agent")

    def chip(level: str) -> str:
        return f'<span class="chip chip-{html.escape(level)}">{html.escape(severity_label(level))}</span>'

    def render_table(headers: list[str], rows: list[list[str]], empty_text: str) -> str:
        if not rows:
            return f'<p class="empty">{html.escape(empty_text)}</p>'
        head = "".join(f"<th>{html.escape(header)}</th>" for header in headers)
        body_rows = []
        for row in rows:
            body_rows.append("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>")
        return f"""
        <div class="table-wrap">
          <table class="report-table">
            <thead><tr>{head}</tr></thead>
            <tbody>{''.join(body_rows)}</tbody>
          </table>
        </div>
        """

    def meter_row(label: str, value: int, css_class: str) -> str:
        width = 0 if total_findings == 0 else max(6, round(value / total_findings * 100))
        if value == 0:
            width = 0
        return f"""
        <div class="meter-row">
          <div class="meter-meta"><span>{html.escape(label)}</span><strong>{value}</strong></div>
          <div class="meter-track"><div class="meter-fill {css_class}" style="width:{width}%"></div></div>
        </div>
        """

    overview_findings = []
    for item in findings[:4]:
        title, detail = localize_finding(item)
        overview_findings.append(
            f"<li>{chip(str(item.get('severity') or 'info'))}<div><strong>{html.escape(title)}</strong><p>{html.escape(detail)}</p></div></li>"
        )

    finding_rows = []
    for item in findings:
        title, detail = localize_finding(item)
        finding_rows.append(
            [
                chip(str(item.get("severity") or "info")),
                html.escape(title),
                html.escape(detail),
            ]
        )

    recommendation_cards = []
    for item in recommendations:
        priority, area, action, why = localize_recommendation(item)
        recommendation_cards.append(
            f"""
            <article class="recommend-card">
              <div class="recommend-top">
                <span class="priority">{html.escape(priority)}</span>
                <h3>{html.escape(area)}</h3>
              </div>
              <p>{html.escape(action)}</p>
              <p class="why">原因：{html.escape(why)}</p>
            </article>
            """
        )

    browser_profile_rows: list[list[str]] = []
    for browser in data.get("browser_languages", []):
        if not isinstance(browser, dict):
            continue
        last_used = str(browser.get("last_used") or "")
        profiles = browser.get("profiles", [])
        if not isinstance(profiles, list) or not profiles:
            browser_profile_rows.append(
                [html.escape(str(browser.get("browser") or "浏览器")), "未发现", "未发现", html.escape(last_used or "未知")]
            )
            continue
        for profile in profiles:
            if not isinstance(profile, dict):
                continue
            current_name = str(profile.get("profile") or "未知")
            is_active = "是" if current_name == last_used and last_used else ""
            browser_profile_rows.append(
                [
                    html.escape(str(browser.get("browser") or "浏览器")),
                    html.escape(current_name),
                    html.escape(str(profile.get("accept_languages") or "未知")),
                    html.escape(is_active or "否"),
                ]
            )

    probe_rows = [
        ["状态", html.escape(probe_status_label(str(browser_probe.get("status") or "")))],
        ["浏览器", esc(browser_probe.get("browser_path"))],
        ["语言提示", esc(browser_probe.get("language_hint"))],
        ["备注", html.escape(localize_browser_probe_note(str(browser_probe.get("note") or "")) or localize_browser_probe_reason(str(browser_probe.get("reason") or "")) or "无")],
        ["navigator.language", esc(navigator_info.get("language"))],
        ["navigator.languages", esc(navigator_info.get("languages"))],
        ["浏览器时区", esc(navigator_info.get("timezone"))],
        ["回显站点看到的 IP", esc(header_echo.get("origin"))],
        ["Accept-Language", esc(accept_language)],
        ["User-Agent", esc(user_agent)],
    ]

    candidate_rows = []
    for candidate in webrtc.get("candidates", []):
        if not isinstance(candidate, dict):
            continue
        scope = candidate_address_scope(str(candidate.get("address") or ""))
        scope_text = {
            "mdns": "匿名 .local 地址",
            "private": "私网",
            "public": "公网",
            "hostname": "主机名",
            "unknown": "未知",
        }.get(scope, scope)
        candidate_rows.append(
            [
                html.escape(str(candidate.get("candidateType") or "unknown")),
                html.escape(str(candidate.get("protocol") or "unknown")),
                f"<code>{html.escape(str(candidate.get('address') or 'unknown'))}:{html.escape(str(candidate.get('port') or 'unknown'))}</code>",
                html.escape(scope_text),
            ]
        )

    network_rows = [
        ["公网 IP", esc(public_summary.get("ip"))],
        ["观测到的 IP", esc(", ".join(public_summary.get("observed_ips", [])))],
        ["ASN / 组织", esc(public_summary.get("asn_org"))],
        ["位置", esc(f"{public_summary.get('city') or '未知'}，{public_summary.get('region') or ''} {public_summary.get('country') or ''}")],
        ["时区", esc(public_summary.get("timezone"))],
        ["ipapi.is 风险", esc(public_summary.get("ipapi_flags"))],
        ["proxycheck 风险", esc(public_summary.get("proxycheck_flags"))],
        ["活跃网络服务", esc((data.get("active_network") or {}).get("service"))],
        ["活跃接口", esc((data.get("active_network") or {}).get("interface"))],
        ["系统 DNS", esc(", ".join((data.get("dns") or {}).get("nameservers", [])))],
        ["当前网络服务 DNS", esc((data.get("dns") or {}).get("wifi_dns_raw"))],
        ["LANG", esc((data.get("locale") or {}).get("lang"))],
        ["LC_ALL", esc((data.get("locale") or {}).get("lc_all"))],
        ["AppleLanguages", esc((data.get("locale") or {}).get("apple_languages"))],
        ["AppleLocale", esc((data.get("locale") or {}).get("apple_locale"))],
        ["本地时间", esc((data.get("locale") or {}).get("timestamp"))],
    ]

    route_rows = []
    default_route = (data.get("route") or {}).get("default") or {}
    if isinstance(default_route, dict):
        for key in ("gateway", "interface", "destination", "mask"):
            route_rows.append([html.escape(key), esc(default_route.get(key))])
    split_routes = (data.get("route") or {}).get("split_tunnel_routes") or []
    if isinstance(split_routes, list):
        route_rows.append(["TUN 分流条目数", html.escape(str(len(split_routes)))])

    listener_rows = []
    listeners = data.get("listeners") or {}
    if isinstance(listeners, dict):
        listener_rows = [
            ["127.0.0.1:53 TCP", "监听中" if listeners.get("tcp_127_0_0_1_53") else "未监听"],
            ["127.0.0.1:53 UDP", "监听中" if listeners.get("udp_127_0_0_1_53") else "未监听"],
            ["127.0.0.1:7890 TCP", "监听中" if listeners.get("tcp_127_0_0_1_7890") else "未监听"],
        ]

    proxy_rows = [
        ["Web 代理", esc((data.get("networksetup") or {}).get("web_proxy"))],
        ["HTTPS 代理", esc((data.get("networksetup") or {}).get("secure_web_proxy"))],
        ["SOCKS 代理", esc((data.get("networksetup") or {}).get("socks_proxy"))],
        ["自动代理 URL", esc((data.get("networksetup") or {}).get("auto_proxy_url"))],
        ["自动代理发现", esc((data.get("networksetup") or {}).get("auto_proxy_discovery"))],
    ]

    client_details = []
    proxy_clients = data.get("proxy_clients", [])
    if isinstance(proxy_clients, list):
        for client in proxy_clients:
            if not isinstance(client, dict):
                continue
            processes = client.get("processes", [])
            paths = client.get("paths", [])
            configs = client.get("configs", [])
            summary_rows = [
                ["进程线索", esc(", ".join(str(item) for item in processes) if isinstance(processes, list) and processes else "未发现")],
                ["配置路径", esc(", ".join(str(item) for item in paths) if isinstance(paths, list) and paths else "未发现")],
            ]
            config_blocks = []
            if isinstance(configs, list):
                for config in configs:
                    if not isinstance(config, dict):
                        continue
                    excerpt = "\n".join(str(line) for line in config.get("excerpt", []))
                    config_blocks.append(
                        f"""
                        <details class="details-block">
                          <summary>{html.escape(str(config.get("path") or "配置文件"))}</summary>
                          <pre>{html.escape(excerpt)}</pre>
                        </details>
                        """
                    )
            client_details.append(
                f"""
                <article class="evidence">
                  <h3>{html.escape(str(client.get("name") or "代理客户端"))}</h3>
                  {render_table(summary_rows, "暂无客户端线索。")}
                  {"".join(config_blocks)}
                </article>
                """
            )

    if not client_details:
        client_details.append(
            '<article class="evidence"><h3>未发现已知客户端</h3><p class="empty">仍会继续基于系统代理、路由、DNS、出口和浏览器结果进行通用审计。</p></article>'
        )

    clash_details = []
    for config in (data.get("clash", {}) or {}).get("configs", []):
        if not isinstance(config, dict):
            continue
        excerpt = "\n".join(str(line) for line in config.get("excerpt", []))
        clash_details.append(
            f"""
            <details class="detail-block">
              <summary>{html.escape(str(config.get("path") or "配置文件"))}</summary>
              <pre>{html.escape(excerpt)}</pre>
            </details>
            """
        )

    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>网络环境指纹审计报告</title>
  <style>
    :root {{
      --bg: #eef2f6;
      --sidebar: #101720;
      --sidebar-line: rgba(255,255,255,0.1);
      --panel: #ffffff;
      --panel-alt: #f8fafc;
      --ink: #18212b;
      --muted: #667483;
      --line: #d7e0ea;
      --accent: #1f6feb;
      --high: #d43d2a;
      --medium: #d27a00;
      --low: #2d8a59;
      --info: #596b95;
      --shadow: 0 14px 42px rgba(10, 24, 40, 0.08);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      color: var(--ink);
      background: linear-gradient(180deg, #eef2f6 0%, #e9eef4 100%);
      font-family: "Avenir Next", "Segoe UI", "Helvetica Neue", Arial, sans-serif;
      line-height: 1.55;
    }}
    .layout {{
      display: grid;
      grid-template-columns: 280px minmax(0, 1fr);
      min-height: 100vh;
    }}
    aside {{
      position: sticky;
      top: 0;
      align-self: start;
      height: 100vh;
      padding: 28px 22px;
      background:
        radial-gradient(circle at top left, rgba(70, 120, 255, 0.18), transparent 30%),
        linear-gradient(180deg, #101720 0%, #15202c 100%);
      color: #eff4fb;
      border-right: 1px solid var(--sidebar-line);
    }}
    .brand {{
      font-size: 12px;
      letter-spacing: 0.14em;
      text-transform: uppercase;
      color: #93b8ff;
      margin-bottom: 14px;
    }}
    aside h1 {{
      margin: 0 0 10px;
      font-size: 28px;
      line-height: 1.05;
      font-weight: 700;
    }}
    .sidebar-copy {{
      color: rgba(239,244,251,0.72);
      font-size: 14px;
      margin-bottom: 22px;
    }}
    .sidebar-meta {{
      display: grid;
      gap: 10px;
      padding: 16px;
      border-radius: 18px;
      background: rgba(255,255,255,0.04);
      border: 1px solid rgba(255,255,255,0.08);
      margin-bottom: 18px;
    }}
    .sidebar-meta label {{
      display: block;
      font-size: 11px;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: rgba(147,184,255,0.82);
      margin-bottom: 4px;
    }}
    .sidebar-meta span {{
      display: block;
      word-break: break-word;
      font-size: 14px;
    }}
    .nav {{
      display: grid;
      gap: 8px;
      margin-top: 16px;
    }}
    .nav a {{
      display: flex;
      justify-content: space-between;
      gap: 12px;
      color: #eff4fb;
      text-decoration: none;
      padding: 10px 12px;
      border-radius: 12px;
      background: rgba(255,255,255,0.03);
      border: 1px solid transparent;
    }}
    .nav a:hover {{
      border-color: rgba(147,184,255,0.35);
      background: rgba(147,184,255,0.08);
    }}
    main {{
      padding: 28px 32px 44px;
      width: min(1280px, 100%);
    }}
    .report-hero, section {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 22px;
      box-shadow: var(--shadow);
    }}
    .report-hero {{
      padding: 26px;
    }}
    .eyebrow {{
      letter-spacing: 0.16em;
      text-transform: uppercase;
      color: var(--accent);
      font-size: 12px;
      margin-bottom: 10px;
    }}
    .report-hero h2 {{
      margin: 0;
      font-size: clamp(30px, 4vw, 44px);
      line-height: 1.06;
      font-weight: 700;
    }}
    .hero-grid {{
      display: grid;
      grid-template-columns: minmax(0, 1.2fr) minmax(280px, 0.8fr);
      gap: 18px;
      margin-top: 18px;
    }}
    .hero-copy {{
      color: var(--muted);
      margin-top: 12px;
      max-width: 760px;
      font-size: 15px;
    }}
    .hero-meta {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px 16px;
      color: var(--muted);
      font-size: 14px;
      margin-top: 14px;
    }}
    .stats {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 14px;
    }}
    .stat {{
      padding: 18px;
      border-radius: 16px;
      background: var(--panel-alt);
      border: 1px solid var(--line);
    }}
    .stat-label {{
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.12em;
    }}
    .stat-value {{
      margin-top: 8px;
      font-size: 26px;
      font-weight: 700;
    }}
    .hero-side {{
      padding: 18px;
      border-radius: 18px;
      background: #0f1720;
      color: #eff4fb;
      display: grid;
      gap: 12px;
    }}
    .hero-side h3 {{
      margin: 0;
      font-size: 18px;
    }}
    .hero-side p {{
      margin: 0;
      color: rgba(239,244,251,0.72);
      font-size: 14px;
    }}
    section {{
      margin-top: 20px;
      padding: 24px;
    }}
    .section-head {{
      display: flex;
      justify-content: space-between;
      align-items: baseline;
      gap: 12px;
      margin-bottom: 16px;
    }}
    .section-head h2 {{
      margin: 0;
      font-size: 26px;
    }}
    .section-head span {{
      color: var(--muted);
      font-size: 13px;
      text-transform: uppercase;
      letter-spacing: 0.12em;
    }}
    .section-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 16px;
    }}
    .report-panel, .recommend-card, .table-panel {{
      background: var(--panel-alt);
      border: 1px solid var(--line);
      border-radius: 18px;
      padding: 18px;
    }}
    .overview-list {{
      list-style: none;
      padding: 0;
      margin: 0;
      display: grid;
      gap: 12px;
    }}
    .overview-list li {{
      display: grid;
      grid-template-columns: auto 1fr;
      gap: 12px;
      align-items: start;
      padding-bottom: 12px;
      border-bottom: 1px solid var(--line);
    }}
    .overview-list li:last-child {{
      border-bottom: 0;
      padding-bottom: 0;
    }}
    .overview-list strong {{
      display: block;
      margin-bottom: 4px;
    }}
    .overview-list p {{
      margin: 0;
      color: var(--muted);
      font-size: 14px;
    }}
    .meter-stack {{
      display: grid;
      gap: 12px;
    }}
    .meter-row {{
      display: grid;
      gap: 8px;
    }}
    .meter-meta {{
      display: flex;
      justify-content: space-between;
      gap: 12px;
      font-size: 14px;
    }}
    .meter-track {{
      height: 10px;
      border-radius: 999px;
      background: #e9eef4;
      overflow: hidden;
    }}
    .meter-fill {{
      height: 100%;
      border-radius: 999px;
    }}
    .meter-fill.high {{ background: var(--high); }}
    .meter-fill.medium {{ background: var(--medium); }}
    .meter-fill.low {{ background: var(--low); }}
    .meter-fill.info {{ background: var(--info); }}
    .chip, .priority {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 11px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      font-weight: 700;
    }}
    .chip-high {{ color: var(--high); background: rgba(212,61,42,0.12); }}
    .chip-medium {{ color: var(--medium); background: rgba(210,122,0,0.12); }}
    .chip-low {{ color: var(--low); background: rgba(45,138,89,0.12); }}
    .chip-info {{ color: var(--info); background: rgba(89,107,149,0.12); }}
    .priority {{ color: var(--accent); background: rgba(31,111,235,0.12); }}
    .recommend-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 16px;
    }}
    .recommend-card h3 {{
      margin: 0;
      font-size: 18px;
    }}
    .recommend-top {{
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: center;
      margin-bottom: 10px;
    }}
    .recommend-card p {{
      margin: 0;
      color: var(--muted);
    }}
    code {{
      font-family: "IBM Plex Mono", "SFMono-Regular", Menlo, Consolas, monospace;
      font-size: 12px;
      background: #eef3f8;
      border-radius: 8px;
      padding: 3px 6px;
      word-break: break-all;
    }}
    .table-wrap {{
      overflow-x: auto;
    }}
    .report-table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 14px;
    }}
    .report-table th {{
      text-align: left;
      font-size: 11px;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: var(--muted);
      padding: 0 0 12px;
      border-bottom: 1px solid var(--line);
    }}
    .report-table td {{
      padding: 14px 0;
      border-bottom: 1px solid var(--line);
      vertical-align: top;
      color: var(--ink);
    }}
    .report-table tbody tr:last-child td {{
      border-bottom: 0;
    }}
    .report-table td + td,
    .report-table th + th {{
      padding-left: 16px;
    }}
    .detail-block {{
      border: 1px solid var(--line);
      border-radius: 16px;
      background: var(--panel-alt);
      padding: 14px 16px;
    }}
    .detail-block + .detail-block {{
      margin-top: 12px;
    }}
    .detail-block summary {{
      cursor: pointer;
      font-weight: 600;
    }}
    .detail-block pre {{
      margin: 12px 0 0;
      padding: 16px;
      border-radius: 12px;
      background: #0f1720;
      color: #dce7f3;
      overflow: auto;
      font-family: "IBM Plex Mono", "SFMono-Regular", Menlo, Consolas, monospace;
      font-size: 12px;
      line-height: 1.5;
    }}
    .empty {{
      color: var(--muted);
      margin: 0;
    }}
    .why {{
      font-size: 14px;
      margin-top: 10px !important;
    }}
    @media (max-width: 1080px) {{
      .layout {{
        grid-template-columns: 1fr;
      }}
      aside {{
        position: static;
        height: auto;
      }}
      main {{
        padding: 20px;
      }}
      .hero-grid {{
        grid-template-columns: 1fr;
      }}
    }}
    @media (max-width: 720px) {{
      main {{
        padding: 14px;
      }}
      section, .report-hero {{
        padding: 18px;
      }}
      .report-table td + td,
      .report-table th + th {{
        padding-left: 10px;
      }}
    }}
  </style>
</head>
<body>
  <div class="layout">
    <aside>
      <div class="brand">Report Navigator</div>
      <h1>网络环境<br>指纹审计</h1>
      <p class="sidebar-copy">参考 NodeSecure/report 这类“结构化报告”的阅读方式重做，重点是目录、概览、表格和模块化信息密度。</p>
      <div class="sidebar-meta">
        <div><label>生成时间</label><span>{esc(data.get("generated_at"))}</span></div>
        <div><label>平台</label><span>{esc((data.get("host") or {}).get("platform"))}</span></div>
        <div><label>项目</label><span>{esc((data.get("host") or {}).get("project_root"))}</span></div>
        <div><label>公网出口</label><span>{esc(public_summary.get("ip"))}</span></div>
        <div><label>浏览器探针</label><span>{html.escape(probe_status_label(str(browser_probe.get("status") or "")))}</span></div>
      </div>
      <nav class="nav">
        <a href="#overview"><span>概览</span><span>{total_findings} 项</span></a>
        <a href="#findings"><span>主要发现</span><span>{high_count}/{medium_count}</span></a>
        <a href="#actions"><span>修复建议</span><span>{len(recommendations)}</span></a>
        <a href="#browser"><span>浏览器与 WebRTC</span><span>{len(webrtc.get("candidates", []))}</span></a>
        <a href="#network"><span>网络与区域</span><span>{esc(", ".join((data.get("dns") or {}).get("nameservers", [])) or "未知")}</span></a>
        <a href="#proxy"><span>代理与路由</span><span>{esc((default_route or {}).get("interface"))}</span></a>
        <a href="#clash"><span>代理快照</span><span>{len((data.get("clash") or {}).get("configs", []))}</span></a>
      </nav>
    </aside>
    <main>
      <header class="report-hero" id="overview">
        <div class="eyebrow">Network Fingerprint Audit</div>
        <h2>把所有“会露馅的信号”放进一份真正能读的报告里</h2>
        <p class="hero-copy">这份报告把出口、DNS、系统语言、浏览器 profile、浏览器请求头和 WebRTC 地址暴露放进统一视图，优先给你结论，再给你证据，而不是把原始字段散在页面各处。</p>
        <div class="hero-meta">
          <span>报告格式：HTML / Markdown / JSON</span>
          <span>浏览器探针：{html.escape(probe_status_label(str(browser_probe.get("status") or "")))}</span>
          <span>出口 ASN：{esc(public_summary.get("asn_org"))}</span>
        </div>
        <div class="hero-grid">
          <div class="report-panel">
            <div class="section-head">
              <h2>摘要</h2>
              <span>Top Signals</span>
            </div>
            <ul class="overview-list">
              {"".join(overview_findings) or '<li><div><strong>当前没有明显异常</strong><p>本次审计没有发现需要优先处理的问题。</p></div></li>'}
            </ul>
          </div>
          <div class="hero-side">
            <h3>严重度分布</h3>
            <p>不是所有异常都该同优先级处理。先看高风险与中风险，再去收尾信息项。</p>
            <div class="stats">
              <div class="stat">
                <div class="stat-label">高风险</div>
                <div class="stat-value">{high_count}</div>
              </div>
              <div class="stat">
                <div class="stat-label">中风险</div>
                <div class="stat-value">{medium_count}</div>
              </div>
              <div class="stat">
                <div class="stat-label">低风险</div>
                <div class="stat-value">{low_count}</div>
              </div>
              <div class="stat">
                <div class="stat-label">信息项</div>
                <div class="stat-value">{info_count}</div>
              </div>
            </div>
            <div class="meter-stack">
              {meter_row("高风险", high_count, "high")}
              {meter_row("中风险", medium_count, "medium")}
              {meter_row("低风险", low_count, "low")}
              {meter_row("信息项", info_count, "info")}
            </div>
          </div>
        </div>
      </header>

      <section id="findings">
        <div class="section-head">
          <h2>主要发现</h2>
          <span>{total_findings} Findings</span>
        </div>
        {render_table(["严重度", "问题", "说明"], finding_rows, "当前没有可展示的发现。")}
      </section>

      <section id="actions">
        <div class="section-head">
          <h2>修复建议</h2>
          <span>{len(recommendations)} Actions</span>
        </div>
        <div class="recommend-grid">
          {"".join(recommendation_cards)}
        </div>
      </section>

      <section id="browser">
        <div class="section-head">
          <h2>浏览器与 WebRTC</h2>
          <span>Browser-side Evidence</span>
        </div>
        <div class="section-grid">
          <div class="table-panel">
            <div class="section-head">
              <h2>浏览器 Profile 语言</h2>
              <span>Profiles</span>
            </div>
            {render_table(["浏览器", "Profile", "Accept-Language", "最近使用"], browser_profile_rows, "未发现浏览器 profile 语言配置。")}
          </div>
          <div class="table-panel">
            <div class="section-head">
              <h2>浏览器探针元数据</h2>
              <span>Probe</span>
            </div>
            {render_table(["字段", "值"], probe_rows, "浏览器探针暂无数据。")}
          </div>
        </div>
        <div class="table-panel" style="margin-top:16px;">
          <div class="section-head">
            <h2>WebRTC 地址明细</h2>
            <span>{len(candidate_rows)} Candidates</span>
          </div>
          {render_table(["类型", "协议", "地址", "范围"], candidate_rows, "未采集到 WebRTC 地址。")}
        </div>
      </section>

      <section id="network">
        <div class="section-head">
          <h2>网络与区域信号</h2>
          <span>Host + Egress</span>
        </div>
        <div class="section-grid">
          <div class="table-panel">
            <div class="section-head">
              <h2>出口 / DNS / 区域</h2>
              <span>Signals</span>
            </div>
            {render_table(["字段", "值"], network_rows, "暂无网络信号数据。")}
          </div>
          <div class="table-panel">
            <div class="section-head">
              <h2>默认路由与监听</h2>
              <span>Route + Local</span>
            </div>
            {render_table(["字段", "值"], route_rows + listener_rows, "暂无路由或监听数据。")}
          </div>
        </div>
      </section>

      <section id="proxy">
        <div class="section-head">
          <h2>代理设置</h2>
          <span>System Proxy</span>
        </div>
        {render_table(["字段", "值"], proxy_rows, "暂无代理设置数据。")}
      </section>

      <section id="clash">
        <div class="section-head">
          <h2>代理运行态快照</h2>
          <span>{len((data.get("clash") or {}).get("configs", []))} Files</span>
        </div>
        {"".join(clash_details) or '<p class="empty">未发现可读的代理运行态配置。当前仅内置 Clash/Mihomo 路径扫描。</p>'}
      </section>
    </main>
  </div>
</body>
</html>
"""


def render_html(data: dict[str, object]) -> str:
    findings = [item for item in data.get("findings", []) if isinstance(item, dict)]
    recommendations = [item for item in data.get("recommendations", []) if isinstance(item, dict)]
    high_count = sum(1 for item in findings if item.get("severity") == "high")
    medium_count = sum(1 for item in findings if item.get("severity") == "medium")
    low_count = sum(1 for item in findings if item.get("severity") == "low")
    info_count = sum(1 for item in findings if item.get("severity") == "info")
    total_findings = len(findings)
    risk_score = min(100, high_count * 35 + medium_count * 18 + low_count * 8 + info_count * 2)

    public_ip = data.get("public_ip", {}) if isinstance(data.get("public_ip"), dict) else {}
    public_summary = public_ip_summary(public_ip)
    active_network = data.get("active_network", {}) if isinstance(data.get("active_network"), dict) else {}
    dns = data.get("dns", {}) if isinstance(data.get("dns"), dict) else {}
    locale = data.get("locale", {}) if isinstance(data.get("locale"), dict) else {}
    route = data.get("route", {}) if isinstance(data.get("route"), dict) else {}
    default_route = route.get("default", {}) if isinstance(route.get("default"), dict) else {}
    networksetup = data.get("networksetup", {}) if isinstance(data.get("networksetup"), dict) else {}
    listeners = data.get("listeners", {}) if isinstance(data.get("listeners"), dict) else {}
    browser_probe = data.get("browser_probe", {}) if isinstance(data.get("browser_probe"), dict) else {}
    probe_result = browser_probe.get("result", {}) if isinstance(browser_probe.get("result"), dict) else {}
    navigator_info = probe_result.get("navigator", {}) if isinstance(probe_result.get("navigator"), dict) else {}
    header_echo = probe_result.get("headerEcho", {}) if isinstance(probe_result.get("headerEcho"), dict) else {}
    webrtc = probe_result.get("webrtc", {}) if isinstance(probe_result.get("webrtc"), dict) else {}
    candidates = webrtc.get("candidates", []) if isinstance(webrtc.get("candidates"), list) else []
    browser_probe_status = str(browser_probe.get("status") or "unknown")
    accept_language = get_case_insensitive(header_echo.get("headers"), "Accept-Language")
    user_agent = get_case_insensitive(header_echo.get("headers"), "User-Agent")

    if high_count:
        posture = ("需要优先处理", "critical", "先看高风险项，再复测浏览器与出口证据。")
    elif medium_count:
        posture = ("存在明显不一致", "review", "建议先处理语言、DNS、WebRTC 这类容易形成组合信号的问题。")
    else:
        posture = ("暂无明显异常", "stable", "本次审计没有发现高优先级风险，建议保留报告用于后续 diff。")

    def esc(value: object) -> str:
        return html.escape(format_value(value))

    def severity_class(level: object) -> str:
        return str(level or "info").lower()

    def severity_pill(level: object) -> str:
        cls = severity_class(level)
        return f'<span class="pill pill-{html.escape(cls)}">{html.escape(severity_label(cls))}</span>'

    def render_table(rows: list[list[str]], empty_text: str) -> str:
        if not rows:
            return f'<p class="empty">{html.escape(empty_text)}</p>'
        rendered_rows = []
        for label, value in rows:
            rendered_rows.append(
                f"<tr><th>{html.escape(label)}</th><td>{value}</td></tr>"
            )
        return f'<table class="kv-table"><tbody>{"".join(rendered_rows)}</tbody></table>'

    def metric(label: str, value: object, helper: str = "") -> str:
        helper_html = f"<small>{html.escape(helper)}</small>" if helper else ""
        return f"""
        <div class="metric">
          <span>{html.escape(label)}</span>
          <strong>{esc(value)}</strong>
          {helper_html}
        </div>
        """

    def signal(label: str, value: object, state: str, detail: str = "") -> str:
        detail_html = f"<small>{html.escape(detail)}</small>" if detail else ""
        return f"""
        <div class="signal signal-{html.escape(state)}">
          <span>{html.escape(label)}</span>
          <strong>{esc(value)}</strong>
          {detail_html}
        </div>
        """

    finding_cards = []
    for index, item in enumerate(findings, start=1):
        title, detail = localize_finding(item)
        severity = severity_class(item.get("severity"))
        finding_cards.append(
            f"""
            <article class="finding finding-{html.escape(severity)}">
              <div class="finding-index">{index:02d}</div>
              <div>
                <div class="finding-top">{severity_pill(severity)}</div>
                <h3>{html.escape(title)}</h3>
                <p>{html.escape(detail)}</p>
              </div>
            </article>
            """
        )

    recommendation_cards = []
    for item in recommendations:
        priority, area, action, why = localize_recommendation(item)
        recommendation_cards.append(
            f"""
            <article class="action-item">
              <div class="priority">{html.escape(priority)}</div>
              <div>
                <h3>{html.escape(area)}</h3>
                <p>{html.escape(action)}</p>
                <small>{html.escape(why)}</small>
              </div>
            </article>
            """
        )

    dns_nameservers = dns.get("nameservers", []) if isinstance(dns.get("nameservers"), list) else []
    observed_ips = public_summary.get("observed_ips", [])
    ipapi_flags = public_summary.get("ipapi_flags")
    proxycheck_flags = public_summary.get("proxycheck_flags")
    ipapi_flag_parts: list[str] = []
    if isinstance(ipapi_flags, dict):
        for key, label in (
            ("is_datacenter", "数据中心"),
            ("is_proxy", "代理"),
            ("is_vpn", "VPN"),
            ("is_tor", "Tor"),
            ("is_abuser", "滥用记录"),
        ):
            if truthy_external_flag(ipapi_flags.get(key)):
                ipapi_flag_parts.append(label)
    if isinstance(proxycheck_flags, dict) and truthy_external_flag(proxycheck_flags.get("proxy")):
        proxy_type = str(proxycheck_flags.get("type") or "proxy")
        proxy_risk = proxycheck_flags.get("risk")
        ip_risk_brief = f"{proxy_type} / risk {proxy_risk}" if proxy_risk not in (None, "") else proxy_type
    elif ipapi_flag_parts:
        ip_risk_brief = " / ".join(ipapi_flag_parts)
    else:
        ip_risk_brief = "未标记代理风险"

    browser_languages = data.get("browser_languages", []) if isinstance(data.get("browser_languages"), list) else []
    profile_count = 0
    active_language = "未知"
    for browser in browser_languages:
        if not isinstance(browser, dict):
            continue
        profiles = browser.get("profiles", [])
        last_used = str(browser.get("last_used") or "")
        if not isinstance(profiles, list):
            continue
        profile_count += len(profiles)
        for profile in profiles:
            if isinstance(profile, dict) and str(profile.get("profile") or "") == last_used:
                active_language = str(profile.get("accept_languages") or active_language)

    webrtc_counts = browser_webrtc_candidate_counts(candidates)
    private_candidates = webrtc_counts["private"]
    public_candidates = webrtc_counts["public"]
    mdns_candidates = webrtc_counts["mdns"]

    webrtc_result = browser_probe_result_label(browser_probe_status, candidates)
    probe_problem_note = browser_probe_problem_note(browser_probe)
    webrtc_result_detail = browser_probe_result_detail(browser_probe_status, candidates)
    webrtc_detail = (
        webrtc_result_detail
        if browser_probe_status == "ok"
        else (probe_problem_note or "未完成浏览器侧检测")
    )

    finding_summary = "".join(finding_cards) or """
      <article class="finding finding-stable">
        <div class="finding-index">OK</div>
        <div><h3>当前没有明显异常</h3><p>本次审计没有发现需要优先处理的问题。</p></div>
      </article>
    """

    action_summary = "".join(recommendation_cards) or '<p class="empty">暂无修复建议。</p>'

    browser_rows = [["WebRTC 结论", html.escape(webrtc_result)]]
    if browser_probe_status == "ok":
        browser_rows.extend(
            [
                ["说明", html.escape(webrtc_result_detail)],
                ["navigator.language", esc(navigator_info.get("language"))],
                ["navigator.languages", esc(navigator_info.get("languages"))],
                ["浏览器时区", esc(navigator_info.get("timezone"))],
                ["回显出口 IP", esc(header_echo.get("origin"))],
                ["Accept-Language", esc(accept_language)],
                ["User-Agent", esc(user_agent)],
            ]
        )
    else:
        browser_rows.append(["检测说明", html.escape(probe_problem_note or "浏览器侧检测未完成。")])

    webrtc_rows: list[list[str]] = []
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        scope = candidate_address_scope(str(candidate.get("address") or ""))
        scope_text = {
            "mdns": "匿名 .local 地址",
            "private": "私网",
            "public": "公网",
            "hostname": "主机名",
            "unknown": "未知",
        }.get(scope, scope)
        address = f"{candidate.get('address') or 'unknown'}:{candidate.get('port') or 'unknown'}"
        webrtc_rows.append(
            [
                f"{candidate.get('candidateType') or 'unknown'} / {candidate.get('protocol') or 'unknown'}",
                f"<code>{html.escape(address)}</code><small>{html.escape(scope_text)}</small>",
            ]
        )

    network_rows = [
        ["公网 IP", esc(public_summary.get("ip"))],
        ["观测 IP", esc(", ".join(observed_ips) if isinstance(observed_ips, list) else observed_ips)],
        ["ASN / 组织", esc(public_summary.get("asn_org"))],
        ["位置", esc(f"{public_summary.get('city') or '未知'}，{public_summary.get('region') or ''} {public_summary.get('country') or ''}")],
        ["时区", esc(public_summary.get("timezone"))],
        ["ipapi.is", esc(public_summary.get("ipapi_flags"))],
        ["proxycheck", esc(public_summary.get("proxycheck_flags"))],
        ["系统 DNS", esc(", ".join(dns_nameservers))],
        ["当前网络服务 DNS", esc(dns.get("wifi_dns_raw"))],
        ["活跃网络服务", esc(active_network.get("service"))],
        ["活跃接口", esc(active_network.get("interface"))],
    ]

    locale_rows = [
        ["LANG", esc(locale.get("lang"))],
        ["LC_ALL", esc(locale.get("lc_all"))],
        ["AppleLanguages", esc(locale.get("apple_languages"))],
        ["AppleLocale", esc(locale.get("apple_locale"))],
        ["本地时间", esc(locale.get("timestamp"))],
    ]

    proxy_rows = [
        ["Web 代理", esc(networksetup.get("web_proxy"))],
        ["HTTPS 代理", esc(networksetup.get("secure_web_proxy"))],
        ["SOCKS 代理", esc(networksetup.get("socks_proxy"))],
        ["自动代理 URL", esc(networksetup.get("auto_proxy_url"))],
        ["自动代理发现", esc(networksetup.get("auto_proxy_discovery"))],
    ]

    route_rows = [
        ["默认网关", esc(default_route.get("gateway"))],
        ["默认接口", esc(default_route.get("interface"))],
        ["目的地", esc(default_route.get("destination"))],
        ["路由 mask", esc(default_route.get("mask"))],
        ["TUN 分流条目数", esc(len(route.get("split_tunnel_routes", [])) if isinstance(route.get("split_tunnel_routes"), list) else 0)],
        ["127.0.0.1:53 TCP", "监听中" if listeners.get("tcp_127_0_0_1_53") else "未监听"],
        ["127.0.0.1:53 UDP", "监听中" if listeners.get("udp_127_0_0_1_53") else "未监听"],
        ["127.0.0.1:7890 TCP", "监听中" if listeners.get("tcp_127_0_0_1_7890") else "未监听"],
    ]

    client_details = []
    proxy_clients = data.get("proxy_clients", [])
    if isinstance(proxy_clients, list):
        for client in proxy_clients:
            if not isinstance(client, dict):
                continue
            processes = client.get("processes", [])
            paths = client.get("paths", [])
            configs = client.get("configs", [])
            summary_rows = [
                ["进程线索", esc(", ".join(str(item) for item in processes) if isinstance(processes, list) and processes else "未发现")],
                ["配置路径", esc(", ".join(str(item) for item in paths) if isinstance(paths, list) and paths else "未发现")],
            ]
            config_blocks = []
            if isinstance(configs, list):
                for config in configs:
                    if not isinstance(config, dict):
                        continue
                    excerpt = "\n".join(str(line) for line in config.get("excerpt", []))
                    config_blocks.append(
                        f"""
                        <details class="details-block">
                          <summary>{html.escape(str(config.get("path") or "配置文件"))}</summary>
                          <pre>{html.escape(excerpt)}</pre>
                        </details>
                        """
                    )
            client_details.append(
                f"""
                <article class="evidence">
                  <h3>{html.escape(str(client.get("name") or "代理客户端"))}</h3>
                  {render_table(summary_rows, "暂无客户端线索。")}
                  {"".join(config_blocks)}
                </article>
                """
            )
    if not client_details:
        client_details.append(
            '<article class="evidence"><h3>未发现已知客户端</h3><p class="empty">仍会继续基于系统代理、路由、DNS、出口和浏览器结果进行通用审计。</p></article>'
        )

    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>网络环境指纹审计报告</title>
  <style>
    :root {{
      --bg: #f5f1ea;
      --surface: #fffdf8;
      --surface-2: #f9f6ef;
      --ink: #1f2933;
      --muted: #64707d;
      --line: #ded7ca;
      --line-strong: #c9bca9;
      --accent: #176b87;
      --accent-2: #8f4b2e;
      --high: #bd2d2d;
      --medium: #a86913;
      --low: #34785f;
      --info: #526b8e;
      --stable: #2f7a5f;
      --shadow: 0 18px 48px rgba(40, 33, 24, 0.09);
    }}
    * {{ box-sizing: border-box; }}
    html {{ scroll-behavior: smooth; }}
    body {{
      margin: 0;
      color: var(--ink);
      background: var(--bg);
      font-family: Inter, "Avenir Next", "Segoe UI", "PingFang SC", "Helvetica Neue", Arial, sans-serif;
      line-height: 1.5;
    }}
    a {{ color: inherit; }}
    .nav-toggle, .nav-button, .nav-backdrop {{
      display: none;
    }}
    .shell {{
      min-height: 100vh;
      display: grid;
      grid-template-columns: 248px minmax(0, 1fr);
    }}
    .rail {{
      position: sticky;
      top: 0;
      height: 100vh;
      padding: 22px 18px;
      background: #18232b;
      color: #f8f4ec;
      border-right: 1px solid rgba(255, 255, 255, 0.08);
    }}
    .brand {{
      display: grid;
      gap: 8px;
      padding-bottom: 18px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.12);
    }}
    .brand span {{
      color: #9ccbd8;
      font-size: 11px;
      letter-spacing: 0.14em;
      text-transform: uppercase;
    }}
    .brand strong {{
      font-size: 22px;
      line-height: 1.12;
    }}
    .nav {{
      display: grid;
      gap: 6px;
      margin-top: 18px;
    }}
    .nav a {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      padding: 10px 11px;
      border-radius: 8px;
      color: rgba(248, 244, 236, 0.82);
      text-decoration: none;
      font-size: 13px;
    }}
    .nav a:hover {{
      background: rgba(255, 255, 255, 0.08);
      color: #fffdf8;
    }}
    .nav em {{
      color: rgba(248, 244, 236, 0.55);
      font-style: normal;
      font-size: 12px;
    }}
    main {{
      width: min(1180px, 100%);
      padding: 28px 32px 48px;
    }}
    .summary {{
      display: grid;
      grid-template-columns: minmax(0, 1fr) 260px;
      gap: 22px;
      align-items: stretch;
      padding-bottom: 24px;
      border-bottom: 1px solid var(--line);
    }}
    .eyebrow {{
      margin: 0 0 10px;
      color: var(--accent);
      font-size: 12px;
      font-weight: 800;
      letter-spacing: 0.13em;
      text-transform: uppercase;
    }}
    h1, h2, h3, p {{ margin-top: 0; }}
    h1 {{
      margin-bottom: 12px;
      font-size: 36px;
      line-height: 1.08;
      letter-spacing: 0;
    }}
    .summary p {{
      max-width: 760px;
      color: var(--muted);
      font-size: 15px;
      margin-bottom: 0;
    }}
    .verdict {{
      display: grid;
      align-content: center;
      gap: 12px;
      padding: 20px;
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
    }}
    .score {{
      display: flex;
      align-items: baseline;
      gap: 8px;
    }}
    .score strong {{
      font-size: 46px;
      line-height: 1;
    }}
    .score span {{ color: var(--muted); }}
    .status {{
      display: inline-flex;
      width: fit-content;
      padding: 6px 10px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 800;
    }}
    .status-critical {{ color: #fff; background: var(--high); }}
    .status-review {{ color: #fff; background: var(--medium); }}
    .status-stable {{ color: #fff; background: var(--stable); }}
    .metrics {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 12px;
      margin-top: 18px;
    }}
    .metric, .signal, .finding, .action-item, .evidence {{
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: 0 10px 30px rgba(40, 33, 24, 0.05);
    }}
    .metric {{
      min-height: 112px;
      padding: 15px;
      display: grid;
      align-content: space-between;
      gap: 10px;
    }}
    .metric span, .signal span {{
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }}
    .metric strong {{
      font-size: 22px;
      line-height: 1.12;
      word-break: break-word;
    }}
    small {{
      display: block;
      color: var(--muted);
      font-size: 12px;
      line-height: 1.45;
    }}
    section {{
      margin-top: 28px;
    }}
    .section-head {{
      display: flex;
      justify-content: space-between;
      gap: 16px;
      align-items: end;
      margin-bottom: 12px;
      padding-bottom: 10px;
      border-bottom: 1px solid var(--line);
    }}
    .section-head h2 {{
      margin: 0;
      font-size: 22px;
    }}
    .section-head span {{
      color: var(--muted);
      font-size: 12px;
      font-weight: 800;
      letter-spacing: 0.1em;
      text-transform: uppercase;
    }}
    .signals {{
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 12px;
    }}
    .signal {{
      padding: 14px;
      border-left: 5px solid var(--line-strong);
    }}
    .signal strong {{
      display: block;
      margin: 8px 0 3px;
      font-size: 17px;
      word-break: break-word;
    }}
    .signal-high {{ border-left-color: var(--high); }}
    .signal-medium {{ border-left-color: var(--medium); }}
    .signal-ok {{
      color: #586470;
      background: #f2efe8;
      border-color: #e0d8cb;
      border-left-color: #b7aea0;
      box-shadow: none;
    }}
    .signal-high strong {{ color: var(--high); }}
    .signal-medium strong {{ color: #7b4a0d; }}
    .signal-ok strong {{ color: #53606b; }}
    .findings-grid {{
      display: grid;
      gap: 10px;
    }}
    .finding {{
      display: grid;
      grid-template-columns: 48px minmax(0, 1fr);
      gap: 14px;
      padding: 16px;
      border-left: 6px solid var(--info);
    }}
    .finding-high {{ border-left-color: var(--high); }}
    .finding-medium {{ border-left-color: var(--medium); }}
    .finding-low {{ border-left-color: var(--low); }}
    .finding-info {{
      color: #55616d;
      background: #f2efe8;
      border-color: #dfd7c9;
      border-left-color: #9aa5ae;
      box-shadow: none;
    }}
    .finding-stable {{ border-left-color: var(--stable); }}
    .finding-index {{
      color: var(--muted);
      font-family: "SFMono-Regular", Menlo, Consolas, monospace;
      font-size: 13px;
      padding-top: 2px;
    }}
    .finding h3, .action-item h3 {{
      margin: 5px 0 6px;
      font-size: 17px;
    }}
    .finding-high h3 {{
      color: #8e1f1f;
      font-weight: 900;
    }}
    .finding-medium h3 {{
      color: #73470f;
      font-weight: 850;
    }}
    .finding-info h3 {{
      color: #46525e;
      font-weight: 700;
    }}
    .finding p, .action-item p {{
      margin: 0;
      color: var(--muted);
    }}
    .pill, .priority {{
      display: inline-flex;
      align-items: center;
      width: fit-content;
      border-radius: 999px;
      padding: 4px 9px;
      font-size: 11px;
      font-weight: 800;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }}
    .pill-high {{ color: var(--high); background: rgba(189, 45, 45, 0.1); }}
    .pill-medium {{ color: var(--medium); background: rgba(168, 105, 19, 0.12); }}
    .pill-low {{ color: var(--low); background: rgba(52, 120, 95, 0.12); }}
    .pill-info {{ color: var(--info); background: rgba(82, 107, 142, 0.12); }}
    .actions-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 12px;
    }}
    .action-item {{
      display: grid;
      grid-template-columns: auto minmax(0, 1fr);
      gap: 12px;
      padding: 15px;
    }}
    .priority {{
      height: fit-content;
      color: #fff;
      background: var(--accent);
    }}
    .evidence-grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 14px;
    }}
    .evidence {{
      padding: 16px;
    }}
    .evidence h3 {{
      margin-bottom: 12px;
      font-size: 16px;
    }}
    .kv-table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }}
    .kv-table th {{
      width: 34%;
      padding: 10px 12px 10px 0;
      color: var(--muted);
      font-weight: 700;
      text-align: left;
      vertical-align: top;
      border-top: 1px solid var(--line);
    }}
    .kv-table td {{
      padding: 10px 0;
      vertical-align: top;
      border-top: 1px solid var(--line);
      word-break: break-word;
    }}
    code {{
      font-family: "SFMono-Regular", Menlo, Consolas, monospace;
      font-size: 12px;
      padding: 2px 5px;
      border-radius: 6px;
      background: #ebe4d8;
      word-break: break-all;
    }}
    .details-block {{
      padding: 14px 16px;
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 8px;
    }}
    .details-block + .details-block {{ margin-top: 10px; }}
    .details-block summary {{
      cursor: pointer;
      font-weight: 700;
    }}
    .details-block pre {{
      margin: 12px 0 0;
      padding: 14px;
      border-radius: 8px;
      color: #f4efe5;
      background: #18232b;
      overflow: auto;
      font-size: 12px;
      line-height: 1.55;
    }}
    .empty {{
      margin: 0;
      color: var(--muted);
    }}
    @media (max-width: 1040px) {{
      .shell {{ grid-template-columns: 1fr; }}
      .summary {{ grid-template-columns: 1fr; }}
      .metrics, .signals, .evidence-grid {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
    }}
    @media (max-width: 720px) {{
      .nav-button {{
        position: fixed;
        left: 12px;
        top: 12px;
        z-index: 40;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-width: 58px;
        height: 38px;
        padding: 0 12px;
        border-radius: 999px;
        color: #f8f4ec;
        background: #18232b;
        box-shadow: 0 10px 28px rgba(24, 35, 43, 0.24);
        font-size: 13px;
        font-weight: 800;
      }}
      .nav-backdrop {{
        position: fixed;
        inset: 0;
        z-index: 25;
        background: rgba(24, 35, 43, 0.42);
      }}
      .nav-toggle:checked + .nav-button + .nav-backdrop {{
        display: block;
      }}
      .rail {{
        position: fixed;
        top: 0;
        bottom: 0;
        left: 0;
        z-index: 35;
        width: min(292px, 84vw);
        height: 100vh;
        padding: 64px 16px 18px;
        transform: translateX(-102%);
        transition: transform 180ms ease;
        box-shadow: 18px 0 40px rgba(24, 35, 43, 0.26);
      }}
      .nav-toggle:checked ~ .shell .rail {{ transform: translateX(0); }}
      .brand {{
        padding-bottom: 10px;
      }}
      .brand strong {{
        font-size: 18px;
      }}
      .nav {{
        grid-template-columns: 1fr;
        gap: 6px;
        margin-top: 14px;
      }}
      .nav a {{
        padding: 11px;
        font-size: 13px;
      }}
      .nav em {{
        display: inline;
      }}
      main {{ padding: 62px 14px 36px; }}
      h1 {{ font-size: 29px; }}
      .metrics, .signals, .evidence-grid {{ grid-template-columns: 1fr; }}
      .finding {{ grid-template-columns: 1fr; }}
      .kv-table th, .kv-table td {{
        display: block;
        width: 100%;
        padding: 8px 0;
      }}
      .kv-table td {{ border-top: 0; padding-top: 0; }}
    }}
  </style>
</head>
<body>
  <input class="nav-toggle" id="nav-toggle" type="checkbox">
  <label class="nav-button" for="nav-toggle">目录</label>
  <label class="nav-backdrop" for="nav-toggle"></label>
  <div class="shell">
    <aside class="rail">
      <div class="brand">
        <span>Network Audit</span>
        <strong>网络环境<br>指纹审计</strong>
      </div>
      <nav class="nav">
        <a href="#summary">摘要 <em>{risk_score}</em></a>
        <a href="#signals">关键证据 <em>{len(observed_ips) if isinstance(observed_ips, list) else 0}</em></a>
        <a href="#findings">主要发现 <em>{total_findings}</em></a>
        <a href="#actions">修复建议 <em>{len(recommendations)}</em></a>
        <a href="#evidence">证据明细 <em>{len(candidates)}</em></a>
        <a href="#proxy">代理配置 <em>{esc(active_network.get("interface"))}</em></a>
      </nav>
    </aside>
    <main>
      <header class="summary" id="summary">
        <div>
          <p class="eyebrow">Audit Summary</p>
          <h1>环境一致性报告</h1>
          <p>{html.escape(posture[2])}</p>
          <div class="metrics">
            {metric("公网出口", public_summary.get("ip") or "未知", str(public_summary.get("asn_org") or "ASN 未知"))}
            {metric("WebRTC 暴露", webrtc_result, webrtc_detail)}
            {metric("DNS 解析器", len(dns_nameservers), ", ".join(str(item) for item in dns_nameservers[:2]) or "未发现")}
            {metric("浏览器 Profile", profile_count, active_language)}
          </div>
        </div>
        <aside class="verdict">
          <span class="status status-{html.escape(posture[1])}">{html.escape(posture[0])}</span>
          <div class="score"><strong>{risk_score}</strong><span>/100</span></div>
          <small>高风险 {high_count}，中风险 {medium_count}，低风险 {low_count}，信息项 {info_count}</small>
        </aside>
      </header>

      <section id="signals">
        <div class="section-head">
          <h2>关键证据</h2>
          <span>scan first</span>
        </div>
        <div class="signals">
          {signal("出口情报", ip_risk_brief, "high" if high_count else "ok", str(public_summary.get("asn_org") or ""))}
          {signal("WebRTC 暴露", webrtc_result, "medium" if private_candidates else "ok", f"公网 {public_candidates} / 本机内网 {private_candidates} / 匿名地址 {mdns_candidates}" if browser_probe_status == "ok" else webrtc_detail)}
          {signal("语言信号", active_language, "medium" if any("Accept-Language" in str(item.get("title") or "") for item in findings) else "ok", str(locale.get("apple_locale") or ""))}
          {signal("DNS", ", ".join(str(item) for item in dns_nameservers) or "未知", "medium" if any("DNS" in str(item.get("title") or "") for item in findings) else "ok", str(active_network.get("service") or ""))}
          {signal("代理路径", active_network.get("interface") or "未知", "ok", str(networksetup.get("service") or ""))}
          {signal("本地监听", f"DNS {'on' if listeners.get('tcp_127_0_0_1_53') or listeners.get('udp_127_0_0_1_53') else 'off'} / 7890 {'on' if listeners.get('tcp_127_0_0_1_7890') else 'off'}", "ok", "localhost")}
        </div>
      </section>

      <section id="findings">
        <div class="section-head">
          <h2>主要发现</h2>
          <span>{total_findings} findings</span>
        </div>
        <div class="findings-grid">
          {finding_summary}
        </div>
      </section>

      <section id="actions">
        <div class="section-head">
          <h2>修复建议</h2>
          <span>{len(recommendations)} actions</span>
        </div>
        <div class="actions-grid">
          {action_summary}
        </div>
      </section>

      <section id="evidence">
        <div class="section-head">
          <h2>证据明细</h2>
          <span>structured evidence</span>
        </div>
        <div class="evidence-grid">
          <article class="evidence">
            <h3>出口 / DNS / 区域</h3>
            {render_table(network_rows, "暂无网络信号数据。")}
          </article>
          <article class="evidence">
            <h3>浏览器探针</h3>
            {render_table(browser_rows, "浏览器探针暂无数据。")}
          </article>
          <article class="evidence">
            <h3>WebRTC 地址明细</h3>
            {render_table(webrtc_rows, "未采集到 WebRTC 地址。")}
          </article>
          <article class="evidence">
            <h3>系统语言与区域</h3>
            {render_table(locale_rows, "暂无语言区域数据。")}
          </article>
        </div>
      </section>

      <section id="proxy">
        <div class="section-head">
          <h2>代理与路由</h2>
          <span>system path</span>
        </div>
        <div class="evidence-grid">
          <article class="evidence">
            <h3>系统代理</h3>
            {render_table(proxy_rows, "暂无代理设置数据。")}
          </article>
          <article class="evidence">
            <h3>路由与本地监听</h3>
            {render_table(route_rows, "暂无路由或监听数据。")}
          </article>
        </div>
      </section>

      <section id="runtime">
        <div class="section-head">
          <h2>代理客户端识别</h2>
          <span>{len(proxy_clients) if isinstance(proxy_clients, list) else 0} clients</span>
        </div>
        <div class="evidence-grid">
          {"".join(client_details)}
        </div>
      </section>
    </main>
  </div>
</body>
</html>
"""


def write_reports(data: dict[str, object], output_dir: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    suffix = ""
    counter = 1
    while True:
        stem = f"audit-{stamp}{suffix}"
        json_path = output_dir / f"{stem}.json"
        md_path = output_dir / f"{stem}.md"
        html_path = output_dir / f"{stem}.html"
        if not json_path.exists() and not md_path.exists() and not html_path.exists():
            break
        suffix = f"-{counter}"
        counter += 1
    json_path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(data), encoding="utf-8")
    html_path.write_text(render_html(data), encoding="utf-8")
    return json_path, md_path, html_path


def open_report(html_path: pathlib.Path) -> dict[str, object]:
    completed = run_command("open", str(html_path), timeout=10)
    return {
        "ok": completed.get("code") == 0,
        "stderr": completed.get("stderr", ""),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit macOS and Windows network and locale signals.")
    parser.add_argument(
        "--output-dir",
        default=str(DEFAULT_REPORTS_DIR),
        help="Directory for generated reports.",
    )
    parser.add_argument(
        "--skip-network",
        action="store_true",
        help="Skip external network lookups. This also skips the browser-side probe.",
    )
    parser.add_argument(
        "--skip-browser-probe",
        action="store_true",
        help="Skip launching a temporary headless browser for WebRTC and header checks.",
    )
    parser.add_argument(
        "--browser-path",
        help="Explicit browser binary path for the browser-side probe.",
    )
    parser.add_argument(
        "--no-open",
        action="store_true",
        help="Generate reports but do not automatically open the HTML report.",
    )
    args = parser.parse_args()

    if sys.platform not in {"darwin", "win32"}:
        print("This tool currently supports macOS and Windows only.", file=sys.stderr)
        return 2

    data = collect_data(
        skip_network=args.skip_network,
        skip_browser_probe=args.skip_browser_probe,
        browser_path=args.browser_path,
    )
    json_path, md_path, html_path = write_reports(data, pathlib.Path(args.output_dir))
    open_result = None if args.no_open else open_report(html_path)

    findings = data.get("findings", [])
    high = sum(1 for item in findings if isinstance(item, dict) and item.get("severity") == "high")
    medium = sum(1 for item in findings if isinstance(item, dict) and item.get("severity") == "medium")
    browser_probe_status = (data.get("browser_probe") or {}).get("status")
    print(f"Generated report: {md_path}")
    print(f"Generated report: {json_path}")
    print(f"Generated report: {html_path}")
    if args.no_open:
        print("HTML auto-open: disabled by --no-open")
    elif open_result and open_result.get("ok"):
        print(f"HTML auto-open: opened {html_path}")
    else:
        print(f"HTML auto-open: failed to open {html_path}")
        if open_result and open_result.get("stderr"):
            print(f"Open error: {open_result.get('stderr')}")
    print(
        f"High findings: {high} | Medium findings: {medium} | Total findings: {len(findings)} | Browser probe: {browser_probe_status}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
