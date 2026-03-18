#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import datetime as dt
import functools
import http.server
import ipaddress
import json
import os
import pathlib
import re
import socket
import subprocess
import sys
import tempfile
import threading
import urllib.error
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

BROWSER_CANDIDATES = [
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


def parse_key_value_block(text: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        parsed[key.strip()] = value.strip()
    return parsed


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
        if "127.0.0.1.53" in line and "LISTEN" in line:
            summary["tcp_127_0_0_1_53"] = True
        if "127.0.0.1.7890" in line and "LISTEN" in line:
            summary["tcp_127_0_0_1_7890"] = True
    for line in udp_raw.splitlines():
        if "127.0.0.1.53" in line:
            summary["udp_127_0_0_1_53"] = True
    return summary


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
    return {"path": str(path), "excerpt": excerpt}


def get_case_insensitive(mapping: object, key: str) -> str | None:
    if not isinstance(mapping, dict):
        return None
    target = key.lower()
    for current_key, value in mapping.items():
        if str(current_key).lower() == target:
            return str(value)
    return None


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


def first_language_tag(value: str | None) -> str | None:
    if not value:
        return None
    first = value.split(",", 1)[0].strip()
    return first or None


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


def find_browser_binary(explicit_path: str | None = None) -> str | None:
    if explicit_path:
        candidate = pathlib.Path(explicit_path).expanduser()
        if candidate.exists() and os.access(candidate, os.X_OK):
            return str(candidate)
        return None
    for candidate in BROWSER_CANDIDATES:
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

    public_ip = data.get("public_ip", {})
    if isinstance(public_ip, dict):
        ipinfo = public_ip.get("ipinfo") or {}
        ifconfig = public_ip.get("ifconfig") or {}
        org = str(ipinfo.get("org") or ifconfig.get("asn_org") or "")
        hostname = str(ipinfo.get("hostname") or ifconfig.get("hostname") or "")
        if any(keyword in org.lower() for keyword in ("cloud", "hosting", "dmit", "vps")) or any(
            keyword in hostname.lower() for keyword in ("host-", "cloud", "vps")
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
    if isinstance(env, dict):
        lang = str(env.get("lang") or "")
        apple_languages = env.get("apple_languages") or []
        if "zh_CN" in lang or any(str(item).lower().startswith("zh") for item in apple_languages):
            findings.append(
                {
                    "severity": "medium",
                    "title": "Local language signals include Chinese",
                    "detail": f"LANG={lang or 'unset'}; AppleLanguages={apple_languages}.",
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

    if "Datacenter egress detected" in finding_titles:
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
                "action": "Reset Wi-Fi DNS to Automatic or point it to your local proxy-managed DNS path so it does not advertise mainland public resolvers.",
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


def collect_data(
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
    wifi_dns_raw = run_command("networksetup", "-getdnsservers", "Wi-Fi")
    wifi_webproxy_raw = run_command("networksetup", "-getwebproxy", "Wi-Fi")
    wifi_secureproxy_raw = run_command("networksetup", "-getsecurewebproxy", "Wi-Fi")
    wifi_socks_raw = run_command("networksetup", "-getsocksfirewallproxy", "Wi-Fi")
    wifi_autoproxy_raw = run_command("networksetup", "-getautoproxyurl", "Wi-Fi")
    wifi_discovery_raw = run_command("networksetup", "-getproxyautodiscovery", "Wi-Fi")
    apple_languages_raw = run_command("defaults", "read", "-g", "AppleLanguages")
    apple_locale_raw = run_command("defaults", "read", "-g", "AppleLocale")
    nwi_raw = run_command("scutil", "--nwi")

    public_ip: dict[str, object] = {}
    if not skip_network:
        public_ip["ipinfo"] = fetch_json("https://ipinfo.io/json") or {}
        public_ip["ifconfig"] = fetch_json("https://ifconfig.co/json") or {}
        public_ip["cloudflare_trace"] = fetch_text("https://www.cloudflare.com/cdn-cgi/trace") or ""

    clash_configs = [
        config
        for config in (sanitize_clash_excerpt(path) for path in CLASH_CONFIG_CANDIDATES)
        if config is not None
    ]

    browser_languages: list[dict[str, object]] = []
    for browser_name, base_path in (
        ("Chrome", pathlib.Path.home() / "Library/Application Support/Google/Chrome"),
        ("Chromium", pathlib.Path.home() / "Library/Application Support/Chromium"),
    ):
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
            "hostname": socket.gethostname(),
            "platform": sys.platform,
            "cwd": str(pathlib.Path.cwd()),
        },
        "public_ip": public_ip,
        "proxy": parse_proxy_settings(str(proxy_raw.get("stdout", ""))),
        "dns": {
            "nameservers": parse_dns_nameservers(str(dns_raw.get("stdout", ""))),
            "wifi_dns_raw": str(wifi_dns_raw.get("stdout", "")),
            "nwi": str(nwi_raw.get("stdout", "")),
        },
        "route": {
            "default": parse_default_route(str(route_raw.get("stdout", ""))),
            "split_tunnel_routes": parse_split_tunnel_routes(str(routes_raw.get("stdout", ""))),
        },
        "listeners": parse_listener_summary(
            str(tcp_raw.get("stdout", "")),
            str(udp_raw.get("stdout", "")),
        ),
        "locale": {
            "lang": os.environ.get("LANG"),
            "lc_all": os.environ.get("LC_ALL"),
            "tz": os.environ.get("TZ"),
            "apple_languages": apple_languages,
            "apple_locale": str(apple_locale_raw.get("stdout", "")),
            "timestamp": now.strftime("%Y-%m-%d %H:%M:%S %Z %z"),
        },
        "browser_languages": browser_languages,
        "browser_probe": browser_probe,
        "networksetup": {
            "web_proxy": parse_key_value_block(str(wifi_webproxy_raw.get("stdout", ""))),
            "secure_web_proxy": parse_key_value_block(str(wifi_secureproxy_raw.get("stdout", ""))),
            "socks_proxy": parse_key_value_block(str(wifi_socks_raw.get("stdout", ""))),
            "auto_proxy_url": parse_key_value_block(str(wifi_autoproxy_raw.get("stdout", ""))),
            "auto_proxy_discovery": str(wifi_discovery_raw.get("stdout", "")),
        },
        "clash": {"configs": clash_configs},
        "raw_command_status": {
            "proxy": proxy_raw,
            "dns": dns_raw,
            "route": route_raw,
            "routes": routes_raw,
            "tcp": tcp_raw,
            "udp": udp_raw,
        },
    }
    data["findings"] = make_findings(data)
    data["recommendations"] = build_recommendations(data)
    return data


def render_markdown(data: dict[str, object]) -> str:
    lines = [
        "# Network Fingerprint Audit",
        "",
        f"- Generated at: {data.get('generated_at')}",
        f"- Hostname: {data.get('host', {}).get('hostname')}",
        "",
        "## Findings",
        "",
    ]

    findings = data.get("findings", [])
    if isinstance(findings, list) and findings:
        for item in findings:
            if not isinstance(item, dict):
                continue
            lines.append(
                f"- [{str(item.get('severity', 'info')).upper()}] {item.get('title')}: {item.get('detail')}"
            )
    else:
        lines.append("- No obvious high-signal inconsistencies were detected.")

    recommendations = data.get("recommendations", [])
    if isinstance(recommendations, list) and recommendations:
        lines.extend(["", "## Recommendations", ""])
        for item in recommendations:
            if not isinstance(item, dict):
                continue
            lines.append(
                f"- [{item.get('priority')}] {item.get('area')}: {item.get('action')} Why: {item.get('why')}"
            )

    public_ip = data.get("public_ip", {})
    if isinstance(public_ip, dict):
        ipinfo = public_ip.get("ipinfo") or {}
        ifconfig = public_ip.get("ifconfig") or {}
        lines.extend(
            [
                "",
                "## Public Egress",
                "",
                f"- IP: {ipinfo.get('ip') or ifconfig.get('ip') or 'unknown'}",
                f"- Org/ASN: {ipinfo.get('org') or ifconfig.get('asn_org') or 'unknown'}",
                f"- Location: {ipinfo.get('city') or ifconfig.get('city') or 'unknown'}, {ipinfo.get('region') or ifconfig.get('region_name') or ''} {ipinfo.get('country') or ifconfig.get('country_iso') or ''}".strip(),
                f"- Timezone: {ipinfo.get('timezone') or ifconfig.get('time_zone') or 'unknown'}",
            ]
        )

    dns = data.get("dns", {})
    if isinstance(dns, dict):
        lines.extend(
            [
                "",
                "## DNS",
                "",
                f"- Nameservers from `scutil --dns`: {', '.join(dns.get('nameservers', [])) or 'none'}",
                f"- Wi-Fi DNS: {dns.get('wifi_dns_raw') or 'none'}",
                f"- NWI summary: `{str(dns.get('nwi', '')).replace(chr(10), ' | ')}`",
            ]
        )

    locale = data.get("locale", {})
    if isinstance(locale, dict):
        lines.extend(
            [
                "",
                "## Locale Signals",
                "",
                f"- LANG: {locale.get('lang') or 'unset'}",
                f"- AppleLanguages: {locale.get('apple_languages') or []}",
                f"- AppleLocale: {locale.get('apple_locale') or 'unknown'}",
                f"- Local time: {locale.get('timestamp') or 'unknown'}",
            ]
        )

    browsers = data.get("browser_languages", [])
    if isinstance(browsers, list):
        lines.extend(["", "## Browser Languages", ""])
        for browser in browsers:
            if not isinstance(browser, dict):
                continue
            lines.append(f"- {browser.get('browser')} last_used={browser.get('last_used') or 'unknown'}")
            for profile in browser.get("profiles", []):
                if not isinstance(profile, dict):
                    continue
                lines.append(
                    f"  - {profile.get('profile')}: {profile.get('accept_languages')}"
                )

    browser_probe = data.get("browser_probe", {})
    if isinstance(browser_probe, dict):
        lines.extend(["", "## Browser Probe", ""])
        lines.append(f"- Status: {browser_probe.get('status')}")
        if browser_probe.get("reason"):
            lines.append(f"- Reason: {browser_probe.get('reason')}")
        if browser_probe.get("browser_path"):
            lines.append(f"- Browser: {browser_probe.get('browser_path')}")
        if browser_probe.get("language_hint"):
            lines.append(f"- Language hint: {browser_probe.get('language_hint')}")
        if browser_probe.get("note"):
            lines.append(f"- Note: {browser_probe.get('note')}")

        probe_result = browser_probe.get("result", {})
        if isinstance(probe_result, dict):
            navigator_info = probe_result.get("navigator", {})
            header_echo = probe_result.get("headerEcho", {})
            webrtc = probe_result.get("webrtc", {})

            if isinstance(navigator_info, dict):
                lines.append(f"- navigator.language: {navigator_info.get('language')}")
                lines.append(f"- navigator.languages: {navigator_info.get('languages')}")
                lines.append(f"- navigator.userAgent: {navigator_info.get('userAgent')}")
                lines.append(f"- Browser timezone: {navigator_info.get('timezone')}")

            if isinstance(header_echo, dict):
                lines.append(f"- Header echo URL: {header_echo.get('url')}")
                lines.append(f"- Header echo origin: {header_echo.get('origin')}")
                accept_language = get_case_insensitive(header_echo.get("headers"), "Accept-Language")
                user_agent = get_case_insensitive(header_echo.get("headers"), "User-Agent")
                lines.append(f"- Echo Accept-Language: {accept_language or 'missing'}")
                lines.append(f"- Echo User-Agent: {user_agent or 'missing'}")

            if isinstance(webrtc, dict):
                candidates = webrtc.get("candidates", [])
                lines.append(f"- WebRTC supported: {webrtc.get('supported')}")
                lines.append(f"- WebRTC candidate count: {len(candidates) if isinstance(candidates, list) else 0}")
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
                "## Proxy Setup",
                "",
                f"- Web proxy: {networksetup.get('web_proxy')}",
                f"- Secure web proxy: {networksetup.get('secure_web_proxy')}",
                f"- SOCKS proxy: {networksetup.get('socks_proxy')}",
                f"- Auto proxy URL: {networksetup.get('auto_proxy_url')}",
                f"- Auto proxy discovery: {networksetup.get('auto_proxy_discovery')}",
            ]
        )

    clash = data.get("clash", {})
    if isinstance(clash, dict) and clash.get("configs"):
        lines.extend(["", "## Clash Snapshot", ""])
        for config in clash["configs"]:
            if not isinstance(config, dict):
                continue
            lines.append(f"- {config.get('path')}")
            for excerpt in config.get("excerpt", []):
                lines.append(f"  - `{excerpt}`")

    return "\n".join(lines) + "\n"


def write_reports(data: dict[str, object], output_dir: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    json_path = output_dir / f"audit-{stamp}.json"
    md_path = output_dir / f"audit-{stamp}.md"
    json_path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(data), encoding="utf-8")
    return json_path, md_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit macOS network and locale signals.")
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
    args = parser.parse_args()

    data = collect_data(
        skip_network=args.skip_network,
        skip_browser_probe=args.skip_browser_probe,
        browser_path=args.browser_path,
    )
    json_path, md_path = write_reports(data, pathlib.Path(args.output_dir))

    findings = data.get("findings", [])
    high = sum(1 for item in findings if isinstance(item, dict) and item.get("severity") == "high")
    medium = sum(1 for item in findings if isinstance(item, dict) and item.get("severity") == "medium")
    browser_probe_status = (data.get("browser_probe") or {}).get("status")
    print(f"Generated report: {md_path}")
    print(f"Generated report: {json_path}")
    print(
        f"High findings: {high} | Medium findings: {medium} | Total findings: {len(findings)} | Browser probe: {browser_probe_status}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
