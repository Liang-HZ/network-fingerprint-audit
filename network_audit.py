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
    if title == "System DNS points to China-oriented public resolvers":
        return ("系统 DNS 指向中国公共解析器", "系统当前配置的解析器里包含常见中国公共 DNS。")
    if title == "Local language signals include Chinese":
        return ("本机语言信号包含中文", detail.replace("; ", "；"))
    match = re.match(r"^(?P<browser>.+) profile exposes Chinese Accept-Language$", title)
    if match:
        return (f"{match.group('browser')} 配置文件暴露中文 Accept-Language", f"检测到 {detail}。")
    if title == "WPAD auto proxy discovery is enabled":
        return ("系统开启了 WPAD 自动代理发现", "自动代理发现会为部分应用增加额外的代理选择路径。")
    if title == "Local DNS interception appears active":
        return ("本地 DNS 劫持看起来是生效的", "Clash/Mihomo 正在监听 127.0.0.1:53，并启用了 DNS 劫持。")
    if title == "Browser probe sent Chinese Accept-Language":
        return ("浏览器探针实际发出了中文语言头", detail.replace("Echo endpoint saw: ", "回显站点看到的 Accept-Language 为："))
    if title == "Browser WebRTC exposes private host candidates":
        return ("浏览器 WebRTC 暴露了私网 host 候选", "浏览器探针看到了原始私网 ICE host 地址。")
    if title == "Browser WebRTC local addresses are obfuscated with mDNS":
        return ("浏览器 WebRTC 已用 mDNS 混淆本地地址", "host 候选显示为 `.local`，没有直接暴露原始私网 IP。")
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
        "Browser probe was skipped by configuration.": "浏览器探针已按配置跳过。",
        "Browser probe was skipped because --skip-network was set.": "由于传入了 --skip-network，浏览器探针已跳过。",
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
        f"- 主机名：{host.get('hostname')}",
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
        ipinfo = public_ip.get("ipinfo") or {}
        ifconfig = public_ip.get("ifconfig") or {}
        lines.extend(
            [
                "",
                "## 公网出口",
                "",
                f"- IP：{ipinfo.get('ip') or ifconfig.get('ip') or '未知'}",
                f"- ASN / 组织：{ipinfo.get('org') or ifconfig.get('asn_org') or '未知'}",
                f"- 位置：{ipinfo.get('city') or ifconfig.get('city') or '未知'}，{ipinfo.get('region') or ifconfig.get('region_name') or ''} {ipinfo.get('country') or ifconfig.get('country_iso') or ''}".strip(),
                f"- 时区：{ipinfo.get('timezone') or ifconfig.get('time_zone') or '未知'}",
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
                f"- Wi-Fi DNS：{dns.get('wifi_dns_raw') or '未知'}",
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
                f"- AppleLanguages：{locale.get('apple_languages') or []}",
                f"- AppleLocale：{locale.get('apple_locale') or '未知'}",
                f"- 本地时间：{locale.get('timestamp') or '未知'}",
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
        lines.append(f"- 状态：{probe_status_label(str(browser_probe.get('status') or ''))}")
        if browser_probe.get("reason"):
            lines.append(f"- 说明：{localize_browser_probe_reason(str(browser_probe.get('reason')))}")
        if browser_probe.get("browser_path"):
            lines.append(f"- 浏览器：{browser_probe.get('browser_path')}")
        if browser_probe.get("language_hint"):
            lines.append(f"- 语言提示：{browser_probe.get('language_hint')}")
        if browser_probe.get("note"):
            lines.append(f"- 备注：{localize_browser_probe_note(str(browser_probe.get('note')))}")

        probe_result = browser_probe.get("result", {})
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
                lines.append(f"- ICE 候选数量：{len(candidates) if isinstance(candidates, list) else 0}")
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

    clash = data.get("clash", {})
    if isinstance(clash, dict) and clash.get("configs"):
        lines.extend(["", "## Clash 运行态快照", ""])
        for config in clash["configs"]:
            if not isinstance(config, dict):
                continue
            lines.append(f"- {config.get('path')}")
            for excerpt in config.get("excerpt", []):
                lines.append(f"  - `{excerpt}`")

    return "\n".join(lines) + "\n"


def render_html(data: dict[str, object]) -> str:
    findings = [item for item in data.get("findings", []) if isinstance(item, dict)]
    recommendations = [item for item in data.get("recommendations", []) if isinstance(item, dict)]
    high_count = sum(1 for item in findings if item.get("severity") == "high")
    medium_count = sum(1 for item in findings if item.get("severity") == "medium")
    low_count = sum(1 for item in findings if item.get("severity") == "low")

    public_ip = data.get("public_ip", {}) if isinstance(data.get("public_ip"), dict) else {}
    ipinfo = public_ip.get("ipinfo") or {}
    ifconfig = public_ip.get("ifconfig") or {}

    browser_probe = data.get("browser_probe", {}) if isinstance(data.get("browser_probe"), dict) else {}
    probe_result = browser_probe.get("result", {}) if isinstance(browser_probe.get("result"), dict) else {}
    navigator_info = probe_result.get("navigator", {}) if isinstance(probe_result.get("navigator"), dict) else {}
    header_echo = probe_result.get("headerEcho", {}) if isinstance(probe_result.get("headerEcho"), dict) else {}
    webrtc = probe_result.get("webrtc", {}) if isinstance(probe_result.get("webrtc"), dict) else {}

    def esc(value: object) -> str:
        return html.escape(format_value(value))

    def severity_chip(level: str) -> str:
        return f'<span class="chip chip-{html.escape(level)}">{html.escape(severity_label(level))}</span>'

    findings_html = []
    for item in findings:
        title, detail = localize_finding(item)
        findings_html.append(
            f"""
            <article class="finding-card level-{html.escape(str(item.get("severity") or "info"))}">
              <div class="finding-top">
                {severity_chip(str(item.get("severity") or "info"))}
                <h3>{html.escape(title)}</h3>
              </div>
              <p>{html.escape(detail)}</p>
            </article>
            """
        )

    recommendations_html = []
    for item in recommendations:
        priority, area, action, why = localize_recommendation(item)
        recommendations_html.append(
            f"""
            <article class="recommend-card">
              <div class="recommend-top">
                <span class="pill">{html.escape(priority)}</span>
                <h3>{html.escape(area)}</h3>
              </div>
              <p>{html.escape(action)}</p>
              <p class="why">原因：{html.escape(why)}</p>
            </article>
            """
        )

    browser_language_blocks = []
    for browser in data.get("browser_languages", []):
        if not isinstance(browser, dict):
            continue
        profiles = []
        for profile in browser.get("profiles", []):
            if not isinstance(profile, dict):
                continue
            profiles.append(
                f"<li><strong>{html.escape(str(profile.get('profile') or '未知'))}</strong><span>{html.escape(str(profile.get('accept_languages') or '未知'))}</span></li>"
            )
        browser_language_blocks.append(
            f"""
            <div class="subcard">
              <div class="subcard-head">
                <h3>{html.escape(str(browser.get("browser") or "浏览器"))}</h3>
                <span>最近使用：{html.escape(str(browser.get("last_used") or "未知"))}</span>
              </div>
              <ul class="profile-list">{"".join(profiles) or "<li><span>未发现 profile 语言配置</span></li>"}</ul>
            </div>
            """
        )

    webrtc_candidates = []
    for candidate in webrtc.get("candidates", []):
        if not isinstance(candidate, dict):
            continue
        webrtc_candidates.append(
            f"<li><strong>{html.escape(str(candidate.get('candidateType') or 'unknown'))}</strong><span>{html.escape(str(candidate.get('protocol') or 'unknown'))}</span><code>{html.escape(str(candidate.get('address') or 'unknown'))}:{html.escape(str(candidate.get('port') or 'unknown'))}</code></li>"
        )

    clash_blocks = []
    for config in (data.get("clash", {}) or {}).get("configs", []):
        if not isinstance(config, dict):
            continue
        excerpts = "".join(f"<li><code>{html.escape(str(line))}</code></li>" for line in config.get("excerpt", []))
        clash_blocks.append(
            f"""
            <div class="subcard">
              <div class="subcard-head">
                <h3>{html.escape(str(config.get("path") or "配置文件"))}</h3>
              </div>
              <ul class="code-list">{excerpts}</ul>
            </div>
            """
        )

    accept_language = get_case_insensitive(header_echo.get("headers"), "Accept-Language")
    user_agent = get_case_insensitive(header_echo.get("headers"), "User-Agent")

    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>网络环境指纹审计报告</title>
  <style>
    :root {{
      --bg: #f6f1e8;
      --panel: rgba(255,255,255,0.78);
      --panel-strong: rgba(255,255,255,0.9);
      --ink: #201812;
      --muted: #6b5d4f;
      --line: rgba(50, 36, 24, 0.12);
      --accent: #9d4f2f;
      --accent-soft: #e7b98d;
      --high: #b33a2b;
      --medium: #d17b0f;
      --low: #4f7d61;
      --info: #5c6d9e;
      --shadow: 0 24px 80px rgba(43, 27, 18, 0.12);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, rgba(212, 153, 109, 0.32), transparent 28%),
        radial-gradient(circle at top right, rgba(129, 152, 212, 0.22), transparent 32%),
        linear-gradient(180deg, #f8f3eb 0%, #f1e6d6 100%);
      font-family: "Iowan Old Style", "Palatino Linotype", "Book Antiqua", Palatino, Georgia, serif;
      line-height: 1.6;
    }}
    main {{
      width: min(1180px, calc(100vw - 40px));
      margin: 28px auto 44px;
    }}
    .hero, section {{
      background: var(--panel);
      backdrop-filter: blur(14px);
      border: 1px solid var(--line);
      border-radius: 28px;
      box-shadow: var(--shadow);
    }}
    .hero {{
      padding: 34px;
      overflow: hidden;
      position: relative;
    }}
    .hero::after {{
      content: "";
      position: absolute;
      inset: auto -20% -45% auto;
      width: 320px;
      height: 320px;
      border-radius: 999px;
      background: radial-gradient(circle, rgba(157,79,47,0.22), transparent 68%);
      pointer-events: none;
    }}
    .eyebrow {{
      letter-spacing: 0.18em;
      text-transform: uppercase;
      color: var(--accent);
      font-size: 12px;
      margin-bottom: 12px;
    }}
    h1 {{
      margin: 0 0 12px;
      font-size: clamp(34px, 5vw, 58px);
      line-height: 1.02;
      font-weight: 700;
    }}
    .hero p {{
      max-width: 720px;
      color: var(--muted);
      margin: 0 0 18px;
      font-size: 17px;
    }}
    .meta {{
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      color: var(--muted);
      font-size: 14px;
    }}
    .stats {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 14px;
      margin-top: 24px;
    }}
    .stat {{
      padding: 18px 20px;
      border-radius: 22px;
      background: var(--panel-strong);
      border: 1px solid var(--line);
    }}
    .stat-label {{
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.14em;
    }}
    .stat-value {{
      margin-top: 8px;
      font-size: 28px;
      font-weight: 700;
    }}
    section {{
      margin-top: 20px;
      padding: 26px;
    }}
    section h2 {{
      margin: 0 0 18px;
      font-size: 28px;
    }}
    .section-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 16px;
    }}
    .finding-grid, .recommend-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 16px;
    }}
    .finding-card, .recommend-card, .subcard {{
      background: var(--panel-strong);
      border: 1px solid var(--line);
      border-radius: 22px;
      padding: 18px;
    }}
    .finding-card p, .recommend-card p, .subcard p {{
      margin: 12px 0 0;
      color: var(--muted);
    }}
    .finding-top, .recommend-top, .subcard-head {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
    }}
    .finding-top h3, .recommend-top h3, .subcard-head h3 {{
      margin: 0;
      font-size: 20px;
    }}
    .chip, .pill {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 6px 10px;
      border-radius: 999px;
      font-size: 12px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      border: 1px solid currentColor;
    }}
    .chip-high {{ color: var(--high); background: rgba(179,58,43,0.09); }}
    .chip-medium {{ color: var(--medium); background: rgba(209,123,15,0.1); }}
    .chip-low {{ color: var(--low); background: rgba(79,125,97,0.1); }}
    .chip-info {{ color: var(--info); background: rgba(92,109,158,0.1); }}
    .pill {{ color: var(--accent); background: rgba(157,79,47,0.08); }}
    .metric-list, .profile-list, .code-list, .candidate-list {{
      list-style: none;
      padding: 0;
      margin: 0;
      display: grid;
      gap: 10px;
    }}
    .metric-list li, .profile-list li, .candidate-list li {{
      display: flex;
      justify-content: space-between;
      gap: 16px;
      padding: 10px 0;
      border-bottom: 1px solid var(--line);
      color: var(--muted);
    }}
    .metric-list li:last-child, .profile-list li:last-child, .candidate-list li:last-child {{
      border-bottom: 0;
      padding-bottom: 0;
    }}
    .metric-list strong, .profile-list strong, .candidate-list strong {{
      color: var(--ink);
      min-width: 112px;
    }}
    code {{
      font-family: "SFMono-Regular", "IBM Plex Mono", Menlo, Consolas, monospace;
      font-size: 12px;
      background: rgba(35, 24, 18, 0.06);
      border-radius: 10px;
      padding: 3px 6px;
      word-break: break-all;
    }}
    .code-list li {{
      margin: 0 0 8px;
    }}
    .why {{
      font-size: 14px;
    }}
    .muted {{
      color: var(--muted);
    }}
    @media (max-width: 720px) {{
      main {{
        width: min(100vw - 24px, 100%);
        margin: 12px auto 28px;
      }}
      .hero, section {{
        border-radius: 22px;
      }}
      .hero {{
        padding: 24px;
      }}
      section {{
        padding: 20px;
      }}
      .metric-list li, .profile-list li, .candidate-list li {{
        flex-direction: column;
      }}
    }}
  </style>
</head>
<body>
  <main>
    <header class="hero">
      <div class="eyebrow">Network Fingerprint Audit</div>
      <h1>网络环境指纹审计报告</h1>
      <p>把 DNS、代理、浏览器语言、WebRTC、出口 ASN 和本机区域信号放进一份可读报告里，方便你快速判断哪些地方还存在不一致。</p>
      <div class="meta">
        <span>生成时间：{esc(data.get("generated_at"))}</span>
        <span>主机名：{esc((data.get("host") or {}).get("hostname"))}</span>
      </div>
      <div class="stats">
        <div class="stat">
          <div class="stat-label">高风险项</div>
          <div class="stat-value">{high_count}</div>
        </div>
        <div class="stat">
          <div class="stat-label">中风险项</div>
          <div class="stat-value">{medium_count}</div>
        </div>
        <div class="stat">
          <div class="stat-label">低风险项</div>
          <div class="stat-value">{low_count}</div>
        </div>
        <div class="stat">
          <div class="stat-label">浏览器探针</div>
          <div class="stat-value">{html.escape(probe_status_label(str(browser_probe.get("status") or "")))}</div>
        </div>
      </div>
    </header>

    <section>
      <h2>主要发现</h2>
      <div class="finding-grid">
        {"".join(findings_html) or '<p class="muted">当前没有发现明显的高信号不一致项。</p>'}
      </div>
    </section>

    <section>
      <h2>修复建议</h2>
      <div class="recommend-grid">
        {"".join(recommendations_html)}
      </div>
    </section>

    <section>
      <h2>关键信号总览</h2>
      <div class="section-grid">
        <div class="subcard">
          <div class="subcard-head"><h3>公网出口</h3></div>
          <ul class="metric-list">
            <li><strong>IP</strong><span>{esc(ipinfo.get("ip") or ifconfig.get("ip"))}</span></li>
            <li><strong>ASN / 组织</strong><span>{esc(ipinfo.get("org") or ifconfig.get("asn_org"))}</span></li>
            <li><strong>位置</strong><span>{esc(f"{ipinfo.get('city') or ifconfig.get('city') or '未知'}，{ipinfo.get('region') or ifconfig.get('region_name') or ''} {ipinfo.get('country') or ifconfig.get('country_iso') or ''}")}</span></li>
            <li><strong>时区</strong><span>{esc(ipinfo.get("timezone") or ifconfig.get("time_zone"))}</span></li>
          </ul>
        </div>
        <div class="subcard">
          <div class="subcard-head"><h3>DNS 信号</h3></div>
          <ul class="metric-list">
            <li><strong>系统 DNS</strong><span>{esc(", ".join((data.get("dns") or {}).get("nameservers", [])))}</span></li>
            <li><strong>Wi‑Fi DNS</strong><span>{esc((data.get("dns") or {}).get("wifi_dns_raw"))}</span></li>
            <li><strong>NWI</strong><span>{esc(str((data.get("dns") or {}).get("nwi") or "").replace(chr(10), " | "))}</span></li>
          </ul>
        </div>
        <div class="subcard">
          <div class="subcard-head"><h3>语言与区域</h3></div>
          <ul class="metric-list">
            <li><strong>LANG</strong><span>{esc((data.get("locale") or {}).get("lang"))}</span></li>
            <li><strong>AppleLanguages</strong><span>{esc((data.get("locale") or {}).get("apple_languages"))}</span></li>
            <li><strong>AppleLocale</strong><span>{esc((data.get("locale") or {}).get("apple_locale"))}</span></li>
            <li><strong>本地时间</strong><span>{esc((data.get("locale") or {}).get("timestamp"))}</span></li>
          </ul>
        </div>
        <div class="subcard">
          <div class="subcard-head"><h3>代理设置</h3></div>
          <ul class="metric-list">
            <li><strong>Web</strong><span>{esc((data.get("networksetup") or {}).get("web_proxy"))}</span></li>
            <li><strong>HTTPS</strong><span>{esc((data.get("networksetup") or {}).get("secure_web_proxy"))}</span></li>
            <li><strong>SOCKS</strong><span>{esc((data.get("networksetup") or {}).get("socks_proxy"))}</span></li>
            <li><strong>自动发现</strong><span>{esc((data.get("networksetup") or {}).get("auto_proxy_discovery"))}</span></li>
          </ul>
        </div>
      </div>
    </section>

    <section>
      <h2>浏览器语言配置</h2>
      <div class="section-grid">
        {"".join(browser_language_blocks) or '<p class="muted">未发现浏览器 profile 语言配置。</p>'}
      </div>
    </section>

    <section>
      <h2>浏览器侧探针</h2>
      <div class="section-grid">
        <div class="subcard">
          <div class="subcard-head"><h3>探针状态</h3></div>
          <ul class="metric-list">
            <li><strong>状态</strong><span>{html.escape(probe_status_label(str(browser_probe.get("status") or "")))}</span></li>
            <li><strong>浏览器</strong><span>{esc(browser_probe.get("browser_path"))}</span></li>
            <li><strong>语言提示</strong><span>{esc(browser_probe.get("language_hint"))}</span></li>
            <li><strong>备注</strong><span>{html.escape(localize_browser_probe_note(str(browser_probe.get("note") or "")) or localize_browser_probe_reason(str(browser_probe.get("reason") or "")) or "无")}</span></li>
          </ul>
        </div>
        <div class="subcard">
          <div class="subcard-head"><h3>浏览器头与时区</h3></div>
          <ul class="metric-list">
            <li><strong>navigator.language</strong><span>{esc(navigator_info.get("language"))}</span></li>
            <li><strong>navigator.languages</strong><span>{esc(navigator_info.get("languages"))}</span></li>
            <li><strong>回显出口 IP</strong><span>{esc(header_echo.get("origin"))}</span></li>
            <li><strong>Accept-Language</strong><span>{esc(accept_language)}</span></li>
            <li><strong>User-Agent</strong><span>{esc(user_agent)}</span></li>
            <li><strong>浏览器时区</strong><span>{esc(navigator_info.get("timezone"))}</span></li>
          </ul>
        </div>
        <div class="subcard">
          <div class="subcard-head"><h3>WebRTC ICE 候选</h3></div>
          <ul class="candidate-list">
            {"".join(webrtc_candidates) or '<li><span>未采集到候选</span></li>'}
          </ul>
        </div>
      </div>
    </section>

    <section>
      <h2>Clash 运行态快照</h2>
      <div class="section-grid">
        {"".join(clash_blocks) or '<p class="muted">未发现可读的 Clash 运行态配置。</p>'}
      </div>
    </section>
  </main>
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
    parser.add_argument(
        "--no-open",
        action="store_true",
        help="Generate reports but do not automatically open the HTML report.",
    )
    args = parser.parse_args()

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
