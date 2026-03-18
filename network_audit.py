#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import re
import socket
import subprocess
import sys
import urllib.error
import urllib.request


PROJECT_ROOT = pathlib.Path(__file__).resolve().parent
DEFAULT_REPORTS_DIR = PROJECT_ROOT / "reports"

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
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError):
        return None


def fetch_text(url: str, timeout: int = 5) -> str | None:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return response.read().decode("utf-8", errors="replace")
    except urllib.error.URLError:
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
    if isinstance(proxy, dict):
        if proxy.get("ProxyAutoDiscoveryEnable") == "1":
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

    return findings


def collect_data(skip_network: bool) -> dict[str, object]:
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

    browser_languages = []
    for browser_name, base_path in (
        ("Chrome", pathlib.Path.home() / "Library/Application Support/Google/Chrome"),
        ("Chromium", pathlib.Path.home() / "Library/Application Support/Chromium"),
    ):
        if base_path.exists():
            browser_languages.append(extract_browser_languages(base_path, browser_name))

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
            "apple_languages": parse_defaults_array(str(apple_languages_raw.get("stdout", ""))),
            "apple_locale": str(apple_locale_raw.get("stdout", "")),
            "timestamp": now.strftime("%Y-%m-%d %H:%M:%S %Z %z"),
        },
        "browser_languages": browser_languages,
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
        help="Skip public IP lookups against external services.",
    )
    args = parser.parse_args()

    data = collect_data(skip_network=args.skip_network)
    json_path, md_path = write_reports(data, pathlib.Path(args.output_dir))

    findings = data.get("findings", [])
    high = sum(1 for item in findings if isinstance(item, dict) and item.get("severity") == "high")
    medium = sum(1 for item in findings if isinstance(item, dict) and item.get("severity") == "medium")
    print(f"Generated report: {md_path}")
    print(f"Generated report: {json_path}")
    print(f"High findings: {high} | Medium findings: {medium} | Total findings: {len(findings)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
