import unittest
from unittest import mock

import network_audit


class NetworkAuditParsingTests(unittest.TestCase):
    def test_parse_cloudflare_trace_extracts_key_value_pairs(self) -> None:
        raw = """fl=1164f50
ip=2605:52c0:1:b90:c438:caff:fe66:a8fc
loc=US
warp=off
malformed
"""
        self.assertEqual(
            network_audit.parse_cloudflare_trace(raw),
            {
                "fl": "1164f50",
                "ip": "2605:52c0:1:b90:c438:caff:fe66:a8fc",
                "loc": "US",
                "warp": "off",
            },
        )

    def test_public_ip_candidates_deduplicates_sources_in_priority_order(self) -> None:
        self.assertEqual(
            network_audit.public_ip_candidates(
                {
                    "ipapi_is": {"ip": "203.0.113.10"},
                    "ipinfo": {"ip": "203.0.113.10"},
                    "ifconfig": {"ip": "198.51.100.20"},
                    "cloudflare_trace_parsed": {"ip": "2001:db8::1"},
                }
            ),
            ["203.0.113.10", "198.51.100.20", "2001:db8::1"],
        )

    def test_make_findings_uses_structured_external_ip_intelligence(self) -> None:
        findings = network_audit.make_findings(
            {
                "public_ip": {
                    "ipapi_is": {
                        "is_datacenter": True,
                        "is_proxy": False,
                        "is_vpn": True,
                        "is_tor": False,
                        "is_abuser": False,
                        "asn": {"type": "hosting"},
                    },
                    "proxycheck": {"proxy": "yes", "type": "VPN", "risk": 66},
                }
            }
        )
        self.assertEqual(findings[0]["title"], "External IP intelligence flags egress risk")
        self.assertIn("ipapi.is:datacenter", findings[0]["detail"])
        self.assertIn("proxycheck:proxy=VPN", findings[0]["detail"])

    def test_browser_probe_result_label_uses_user_facing_webrtc_language(self) -> None:
        self.assertEqual(
            network_audit.browser_probe_result_label(
                "ok",
                [
                    {
                        "candidateType": "host",
                        "address": "abcd.local",
                    }
                ],
            ),
            "未发现本机内网 IP 泄露",
        )
        self.assertEqual(
            network_audit.browser_probe_result_label(
                "ok",
                [
                    {
                        "candidateType": "host",
                        "address": "192.168.1.12",
                    }
                ],
            ),
            "发现本机内网 IP 泄露",
        )

    def test_detect_proxy_clients_matches_processes_without_exposing_args(self) -> None:
        raw = """/Applications/Surge.app/Contents/MacOS/Surge --config /Users/alice/private.conf
/usr/local/bin/sing-box run -c /Users/alice/sensitive.json
/Applications/Notes.app/Contents/MacOS/Notes
"""
        clients = network_audit.detect_proxy_clients(raw)
        by_name = {client["name"]: client for client in clients}
        self.assertIn("Surge", by_name)
        self.assertIn("sing-box", by_name)
        self.assertEqual(by_name["Surge"]["processes"], ["Surge"])
        self.assertEqual(by_name["sing-box"]["processes"], ["sing-box"])
        self.assertNotIn("private.conf", str(clients))
        self.assertNotIn("sensitive.json", str(clients))

    def test_detect_proxy_clients_handles_windows_paths_with_spaces(self) -> None:
        raw = r"""C:\Program Files\Surge\Surge.exe
C:\Users\alice\AppData\Roaming\v2rayN\v2rayN.exe
"""
        clients = network_audit.detect_proxy_clients(raw)
        by_name = {client["name"]: client for client in clients}
        self.assertEqual(by_name["Surge"]["processes"], ["Surge"])
        self.assertEqual(by_name["V2Ray/v2rayN"]["processes"], ["v2rayN"])

    def test_parse_enabled_network_services_ignores_disabled_entries(self) -> None:
        raw = """An asterisk (*) denotes that a network service is disabled.
*USB LAN
Thunderbolt Bridge
Wi-Fi
"""
        self.assertEqual(
            network_audit.parse_enabled_network_services(raw),
            ["Thunderbolt Bridge", "Wi-Fi"],
        )

    def test_parse_windows_ipconfig_dns_extracts_continued_dns_servers(self) -> None:
        raw = """
Windows IP Configuration

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . :
   DNS Servers . . . . . . . . . . . : 1.1.1.1
                                       8.8.8.8
   NetBIOS over Tcpip. . . . . . . . : Enabled
"""
        self.assertEqual(
            network_audit.parse_windows_ipconfig_dns(raw),
            ["1.1.1.1", "8.8.8.8"],
        )

    def test_parse_listener_summary_supports_windows_netstat_format(self) -> None:
        tcp_raw = """
  TCP    127.0.0.1:7890         0.0.0.0:0              LISTENING       1234
  TCP    127.0.0.1:53           0.0.0.0:0              LISTENING       5678
"""
        udp_raw = """
  UDP    127.0.0.1:53           *:*                                    5678
"""
        self.assertEqual(
            network_audit.parse_listener_summary(tcp_raw, udp_raw),
            {
                "tcp_127_0_0_1_53": True,
                "udp_127_0_0_1_53": True,
                "tcp_127_0_0_1_7890": True,
            },
        )

    def test_windows_collection_does_not_fallback_to_process_locale(self) -> None:
        def fake_run_command(*args: str, timeout: int = 5) -> dict[str, object]:
            if args[:3] == ("powershell", "-NoProfile", "-Command") and "Get-Culture" in args[3]:
                return {"cmd": list(args), "code": 1, "stdout": "", "stderr": "culture failed"}
            if args[:3] == ("powershell", "-NoProfile", "-Command") and "Get-WinSystemLocale" in args[3]:
                return {"cmd": list(args), "code": 1, "stdout": "", "stderr": "locale failed"}
            if args[:1] == ("tzutil",):
                return {"cmd": list(args), "code": 1, "stdout": "", "stderr": "timezone failed"}
            return {"cmd": list(args), "code": 0, "stdout": "", "stderr": ""}

        with (
            mock.patch.dict(
                "os.environ",
                {"LANG": "zh_CN.UTF-8", "LC_ALL": "zh_CN.UTF-8", "TZ": "Asia/Shanghai"},
            ),
            mock.patch.object(network_audit, "run_command", side_effect=fake_run_command),
            mock.patch.object(network_audit, "collect_public_ip", return_value={}),
            mock.patch.object(network_audit, "browser_profile_roots", return_value=[]),
            mock.patch.object(
                network_audit,
                "run_browser_probe",
                return_value={"status": "skipped", "reason": "test"},
            ),
        ):
            data = network_audit.collect_windows_data(
                skip_network=True,
                skip_browser_probe=True,
                browser_path=None,
            )

        self.assertEqual(data["locale"]["lang"], "")
        self.assertEqual(data["locale"]["lc_all"], "")
        self.assertEqual(data["locale"]["tz"], "")
        self.assertEqual(data["locale"]["apple_locale"], "")
        self.assertIn("culture:", data["collection_errors"][0])
        self.assertEqual(data["findings"][0]["title"], "Required data collection failed")

    def test_parse_network_service_order_extracts_service_and_device(self) -> None:
        raw = """An asterisk (*) denotes that a network service is disabled.
(1) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)

(2) USB LAN
(Hardware Port: USB 10/100/1000 LAN, Device: en7)
"""
        self.assertEqual(
            network_audit.parse_network_service_order(raw),
            [
                {
                    "service": "Wi-Fi",
                    "enabled": True,
                    "hardware_port": "Wi-Fi",
                    "device": "en0",
                },
                {
                    "service": "USB LAN",
                    "enabled": True,
                    "hardware_port": "USB 10/100/1000 LAN",
                    "device": "en7",
                },
            ],
        )

    def test_choose_active_network_service_prefers_default_route_interface(self) -> None:
        selected = network_audit.choose_active_network_service(
            "en7",
            [
                {"service": "Wi-Fi", "enabled": True, "device": "en0"},
                {"service": "USB LAN", "enabled": True, "device": "en7"},
            ],
            ["Wi-Fi", "USB LAN"],
        )
        self.assertEqual(
            selected,
            {"service": "USB LAN", "interface": "en7", "source": "default-route"},
        )

    def test_choose_active_network_service_uses_wifi_heuristic(self) -> None:
        selected = network_audit.choose_active_network_service(
            None,
            [{"service": "Wi-Fi", "enabled": True, "device": "en0"}],
            ["Wi-Fi"],
        )
        self.assertEqual(
            selected,
            {"service": "Wi-Fi", "interface": None, "source": "heuristic-wifi"},
        )

    def test_locale_signals_include_chinese_uses_multiple_sources(self) -> None:
        self.assertTrue(
            network_audit.locale_signals_include_chinese(
                {
                    "lang": "",
                    "lc_all": "zh_CN.UTF-8",
                    "apple_languages": ["en-US"],
                    "apple_locale": "en_US",
                }
            )
        )
        self.assertTrue(
            network_audit.locale_signals_include_chinese(
                {
                    "lang": "",
                    "lc_all": "",
                    "apple_languages": ["en-US"],
                    "apple_locale": "zh_CN",
                }
            )
        )
        self.assertFalse(
            network_audit.locale_signals_include_chinese(
                {
                    "lang": "en_US.UTF-8",
                    "lc_all": "",
                    "apple_languages": ["en-US"],
                    "apple_locale": "en_US",
                }
            )
        )


if __name__ == "__main__":
    unittest.main()
