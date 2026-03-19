import unittest

import network_audit


class NetworkAuditParsingTests(unittest.TestCase):
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

    def test_choose_active_network_service_falls_back_to_wifi(self) -> None:
        selected = network_audit.choose_active_network_service(
            None,
            [{"service": "Wi-Fi", "enabled": True, "device": "en0"}],
            ["Wi-Fi"],
        )
        self.assertEqual(
            selected,
            {"service": "Wi-Fi", "interface": None, "source": "fallback-wifi"},
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
