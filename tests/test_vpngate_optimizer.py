import base64
import importlib.util
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location(
    "vpngate", Path(__file__).parents[1] / "scripts" / "vpngate_optimizer.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class Tests(unittest.TestCase):
    def test_tcp(self):
        config = """proto tcp-client
remote 203.0.113.1 443
<ca>
CA
</ca>
"""
        proxy = module.parse_profile(config, {"CountryLong": "Japan"})["proxy"]
        self.assertEqual(proxy["type"], "openvpn")
        self.assertEqual(proxy["proto"], "tcp")
        self.assertFalse(proxy["udp"])
        self.assertEqual(proxy["username"], "vpn")
        self.assertEqual(proxy["password"], "vpn")

    def test_udp_tls_auth(self):
        config = """proto udp
remote 198.51.100.1 1194
key-direction 1
<ca>
CA
</ca>
<tls-auth>
KEY
</tls-auth>
"""
        proxy = module.parse_profile(config, {"CountryLong": "US"})["proxy"]
        self.assertTrue(proxy["udp"])
        self.assertEqual(proxy["key-direction"], "1")
        self.assertIn("KEY", proxy["tls-auth"])

    def test_csv(self):
        config = "proto tcp-client\nremote 203.0.113.2 443\n<ca>\nCA\n</ca>\n"
        encoded = base64.b64encode(config.encode()).decode()
        raw = (
            "*vpn_servers\n"
            "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,"
            "Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\n"
            "vpn1,203.0.113.2,90,10,1000,Japan,JP,1,2,3,4,0,op,msg,"
            + encoded
            + "\n*vpn_servers_end\n"
        )
        nodes = module.parse_csv(raw)
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0]["country"], "Japan")
        self.assertNotIn("ping", nodes[0])
        self.assertNotIn("speed", nodes[0])

    def test_reject_incomplete(self):
        self.assertIsNone(module.parse_profile("proto tcp\nremote x 443\n", {}))
        self.assertIsNone(module.parse_profile("proto tcp\n<ca>\nCA\n</ca>", {}))

    def test_site_order_is_preserved(self):
        items = [
            {"proxy": {"name": "first"}},
            {"proxy": {"name": "second"}},
            {"proxy": {"name": "third"}},
        ]
        self.assertEqual(
            [item["proxy"]["name"] for item in module.rank(items, 2)],
            ["first", "second"],
        )

    def test_connectivity_accepts_success_status(self):
        response = Mock(status_code=204)
        with patch.object(module.requests, "get", return_value=response):
            self.assertTrue(module.check_connectivity("http://127.0.0.1:7890"))
        response.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
