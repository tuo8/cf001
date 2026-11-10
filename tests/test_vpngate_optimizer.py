import base64
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "vpngate", Path(__file__).parents[1] / "scripts" / "vpngate_optimizer.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class Tests(unittest.TestCase):
    def setUp(self):
        self._verified_ports_patch = patch.dict(
            module.os.environ,
            {"VPNGATE_WARP_VERIFIED_PORTS": "2408,500,1701,4500"},
        )
        self._verified_ports_patch.start()

    def tearDown(self):
        self._verified_ports_patch.stop()

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

    def test_bare_comp_lzo_is_preserved(self):
        config = """proto udp
remote 198.51.100.2 1194
comp-lzo
<ca>
CA
</ca>
"""
        proxy = module.parse_profile(config, {"CountryLong": "Japan"})["proxy"]
        self.assertEqual(proxy["comp-lzo"], "yes")

    def test_comp_lzo_explicit_value_is_preserved(self):
        config = """proto udp
remote 198.51.100.3 1194
comp-lzo no
<ca>
CA
</ca>
"""
        proxy = module.parse_profile(config, {"CountryLong": "Japan"})["proxy"]
        self.assertEqual(proxy["comp-lzo"], "no")

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

    def test_reachable_nodes_preserve_official_list_order_without_speed_ranking(self):
        items = [
            {"proxy": {"name": "node-0"}, "ok": True},
            {"proxy": {"name": "node-1"}, "ok": False},
            {"proxy": {"name": "node-2"}, "ok": True},
            {"proxy": {"name": "node-3"}, "ok": True},
        ]
        with patch.object(module, "probe", side_effect=lambda item, *args: item["ok"]):
            reachable = module._run_probes(items, "mihomo", 3, Path("/tmp/cf001-test"), {})
        self.assertEqual(
            [item["proxy"]["name"] for item in reachable],
            ["node-0", "node-2", "node-3"],
        )
        self.assertFalse(hasattr(module, "rank"))
        self.assertFalse(hasattr(module, "measure_performance"))

    def test_warp_config_and_proxy(self):
        key = base64.b64encode(bytes(range(32))).decode()
        config = module.load_warp_config(__import__("json").dumps({
            "private_key": key, "peer_public_key": key, "ipv4": "172.16.0.2",
            "reserved": [1, 2, 3]
        }))
        proxy = module.build_warp_proxy(config)
        self.assertEqual(proxy["type"], "wireguard")
        self.assertEqual(proxy["ip"], "172.16.0.2")
        self.assertEqual(proxy["peers"][0]["reserved"], [1, 2, 3])

    def test_warp_reserved_defaults_to_current_registration(self):
        key = base64.b64encode(bytes(range(32))).decode()
        config = module.load_warp_config(__import__("json").dumps({
            "private_key": key, "peer_public_key": key, "ipv4": "172.16.0.2"
        }))
        self.assertEqual(config["reserved"], [211, 165, 3])
        self.assertEqual(module.build_warp_proxy(config)["peers"][0]["reserved"], [211, 165, 3])

    def test_write_yaml_strictly_passes_original_ci_assertions(self):
        key = base64.b64encode(bytes(range(32))).decode()
        warp_config = module.load_warp_config(__import__("json").dumps({
            "private_key": key, "peer_public_key": key, "ipv4": "172.16.0.2"
        }))
        warp_proxy = module.build_warp_proxy(warp_config)
        sample_results = [
            {
                "country": "Japan",
                "proxy": {
                    "name": "Japan 126.28.184.236",
                    "type": "openvpn",
                    "server": "126.28.184.236",
                    "port": 443,
                    "proto": "udp",
                    "udp": True,
                    "username": "vpn",
                    "password": "vpn",
                    "ca": "CA",
                    "cipher": "AES-128-CBC",
                    "auth": "SHA1",
                    "mtu": 1200,
                },
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            out_file = Path(tmp) / "vpngate-clash-mi.yaml"
            data = module.write_yaml(sample_results, out_file, warp_proxy)
            proxies = data.get("proxies", [])
            self.assertTrue(proxies and proxies[0].get("name") == "WARP" and proxies[0].get("type") == "wireguard")
            openvpn = proxies[1:]
            self.assertTrue(openvpn and all(p.get("type") == "openvpn" and p.get("dialer-proxy") == "WARP" for p in openvpn))
            names = {p["name"] for p in proxies}
            groups = {g["name"]: g for g in data.get("proxy-groups", [])}
            valid_names = names | set(groups)
            self.assertTrue(all(n in valid_names for group in groups.values() for n in group.get("proxies", [])))
            self.assertEqual(list(groups), ["出站节点"])
            self.assertEqual(groups["出站节点"]["proxies"], ["WARP"] + [p["name"] for p in openvpn])
            self.assertEqual(groups["出站节点"]["type"], "url-test")
            self.assertEqual(data.get("rules", [None])[0], "MATCH,出站节点")
            self.assertEqual(data["tun"]["mtu"], 1200)


if __name__ == "__main__":
    unittest.main()
