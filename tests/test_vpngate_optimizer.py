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

    def test_csv_and_metadata_extraction(self):
        config = "proto tcp-client\nremote 203.0.113.2 443\n<ca>\nCA\n</ca>\n"
        encoded = base64.b64encode(config.encode()).decode()
        raw = (
            "*vpn_servers\n"
            "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,"
            "Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\n"
            "vpn1,203.0.113.2,90,10,50000000,Japan,JP,1,2,3,4,0,op,msg,"
            + encoded
            + "\n*vpn_servers_end\n"
        )
        nodes = module.parse_csv(raw)
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0]["country"], "Japan")
        self.assertEqual(nodes[0]["country_short"], "JP")
        self.assertEqual(nodes[0]["speed_bps"], 50000000)
        self.assertEqual(nodes[0]["ping_ms"], 10)

    def test_reject_incomplete(self):
        self.assertIsNone(module.parse_profile("proto tcp\nremote x 443\n", {}))
        self.assertIsNone(module.parse_profile("proto tcp\n<ca>\nCA\n</ca>", {}))

    def test_reachable_nodes_sorted_by_latency_when_measured(self):
        items = [
            {"proxy": {"name": "node-slow"}, "ok": True, "latency_ms": 650},
            {"proxy": {"name": "node-dead"}, "ok": False},
            {"proxy": {"name": "node-fast"}, "ok": True, "latency_ms": 180},
            {"proxy": {"name": "node-mid"}, "ok": True, "latency_ms": 320},
        ]
        with patch.object(module, "probe", side_effect=lambda item, *args: item["ok"]):
            reachable = module._run_probes(items, "mihomo", 4, Path("/tmp/cf001-test"), {})
        self.assertEqual(
            [item["proxy"]["name"] for item in reachable],
            ["node-fast", "node-mid", "node-slow"],
        )

    def test_warp_config_and_proxy(self):
        key = base64.b64encode(bytes(range(32))).decode()
        config = module.load_warp_config(__import__("json").dumps({
            "private_key": key, "peer_public_key": key, "ipv4": "172.16.0.2",
            "reserved": [1, 2, 3]
        }))
        self.assertEqual(config["mtu"], 1280)
        self.assertEqual(config["keepalive"], 25)
        proxy = module.build_warp_proxy(config)
        self.assertEqual(proxy["type"], "wireguard")
        self.assertEqual(proxy["ip"], "172.16.0.2")
        self.assertEqual(proxy["peers"][0]["reserved"], [1, 2, 3])

    def test_warp_amnezia_wg_published_by_default(self):
        key = base64.b64encode(bytes(range(32))).decode()
        config = module.load_warp_config(__import__("json").dumps({
            "private_key": key, "peer_public_key": key, "ipv4": "172.16.0.2"
        }))
        primary = module.build_warp_proxy(config)
        pool = module.build_warp_proxies(config, primary, verified_ports=[2408, 500])
        self.assertNotEqual(pool[0]["peers"][0]["server"], "engage.cloudflareclient.com")
        self.assertIn("amnezia-wg-option", pool[0])
        self.assertEqual(pool[0]["amnezia-wg-option"]["jc"], 4)

    def test_warp_reserved_defaults_to_current_registration(self):
        key = base64.b64encode(bytes(range(32))).decode()
        config = module.load_warp_config(__import__("json").dumps({
            "private_key": key, "peer_public_key": key, "ipv4": "172.16.0.2"
        }))
        self.assertEqual(config["reserved"], [211, 165, 3])
        self.assertEqual(module.build_warp_proxy(config)["peers"][0]["reserved"], [211, 165, 3])

    def test_write_yaml_generates_direct_and_chained_nodes_without_dns_deadlock(self):
        key = base64.b64encode(bytes(range(32))).decode()
        warp_config = module.load_warp_config(__import__("json").dumps({
            "private_key": key, "peer_public_key": key, "ipv4": "172.16.0.2"
        }))
        warp_proxy = module.build_warp_proxy(warp_config)
        sample_results = [
            {
                "country": "Japan",
                "proxy": {
                    "name": "Japan 203.0.113.10",
                    "type": "openvpn",
                    "server": "203.0.113.10",
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
            doc = module.write_yaml(
                sample_results,
                out_file,
                warp_proxy,
                warp_config=warp_config,
                verified_ports=[2408, 500],
            )
            group_names = [g["name"] for g in doc["proxy-groups"]]
            self.assertIn("出站节点", group_names)
            self.assertIn("⚡ 自动优选 (最快)", group_names)
            self.assertIn("🛡️ 故障转移 (稳定)", group_names)
            self.assertIn("🚀 直连节点池 (免WARP)", group_names)
            self.assertIn("🔗 链式节点池 (过WARP)", group_names)
            self.assertIn("🌐 WARP 前置池", group_names)
            openvpn_nodes = [p for p in doc["proxies"] if p["type"] == "openvpn"]
            self.assertEqual(len(openvpn_nodes), 2)
            self.assertNotIn("dialer-proxy", openvpn_nodes[0])
            self.assertEqual(openvpn_nodes[1]["dialer-proxy"], "🌐 WARP 前置池")
            # Confirm DNS no longer deadlocks on #WARP
            self.assertFalse(any("#WARP" in ns for ns in doc["dns"]["nameserver"]))


if __name__ == "__main__":
    unittest.main()
