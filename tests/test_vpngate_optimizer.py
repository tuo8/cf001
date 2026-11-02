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

    def test_warp_port_override(self):
        key = base64.b64encode(bytes(range(32))).decode()
        raw = __import__("json").dumps({
            "private_key": key, "peer_public_key": key, "ipv4": "172.16.0.2", "port": 2408
        })
        with patch.dict("os.environ", {"VPNGATE_WARP_PORT": "500"}):
            config = module.load_warp_config(raw)
        self.assertEqual(config["port"], 500)
        self.assertEqual(module.build_warp_proxy(config)["peers"][0]["port"], 500)

    def test_missing_warp_config_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, "Missing VPNGATE_WARP_CONFIG"):
            module.load_warp_config("")

    def test_invalid_warp_key_rejected(self):
        with self.assertRaisesRegex(ValueError, "32 bytes"):
            module.load_warp_config(__import__("json").dumps({
                "private_key": "YQ==", "peer_public_key": "YQ==", "ipv4": "172.16.0.2"
            }))


    def test_output_deduplicates_proxy_names(self):
        key = base64.b64encode(bytes(range(32))).decode()
        cfg = module.load_warp_config(__import__("json").dumps({
            "private_key": key, "peer_public_key": key, "ipv4": "172.16.0.2"
        }))
        warp = module.build_warp_proxy(cfg)
        items = [
            {"proxy": {"name": "Duplicate", "type": "openvpn", "server": "198.51.100.1", "port": 1194}},
            {"proxy": {"name": "Duplicate", "type": "openvpn", "server": "198.51.100.2", "port": 1194}},
            {"proxy": {"name": "WARP", "type": "openvpn", "server": "198.51.100.3", "port": 1194}},
        ]
        with __import__("tempfile").TemporaryDirectory() as tmp:
            module.write_yaml(items, Path(tmp) / "out.yaml", warp)
            parsed = __import__("yaml").safe_load((Path(tmp) / "out.yaml").read_text())
        names = [proxy["name"] for proxy in parsed["proxies"]]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(names, ["WARP", "Duplicate", "Duplicate (2)", "WARP (2)"])
        self.assertEqual(
            parsed["proxy-groups"][0]["proxies"],
            ["WARP"],
        )
        self.assertEqual(
            parsed["proxy-groups"][1]["proxies"],
            ["Duplicate", "Duplicate (2)", "WARP (2)"],
        )
        self.assertEqual(
            parsed["proxy-groups"][2],
            {"name": "出站模式", "type": "select", "proxies": ["WARP 直连测试", "VPN Gate 优选"]},
        )
        self.assertEqual(parsed["rules"], ["MATCH,出站模式"])

    def test_output_contains_warp_and_chains_every_openvpn(self):
        key = base64.b64encode(bytes(range(32))).decode()
        cfg = module.load_warp_config(__import__("json").dumps({
            "private_key": key, "peer_public_key": key, "ipv4": "172.16.0.2"
        }))
        warp = module.build_warp_proxy(cfg)
        item = {"proxy": {"name": "VPN Japan", "type": "openvpn", "server": "198.51.100.1", "port": 1194}}
        with __import__("tempfile").TemporaryDirectory() as tmp:
            doc = module.write_yaml([item], Path(tmp) / "out.yaml", warp)
            parsed = __import__("yaml").safe_load((Path(tmp) / "out.yaml").read_text())
        self.assertEqual(parsed["proxies"][0]["type"], "wireguard")
        self.assertEqual(parsed["proxies"][1]["dialer-proxy"], "WARP")
        self.assertEqual(doc["proxy-groups"][0]["proxies"], ["WARP"])
        self.assertEqual(doc["proxy-groups"][1]["proxies"], ["VPN Japan"])
        self.assertEqual(doc["proxy-groups"][2]["proxies"], ["WARP 直连测试", "VPN Gate 优选"])
        self.assertEqual(doc["rules"], ["MATCH,出站模式"])

    def test_warp_port_candidates_accepts_only_go_verified_ports(self):
        with patch.dict(module.os.environ, {"VPNGATE_WARP_VERIFIED_PORTS": "1701,2408,500,4500"}):
            self.assertEqual(module.warp_port_candidates({"port": 2408}), [1701, 2408, 500, 4500])
        with patch.dict(module.os.environ, {"VPNGATE_WARP_VERIFIED_PORTS": "2408,500,2408"}):
            self.assertEqual(module.warp_port_candidates({"port": 2408}), [2408, 500])

    def test_warp_port_candidates_fails_closed_without_go_output(self):
        with patch.dict(module.os.environ, {"VPNGATE_WARP_VERIFIED_PORTS": ""}):
            with self.assertRaisesRegex(RuntimeError, "Go WARP probe"):
                module.warp_port_candidates({"port": 2408})

    def test_warp_port_candidates_rejects_invalid_ports(self):
        with patch.dict(module.os.environ, {"VPNGATE_WARP_VERIFIED_PORTS": "2408,65536"}):
            with self.assertRaisesRegex(ValueError, "out-of-range"):
                module.warp_port_candidates({"port": 2408})

    def test_warp_connectivity_accepts_https_success(self):
        response = Mock(status_code=204)
        with patch.object(module.requests, "get", return_value=response):
            self.assertTrue(module.check_warp_connectivity("http://127.0.0.1:7890"))
        response.close.assert_called_once()

    def test_probe_warp_uses_next_port_after_data_plane_failure(self):
        key = base64.b64encode(bytes(range(32))).decode()
        config = module.load_warp_config(__import__("json").dumps({
            "private_key": key, "peer_public_key": key, "ipv4": "172.16.0.2", "port": 2408
        }))
        process, log = Mock(), Mock()
        with __import__("tempfile").TemporaryDirectory() as tmp:
            with patch.object(module, "start_warp", return_value=(process, log, 7890)) as start, \
                 patch.object(module, "check_warp_connectivity", side_effect=[False, True]), \
                 patch.object(module, "stop_node") as stop:
                proxy = module.probe_warp("mihomo", config, Path(tmp))
        self.assertEqual(proxy["peers"][0]["port"], 500)
        self.assertEqual(start.call_count, 2)
        self.assertEqual(stop.call_count, 2)

    def test_probe_warp_fails_closed_when_all_ports_fail(self):
        key = base64.b64encode(bytes(range(32))).decode()
        config = module.load_warp_config(__import__("json").dumps({
            "private_key": key, "peer_public_key": key, "ipv4": "172.16.0.2", "port": 2408
        }))
        with __import__("tempfile").TemporaryDirectory() as tmp:
            with patch.object(module, "start_warp", side_effect=RuntimeError("no tunnel")) as start:
                with self.assertRaisesRegex(RuntimeError, "refusing to test VPN Gate"):
                    module.probe_warp("mihomo", config, Path(tmp))
        self.assertEqual(start.call_count, 4)

    def test_connectivity_accepts_success_status(self):
        response = Mock(status_code=204)
        with patch.object(module.requests, "get", return_value=response):
            self.assertTrue(module.check_connectivity("http://127.0.0.1:7890"))
        response.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
