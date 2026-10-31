import base64,importlib.util,unittest
from pathlib import Path
s=importlib.util.spec_from_file_location("vpngate",Path(__file__).parents[1]/"scripts"/"vpngate_optimizer.py")
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Tests(unittest.TestCase):
 def test_tcp(self):
  c="""proto tcp-client
remote 203.0.113.1 443
<ca>
CA
</ca>
"""
  p=m.parse_profile(c,{"CountryLong":"Japan"})["proxy"]
  self.assertEqual(p["type"],"openvpn");self.assertEqual(p["proto"],"tcp");self.assertFalse(p["udp"])
  self.assertEqual(p["username"],"vpn");self.assertEqual(p["password"],"vpn")
 def test_udp_tls_auth(self):
  c="""proto udp
remote 198.51.100.1 1194
key-direction 1
<ca>
CA
</ca>
<tls-auth>
KEY
</tls-auth>
"""
  p=m.parse_profile(c,{"CountryLong":"US"})["proxy"]
  self.assertTrue(p["udp"]);self.assertEqual(p["key-direction"],"1");self.assertIn("KEY",p["tls-auth"])
 def test_csv(self):
  c="proto tcp-client\nremote 203.0.113.2 443\n<ca>\nCA\n</ca>\n";b=base64.b64encode(c.encode()).decode()
  raw="*vpn_servers\n#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_Config\nvpn1,203.0.113.2,90,10,1000,Japan,JP,1,2,3,4,0,op,msg,"+b+"\n*vpn_servers_end\n"
  x=m.parse_csv(raw);self.assertEqual(len(x),1);self.assertEqual(x[0]["ping"],10)
 def test_reject_incomplete(self):
  self.assertIsNone(m.parse_profile("proto tcp\nremote x 443\n",{}))
  self.assertIsNone(m.parse_profile("proto tcp\n<ca>\nCA\n</ca>",{}))
 def test_rank(self):
  a=[{"ping":15,"speed":1,"proxy":{"name":"a"}},{"ping":10,"speed":1,"proxy":{"name":"b"}},{"ping":10,"speed":2,"proxy":{"name":"c"}}]
  self.assertEqual([x["proxy"]["name"] for x in m.rank(a,2)],["c","b"])
if __name__=="__main__":unittest.main()
