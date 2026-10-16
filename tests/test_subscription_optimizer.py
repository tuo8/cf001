import base64,importlib.util,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location("opt",Path(__file__).parents[1]/"scripts"/"subscription_optimizer.py")
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Tests(unittest.TestCase):
 def test_ss(self):
  p=m.uri("ss://YWVzLTI1Ni1nY206cGFzcw==@example.com:443#Singapore");self.assertEqual(p["cipher"],"aes-256-gcm");self.assertEqual(p["password"],"pass")
 def test_trojan(self):
  p=m.uri("trojan://secret@example.com:443?sni=example.org#Tokyo");self.assertTrue(p["tls"]);self.assertEqual(p["servername"],"example.org")
 def test_yaml(self):
  d=m.parse("proxies:\n  - name: 'Hong Kong 01'\n    type: ss\n    server: example.com\n    port: 443\n    cipher: aes-128-gcm\n    password: secret\n");self.assertEqual(d[0]["name"],"Hong Kong 01")
 def test_base64(self):
  s="trojan://secret@example.com:443#Singapore";self.assertIn("trojan://",m.decode(base64.b64encode(s.encode())))
if __name__=="__main__":unittest.main()
