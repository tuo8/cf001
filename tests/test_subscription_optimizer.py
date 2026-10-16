import base64,importlib.util,unittest
from unittest.mock import patch
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

 def test_source_items_multiple_lines(self):
  self.assertEqual(m.source_items("https://one.example/sub\n\n# comment\nhttps://two.example/sub\n"),["https://one.example/sub","https://two.example/sub"])
 def test_load_multiple_subscriptions_and_deduplicate(self):
  a=b"proxies:\n  - name: Singapore A\n    type: ss\n    server: one.example\n    port: 443\n    cipher: aes-128-gcm\n    password: pass\n"
  b=b"proxies:\n  - name: Singapore duplicate\n    type: ss\n    server: one.example\n    port: 443\n    cipher: aes-128-gcm\n    password: pass\n  - name: Tokyo B\n    type: trojan\n    server: two.example\n    port: 443\n    password: pass2\n"
  class Response:
   def __init__(self,content): self.content=content
   def raise_for_status(self): pass
  with patch.object(m.requests,"get",side_effect=[Response(a),Response(b)]) as get: nodes=m.load_nodes("https://one.example/sub\nhttps://two.example/sub")
  self.assertEqual(get.call_count,2);self.assertEqual(len(nodes),3)
  clean=m.clean_nodes(nodes);self.assertEqual(len(clean),2);self.assertEqual(clean[0]["name"],"Singapore A")
 def test_detect_endpoint_list_not_proxy_subscription(self):
  sample="162.159.198.1:443#VPS789 TOP20\\ncfyx.aliyun.20237737.xyz:443#VPS789优选\\n"
  self.assertTrue(m.looks_like_endpoint_list(sample))
  self.assertFalse(m.looks_like_endpoint_list("trojan://secret@example.com:443#Singapore\\n"))
 def test_endpoint_template_builds_proxy_nodes(self):
  template='name: Base\\ntype: trojan\\nserver: original.example\\nport: 443\\npassword: secret\\ntls: true\\nservername: service.example\\n'
  sample="162.159.198.1:443#candidate one\\ncfyx.aliyun.20237737.xyz:8443#candidate two\\n"
  with patch.dict("os.environ",{"CLASH_PROXY_TEMPLATE":template,"ENDPOINT_MAX_CANDIDATES":"1"}):
   class Response:
    content=sample.encode()
    def raise_for_status(self): pass
   with patch.object(m.requests,"get",return_value=Response()):
    nodes=m.load_nodes("https://one.example/list")
  self.assertEqual(len(nodes),1)
  self.assertEqual(nodes[0]["server"],"162.159.198.1")
  self.assertEqual(nodes[0]["port"],443)
  self.assertEqual(nodes[0]["password"],"secret")
  self.assertEqual(nodes[0]["servername"],"service.example")
 def test_single_subscription_still_supported(self):
  class Response:
   content=b"trojan://secret@example.com:443#Singapore"
   def raise_for_status(self): pass
  with patch.object(m.requests,"get",return_value=Response()): nodes=m.load_nodes("https://one.example/sub")
  self.assertEqual(len(nodes),1);self.assertEqual(nodes[0]["type"],"trojan")


 def test_full_clash_yaml_with_top_level_settings(self):
  raw="mixed-port: 7890\nmode: rule\nproxies:\n  - name: 'Singapore 01'\n    type: ss\n    server: example.com\n    port: 443\n    cipher: aes-128-gcm\n    password: secret\n"
  self.assertEqual(len(m.parse(raw)),1)
  self.assertEqual(len(m.parse(m.decode(base64.b64encode(raw.encode())))),1)

 def test_nested_base64_subscription(self):
  raw="trojan://secret@example.com:443#Singapore"
  nested=base64.b64encode(base64.b64encode(raw.encode()))
  self.assertIn("trojan://",m.decode(nested))

 def test_base64_with_provider_comments(self):
  raw="trojan://secret@example.com:443#Singapore"
  body="# profile-title: Test\n# update-interval: 24\n"+base64.b64encode(raw.encode()).decode()
  self.assertIn("trojan://",m.decode(body.encode()))

if __name__=="__main__":unittest.main()
