import base64,importlib.util,unittest
from unittest.mock import patch
from pathlib import Path
spec=importlib.util.spec_from_file_location("opt",Path(__file__).parents[1]/"scripts"/"subscription_optimizer.py")
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Tests(unittest.TestCase):
 def test_configured_urls_deduplicates_and_appends_fallbacks(self):
  with patch.dict("os.environ",{"LATENCY_TEST_URLS":"https://a.example/ping, https://b.example/ping\nhttps://a.example/ping"}):
   self.assertEqual(m.configured_urls("LATENCY_TEST_URLS",["https://b.example/ping","https://c.example/ping"]),["https://a.example/ping","https://b.example/ping","https://c.example/ping"])
 def test_format_latency_supports_missing_measurement(self):
  self.assertEqual(m.format_latency(None), "NA")
  self.assertEqual(m.format_latency(12.4), "12 ms")
 def test_configured_urls_uses_defaults_when_unset(self):
  with patch.dict("os.environ",{},clear=True):
   self.assertEqual(m.configured_urls("LATENCY_TEST_URLS",["https://a.example/ping"]),["https://a.example/ping"])
 def test_v2rayn_ss_uri(self):
  p={"name":"Singapore","type":"ss","server":"example.com","port":443,"cipher":"aes-256-gcm","password":"secret"}
  uri=m.proxy_to_share_uri(p)
  self.assertTrue(uri.startswith("ss://"))
  self.assertIn("#Singapore",uri)
 def test_v2rayn_vless_reality_uri(self):
  p={"name":"Tokyo","type":"vless","server":"example.com","port":443,"uuid":"test-id","tls":True,"servername":"www.example.com","reality-opts":{"public-key":"pub","short-id":"abcd"},"network":"tcp"}
  uri=m.proxy_to_share_uri(p)
  self.assertIn("vless://test-id@example.com:443?",uri)
  self.assertIn("security=reality",uri)
  self.assertIn("pbk=pub",uri)
 def test_v2rayn_base64_subscription(self):
  import tempfile
  p={"name":"Singapore","type":"trojan","server":"example.com","port":443,"password":"secret","tls":True}
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/"v2rayn.txt"
   self.assertEqual(m.write_v2rayn_subscription([(p,20,5.0)],path),1)
   decoded=base64.b64decode(path.read_text().strip()).decode()
   self.assertIn("trojan://secret@example.com:443",decoded)
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
  sample="162.159.198.1:443#VPS789 TOP20\ncfyx.aliyun.20237737.xyz:443#VPS789优选\n"
  self.assertTrue(m.looks_like_endpoint_list(sample))
  self.assertFalse(m.looks_like_endpoint_list("trojan://secret@example.com:443#Singapore\n"))
 def test_extract_endpoint_candidates(self):
  sample="162.159.198.1:443#candidate one\nexample.com:8443#candidate two\n127.0.0.1:443\nexample.local:443\nexample.com:99999\n"
  self.assertEqual(m.extract_endpoint_candidates(sample),[("162.159.198.1",443),("example.com",8443)])
 def test_endpoint_template_builds_proxy_nodes(self):
  template='name: Base\ntype: vless\nserver: original.example\nport: 443\nuuid: test-uuid\ntls: true\nservername: service.example\nnetwork: ws\nws-opts:\n  path: /\n  headers:\n    Host: service.example\n'
  sample="162.159.198.1:443#candidate one\ncfyx.aliyun.20237737.xyz:8443#candidate two\n"
  with patch.dict("os.environ",{"CLASH_PROXY_TEMPLATE":template,"ENDPOINT_MAX_CANDIDATES":"1"}):
   class Response:
    content=sample.encode()
    def raise_for_status(self): pass
   with patch.object(m.requests,"get",return_value=Response()):
    nodes=m.load_nodes("https://one.example/list")
  self.assertEqual(len(nodes),2)
  self.assertEqual(nodes[0]["server"],"162.159.198.1")
  self.assertEqual(nodes[0]["port"],443)
  self.assertEqual(nodes[0]["uuid"],"test-uuid")
  self.assertEqual(nodes[0]["servername"],"service.example")
  self.assertNotIn("Host",nodes[0]["ws-opts"].get("headers",{}))
  self.assertEqual(nodes[1]["ws-opts"]["headers"]["Host"],"service.example")
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

 def test_speed_sort_prefers_throughput_then_latency(self):
  rows=[({"name":"slow"},10,20.0),({"name":"fast-high-latency"},100,80.0),({"name":"fast-low-latency"},20,80.0)]
  rows.sort(key=lambda z:(z[2] is None,-(z[2] or 0),z[1] is None,z[1] or 1e9))
  self.assertEqual([r[0]["name"] for r in rows],["fast-low-latency","fast-high-latency","slow"])

 def test_download_once_uses_received_body_bytes(self):
  class Response:
   status_code=200
   def __init__(self):self.closed=False
   def iter_content(self,chunk_size):yield b"x"*65536;yield b"y"*65536
   def close(self):self.closed=True
  response=Response()
  with patch.object(m.requests,"get",return_value=response) as get:
   speed,error=m.download_once("https://speed.cloudflare.com/__down?bytes=1000000",{},131072)
  self.assertIsNotNone(speed);self.assertGreater(speed,0);self.assertIsNone(error);self.assertTrue(response.closed)
  self.assertIn("bytes=131072",get.call_args.args[0])

 def test_download_once_rejects_http_errors(self):
  class Response:
   status_code=503
   def close(self):pass
  with patch.object(m.requests,"get",return_value=Response()):
   speed,error=m.download_once("https://example.com/file",{},1024)
  self.assertIsNone(speed);self.assertEqual(error,"HTTP503")

if __name__=="__main__":unittest.main()
