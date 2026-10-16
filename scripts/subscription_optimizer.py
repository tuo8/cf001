#!/usr/bin/env python3
"""Parse common proxy subscriptions and create a Clash YAML config. Never log source URLs."""
import argparse,base64,json,os,re,shutil,socket,subprocess,sys,tempfile,time
from pathlib import Path
from urllib.parse import urlsplit,parse_qs,unquote
import requests,yaml

def is_clash_yaml(s):
 try:
  d=yaml.safe_load(s)
  return isinstance(d,dict) and isinstance(d.get("proxies"),list)
 except Exception:return False
def decode(b):
 s=b.decode("utf-8-sig","replace").strip()
 for _ in range(3):
  if s.startswith(("proxies:","---")) or "://" in s or is_clash_yaml(s): return s
  lines=[line.strip() for line in s.splitlines() if line.strip() and not line.lstrip().startswith(("#","//"))]
  candidates=[re.sub(r"\s+","",s),"".join(line for line in lines if re.fullmatch(r"[A-Za-z0-9+/=]+",line))]
  decoded=None
  for candidate in candidates:
   if not candidate: continue
   try:
    d=base64.b64decode(candidate,validate=True).decode("utf-8-sig").strip()
    if d and d!=s and ("://" in d or is_clash_yaml(d) or re.fullmatch(r"[A-Za-z0-9+/=\s]+",d)):
     decoded=d;break
   except Exception: pass
  if decoded is None: break
  s=decoded
 return s

def source(s):
 if s.startswith(("http://","https://")):
  r=requests.get(s,timeout=20,headers={"User-Agent":"cf001-subscription-optimizer"}); r.raise_for_status(); return decode(r.content)
 p=Path(s)
 if p.is_file(): return decode(p.read_bytes())
 raise ValueError("invalid source")
def looks_like_endpoint_list(s):
 """Detect IP/domain:port candidate lists; these are not proxy subscriptions."""
 rows=[line.strip() for line in s.splitlines() if line.strip() and not line.lstrip().startswith(("#","//"))]
 if not rows:return False
 matched=0
 for line in rows:
  candidate=line.split("#",1)[0].strip()
  if re.fullmatch(r"(?:[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?):\d{1,5}",candidate):
   matched+=1
 return matched >= 1 and matched / len(rows) >= 0.6

def parse_proxy_template(value):
 if not value.strip():return None
 try:p=yaml.safe_load(value)
 except Exception as e:raise ValueError("invalid proxy template YAML/JSON") from e
 if not isinstance(p,dict) or not p.get("type") or not p.get("server") or not p.get("port"):
  raise ValueError("proxy template must be one Clash proxy mapping with type, server and port")
 return p

def endpoint_nodes(text,template):
 if not template:return []
 result=[]
 for line in text.splitlines():
  line=line.strip()
  if not line or line.startswith(("#","//")):continue
  match=re.fullmatch(r"(?P<host>[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?):(?P<port>\d{1,5})(?:\s*#(?P<remark>.*))?",line)
  if not match:continue
  port=int(match.group("port"))
  if not 1<=port<=65535:continue
  base=dict(template)
  base["server"]=match.group("host");base["port"]=port
  suffix=(match.group("remark") or "").strip()
  label=f"{base['server']}:{port}"+(f" {suffix}" if suffix else "")
  variants=[]
  ws_opts=base.get("ws-opts")
  if base.get("network")=="ws" and isinstance(ws_opts,dict):
   # Try no explicit WebSocket Host first, then the configured TLS servername.
   without_host=dict(base)
   opts=dict(ws_opts)
   headers=dict(opts.get("headers") or {})
   headers.pop("Host",None)
   if headers:opts["headers"]=headers
   else:opts.pop("headers",None)
   without_host["ws-opts"]=opts
   variants.append((without_host,"Host-auto"))
   with_sni=dict(base)
   opts=dict(ws_opts)
   headers=dict(opts.get("headers") or {})
   host_value=str(base.get("servername") or headers.get("Host") or "").strip()
   if host_value:
    headers["Host"]=host_value
    opts["headers"]=headers
    with_sni["ws-opts"]=opts
    variants.append((with_sni,"Host-SNI"))
   else:
    variants.append((dict(base),"Host-template"))
  else:
   variants.append((base,""))
  for p,mode in variants:
   p["name"]=f"{template.get('name','Proxy')} {label}"+(f" [{mode}]" if mode else "")
   result.append(p)
 return result

def source_items(value):
 items=[line.strip() for line in value.splitlines() if line.strip() and not line.strip().startswith("#")]
 if not items: raise ValueError("empty source list")
 return items
def node_key(p):
 return json.dumps({k:v for k,v in p.items() if k != "name"},sort_keys=True,separators=(",",":"),ensure_ascii=False)
def load_nodes(value):
 nodes=[];endpoint_groups=[]
 items=source_items(value)
 template_text=os.getenv("CLASH_PROXY_TEMPLATE","")
 template=None
 for index,item in enumerate(items,1):
  text=source(item)
  parsed=parse(text)
  if not parsed:
   stripped=text.lstrip()
   if looks_like_endpoint_list(text):
    rows=[line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith(("#","//"))]
    if template_text.strip() and template is None:template=parse_proxy_template(template_text)
    candidates=endpoint_nodes(text,template)
    endpoint_groups.append(candidates)
    count=sum(1 for line in rows if re.fullmatch(r"(?:[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?):\d{1,5}(?:\s*#.*)?",line))
    print(f"订阅源#{index}: 格式=endpoint_list_not_proxy_subscription，候选地址数={count}，模板生成节点数={len(candidates)}")
    continue
   if stripped.startswith("<"):kind="html_or_xml"
   elif stripped.startswith(("{","[")):kind="json_or_yaml_without_proxies"
   elif is_clash_yaml(text):kind="clash_yaml"
   elif "://" in text:kind="unsupported_uri_or_format"
   elif not stripped:kind="empty_response"
   else:
    try:
     obj=yaml.safe_load(text)
     if isinstance(obj,dict):kind="yaml_mapping_without_proxies"
     elif isinstance(obj,list):kind="yaml_list_without_recognized_nodes"
     elif re.fullmatch(r"[A-Za-z0-9+/=\s]+",text):kind="base64_or_encoded_text"
     else:kind="unrecognized_text"
    except Exception:kind="base64_or_encoded_text" if re.fullmatch(r"[A-Za-z0-9+/=\s]+",text) else "unrecognized_text"
   print(f"订阅源#{index}: 解码字符数={len(text)}，格式={kind}，首字符码点={ord(stripped[0]) if stripped else 0}，节点数=0")
  else:
   print(f"订阅源#{index}: 解码字符数={len(text)}，节点数={len(parsed)}")
  nodes.extend(parsed)
 if endpoint_groups:
  if not template_text.strip():
   print("提示：检测到 Cloudflare IP/域名候选列表，但未设置 CLASH_PROXY_TEMPLATE；这些地址无法单独构成代理节点")
  else:
   limit=max(1,int(os.getenv("ENDPOINT_MAX_CANDIDATES","60")))
   picked=[];depth=0
   def endpoint_keys(group):
    keys=[]
    for node in group:
     key=(node.get("server"),node.get("port"))
     if key not in keys:keys.append(key)
    return keys
   while any(depth<len(endpoint_keys(group)) for group in endpoint_groups) and depth<limit:
    for group in endpoint_groups:
     keys=endpoint_keys(group)
     if depth<len(keys):
      key=keys[depth]
      picked.extend(node for node in group if (node.get("server"),node.get("port"))==key)
    depth+=1
   nodes.extend(picked)
   print(f"模板生成候选节点总数={sum(len(g) for g in endpoint_groups)}；本轮最多测试={len(picked)}（ENDPOINT_MAX_CANDIDATES）")
 return nodes
def clean_nodes(nodes):
 used=set();seen=set();clean=[]
 for raw in nodes:
  p=dict(raw);key=node_key(p)
  if key in seen:continue
  seen.add(key)
  base=str(p.get("name") or "proxy")[:80];n=base;i=2
  while n in used:n=f"{base}-{i}";i+=1
  used.add(n);p["name"]=n;clean.append(p)
 return clean
def uri(s):
 if s.startswith("vmess://"):
  try:
   b=s.split("://",1)[1]; d=json.loads(base64.urlsafe_b64decode(b+"="*(-len(b)%4)))
   p={"name":d.get("ps") or d["add"],"type":"vmess","server":d["add"],"port":int(d["port"]),"uuid":d["id"],"alterId":int(d.get("aid",0)),"cipher":d.get("scy") or "auto"}
   if d.get("tls")=="tls": p["tls"]=True
   if d.get("sni"): p["servername"]=d["sni"]
   if d.get("net")=="ws": p.update(network="ws",**{"ws-opts":{"path":d.get("path") or "/","headers":{"Host":d.get("host") or d["add"]}}})
   return p
  except Exception: return None
 try:
  u=urlsplit(s); k=u.scheme.lower(); q=parse_qs(u.query)
  if k not in {"ss","trojan","vless","socks","socks5","http","hysteria2","hy2"} or not u.hostname or not u.port:return None
  p={"name":unquote(u.fragment) or f"{k}-{u.hostname}:{u.port}","server":u.hostname,"port":u.port}
  if k=="ss":
   z=unquote(u.netloc.rsplit("@",1)[0])
   if ":" not in z:z=base64.urlsafe_b64decode(z+"="*(-len(z)%4)).decode()
   c,pw=z.split(":",1);p.update(type="ss",cipher=c,password=pw)
  elif k in {"trojan","vless","hysteria2","hy2"}:
   p["type"]="hysteria2" if k=="hy2" else k;p["uuid" if k=="vless" else "password"]=unquote(u.username or "")
   if k in {"trojan","hysteria2","hy2"} or q.get("security",[""])[0] in {"tls","reality"}:
    p["tls"]=True
    if q.get("sni"):p["servername"]=q["sni"][0]
    if q.get("insecure",["0"])[0] in {"1","true"}:p["skip-cert-verify"]=True
   if k=="vless" and q.get("flow"):p["flow"]=q["flow"][0]
   if k=="vless" and q.get("type",[""])[0]=="ws":p.update(network="ws",**{"ws-opts":{"path":q.get("path",["/"])[0],"headers":{"Host":q.get("host",[u.hostname])[0]}}})
  else:
   p["type"]="socks5" if k in {"socks","socks5"} else "http"
   if u.username:p["username"]=unquote(u.username)
   if u.password:p["password"]=unquote(u.password)
  return p
 except Exception:return None
def parse(s):
 if s.lstrip().startswith(("proxies:","---")) or is_clash_yaml(s):
  try:
   d=yaml.safe_load(s)
   if isinstance(d,dict) and isinstance(d.get("proxies"),list):return [p for p in d["proxies"] if isinstance(p,dict) and p.get("type") and p.get("server") and p.get("port")]
  except yaml.YAMLError:pass
 return [p for line in s.splitlines() if line.strip() and not line.strip().startswith(("#","//")) and "://" in line for p in [uri(line.strip())] if p]
def region(p):
 n=str(p.get("name","")).upper()
 for c,ws in {"HKG":["HKG","HONG KONG","香港"],"TPE":["TPE","TAIPEI","台北","台湾"],"NRT":["NRT","TOKYO","JAPAN","东京","日本"],"ICN":["ICN","SEOUL","KOREA","首尔","韩国"],"SIN":["SIN","SINGAPORE","新加坡"],"LAX":["LAX","LOS ANGELES","美国","US"],"FRA":["FRA","FRANKFURT","GERMANY","德国"],"LON":["LON","LONDON","英国"]}.items():
  if any(w in n for w in ws):return c
 return "UNKNOWN"
def probe(p,binary,folder):
 cfg={"mixed-port":17890,"mode":"rule","log-level":"error","proxies":[p],"proxy-groups":[{"name":"TEST","type":"select","proxies":[p["name"]]}],"rules":["MATCH,TEST"]}
 f=folder/"p.yaml";f.write_text(yaml.safe_dump(cfg,allow_unicode=True,sort_keys=False))
 proc=subprocess.Popen([binary,"-f",str(f)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
 stage="mihomo_start"
 try:
  end=time.time()+8
  while time.time()<end:
   if proc.poll() is not None:
    out,err=proc.communicate(timeout=1)
    lines=(err or out or "").strip().splitlines()
    detail=lines[-1][:180] if lines else "进程提前退出且没有错误文本"
    print(f"节点测试失败：type={p.get('type','unknown')}；阶段={stage}；原因={detail}")
    return None
   try:
    with socket.create_connection(("127.0.0.1",17890),timeout=.2):break
   except OSError:time.sleep(.1)
  else:
   print(f"节点测试失败：type={p.get('type','unknown')}；阶段=mixed_port_start_timeout")
   return None
  px={"http":"http://127.0.0.1:17890","https":"http://127.0.0.1:17890"};t=time.monotonic();stage="latency_request"
  r=requests.get("https://www.gstatic.com/generate_204",proxies=px,timeout=8);lat=(time.monotonic()-t)*1000
  if r.status_code not in (200,204,301,302):
   print(f"节点测试失败：type={p.get('type','unknown')}；阶段=latency_http；状态码={r.status_code}")
   return None
  t=time.monotonic();stage="download_request"
  r=requests.get(os.getenv("DOWNLOAD_TEST_URL","https://speed.cloudflare.com/__down?bytes=1000000"),proxies=px,timeout=12,stream=True);size=0
  for chunk in r.iter_content(65536):
   size+=len(chunk)
   if size>=250000:break
  r.close()
  if size<32768:
   print(f"节点测试失败：type={p.get('type','unknown')}；阶段=download_too_small；字节数={size}")
   return None
  return (lat,size*8/max(time.monotonic()-t,.001)/1e6)
 except Exception as e:
  print(f"节点测试失败：type={p.get('type','unknown')}；阶段={stage}；异常={type(e).__name__}")
  return None
 finally:
  if proc.poll() is None:
   proc.terminate()
   try:proc.wait(timeout=2)
   except subprocess.TimeoutExpired:proc.kill()
def main():
 a=argparse.ArgumentParser();a.add_argument("--input",default=os.getenv("SUBSCRIPTION_URL",""));a.add_argument("--output",default="subscription/clash-mi.yaml");a.add_argument("--region",default=os.getenv("REGION_FILTER",""));a.add_argument("--name-filter",default=os.getenv("NODE_NAME_FILTER",""));a.add_argument("--sort",choices=["balanced","latency","speed"],default=os.getenv("SORT_BY","balanced"));a.add_argument("--top",type=int,default=int(os.getenv("TOP_N","30")));a.add_argument("--parse-only",action="store_true");x=a.parse_args()
 if not x.input:print("缺少 SUBSCRIPTION_URL",file=sys.stderr);return 2
 try:nodes=load_nodes(x.input)
 except Exception as e:print("订阅读取失败："+type(e).__name__,file=sys.stderr);return 2
 print(f"订阅源数: {len(source_items(x.input))}; 解析节点数: {len(nodes)}")
 clean=clean_nodes(nodes)
 print(f"去重后节点数: {len(clean)}")
 if x.name_filter.strip():
  needle=x.name_filter.strip().casefold()
  before=len(clean)
  clean=[p for p in clean if needle in str(p.get("name","")).casefold()]
  print(f"名称筛选: 关键字={x.name_filter.strip()!r}；筛选前={before}；匹配节点={len(clean)}")
  if not clean:
   print("名称筛选没有匹配节点；请核对订阅中的节点名称",file=sys.stderr);return 6
 allowed={z.strip().upper() for z in x.region.split(",") if z.strip()}
 if allowed:clean=[p for p in clean if region(p) in allowed]
 print(f"地区筛选后节点数: {len(clean)}")
 res=[]
 if x.parse_only:res=[(p,None,None) for p in clean]
 else:
  binary=shutil.which(os.getenv("MIHOMO_PATH","mihomo"))
  if not binary:print("找不到 Mihomo；不会把未测速节点标记为可用",file=sys.stderr);return 4
  with tempfile.TemporaryDirectory() as d:
   for p in clean:
    v=probe(p,binary,Path(d))
    if v:res.append((p,*v))
 if x.sort=="latency":res.sort(key=lambda z:(z[1] is None,z[1] or 1e9))
 elif x.sort=="speed":res.sort(key=lambda z:(z[2] is None,-(z[2] or 0)))
 else:res.sort(key=lambda z:(z[1] is None,z[1] or 1e9,-(z[2] or 0)))
 res=res[:max(1,x.top)]
 if not res:print(f"测速未通过：待测节点 {len(clean)}，通过节点 {len(res)}；未生成配置",file=sys.stderr);return 5
 doc={"proxies":[z[0] for z in res],"proxy-groups":[{"name":"优选节点","type":"select","proxies":[z[0]["name"] for z in res]}],"rules":["MATCH,优选节点"]}
 dest=Path(x.output);dest.parent.mkdir(parents=True,exist_ok=True);dest.write_text(yaml.safe_dump(doc,allow_unicode=True,sort_keys=False),encoding="utf-8")
 assert len(yaml.safe_load(dest.read_text())["proxies"])==len(res)
 print(f"已生成配置：{dest}；节点数={len(res)}；模式={'仅解析，未测速' if x.parse_only else '真实测速'}")
 if not x.parse_only:
  for p,lat,spd in res:print(f"{p['name'][:48]}\t{lat:.0f} ms\t{spd:.2f} Mbps")
 return 0
if __name__=="__main__":raise SystemExit(main())
