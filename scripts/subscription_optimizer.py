#!/usr/bin/env python3
"""Parse common proxy subscriptions and create a Clash YAML config. Never log source URLs."""
import argparse,base64,concurrent.futures,ipaddress,json,os,re,shutil,socket,subprocess,sys,tempfile,time
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
  p=dict(raw)
  # Trojan requires TLS in Mihomo; some imported Clash YAML omits tls: true.
  if str(p.get("type","")).lower()=="trojan":p["tls"]=True
  key=node_key(p)
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
   security=q.get("security",[""])[0].lower()
   if k in {"trojan","hysteria2","hy2"} or security in {"tls","reality"}:
    p["tls"]=True
    sni=q.get("sni",q.get("servername",[]))
    if sni and sni[0]:p["servername"]=sni[0]
    if q.get("insecure",["0"])[0].lower() in {"1","true"}:p["skip-cert-verify"]=True
   if k=="vless":
    if q.get("flow") and q["flow"][0]:p["flow"]=q["flow"][0]
    fp=q.get("fp",q.get("fingerprint",[]))
    if fp and fp[0]:p["client-fingerprint"]=fp[0]
    alpn=q.get("alpn",[])
    if alpn and alpn[0]:p["alpn"]=[x for x in alpn[0].split(",") if x]
    if security=="reality":
     pbk=q.get("pbk",q.get("public-key",[]))
     sid=q.get("sid",q.get("short-id",[]))
     reality={}
     if pbk and pbk[0]:reality["public-key"]=pbk[0]
     if sid and sid[0]:reality["short-id"]=sid[0]
     if reality:p["reality-opts"]=reality
    network=q.get("type",["tcp"])[0].lower()
    if network=="ws":
     p.update(network="ws",**{"ws-opts":{"path":q.get("path",["/"])[0],"headers":{"Host":q.get("host",[u.hostname])[0]}}})
    elif network=="grpc":
     p["network"]="grpc"
     service=q.get("serviceName",q.get("service_name",q.get("grpc-service-name",[""])))[0]
     if service:p["grpc-opts"]={"grpc-service-name":service}
    elif network in {"httpupgrade","xhttp","h2"}:
     p["network"]=network
     path=q.get("path",["/"])[0]
     host=q.get("host",[u.hostname])[0]
     if network=="httpupgrade":p["http-upgrade-opts"]={"path":path,"headers":{"Host":host}}
     elif network=="xhttp":p["xhttp-opts"]={"path":path,"host":host}
     else:p["h2-opts"]={"path":path,"host":host}
   if k=="trojan":
    network=q.get("type",["tcp"])[0].lower()
    if network=="ws":
     p.update(network="ws",**{"ws-opts":{"path":q.get("path",["/"])[0],"headers":{"Host":q.get("host",[u.hostname])[0]}}})
    elif network=="grpc":
     p["network"]="grpc"
     service=q.get("serviceName",q.get("service_name",q.get("grpc-service-name",[""])))[0]
     if service:p["grpc-opts"]={"grpc-service-name":service}
    elif network in {"httpupgrade","xhttp","h2"}:
     p["network"]=network
     path=q.get("path",["/"])[0]
     host=q.get("host",[u.hostname])[0]
     if network=="httpupgrade":p["http-upgrade-opts"]={"path":path,"headers":{"Host":host}}
     elif network=="xhttp":p["xhttp-opts"]={"path":path,"host":host}
     else:p["h2-opts"]={"path":path,"host":host}
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
def configured_urls(env_name, defaults):
 raw=os.getenv(env_name, "")
 values=[u.strip() for u in re.split(r"[,\n]", raw) if u.strip()]
 return list(dict.fromkeys(values + list(defaults)))

def format_latency(value):
 return "NA" if value is None else f"{value:.0f} ms"

def download_test_urls():
 """Use independent HTTPS mirrors so one blocked endpoint does not reject a working proxy."""
 return configured_urls("DOWNLOAD_TEST_URLS",[
  os.getenv("DOWNLOAD_TEST_URL","https://speed.cloudflare.com/__down?bytes=5242880"),
  "https://proof.ovh.net/files/10Mb.dat",
  "https://speedtest.tele2.net/10MB.zip",
  "https://ipv4.download.thinkbroadband.com/5MB.zip",
 ])

def mihomo_error_labels(log_text):
 """Extract safe, coarse failure labels from Mihomo logs without exposing endpoints or credentials."""
 text=str(log_text).lower()
 labels=[]
 for marker,label in (
  ("reality","reality"),
  ("certificate","certificate"),
  ("tls","tls"),
  ("handshake","handshake"),
  ("unexpected eof","remote_eof"),
  ("eof","remote_eof"),
  ("timeout","timeout"),
  ("refused","connection_refused"),
  ("no such host","dns_failure"),
  ("network is unreachable","network_unreachable"),
  ("proxy error","proxy_error"),
  ("failed to dial","dial_failure"),
 ):
  if marker in text and label not in labels:labels.append(label)
 return labels[:6]

def exception_label(exc):
 """Return a compact diagnostic category without logging URLs or credentials."""
 message=str(exc)
 match=re.search(r"\[SSL:\s*([A-Z0-9_]+)",message)
 if match:return f"{type(exc).__name__}:{match.group(1)}"
 for marker in ("CERTIFICATE_VERIFY_FAILED","WRONG_VERSION_NUMBER","UNEXPECTED_EOF_WHILE_READING","TLSV1_ALERT"):
  if marker in message:return f"{type(exc).__name__}:{marker}"
 return type(exc).__name__
def download_once(url, px, target_bytes, timeout=12):
 """Measure throughput from bytes actually received, not latency or declared size."""
 from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
 parts=urlsplit(url);query=parse_qsl(parts.query,keep_blank_values=True)
 if parts.hostname=="speed.cloudflare.com" and parts.path.rstrip("/")=="/__down":
  query=[(k,v) for k,v in query if k!="bytes"];query.append(("bytes",str(target_bytes)))
  url=urlunsplit((parts.scheme,parts.netloc,parts.path,urlencode(query),parts.fragment))
 response=None;size=0;first_byte=None;last_byte=None;read_error=None;started=time.monotonic();body_started=None
 try:
  response=requests.get(url,proxies=px,timeout=(3,max(5,timeout)),stream=True,headers={"Cache-Control":"no-cache","Pragma":"no-cache"})
  if response.status_code != 200:return None, f"HTTP{response.status_code}"
  body_started=time.monotonic()
  for chunk in response.iter_content(65536):
   if not chunk:continue
   now=time.monotonic()
   if first_byte is None:first_byte=now
   size+=len(chunk);last_byte=now
   if size>=target_bytes:break
   if now-started>=timeout:break
 except Exception as exc:read_error=exception_label(exc)
 finally:
  if response is not None:response.close()
 minimum=min(target_bytes,max(65536,int(target_bytes*0.75)))
 if size<minimum or first_byte is None or last_byte is None:return None,read_error or f"small_body_{size}"
 elapsed=max(last_byte-(body_started if body_started is not None else first_byte),0.001)
 return min(size,target_bytes)*8/elapsed/1_000_000,None

def measure_download(px, urls, target_bytes, timeout):
 errors=[]
 for url in urls:
  speed,error=download_once(url,px,target_bytes,timeout=timeout)
  if speed is not None:return speed
  errors.append(error or "unknown")
 print(f"下载测速失败：目标数={len(urls)}；错误详情={','.join(errors)}")
 return None

def probe(p,binary,folder,precision=False):
 folder.mkdir(parents=True,exist_ok=True)
 with socket.socket() as sock:sock.bind(("127.0.0.1",0));port=sock.getsockname()[1]
 cfg={"mixed-port":port,"mode":"rule","log-level":"debug","proxies":[p],"proxy-groups":[{"name":"TEST","type":"select","proxies":[p["name"]]}],"rules":["MATCH,TEST"]}
 f=folder/"p.yaml";f.write_text(yaml.safe_dump(cfg,allow_unicode=True,sort_keys=False))
 log_path=folder/"mihomo.log"
 log_handle=log_path.open("w",encoding="utf-8")
 proc=subprocess.Popen([binary,"-f",str(f)],stdout=log_handle,stderr=subprocess.STDOUT,text=True)
 stage="mihomo_start"
 try:
  end=time.monotonic()+8
  while time.monotonic()<end:
   if proc.poll() is not None:
    proc.communicate(timeout=1);log_handle.flush()
    labels=mihomo_error_labels(log_path.read_text(encoding="utf-8",errors="replace")[-20000:])
    detail=",".join(labels) if labels else "mihomo_exited_early"
    print(f"节点测试失败：type={p.get('type','unknown')}；阶段={stage}；原因={detail}");return None
   try:
    with socket.create_connection(("127.0.0.1",port),timeout=.2):break
   except OSError:time.sleep(.1)
  else:print(f"节点测试失败：type={p.get('type','unknown')}；阶段=mixed_port_start_timeout");return None
  px={"http":f"http://127.0.0.1:{port}","https":f"http://127.0.0.1:{port}"}
  relaxed=os.getenv("RELAXED_MODE","false").strip().lower() in {"1","true","yes","on"}
  lat=None
  if not relaxed:
   latency_urls=configured_urls("LATENCY_TEST_URLS",["https://cp.cloudflare.com/generate_204","https://www.gstatic.com/generate_204","https://www.google.com/generate_204"])
   lat_errors=[];deadline=time.monotonic()+12
   for url in latency_urls:
    if time.monotonic()>=deadline:break
    stage="latency_request";t=time.monotonic();r=None
    try:
     r=requests.get(url,proxies=px,timeout=(3,4));elapsed=(time.monotonic()-t)*1000
     if r.status_code in (200,204,301,302):lat=elapsed;break
     lat_errors.append(f"HTTP{r.status_code}")
    except Exception as exc:lat_errors.append(exception_label(exc))
    finally:
     if r is not None:r.close()
   if lat is None:print(f"延迟探测失败：type={p.get('type','unknown')}；继续独立下载探测；错误类型={','.join(lat_errors)}")
  else:
   print("宽松测速模式：跳过延迟探测，按实际下载速度筛选")
  download_urls=download_test_urls()
  if precision:
   speeds=[]
   for attempt in range(2):
    stage=f"precision_download_{attempt+1}";v=measure_download(px,download_urls,5*1024*1024,20)
    if v is not None:speeds.append(v)
   if len(speeds)<2:
    print(f"节点测试失败：type={p.get('type','unknown')}；阶段=precision_download_incomplete；成功样本={len(speeds)}/2")
    return None
   import statistics
   speed=statistics.median(speeds)
  else:
   relaxed=os.getenv("RELAXED_MODE","false").strip().lower() in {"1","true","yes","on"}
   target_bytes=64*1024 if relaxed else 256*1024
   timeout=12 if relaxed else 8
   stage="relaxed_download" if relaxed else "quick_download"
   speed=measure_download(px,download_urls,target_bytes,timeout)
   if speed is None:print(f"节点测试失败：type={p.get('type','unknown')}；阶段={stage}_failed");return None
   if relaxed and speed < float(os.getenv("MIN_DOWNLOAD_SPEED_MBPS","0.10")):
    floor=float(os.getenv("MIN_DOWNLOAD_SPEED_MBPS","0.10"))
    print(f"节点测试失败：type={p.get('type','unknown')}；阶段=minimum_download_speed；实测={speed:.3f} Mbps；门槛={floor:.3f} Mbps")
    return None
  return (lat,speed)
 except Exception as exc:print(f"节点测试失败：type={p.get('type','unknown')}；阶段={stage}；异常={exception_label(exc)}");return None
 finally:
  if proc.poll() is None:proc.terminate()
  try:proc.communicate(timeout=2)
  except subprocess.TimeoutExpired:
   proc.kill()
   try:proc.communicate(timeout=1)
   except subprocess.TimeoutExpired:pass
  log_handle.flush();log_handle.close()
  try:log_text=log_path.read_text(encoding="utf-8",errors="replace")[-20000:]
  except OSError:log_text=""
  labels=mihomo_error_labels(log_text)
  if labels:print(f"Mihomo诊断：type={p.get('type','unknown')}；阶段={stage}；分类={','.join(labels)}")

def extract_endpoint_candidates(text):
 """Return host/port pairs from an endpoint list, without assuming they are proxy configs."""
 rows=[]
 for line in text.splitlines():
  line=line.strip()
  if not line or line.startswith(("#","//")):continue
  candidate=line.split("#",1)[0].strip()
  m=re.fullmatch(r"(?P<host>[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?):\d{1,5}",candidate)
  if not m:continue
  port=int(candidate.rsplit(":",1)[1])
  if not 1<=port<=65535:continue
  host=m.group("host")
  try:
   addr=ipaddress.ip_address(host)
   if not addr.is_global:continue
  except ValueError:
   if host.lower() == "localhost" or host.lower().endswith((".local",".localhost",".internal")):continue
  pair=(host,port)
  if pair not in rows:rows.append(pair)
 return rows

def endpoint_connectivity(value):
 """TCP-check subscription endpoints only; this does not validate proxy protocol/auth."""
 items=source_items(value); candidates=[]
 for index,item in enumerate(items,1):
  try:text=source(item)
  except Exception as exc:
   print(f"订阅源#{index}: 读取失败={type(exc).__name__}");continue
  parsed=parse(text)
  if parsed:
   group=[]
   for p in parsed:
    host=str(p.get("server","")).strip()
    try:port=int(p.get("port",0))
    except (TypeError,ValueError):continue
    if host and 1<=port<=65535 and (host,port) not in group:group.append((host,port))
  elif looks_like_endpoint_list(text):group=extract_endpoint_candidates(text)
  else:
   print(f"订阅源#{index}: 未识别为代理节点或 host:port 清单");continue
  candidates.extend(pair for pair in group if pair not in candidates)
 limit=max(1,int(os.getenv("ENDPOINT_DIAGNOSTIC_MAX","1000")))
 if len(candidates)>limit:
  print(f"候选地址总数={len(candidates)}；本轮按上限测试={limit}");candidates=candidates[:limit]
 else:print(f"候选地址总数={len(candidates)}；本轮全部测试")
 def check(pair):
  try:
   with socket.create_connection(pair,timeout=2):return True
  except (OSError,TimeoutError):return False
 with concurrent.futures.ThreadPoolExecutor(max_workers=40) as pool:results=list(pool.map(check,candidates))
 opened=[pair for pair,ok in zip(candidates,results) if ok]
 ip_results=[];domain_count=0
 for pair,ok in zip(candidates,results):
  try:ipaddress.ip_address(pair[0]);ip_results.append((pair,ok))
  except ValueError:domain_count+=1
 print(f"TCP 可连接={len(opened)}；TCP 未连接={len(candidates)-len(opened)}；其中 IP 地址={len(ip_results)}；域名地址={domain_count}")
 print("IP 地址 TCP 结果（只代表 TCP 端口可连接，不代表代理认证或转发可用）:")
 for (host,port),ok in ip_results:print(f"{host}:{port} TCP={'OPEN' if ok else 'CLOSED'}")
 return 0


def proxy_to_share_uri(p):
 from urllib.parse import quote, urlencode
 kind=str(p.get("type","")).lower(); name=quote(str(p.get("name") or p.get("server","proxy")),safe="")
 host=str(p.get("server","")); port=int(p.get("port",0))
 if not host or not 1<=port<=65535:return None
 def q(items): return urlencode([(k,str(v)) for k,v in items if v is not None and str(v)!=""],quote_via=quote,safe="/")
 if kind=="ss":
  method=str(p.get("cipher","")); password=str(p.get("password",""))
  if not method or not password:return None
  raw=f"{method}:{password}@{host}:{port}".encode()
  return "ss://"+base64.urlsafe_b64encode(raw).decode().rstrip("=")+"#"+name
 if kind=="vmess":
  if not p.get("uuid"):return None
  net=str(p.get("network","tcp")); ws=p.get("ws-opts") or {}; headers=ws.get("headers") or {}
  obj={"v":"2","ps":str(p.get("name") or host),"add":host,"port":str(port),"id":str(p["uuid"]),"aid":str(p.get("alterId",0)),"scy":str(p.get("cipher","auto")),"net":net,"type":"none","host":str(headers.get("Host","")),"path":str(ws.get("path","")),"tls":"tls" if p.get("tls") else ""}
  if p.get("servername"):obj["sni"]=str(p["servername"])
  return "vmess://"+base64.b64encode(json.dumps(obj,separators=(",",":")).encode()).decode()
 if kind in {"vless","trojan"}:
  user=p.get("uuid") if kind=="vless" else p.get("password")
  if not user:return None
  params=[]; net=str(p.get("network","tcp"))
  if net and net!="tcp":params.append(("type",net))
  reality=p.get("reality-opts") if isinstance(p.get("reality-opts"),dict) else {}
  if reality:params.append(("security","reality"))
  elif p.get("tls"):params.append(("security","tls"))
  if p.get("servername"):params.append(("sni",p["servername"]))
  if p.get("client-fingerprint"):params.append(("fp",p["client-fingerprint"]))
  if kind=="vless" and p.get("flow"):params.append(("flow",p["flow"]))
  if reality.get("public-key"):params.append(("pbk",reality["public-key"]))
  if reality.get("short-id"):params.append(("sid",reality["short-id"]))
  if net=="ws":
   ws=p.get("ws-opts") or {}; headers=ws.get("headers") or {}
   if ws.get("path"):params.append(("path",ws["path"]))
   if headers.get("Host"):params.append(("host",headers["Host"]))
  if net=="grpc":
   grpc=p.get("grpc-opts") or {}
   if grpc.get("grpc-service-name"):params.append(("serviceName",grpc["grpc-service-name"]))
  return f"{kind}://{quote(str(user),safe='')}@{host}:{port}?{q(params)}#{name}"
 if kind=="hysteria2":
  password=p.get("password") or p.get("auth")
  if not password:return None
  params=[]
  if p.get("servername"):params.append(("sni",p["servername"]))
  if p.get("skip-cert-verify"):params.append(("insecure","1"))
  obfs=p.get("obfs")
  if isinstance(obfs,dict) and obfs.get("type"):params.append(("obfs",obfs["type"]))
  if isinstance(obfs,dict) and obfs.get("password"):params.append(("obfs-password",obfs["password"]))
  return f"hysteria2://{quote(str(password),safe='')}@{host}:{port}?{q(params)}#{name}"
 if kind in {"socks5","socks","http"}:
  scheme="socks" if kind in {"socks5","socks"} else "http"; auth=""
  if p.get("username"):auth=quote(str(p["username"]),safe="")+(":"+quote(str(p.get("password","")),safe="") if p.get("password") else "")+"@"
  return f"{scheme}://{auth}{host}:{port}#{name}"
 return None

def write_v2rayn_subscription(results, output):
 uris=[]; skipped={}
 for p,*_ in results:
  value=proxy_to_share_uri(p)
  if value:uris.append(value)
  else:
   kind=str(p.get("type","unknown"));skipped[kind]=skipped.get(kind,0)+1
 if not uris:raise ValueError("没有可转换为 v2rayN 分享链接的节点类型")
 Path(output).parent.mkdir(parents=True,exist_ok=True)
 Path(output).write_text(base64.b64encode(("\n".join(uris)+"\n").encode()).decode()+"\n",encoding="utf-8")
 print(f"v2rayN 订阅已生成：可转换节点={len(uris)}；跳过不支持类型={sum(skipped.values())}")
 return len(uris)

def main():
 a=argparse.ArgumentParser();a.add_argument("--input",default=os.getenv("SUBSCRIPTION_URL",""));a.add_argument("--output",default="subscription/clash-mi.yaml");a.add_argument("--region",default=os.getenv("REGION_FILTER",""));a.add_argument("--name-filter",default=os.getenv("NODE_NAME_FILTER",""));a.add_argument("--server-filter",default=os.getenv("NODE_SERVER_FILTER",""));a.add_argument("--inventory-only",action="store_true",help="print safe node inventory without testing or writing credentials");a.add_argument("--diagnostics-only",action="store_true",help="probe a small spread of nodes without generating or publishing subscriptions");a.add_argument("--endpoint-check-only",action="store_true",help="TCP-check subscription host:port endpoints without creating proxy configs");a.add_argument("--sort",choices=["balanced","latency","speed"],default=os.getenv("SORT_BY","balanced"));a.add_argument("--top",type=int,default=int(os.getenv("TOP_N","100")));a.add_argument("--parse-only",action="store_true");a.add_argument("--v2rayn-output",default=os.getenv("V2RAYN_OUTPUT",""));x=a.parse_args()
 if not x.input:print("缺少 SUBSCRIPTION_URL",file=sys.stderr);return 2
 if x.endpoint_check_only:return endpoint_connectivity(x.input)
 try:nodes=load_nodes(x.input)
 except Exception as e:print("订阅读取失败："+type(e).__name__,file=sys.stderr);return 2
 print(f"订阅源数: {len(source_items(x.input))}; 解析节点数: {len(nodes)}")
 clean=clean_nodes(nodes)
 print(f"去重后节点数: {len(clean)}")
 if x.inventory_only:
  from collections import Counter
  type_counts=Counter(str(p.get("type","unknown")) for p in clean)
  network_counts=Counter(str(p.get("network","tcp")).lower() for p in clean)
  tls_field=Counter("true" if p.get("tls") is True else "false_or_missing" for p in clean)
  sni_field=Counter("present" if p.get("servername") else "missing" for p in clean)
  reality_field=Counter("present" if p.get("reality-opts") else "missing" for p in clean)
  ws_host=Counter("present" if ((p.get("ws-opts") or {}).get("headers") or {}).get("Host") else "missing" for p in clean)
  ws_path=Counter("present" if (p.get("ws-opts") or {}).get("path") else "missing" for p in clean)
  skip_verify=Counter("true" if p.get("skip-cert-verify") is True else "false_or_missing" for p in clean)
  server_kind=Counter()
  for p in clean:
   try:ipaddress.ip_address(str(p.get("server","")));server_kind["IP"]+=1
   except ValueError:server_kind["domain"]+=1
  print("元数据统计（仅计数，不含凭据或具体地址）：")
  print("  type="+str(dict(type_counts)))
  print("  network="+str(dict(network_counts)))
  print("  tls_field="+str(dict(tls_field))+"；servername="+str(dict(sni_field))+"；reality_opts="+str(dict(reality_field)))
  print("  ws_host="+str(dict(ws_host))+"；ws_path="+str(dict(ws_path))+"；skip_cert_verify="+str(dict(skip_verify)))
  print("  server_kind="+str(dict(server_kind)))
  needle=x.server_filter.strip().casefold()
  print("节点清单（仅名称、服务器地址、端口；不含凭据）:")
  for i,p in enumerate(clean,1):
   server=str(p.get("server", ""))
   try: direct_match = bool(needle) and server.casefold() == needle
   except Exception: direct_match = False
   print(f"{i:02d}\t{str(p.get('name', 'proxy'))[:100]}\t{server}\t{p.get('port', '')}\t直接匹配目标IP={'是' if direct_match else '否'}")
  return 0
 if x.name_filter.strip():
  needle=x.name_filter.strip().casefold()
  before=len(clean)
  clean=[p for p in clean if needle in str(p.get("name","")).casefold()]
  print(f"名称筛选: 关键字={x.name_filter.strip()!r}；筛选前={before}；匹配节点={len(clean)}")
  if not clean:
   print("名称筛选没有匹配节点；请核对订阅中的节点名称",file=sys.stderr);return 6
 if x.server_filter.strip():
  needle=x.server_filter.strip().casefold()
  before=len(clean)
  clean=[p for p in clean if needle == str(p.get("server","")).casefold()]
  print(f"服务器地址筛选: 目标={x.server_filter.strip()!r}；筛选前={before}；匹配节点={len(clean)}")
  if not clean:
   print("服务器地址筛选没有匹配节点；请核对订阅中的 server 地址",file=sys.stderr);return 7
 allowed={z.strip().upper() for z in x.region.split(",") if z.strip()}
 if allowed:clean=[p for p in clean if region(p) in allowed]
 print(f"地区筛选后节点数: {len(clean)}")
 if x.diagnostics_only:
  if not clean:print("诊断样本为空",file=sys.stderr);return 6
  limit=max(1,min(len(clean),int(os.getenv("DIAGNOSTICS_SAMPLE_SIZE","32"))))
  # Stratify by proxy type so a large pool of one type cannot hide other types.
  by_type={}
  for p in clean:by_type.setdefault(str(p.get("type","unknown")).lower(),[]).append(p)
  kinds=sorted(by_type)
  quotas={k:limit//len(kinds)+(1 if i<limit%len(kinds) else 0) for i,k in enumerate(kinds)}
  picked={}
  for k in kinds:
   group=by_type[k];count=min(quotas[k],len(group))
   if count==1:picked[k]=[group[len(group)//2]]
   elif count>1:picked[k]=[group[round(i*(len(group)-1)/(count-1))] for i in range(count)]
   else:picked[k]=[]
  sample=[]
  for i in range(max((len(v) for v in picked.values()),default=0)):
   for k in kinds:
    if i<len(picked[k]) and len(sample)<limit:sample.append(picked[k][i])
  print(f"只读代理诊断：样本数={len(sample)}；候选总数={len(clean)}；分类型抽样；不生成配置、不发布订阅")
  binary=shutil.which(os.getenv("MIHOMO_PATH","mihomo"))
  if not binary:print("找不到 Mihomo；无法执行诊断",file=sys.stderr);return 4
  for i,p in enumerate(sample,1):
   print(f"诊断样本 {i}/{len(sample)}：type={p.get('type','unknown')}；network={p.get('network','tcp')}；tls={'yes' if p.get('tls') else 'no'}；sni={'yes' if p.get('servername') else 'no'}；reality={'yes' if p.get('reality-opts') else 'no'}；port={p.get('port','?')}")
  # Run parallel first in this round to separate concurrency effects from test-order/rate-limit effects.
  parallel_passed=0
  with tempfile.TemporaryDirectory() as d:
   with concurrent.futures.ThreadPoolExecutor(max_workers=min(2,len(sample))) as pool:
    futures={pool.submit(probe,p,binary,Path(d)/f"parallel-{i}",False):(i,p) for i,p in enumerate(sample,1)}
    for future in concurrent.futures.as_completed(futures):
     i,p=futures[future]
     try:value=future.result()
     except Exception as exc:
      print(f"并发诊断 {i}/{len(sample)}：ERROR；异常={type(exc).__name__}")
      value=None
     if value:
      parallel_passed+=1
      print(f"并发诊断 {i}/{len(sample)}：PASS；延迟={format_latency(value[0])}；下载={value[1]:.2f} Mbps")
     elif not future.exception():print(f"并发诊断 {i}/{len(sample)}：FAIL；type={p.get('type','unknown')}")
  serial_passed=0
  with tempfile.TemporaryDirectory() as d:
   for i,p in enumerate(sample,1):
    try:value=probe(p,binary,Path(d)/f"serial-{i}",False)
    except Exception as exc:
     print(f"串行诊断 {i}/{len(sample)}：ERROR；异常={type(exc).__name__}")
     value=None
    if value:
     serial_passed+=1
     print(f"串行诊断 {i}/{len(sample)}：PASS；延迟={format_latency(value[0])}；下载={value[1]:.2f} Mbps")
    else:print(f"串行诊断 {i}/{len(sample)}：FAIL；type={p.get('type','unknown')}")
  print(f"同批节点对照：样本={len(sample)}；串行通过={serial_passed}；并发通过={parallel_passed}；顺序=先并发后串行")
  return 0
 res=[]
 if x.parse_only:res=[(p,None,None) for p in clean]
 else:
  binary=shutil.which(os.getenv("MIHOMO_PATH","mihomo"))
  if not binary:print("找不到 Mihomo；不会把未测速节点标记为可用",file=sys.stderr);return 4
  workers=max(1,min(16,int(os.getenv("PROBE_WORKERS","8"))))
  print(f"初筛并发测速工作线程: {workers}")
  with tempfile.TemporaryDirectory() as d:
   with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
    futures={pool.submit(probe,p,binary,Path(d)/f"quick-{i}",False):(i,p) for i,p in enumerate(clean)}
    completed=0
    for future in concurrent.futures.as_completed(futures):
     _,p=futures[future]
     try:v=future.result()
     except Exception as exc:print(f"节点初筛异常：type={p.get('type','unknown')}；异常={type(exc).__name__}");v=None
     if v:res.append((p,*v))
     completed+=1
     if completed%50==0 or completed==len(clean):print(f"初筛进度: {completed}/{len(clean)}；通过={len(res)}")
   res.sort(key=lambda z:(z[2] is None,-(z[2] or 0),z[1] is None,z[1] or 1e9))
   quick_ranked=list(res)
   relaxed=os.getenv("RELAXED_MODE","false").strip().lower() in {"1","true","yes","on"}
   if relaxed:
    # A small paired diagnostic showed that some VLESS nodes fail under concurrent
    # probing but pass when retried serially. Retry a bounded, evenly spaced sample
    # of failed VLESS nodes serially; never include a node unless real download passes.
    res=quick_ranked
    target_count=x.top if x.top>0 else 100
    if len(res)<target_count:
     passed_keys={node_key(z[0]) for z in res}
     failed_vless=[p for p in clean if str(p.get("type","")).lower()=="vless" and node_key(p) not in passed_keys]
     retry_limit=max(0,int(os.getenv("SERIAL_FALLBACK_CANDIDATES","300")))
     retry_count=min(len(failed_vless),retry_limit)
     if retry_count:
      if retry_count==1:retry_candidates=[failed_vless[len(failed_vless)//2]]
      else:retry_candidates=[failed_vless[round(i*(len(failed_vless)-1)/(retry_count-1))] for i in range(retry_count)]
      print(f"串行复测：并发初筛未通过的 VLESS 候选={len(failed_vless)}；本轮上限={len(retry_candidates)}；当前通过={len(res)}；目标={target_count}")
      retried_passed=0
      with tempfile.TemporaryDirectory() as retry_dir:
       for i,p in enumerate(retry_candidates,1):
        try:v=probe(p,binary,Path(retry_dir)/f"serial-fallback-{i}",False)
        except Exception as exc:
         print(f"串行复测异常：type=vless；异常={type(exc).__name__}");v=None
        if v:
         res.append((p,*v));retried_passed+=1
        if i%25==0 or i==len(retry_candidates) or len(res)>=target_count:
         print(f"串行复测进度：{i}/{len(retry_candidates)}；复测新增通过={retried_passed}；总通过={len(res)}")
        if len(res)>=target_count:break
     print(f"串行复测结束：新增通过={retried_passed}；最终候选={len(res)}")
    print(f"宽松测速模式：跳过双次 5 MiB 精测；保留真实下载测速通过节点={len(res)}")
   else:
    target=x.top if x.top>0 else len(res);batch_size=max(200,target*2) if target else max(1,len(res))
    precise=[]
    for batch_start in range(0,len(quick_ranked),batch_size):
     batch=quick_ranked[batch_start:batch_start+batch_size]
     print(f"开始下载精测：候选 {batch_start+1}-{batch_start+len(batch)} / {len(quick_ranked)}；每节点最多 2 次")
     with concurrent.futures.ThreadPoolExecutor(max_workers=max(1,min(4,workers))) as pool:
      futures={pool.submit(probe,z[0],binary,Path(d)/f"precision-{batch_start+i}",True):z[0] for i,z in enumerate(batch)}
      completed=0
      for future in concurrent.futures.as_completed(futures):
       p=futures[future]
       try:v=future.result()
       except Exception as exc:print(f"节点精测异常：type={p.get('type','unknown')}；异常={type(exc).__name__}");v=None
       if v:precise.append((p,*v))
       completed+=1
       if completed%25==0 or completed==len(batch):print(f"精测进度: {batch_start+completed}/{len(quick_ranked)}；精测合格={len(precise)}")
     precise.sort(key=lambda z:(z[2] is None,-(z[2] or 0),z[1] is None,z[1] or 1e9))
     if x.top>0 and len(precise)>=x.top:break
    res=precise
 if x.sort=="latency":res.sort(key=lambda z:(z[1] is None,z[1] or 1e9))
 elif x.sort=="speed":res.sort(key=lambda z:(z[2] is None,-(z[2] or 0),z[1] is None,z[1] or 1e9))
 else:res.sort(key=lambda z:(z[2] is None,-(z[2] or 0),z[1] is None,z[1] or 1e9))
 if x.top > 0:res=res[:x.top]
 if not res:print(f"测速未通过：待测节点 {len(clean)}，通过节点 {len(res)}；未生成配置",file=sys.stderr);return 5
 doc={"proxies":[z[0] for z in res],"proxy-groups":[{"name":"优选节点","type":"select","proxies":[z[0]["name"] for z in res]}],"rules":["MATCH,优选节点"]}
 dest=Path(x.output);dest.parent.mkdir(parents=True,exist_ok=True);dest.write_text(yaml.safe_dump(doc,allow_unicode=True,sort_keys=False),encoding="utf-8")
 assert len(yaml.safe_load(dest.read_text())["proxies"])==len(res)
 print(f"已生成配置：{dest}；节点数={len(res)}；模式={'仅解析，未测速' if x.parse_only else '真实测速'}")
 if x.v2rayn_output:
  try: write_v2rayn_subscription(res,x.v2rayn_output)
  except ValueError as e: print(str(e),file=sys.stderr);return 8
 if not x.parse_only:
  for p,lat,spd in res:print(f"{p['name'][:48]}\t{format_latency(lat)}\t{spd:.2f} Mbps")
 return 0
if __name__=="__main__":raise SystemExit(main())
