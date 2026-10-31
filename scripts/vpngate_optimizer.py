#!/usr/bin/env python3
"""VPN Gate official CSV -> tested Mihomo OpenVPN subscription."""
import argparse,base64,concurrent.futures,csv,os,re,shutil,socket,statistics,subprocess,tempfile,time
from pathlib import Path
import requests,yaml
API="https://www.vpngate.net/api/iphone/"

def decode_config(s):
    try:
        s=(s or "").strip()
        return base64.b64decode(s+"="*(-len(s)%4)).decode("utf-8","replace") if s else ""
    except Exception:return ""
def num(v):
    try:
        n=float(v);return n if n>=0 else None
    except (TypeError,ValueError):return None

def parse_profile(config,row):
    blocks,directives={},[];block,buf=None,[]
    for raw in config.splitlines():
        line=raw.strip()
        if block:
            if line.lower()==f"</{block}>":blocks[block]="\n".join(buf).strip()+"\n";block,buf=None,[]
            else:buf.append(raw)
            continue
        if not line or line.startswith(("#",";")):continue
        m=re.fullmatch(r"<(ca|cert|key|tls-auth|tls-crypt|tls-crypt-v2)\s*>",line,re.I)
        if m:block=m.group(1).lower();continue
        p=line.split();directives.append((p[0].lower(),p[1:]))
    if block:return None
    def vals(k):return [v for n,v in directives if n==k and v]
    rem=vals("remote")
    if not rem or len(rem[0])<2 or not blocks.get("ca"):return None
    host=rem[0][0]
    try:port=int(rem[0][1])
    except ValueError:return None
    if not host or not 1<=port<=65535:return None
    pv=vals("proto");proto=pv[0][0].lower() if pv else "udp"
    if proto in ("tcp","tcp-client","tcp4-client","tcp6-client"):proto="tcp"
    elif proto in ("udp","udp4","udp6"):proto="udp"
    else:return None
    country=(row.get("CountryLong") or row.get("CountryShort") or "Unknown").strip()
    label=re.sub(r"[^A-Za-z0-9._ -]","",f"VPNGate {country} {row.get('IP') or host}")[:80]
    node={"name":label,"type":"openvpn","server":host,"port":port,"proto":proto,"udp":proto=="udp","username":"vpn","password":"vpn","ca":blocks["ca"]}
    for k in ("cert","key","tls-auth","tls-crypt","tls-crypt-v2"):
        if blocks.get(k):node[k]=blocks[k]
    kd=vals("key-direction")
    if kd:node["key-direction"]=kd[0][0]
    for k in ("cipher","data-ciphers-fallback","auth"):
        v=vals(k)
        if v:node[k]=v[0][0].upper()
    dc=vals("data-ciphers")
    if dc:node["data-ciphers"]=[x.upper() for x in re.split(r"[:,\s]+"," ".join(dc[0])) if x]
    comp=vals("comp-lzo")
    if comp:node["comp-lzo"]=comp[0][0].lower()
    elif vals("compress"):node["comp-lzo"]="yes"
    return {"proxy":node,"country":country,"ping":num(row.get("Ping")),"speed":num(row.get("Speed"))}

def parse_csv(text):
    lines=[x for x in text.splitlines() if x.strip()]
    i=next((i for i,x in enumerate(lines) if x.lstrip("#").startswith("HostName,")),None)
    if i is None:raise ValueError("VPN Gate CSV header not found")
    rows=csv.DictReader([lines[i].lstrip("#")]+lines[i+1:]);out=[];seen=set()
    for row in rows:
        if not row.get("HostName") or row["HostName"].startswith("*"):continue
        item=parse_profile(decode_config(row.get("OpenVPN_Config")),row)
        if item:
            p=item["proxy"];key=(p["server"],p["port"],p["proto"])
            if key not in seen:seen.add(key);out.append(item)
    return out
def fetch():
    r=requests.get(API,timeout=40,headers={"User-Agent":"cf001-vpngate/1.0"});r.raise_for_status();r.encoding="utf-8";return parse_csv(r.text)
def rank(items,limit):
    return sorted(items,key=lambda x:(x["ping"] is None,x["ping"] if x["ping"] is not None else 10**9,-(x["speed"] or 0)))[:max(1,limit)]
def free_port():
    with socket.socket() as s:s.bind(("127.0.0.1",0));return s.getsockname()[1]
def start_node(node,binary,folder):
    folder.mkdir(parents=True,exist_ok=True);port=free_port()
    cfg={"mixed-port":port,"mode":"rule","log-level":"warning","proxies":[node],"proxy-groups":[{"name":"TEST","type":"select","proxies":[node["name"]]}],"rules":["MATCH,TEST"]}
    path=folder/"test.yaml";path.write_text(yaml.safe_dump(cfg,allow_unicode=True),encoding="utf-8")
    log=(folder/"mihomo.log").open("w",encoding="utf-8");proc=subprocess.Popen([binary,"-f",str(path)],stdout=log,stderr=subprocess.STDOUT)
    deadline=time.monotonic()+10
    while time.monotonic()<deadline:
        if proc.poll() is not None:log.flush();raise RuntimeError("mihomo startup failed")
        try:
            with socket.create_connection(("127.0.0.1",port),timeout=.2):return proc,log,port
        except OSError:time.sleep(.1)
    proc.terminate();log.close();raise RuntimeError("mihomo startup timeout")
def stop_node(proc,log):
    if proc.poll() is None:proc.terminate()
    try:proc.wait(timeout=3)
    except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=2)
    log.close()
def latency(px):
    for url in ("https://cp.cloudflare.com/generate_204","https://www.gstatic.com/generate_204"):
        try:
            t=time.monotonic();r=requests.get(url,proxies={"http":px,"https":px},timeout=(4,7));ms=(time.monotonic()-t)*1000
            if r.status_code in (200,204,301,302):r.close();return ms
            r.close()
        except requests.RequestException:pass
    return None
def download(px,size,timeout):
    for url in (f"https://speed.cloudflare.com/__down?bytes={size}","https://proof.ovh.net/files/10Mb.dat"):
        r=None
        try:
            r=requests.get(url,proxies={"http":px,"https":px},timeout=(5,timeout),stream=True)
            if r.status_code!=200:continue
            n=0;t=time.monotonic()
            for chunk in r.iter_content(65536):
                if chunk:n+=len(chunk)
                if n>=size or time.monotonic()-t>timeout:break
            elapsed=max(time.monotonic()-t,.001)
            if n>=int(size*.75):return min(n,size)*8/elapsed/1e6
        except requests.RequestException:pass
        finally:
            if r:r.close()
    return None
def probe(item,binary,folder,strict):
    proc=log=None
    try:
        proc,log,port=start_node(item["proxy"],binary,folder);px=f"http://127.0.0.1:{port}";ms=latency(px)
        if strict:
            speeds=[download(px,5*1024*1024,25) for _ in range(2)]
            if any(x is None for x in speeds):return None
            speed=statistics.median(speeds)
        else:
            speed=download(px,128*1024,12)
            if speed is None:return None
        return ms,speed
    except Exception as e:
        print(f"测试失败 {item['proxy']['name']}: {type(e).__name__}");return None
    finally:
        if proc is not None:stop_node(proc,log)
def test_many(items,binary,workers,strict=False):
    ok=[]
    with tempfile.TemporaryDirectory(prefix="vpngate-") as tmp:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1,min(workers,5))) as pool:
            jobs={pool.submit(probe,x,binary,Path(tmp)/str(i),strict):x for i,x in enumerate(items)}
            for f in concurrent.futures.as_completed(jobs):
                try:r=f.result()
                except Exception as e:print("probe error:",type(e).__name__);r=None
                if r:ok.append((jobs[f],r[0],r[1]))
    return sorted(ok,key=lambda x:(x[1] is None,x[1] if x[1] is not None else 10**9,-x[2]))
def write_yaml(results,path):
    nodes=[x[0]["proxy"] for x in results]
    if not nodes:raise RuntimeError("zero tested nodes; refusing to publish empty subscription")
    doc={"proxies":nodes,"proxy-groups":[{"name":"VPN Gate 优选","type":"select","proxies":[n["name"] for n in nodes]}],"rules":["MATCH,VPN Gate 优选"]}
    Path(path).parent.mkdir(parents=True,exist_ok=True);Path(path).write_text(yaml.safe_dump(doc,allow_unicode=True,sort_keys=False),encoding="utf-8")
    return doc
def main():
    a=argparse.ArgumentParser();a.add_argument("--output",default="vpngate-clash-mi.yaml");a.add_argument("--max-candidates",type=int,default=int(os.getenv("VPNGATE_MAX_CANDIDATES","60")));a.add_argument("--top",type=int,default=int(os.getenv("VPNGATE_TOP_N","20")));a.add_argument("--workers",type=int,default=int(os.getenv("VPNGATE_PROBE_WORKERS","3")));a.add_argument("--parse-only",action="store_true");x=a.parse_args()
    try:
        all_nodes=fetch();candidates=rank(all_nodes,x.max_candidates);print(f"VPN Gate profiles parsed={len(all_nodes)}; candidates={len(candidates)}")
        if x.parse_only:print("Parse-only: no connectivity claims, no YAML output, no publishing.");return 0
        binary=shutil.which(os.getenv("MIHOMO_PATH","mihomo"))
        if not binary:raise RuntimeError("Mihomo binary not found")
        quick=test_many(candidates,binary,x.workers);print(f"Quick tests passed={len(quick)}")
        strict=test_many([v[0] for v in quick[:max(x.top*2,x.top)]],binary,x.workers,True)[:max(1,x.top)]
        doc=write_yaml(strict,x.output);print(f"Strictly tested nodes={len(doc['proxies'])}")
        for item,ms,mbps in strict:print(f"{item['country']} | {item['proxy']['proto']} | {ms:.0f} ms | {mbps:.2f} Mbps" if ms is not None else f"{item['country']} | {item['proxy']['proto']} | latency N/A | {mbps:.2f} Mbps")
        return 0
    except Exception as e:print(f"VPN Gate task failed: {type(e).__name__}: {str(e)[:160]}");return 1
if __name__=="__main__":raise SystemExit(main())
