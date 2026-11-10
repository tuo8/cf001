/**
 * VPN Gate & WARP High-Availability Subscription Worker.
 *
 * Automatically upgrades the KV YAML on the fly when fetched by FlClash / Clash Mi:
 *   1. Replaces any #WARP / 8.8.8.8 / 1.1.1.1 DNS bootstrap deadlock with domestic Alidns/DNSPod (223.5.5.5, 119.29.29.29).
 *   2. Replaces blocked 'engage.cloudflareclient.com' with preferred Anycast IP (162.159.193.1) or ?endpoint=IP:PORT.
 *   3. Clones every OpenVPN node into a Direct mode node ("⚡直连 <Name>", no WARP dependency, MTU 1400) alongside the WARP-chained node so domestic clients can connect even when Cloudflare WARP UDP is completely blocked by the ISP.
 *   4. Injects auto-testing url-test ("⚡ 自动优选 (最快)") and fallback ("🛡️ 故障转移 (稳定)") proxy groups as the first choices in "出站节点".
 *   5. Prepends domestic DIRECT routing rules (cn, huaban.com, qq.com, baidu.com, LAN CIDRs) before MATCH,出站节点.
 *
 * Optional Query Parameters:
 *   - ?endpoint=162.159.195.1:500   Custom WARP endpoint IP:port
 *   - ?awg=1                        Injects AmneziaWG pulse obfuscation (jc: 4, jmin: 40, jmax: 70) into WARP
 *   - ?raw=1                        Returns the unenhanced raw YAML from KV
 *   - ?nocache=1                    Bypasses KV cache
 */

const DOMESTIC_DNS_BLOCK = `dns:
  enable: true
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
  - '*.lan'
  - '*.local'
  - localhost.ptlogin2.qq.com
  - +.msftconnecttest.com
  - +.msftncsi.com
  - ipv6.*
  - '*.ipv6.*'
  default-nameserver:
  - 223.5.5.5
  - 119.29.29.29
  - 180.76.76.76
  nameserver:
  - https://dns.alidns.com/dns-query
  - https://doh.pub/dns-query
  - 223.5.5.5
  proxy-server-nameserver:
  - https://dns.alidns.com/dns-query
  - https://doh.pub/dns-query
  - 223.5.5.5`;

const DOMESTIC_RULES_BLOCK = `rules:
- DOMAIN-SUFFIX,cn,DIRECT
- DOMAIN-SUFFIX,alimama.com,DIRECT
- DOMAIN-SUFFIX,alipay.com,DIRECT
- DOMAIN-SUFFIX,baidu.com,DIRECT
- DOMAIN-SUFFIX,bilibili.com,DIRECT
- DOMAIN-SUFFIX,huaban.com,DIRECT
- DOMAIN-SUFFIX,jd.com,DIRECT
- DOMAIN-SUFFIX,qq.com,DIRECT
- DOMAIN-SUFFIX,taobao.com,DIRECT
- DOMAIN-SUFFIX,tmall.com,DIRECT
- DOMAIN-SUFFIX,weibo.com,DIRECT
- IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
- IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
- IP-CIDR,172.16.0.0/12,DIRECT,no-resolve
- IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
- MATCH,出站节点`;

function enhanceSubscriptionYaml(yamlText, searchParams) {
  if (searchParams.get("raw") === "1") {
    return yamlText;
  }

  let output = yamlText;

  // 1. Replace blocked engage.cloudflareclient.com with preferred Anycast IP 162.159.193.1
  output = output.replace(/server:\s*engage\.cloudflareclient\.com/g, "server: 162.159.193.1");

  // 2. Apply custom ?endpoint=IP:PORT or ?ip= / ?port= overrides
  const endpointParam = (searchParams.get("endpoint") || "").trim();
  let customHost = (searchParams.get("ip") || "").trim();
  let customPort = (searchParams.get("port") || "").trim();

  if (endpointParam) {
    const lastColon = endpointParam.lastIndexOf(":");
    if (lastColon > 0 && !endpointParam.endsWith("]")) {
      customHost = endpointParam.slice(0, lastColon).trim();
      customPort = endpointParam.slice(lastColon + 1).trim();
    } else {
      customHost = endpointParam;
    }
  }

  if (customHost && /^[A-Za-z0-9._-]+$/.test(customHost)) {
    output = output.replace(
      /(-\s*name:\s*WARP[\s\S]*?peers:\s*\n\s*-\s*server:\s*)([^\s\n]+)/,
      `$1${customHost}`
    );
  }
  if (customPort && /^\d+$/.test(customPort)) {
    const portNum = parseInt(customPort, 10);
    if (portNum >= 1 && portNum <= 65535) {
      output = output.replace(
        /(-\s*name:\s*WARP[\s\S]*?peers:\s*\n\s*-\s*server:\s*[^\s\n]+\n\s*port:\s*)(\d+)/,
        `$1${portNum}`
      );
    }
  }

  // 3. Eliminate #WARP DNS deadlock by replacing the dns: section with domestic DoH/DNS
  output = output.replace(/dns:\n(?:\s+.*\n|- .*\n)+?(?=proxies:)/, `${DOMESTIC_DNS_BLOCK}\n`);

  // 4. Generate Direct-mode clones for every OpenVPN node so FlClash can connect without WARP
  const proxyGroupsIdx = output.indexOf("\nproxy-groups:");
  const proxiesIdx = output.indexOf("\nproxies:");
  if (proxiesIdx !== -1 && proxyGroupsIdx !== -1 && proxyGroupsIdx > proxiesIdx) {
    const proxiesSection = output.slice(proxiesIdx + 1, proxyGroupsIdx);
    const itemBlocks = proxiesSection.split(/\n(?=\s*-\s*name:\s*)/);
    const directBlocks = [];
    const directNames = [];
    const chainedNames = [];

    for (let i = 1; i < itemBlocks.length; i++) {
      const block = itemBlocks[i];
      if (block.includes("type: openvpn")) {
        const nameMatch = block.match(/^(\s*)-\s*name:\s*(.+)$/m);
        if (nameMatch) {
          const indent = nameMatch[1] || "";
          const rawName = nameMatch[2].trim().replace(/^['"]|['"]$/g, "");
          chainedNames.push(rawName);
          const directName = `⚡直连 ${rawName}`;
          directNames.push(directName);
          const directBlock = block
            .replace(/^(\s*)-\s*name:\s*.+$/m, `${indent}- name: '${directName}'`)
            .replace(/\n\s*dialer-proxy:\s*[^\n]+/g, "")
            .replace(/mtu:\s*\d+/g, "mtu: 1400");
          directBlocks.push(directBlock);
        }
      }
    }

    if (directBlocks.length > 0) {
      const allCandidateNames = [
        ...directNames.map((n) => `  - '${n}'`),
        "  - WARP",
        ...chainedNames.map((n) => `  - '${n}'`),
      ].join("\n");

      const selectList = [
        "  - ⚡ 自动优选 (最快)",
        "  - 🛡️ 故障转移 (稳定)",
        "  - 🚀 直连节点 (免WARP)",
        "  - WARP",
        ...directNames.map((n) => `  - '${n}'`),
        ...chainedNames.map((n) => `  - '${n}'`),
      ].join("\n");

      const directOnlyList = directNames.map((n) => `  - '${n}'`).join("\n");

      const enhancedProxyGroups = `proxy-groups:
- name: 出站节点
  type: select
  proxies:
${selectList}
- name: ⚡ 自动优选 (最快)
  type: url-test
  url: https://cp.cloudflare.com/generate_204
  interval: 120
  tolerance: 50
  lazy: false
  proxies:
${allCandidateNames}
- name: 🛡️ 故障转移 (稳定)
  type: fallback
  url: https://cp.cloudflare.com/generate_204
  interval: 90
  lazy: false
  proxies:
${allCandidateNames}
- name: 🚀 直连节点 (免WARP)
  type: url-test
  url: https://cp.cloudflare.com/generate_204
  interval: 120
  tolerance: 50
  lazy: false
  proxies:
${directOnlyList}
`;
      const beforeProxies = output.slice(0, proxyGroupsIdx);
      output = `${beforeProxies}\n${directBlocks.join("\n")}\n${enhancedProxyGroups}${DOMESTIC_RULES_BLOCK}\n`;
    }
  }

  // 5. Optional AmneziaWG injection via ?awg=1 matching exact key indentation
  const awgParam = (searchParams.get("awg") || "").trim().toLowerCase();
  if (awgParam === "1" || awgParam === "true" || awgParam === "on") {
    if (!output.includes("amnezia-wg-option:")) {
      output = output.replace(/^([ \t]*)type:\s*wireguard$/gm, (match, indent) => {
        const sub = `${indent}  `;
        return `${match}\n${indent}amnezia-wg-option:\n${sub}jc: 4\n${sub}jmin: 40\n${sub}jmax: 70\n${sub}s1: 0\n${sub}s2: 0\n${sub}h1: 1\n${sub}h2: 2\n${sub}h3: 3\n${sub}h4: 4`;
      });
    }
  }

  return output;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const parts = url.pathname.split("/").filter(Boolean);
    if (request.method !== "GET" || parts.length !== 2) {
      return new Response("Not found", {
        status: 404,
        headers: { "Cache-Control": "no-store" },
      });
    }

    let key = null;
    if (parts[0] === "sub" && env.SUBSCRIPTION_TOKEN && parts[1] === env.SUBSCRIPTION_TOKEN) {
      key = "clash-mi.yaml";
    } else if (parts[0] === "vpngate" && env.VPNGATE_TOKEN && parts[1] === env.VPNGATE_TOKEN) {
      key = "vpngate-clash-mi.yaml";
    }
    if (!key) {
      return new Response("Not found", {
        status: 404,
        headers: { "Cache-Control": "no-store" },
      });
    }
    if (!env.SUBSCRIPTIONS) {
      return new Response("Subscription storage is not configured", {
        status: 503,
        headers: { "Cache-Control": "no-store" },
      });
    }

    const noCache = url.searchParams.get("nocache") === "1";
    const kvOptions = noCache ? { type: "text" } : { type: "text", cacheTtl: 300 };
    const rawBody = await env.SUBSCRIPTIONS.get(key, kvOptions);
    if (!rawBody) {
      return new Response("Subscription has not been published yet", {
        status: 503,
        headers: { "Cache-Control": "no-store" },
      });
    }

    const finalBody = enhanceSubscriptionYaml(rawBody, url.searchParams);
    const cacheHeader = noCache
      ? "no-store, max-age=0"
      : "public, max-age=300, s-maxage=600, stale-while-revalidate=1800";

    return new Response(finalBody, {
      status: 200,
      headers: {
        "Content-Type": "text/yaml; charset=utf-8",
        "Cache-Control": cacheHeader,
        "Profile-Update-Interval": "1",
        "X-Content-Type-Options": "nosniff",
      },
    });
  },
};
