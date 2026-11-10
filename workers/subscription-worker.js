/**
 * VPN Gate subscription Worker. The generator produces the complete, validated
 * Clash Mi YAML. This Worker serves it without cloning or rebuilding YAML blocks,
 * which would duplicate PyYAML anchors and corrupt the subscription.
 *
 * Routes: /vpngate/<VPNGATE_TOKEN> and legacy /sub/<SUBSCRIPTION_TOKEN>
 * Optional query parameters: ?endpoint=IP:PORT, ?awg=1, ?raw=1, ?nocache=1
 */
function enhanceSubscriptionYaml(yamlText, searchParams) {
  if (searchParams.get("raw") === "1") return yamlText;
  let output = yamlText;
  const endpointParam = (searchParams.get("endpoint") || "").trim();
  let customHost = (searchParams.get("ip") || "").trim();
  let customPort = (searchParams.get("port") || "").trim();
  if (endpointParam) {
    const lastColon = endpointParam.lastIndexOf(":");
    if (lastColon > 0 && !endpointParam.endsWith("]")) { customHost = endpointParam.slice(0, lastColon).trim(); customPort = endpointParam.slice(lastColon + 1).trim(); }
    else customHost = endpointParam;
  }
  if (customHost && /^[A-Za-z0-9._-]+$/.test(customHost)) {
    output = output.replace(/(^-\s*name:\s*WARP\s*\n[\s\S]*?^\s*-\s*server:\s*)[^\s\n]+/m, `$1${customHost}`);
  }
  if (customPort && /^\d+$/.test(customPort)) {
    const portNum = Number(customPort);
    if (portNum >= 1 && portNum <= 65535) output = output.replace(/(^-\s*name:\s*WARP\s*\n[\s\S]*?^\s*-\s*server:\s*[^\s\n]+\n\s*port:\s*)\d+/m, `$1${portNum}`);
  }
  const awgParam = (searchParams.get("awg") || "").trim().toLowerCase();
  if (["1", "true", "on"].includes(awgParam) && !output.includes("amnezia-wg-option:")) {
    output = output.replace(/^([ \t]*)type:\s*wireguard\s*$/gm, (match, indent) => {
      const sub = `${indent}  `;
      return `${match}\n${indent}amnezia-wg-option:\n${sub}jc: 4\n${sub}jmin: 40\n${sub}jmax: 70\n${sub}s1: 0\n${sub}s2: 0\n${sub}h1: 1\n${sub}h2: 2\n${sub}h3: 3\n${sub}h4: 4`;
    });
  }
  return output;
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const parts = url.pathname.split("/").filter(Boolean);
    if (request.method !== "GET" || parts.length !== 2) return new Response("Not found", { status: 404, headers: { "Cache-Control": "no-store" } });
    let key = null;
    if (parts[0] === "sub" && env.SUBSCRIPTION_TOKEN && parts[1] === env.SUBSCRIPTION_TOKEN) key = "clash-mi.yaml";
    else if (parts[0] === "vpngate" && env.VPNGATE_TOKEN && parts[1] === env.VPNGATE_TOKEN) key = "vpngate-clash-mi.yaml";
    if (!key) return new Response("Not found", { status: 404, headers: { "Cache-Control": "no-store" } });
    if (!env.SUBSCRIPTIONS) return new Response("Subscription storage is not configured", { status: 503, headers: { "Cache-Control": "no-store" } });
    const noCache = url.searchParams.get("nocache") === "1";
    const options = noCache ? { type: "text" } : { type: "text", cacheTtl: 300 };
    const rawBody = await env.SUBSCRIPTIONS.get(key, options);
    if (!rawBody) return new Response("Subscription has not been published yet", { status: 503, headers: { "Cache-Control": "no-store" } });
    const body = enhanceSubscriptionYaml(rawBody, url.searchParams);
    return new Response(body, { status: 200, headers: { "Content-Type": "text/yaml; charset=utf-8", "Cache-Control": noCache ? "no-store, max-age=0" : "public, max-age=300, s-maxage=600, stale-while-revalidate=1800", "Profile-Update-Interval": "1", "X-Content-Type-Options": "nosniff" } });
  },
};
