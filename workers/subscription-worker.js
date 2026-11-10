/**
 * VPN Gate & WARP High-Availability Subscription Worker.
 *
 * Supported Routes:
 *   - GET /sub/<SUBSCRIPTION_TOKEN>       -> serves "clash-mi.yaml"
 *   - GET /vpngate/<VPNGATE_TOKEN>        -> serves "vpngate-clash-mi.yaml"
 *
 * Supported Query Parameters (for local ISP customization without re-running CI):
 *   - ?endpoint=162.159.193.1:2408  Overrides primary WARP server & port with locally tested optimal IP:port
 *   - ?ip=162.159.193.1             Overrides primary WARP server IP
 *   - ?port=500                     Overrides primary WARP UDP port (e.g. 2408, 500, 1701, 4500)
 *   - ?mtu=1380                     Overrides WARP MTU
 *   - ?awg=0                        Strips amnezia-wg-option block for legacy clients that do not support AmneziaWG
 *   - ?dialer=pool                  Chains all OpenVPN nodes to "🌐 WARP 前置池" (auto url-test group) instead of single "WARP"
 *   - ?nocache=1                    Bypasses edge cache and reads directly from KV
 */

function applyDynamicOverrides(yamlText, searchParams) {
  let output = yamlText;

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

  // Override primary WARP server endpoint if valid hostname/IPv4 is provided
  if (customHost && /^[A-Za-z0-9._-]+$/.test(customHost)) {
    output = output.replace(
      /(-\s*name:\s*WARP[\s\S]*?peers:\s*\n\s*-\s*server:\s*)([^\s\n]+)/,
      `$1${customHost}`
    );
  }

  // Override primary WARP UDP port if valid port is provided
  if (customPort && /^\d+$/.test(customPort)) {
    const portNum = parseInt(customPort, 10);
    if (portNum >= 1 && portNum <= 65535) {
      output = output.replace(
        /(-\s*name:\s*WARP[\s\S]*?peers:\s*\n\s*-\s*server:\s*[^\s\n]+\n\s*port:\s*)(\d+)/,
        `$1${portNum}`
      );
    }
  }

  // Override WARP MTU if requested
  const mtuParam = (searchParams.get("mtu") || "").trim();
  if (mtuParam && /^\d+$/.test(mtuParam)) {
    const mtuNum = parseInt(mtuParam, 10);
    if (mtuNum >= 576 && mtuNum <= 1500) {
      output = output.replace(
        /(-\s*name:\s*WARP[\s\S]*?\n\s*mtu:\s*)(\d+)/,
        `$1${mtuNum}`
      );
    }
  }

  // Switch OpenVPN dialer-proxy to the auto-tested WARP pool if ?dialer=pool is set
  const dialerParam = (searchParams.get("dialer") || "").trim().toLowerCase();
  if (dialerParam === "pool" || dialerParam === "auto") {
    output = output.replace(/dialer-proxy:\s*WARP\b/g, "dialer-proxy: 🌐 WARP 前置池");
  }

  // Strip amnezia-wg-option block if ?awg=0 is passed for older Mihomo cores
  const awgParam = (searchParams.get("awg") || "").trim().toLowerCase();
  if (awgParam === "0" || awgParam === "false" || awgParam === "off") {
    output = output.replace(/\n\s*amnezia-wg-option:\n(?:\s{4,}.*\n)*/g, "\n");
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
    // Utilize KV edge caching (cacheTtl: 300s) to accelerate repeated subscription fetches
    const kvOptions = noCache ? { type: "text" } : { type: "text", cacheTtl: 300 };
    const rawBody = await env.SUBSCRIPTIONS.get(key, kvOptions);
    if (!rawBody) {
      return new Response("Subscription has not been published yet", {
        status: 503,
        headers: { "Cache-Control": "no-store" },
      });
    }

    const finalBody = applyDynamicOverrides(rawBody, url.searchParams);
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
