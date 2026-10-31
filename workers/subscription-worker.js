/**
 * VPN Gate subscription Worker.
 * Legacy /sub/<old token> remains available; /vpngate/<new secret> serves the refreshed VPN Gate key.
 * KV binding: SUBSCRIPTIONS
 * Legacy compatibility binding: SUBSCRIPTION_TOKEN
 * New secret binding: VPNGATE_TOKEN (secret_text)
 */
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const parts = url.pathname.split("/").filter(Boolean);
    if (request.method !== "GET" || parts.length !== 2) {
      return new Response("Not found", { status: 404, headers: { "Cache-Control": "no-store" } });
    }

    let key = null;
    if (parts[0] === "sub" && env.SUBSCRIPTION_TOKEN && parts[1] === env.SUBSCRIPTION_TOKEN) {
      key = "clash-mi.yaml";
    } else if (parts[0] === "vpngate" && env.VPNGATE_TOKEN && parts[1] === env.VPNGATE_TOKEN) {
      key = "vpngate-clash-mi.yaml";
    }
    if (!key) return new Response("Not found", { status: 404, headers: { "Cache-Control": "no-store" } });
    if (!env.SUBSCRIPTIONS) return new Response("Subscription storage is not configured", { status: 503, headers: { "Cache-Control": "no-store" } });

    const body = await env.SUBSCRIPTIONS.get(key);
    if (!body) return new Response("Subscription has not been published yet", { status: 503, headers: { "Cache-Control": "no-store" } });
    return new Response(body, { status: 200, headers: {
      "Content-Type": "text/yaml; charset=utf-8",
      "Cache-Control": "no-store, max-age=0",
      "X-Content-Type-Options": "nosniff"
    }});
  }
};
