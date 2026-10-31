/**
 * VPN Gate-only private subscription endpoint.
 * KV binding: SUBSCRIPTIONS. Worker secret: SUBSCRIPTION_TOKEN.
 * URL: https://your-domain.example/vpngate/<SUBSCRIPTION_TOKEN>
 */
export default {
  async fetch(request, env) {
    const p = new URL(request.url).pathname.split("/").filter(Boolean);
    if (request.method !== "GET" || p.length !== 2 || p[0] !== "vpngate" ||
        !env.SUBSCRIPTION_TOKEN || p[1] !== env.SUBSCRIPTION_TOKEN) {
      return new Response("Not found", { status: 404, headers: { "Cache-Control": "no-store" } });
    }
    if (!env.SUBSCRIPTIONS) return new Response("KV binding missing", { status: 503 });
    const body = await env.SUBSCRIPTIONS.get("vpngate-clash-mi.yaml");
    if (!body) return new Response("No tested subscription published yet", { status: 503 });
    return new Response(body, { status: 200, headers: {
      "Content-Type": "text/yaml; charset=utf-8",
      "Cache-Control": "no-store, max-age=0",
      "X-Content-Type-Options": "nosniff"
    }});
  }
};
