/**
 * Private Clash Mi subscription endpoint.
 *
 * Cloudflare setup:
 * - Bind the KV namespace as SUBSCRIPTIONS.
 * - Add Worker secret SUBSCRIPTION_TOKEN with a long random value.
 * - Clash Mi URL: https://<domain>/sub/<same-token>
 * - v2rayN URL: https://<domain>/v2rayn/<same-token>
 */
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const parts = url.pathname.split("/").filter(Boolean);
    const expected = env.SUBSCRIPTION_TOKEN;
    const keys = { sub: "clash-mi.yaml", v2rayn: "v2rayn.txt" };
    const key = parts.length === 2 && parts[1] === expected ? keys[parts[0]] : null;
    if (request.method !== "GET" || !expected || !key) {
      return new Response("Not found", { status: 404, headers: { "Cache-Control": "no-store" } });
    }

    if (!env.SUBSCRIPTIONS) {
      return new Response("Subscription storage is not configured", {
        status: 503,
        headers: { "Cache-Control": "no-store" },
      });
    }

    const yaml = await env.SUBSCRIPTIONS.get(key);
    if (!yaml) {
      return new Response("Subscription has not been published yet", {
        status: 503,
        headers: { "Cache-Control": "no-store" },
      });
    }

    return new Response(yaml, {
      status: 200,
      headers: {
        "Content-Type": key === "clash-mi.yaml" ? "text/yaml; charset=utf-8" : "text/plain; charset=utf-8",
        "Cache-Control": "no-store, max-age=0",
        "X-Content-Type-Options": "nosniff",
      },
    });
  },
};
