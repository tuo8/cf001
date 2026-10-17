/**
 * Private Clash Mi subscription endpoint.
 *
 * Cloudflare setup:
 * - Bind the KV namespace as SUBSCRIPTIONS.
 * - Add Worker secret SUBSCRIPTION_TOKEN with a long random value.
 * - Request URL: https://<worker>.<subdomain>.workers.dev/sub/<same-token>
 */
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const parts = url.pathname.split("/").filter(Boolean);
    const expected = env.SUBSCRIPTION_TOKEN;

    // Return 404 rather than disclose whether the endpoint or secret exists.
    if (
      request.method !== "GET" ||
      parts.length !== 2 ||
      parts[0] !== "sub" ||
      !expected ||
      parts[1] !== expected
    ) {
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

    const yaml = await env.SUBSCRIPTIONS.get("clash-mi.yaml");
    if (!yaml) {
      return new Response("Subscription has not been published yet", {
        status: 503,
        headers: { "Cache-Control": "no-store" },
      });
    }

    return new Response(yaml, {
      status: 200,
      headers: {
        "Content-Type": "text/yaml; charset=utf-8",
        "Cache-Control": "no-store, max-age=0",
        "X-Content-Type-Options": "nosniff",
      },
    });
  },
};
