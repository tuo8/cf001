import assert from "node:assert/strict";
import worker from "../workers/subscription-worker.js";
const rawYaml = `dns:
  enable: true
proxies:
- name: WARP
  type: wireguard
  peers:
  - server: 162.159.195.1
    port: 2408
- name: Japan A
  type: openvpn
  dialer-proxy: WARP
  dns: &id002
  - 1.1.1.1
  - 8.8.8.8
- name: Japan B
  type: openvpn
  dialer-proxy: WARP
  dns: *id002
proxy-groups:
- name: 出站节点
  type: select
  proxies:
  - WARP
  - Japan A
  - Japan B
rules:
- MATCH,出站节点
`;
async function fetchSubscription(query = "") {
 const request = new Request(`https://example.test/vpngate/test-token${query}`);
 const env = { VPNGATE_TOKEN: "test-token", SUBSCRIPTIONS: { get: async (key) => { assert.equal(key, "vpngate-clash-mi.yaml"); return rawYaml; } } };
 return worker.fetch(request, env);
}
const response = await fetchSubscription("?nocache=1");
assert.equal(response.status, 200);
assert.equal(response.headers.get("content-type"), "text/yaml; charset=utf-8");
const body = await response.text();
assert.equal(body, rawYaml);
assert.equal((body.match(/&id002/g) || []).length, 1);
assert.equal((body.match(/type: openvpn/g) || []).length, 2);
const overridden = await (await fetchSubscription("?endpoint=162.159.193.1:500")).text();
assert.match(overridden, /server: 162\.159\.193\.1\n    port: 500/);
assert.equal((overridden.match(/&id002/g) || []).length, 1);
const raw = await (await fetchSubscription("?raw=1&endpoint=162.159.193.1:500")).text();
assert.equal(raw, rawYaml);
console.log("Worker subscription pass-through and endpoint tests passed.");
