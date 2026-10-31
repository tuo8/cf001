# WARP 前置模式

生产运行链路为 `WARP WireGuard → VPN Gate OpenVPN → Internet`。每个 OpenVPN 节点都设置 `dialer-proxy: WARP`；WARP 是传输前置，VPN Gate 才是最终出口。

## GitHub Actions Secret

工作流读取仓库 Actions Secret：`VPNGATE_WARP_CONFIG`。Secret 值是 JSON 对象，字段如下：

```json
{
  "private_key": "BASE64_WIREGUARD_CLIENT_PRIVATE_KEY",
  "peer_public_key": "BASE64_CLOUDFLARE_PEER_PUBLIC_KEY",
  "ipv4": "172.16.0.2",
  "endpoint": "engage.cloudflareclient.com",
  "port": 2408,
  "mtu": 1280,
  "keepalive": 25,
  "reserved": [0, 0, 0]
}
```

`private_key` 和 `peer_public_key` 必须是 Base64 编码的 32 字节 WireGuard 密钥。`ipv4` 是接口 IPv4 地址；`endpoint`、`port`、`mtu`、`keepalive` 可省略并使用默认值。`reserved` 是可选的三字节数组，只有账户配置要求时才填写。上面的密钥和地址仅为格式示例，不能直接使用。

## 安全与发布规则

- 没有 `VPNGATE_WARP_CONFIG`、JSON 无效或密钥格式错误时，任务立即失败；不会回退到 VPN Gate 直连，也不会更新 Cloudflare KV。
- 生成的 Clash 订阅必须包含 WARP 私钥，客户端才能建立外层 WireGuard 隧道。因此订阅 URL 是敏感 bearer 凭据，不应公开分享。
- GitHub Actions/Linux 上通过 Mihomo 的验证，不等于 iOS Clash Mi 1.0.14 已兼容；仍需在 iPhone 上单独导入测试。
- Cloudflare WARP 注册接口可能变化；当前实现不承诺该非公开客户端接口永久稳定。
