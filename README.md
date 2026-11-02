# VPN Gate → Clash Mi

本项目自动获取 VPN Gate 官方 OpenVPN 节点，通过 Mihomo 实际验证 **WARP-only** 数据面，再逐个验证 **WARP → VPN Gate OpenVPN → HTTPS** 完整链路。仅发布完整链路检查通过的节点。

## 自动流程

1. 从 VPN Gate 官方接口 `https://www.vpngate.net/api/iphone/` 拉取最新 CSV 快照并解析有效 OpenVPN profile。
2. 从 GitHub Actions Secret `VPNGATE_WARP_CONFIG` 读取 WARP WireGuard 配置；不会使用直连作为失败回退。
3. 按配置端口优先，然后依次尝试 UDP `2408`、`500`、`1701`、`4500`。每个端口均启动只含 WARP 的独立 Mihomo 配置，并通过 HTTPS 请求验证数据面；全部失败则停止，不测试节点、不发布。
4. 对全部有效 VPN Gate 节点逐个启动 Mihomo，OpenVPN outbound 显式设置 `dialer-proxy: WARP`，通过 HTTPS 验证完整链路。
5. 对通过的节点测量延迟和下载速度；优先按综合表现排序，缺少有效测速值的节点排在已测节点之后。
6. 生成 Clash Mi YAML，包含 `WARP` WireGuard 节点、`WARP 直连测试` 独立测试组，以及 `VPN Gate 优选` OpenVPN 节点组。每个 OpenVPN 节点都经 WARP 出站。
7. Mihomo 校验 YAML 后才写入 Cloudflare KV。零节点、WARP 预检失败或 YAML 校验失败时，不覆盖上一次已发布订阅。
8. 每小时 UTC 第 17 分钟自动更新，也可在 GitHub Actions 手动运行。

## iPhone Clash Mi 验证

订阅更新后，在代理页面先选择 **WARP 直连测试** 组，再选择其中的 **WARP** 节点，单独访问 HTTPS 网站。此项用于判断 iPhone 上的 WARP 数据面是否可用。

随后切换到 **VPN Gate 优选** 组，选择一个 OpenVPN 节点，再访问 HTTPS 网站。此项验证完整的 WARP → OpenVPN 链路。

如果 WARP-only 组在 iPhone 上失败，但 CI 通过，不要先换 VPN Gate 节点；应检查 Clash Mi 内核兼容性、WireGuard reserved、UDP 网络环境和 iOS 网络权限。测试时可记录失败日志，但不要分享或公开 WARP 私钥、完整配置或订阅令牌。

## Cloudflare 设置

- Worker 文件：`workers/subscription-worker.js`
- KV binding：`SUBSCRIPTIONS`
- Worker secret：`VPNGATE_TOKEN`（新路径）或兼容旧路径的 `SUBSCRIPTION_TOKEN`
- 新订阅路径：`/vpngate/<VPNGATE_TOKEN>`
- KV key：`vpngate-clash-mi.yaml`

## GitHub Actions 设置

Settings → Secrets and variables → Actions：

- Secret `VPNGATE_WARP_CONFIG`：WARP JSON 配置（私钥只存 Secret）。
- Secret `CLOUDFLARE_API_TOKEN`：目标账户 KV 写入权限。
- Secret `CLOUDFLARE_ACCOUNT_ID`：Cloudflare Account ID。
- Variable `CLOUDFLARE_KV_NAMESPACE_ID`：KV namespace ID。

## 限制

Mihomo OpenVPN outbound 从 v1.19.25 起提供；工作流固定 v1.19.33 并校验 SHA-256。iPhone Clash Mi 内核也必须支持 WireGuard 与 OpenVPN outbound。CI 成功只证明 GitHub runner 上的链路可用，不保证每台 iPhone、每个运营商网络均可用。VPN Gate 是志愿者公共节点，可能下线或记录流量，不要用于敏感账号或重要业务。Worker 只发布 HTTPS 配置，不转发 VPN 隧道。
