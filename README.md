# VPN Gate → Clash Mi

此仓库现在只负责 VPN Gate 官方 OpenVPN 节点：获取官方 CSV、解析 OpenVPN profile、用 Mihomo 实际连接和测速、生成 Clash Mi YAML，并通过 Cloudflare KV 和自有域名 HTTPS 发布。

## 自动流程
1. 从 `https://www.vpngate.net/api/iphone/` 获取官方 CSV。
2. 解码 `OpenVPN_Config`，仅接收包含 remote 与 CA 的 OpenVPN 节点。
3. 按官方 Ping/Speed 初筛，再由 Mihomo 实际连接。
4. 初筛通过后还必须连续通过两次独立 5 MiB 下载精测。
5. 延迟优先、下载速度其次；默认候选 60 个，最终保留 20 个。
6. 只写入 KV；不会把带账号信息的 YAML 提交到公开仓库或上传 artifact。

## Cloudflare 设置
- 创建 Workers KV namespace。
- 部署 `workers/subscription-worker.js`。
- Worker KV binding 名称设为 `SUBSCRIPTIONS`。
- Worker secret `SUBSCRIPTION_TOKEN` 设置为长随机字符串。
- 将自己的域名绑定到 Worker，启用 HTTPS。

## GitHub 设置
Settings → Secrets and variables → Actions:
- Secret `CLOUDFLARE_API_TOKEN`：授予目标账户 KV 写入权限。
- Secret `CLOUDFLARE_ACCOUNT_ID`：Account ID。
- Variable `CLOUDFLARE_KV_NAMESPACE_ID`：KV namespace ID。

## 运行
Actions → VPN Gate OpenVPN Optimizer → Run workflow。parse-only 只解析不测速。每天 UTC 03:41 和 15:41 自动更新。

Clash Mi 远程订阅地址：`https://你的域名/vpngate/你的SUBSCRIPTION_TOKEN`。

## 限制
Mihomo OpenVPN outbound 从 v1.19.25 起提供；工作流固定 v1.19.33 并验证 SHA-256。iPhone Clash Mi 内核也必须支持 OpenVPN outbound。VPN Gate 为志愿者公共节点，可能下线或记录流量，不要用于敏感账号或重要业务。Worker 仅发布 HTTPS 配置，不转发 VPN 隧道。无节点通过严格测试时不会覆盖上一次 KV 订阅。
