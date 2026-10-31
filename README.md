# VPN Gate → Clash Mi

此仓库只负责 VPN Gate 官方 OpenVPN 节点：每次运行都重新获取官网 CSV，解析 OpenVPN profile，用 Mihomo 实际检查节点连通性，生成 Clash Mi YAML，并通过 Cloudflare KV 和自有域名 HTTPS 发布。

## 自动流程
1. 每次运行时从 VPN Gate 官方接口 `https://www.vpngate.net/api/iphone/` 拉取最新列表快照。
2. 解析 OpenVPN 配置，仅接收包含 remote 与 CA 的节点。
3. 按官网当前列表的原始顺序选取候选节点，不再按 Ping、延迟或 Speed 排序。
4. 由 Mihomo 启动 OpenVPN 节点，并通过代理请求 HTTPS 检查真实出站连通性。
5. 只保留连通性检查通过的节点，默认最多保留 20 个。
6. 不进行延迟测试、下载测速或流量下载测试。
7. 每小时 UTC 第 17 分钟自动重新拉取官网列表并更新订阅；也可手动运行。
8. 只写入 KV；不会把带账号信息的 YAML 提交到公开仓库或上传 artifact。

说明：VPN Gate 官方 CSV 没有提供每个节点独立的“最后更新时间”字段。因此本项目以每次拉取时官网返回的最新列表快照为准，并每小时重新获取；不会把 Uptime 当作更新时间，也不会伪造节点更新时间。

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
Actions → VPN Gate OpenVPN Optimizer → Run workflow。parse-only 只解析，不连接和发布。每天改为每小时 UTC 第 17 分钟自动更新。

Clash Mi 远程订阅地址：`https://你的域名/vpngate/你的SUBSCRIPTION_TOKEN`。

## 限制
Mihomo OpenVPN outbound 从 v1.19.25 起提供；工作流固定 v1.19.33 并验证 SHA-256。iPhone Clash Mi 内核也必须支持 OpenVPN outbound。VPN Gate 为志愿者公共节点，可能下线或记录流量，不要用于敏感账号或重要业务。Worker 仅发布 HTTPS 配置，不转发 VPN 隧道。无节点通过连通性检查时不会覆盖上一次 KV 订阅。
