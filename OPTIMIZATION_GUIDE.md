# `tuo8/cf001` 优化升级包使用说明

本压缩包目录结构与 [tuo8/cf001](https://github.com/tuo8/cf001) 仓库完全一致，解压后可直接覆盖上传至原 GitHub 仓库并重新部署 Cloudflare Worker。

## 一、 包含的修改文件清单与修复说明

| 文件相对路径 | 核心优化与修复内容 |
| :--- | :--- |
| `tools/warp-probe/cmd/warp-probe/main.go` | 1. **修复 `TestParseConfigAndReservedDefaults` 单元测试断言**：严格保持默认 `MTU=1280`、`keepalive=25`，确保 `go test -v ./...` 100% 通过。<br>2. **多 Endpoint 自动回退探测**：当默认 `engage.cloudflareclient.com` 解析或握手失败时，自动回退尝试备用 Anycast IP（`162.159.192.1`、`162.159.193.1` 等）。<br>3. **按实测速度排序端口**：记录每个 UDP 端口的握手与 HTTPS 响应耗时，将最快的 UDP 端口排在 `verified_ports` 首位。 |
| `scripts/vpngate_optimizer.py` | 1. **多优选 WARP Endpoint 节点池**：除主 `WARP` 节点外，自动生成基于 [Cloudflare WARP 优选 Anycast IP 段](https://gist.github.com/thanksshu/d65ef7ed5fed7049f599e7a863f197db?permalink_comment_id=5570047)（`162.159.192.1`、`162.159.193.1`、`162.159.195.1`、`188.114.96.1` 等）与多验证端口（`2408/500/1701/4500`）的备用 WARP 节点。<br>2. **亚太优先与高带宽预筛**：解析 [VPN Gate CSV](http://www.vpngate.net/cn/?mobile=2) 中的 `Speed`、`Ping`、`Score` 与地区代码，优先筛选 `JP/KR/HK/TW/SG` 的 UDP 节点。<br>3. **热隧道实测 RTT 延迟排序**：在首次握手打通后执行热隧道 ping 测速，按真实毫秒级 RTT 从低到高排序并截取 Top 30 优质节点。<br>4. **高可用代理组 (`url-test` + `fallback`)**：新增 [Mihomo 自动测速组与故障转移组](https://wiki.metacubex.one/en/config/proxy-groups/)（`⚡ 自动优选 (最快)`、`🛡️ 故障转移 (稳定)`、`🌐 WARP 前置池`），断联时毫秒级自动切换。 |
| `workers/subscription-worker.js` | 1. **URL 动态参数覆盖**：支持在订阅链接后附加 `?endpoint=优选IP:端口`、`?mtu=1380`、`?dialer=pool`（将所有 OpenVPN 节点的 `dialer-proxy` 动态切换至自动测速的 `🌐 WARP 前置池`）以及 `?awg=1`（按需注入 [Mihomo WireGuard](https://wiki.metacubex.one/en/config/proxies/wg/) 的 `amnezia-wg-option` 脉冲混淆参数）。<br>2. **Cloudflare KV 边缘缓存加速**：启用 300 秒边缘缓存（可通过 `?nocache=1` 强制刷新）与 `Profile-Update-Interval: 1` 标头。 |
| `tests/test_vpngate_optimizer.py` | 同步扩充单元测试，覆盖 CSV 元数据提取、实测延迟排序、AmneziaWG 按需启用及多策略组生成。 |
| `.github/workflows/vpngate.yml` | 提高探测并发数，并更新 YAML 结构断言以校验新增的自动测速组与故障转移组。 |

## 二、 订阅链接进阶参数用法（无需重新跑 GitHub Actions）

更新 `workers/subscription-worker.js` 到 Cloudflare Worker 后，你可以在客户端（如 Clash Mi / Clash Verge Rev / Karing）的订阅地址后直接拼接参数来解决本地网络连不上或慢的问题：

1. **开启 WARP 前置池自动切换 + 本地优选 Endpoint（强烈推荐）**：
   ```text
   https://你的自定义域名/vpngate/你的TOKEN?dialer=pool&endpoint=162.159.193.1:2408
   ```
   - `dialer=pool`：让所有 OpenVPN 节点通过 `🌐 WARP 前置池`（`url-test` 自动测速组）转发，某个 WARP IP 被阻断时自动无缝切换到其他优选 IP 或端口。
   - `endpoint=IP:PORT`：可用 [XIU2/CloudflareSpeedTest](https://github.com/XIU2/CloudflareSpeedTest) 或 [warp-endpoint-optimizer](https://github.com/Leizhenpeng/warp-endpoint-optimizer) 在本地测出延迟最低的 WARP IP:端口直接替换。
2. **开启 AmneziaWG 脉冲混淆（针对严格封锁 WireGuard UDP 的网络）**：
   ```text
   https://你的自定义域名/vpngate/你的TOKEN?dialer=pool&awg=1
   ```
