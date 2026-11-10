# `tuo8/cf001` 优化升级包使用说明

本压缩包目录结构与 [tuo8/cf001](https://github.com/tuo8/cf001) 仓库完全一致，解压后可直接覆盖上传至原 GitHub 仓库并重新部署 Cloudflare Worker。

## 一、 包含的修改文件清单

| 文件相对路径 | 核心优化内容 |
| :--- | :--- |
| `scripts/vpngate_optimizer.py` | 1. **AmneziaWG 1.0 脉冲混淆注入**：默认注入 [Mihomo WireGuard](https://wiki.metacubex.one/en/config/proxies/wg/) 支持的 `amnezia-wg-option`（`jc: 4, jmin: 40, jmax: 70` 等），绕过国内运营商对标准 WireGuard 的 UDP DPI 阻断。<br>2. **多优选 WARP Endpoint 节点池**：除主 `WARP` 节点外，自动生成基于 [Cloudflare WARP 优选 Anycast IP 段](https://gist.github.com/thanksshu/d65ef7ed5fed7049f599e7a863f197db?permalink_comment_id=5570047)（`162.159.192.1`、`162.159.193.1`、`162.159.195.1`、`188.114.96.1` 等）与多验证端口（`2408/500/1701/4500`）的备用 WARP 节点。<br>3. **亚太优先与高带宽预筛**：解析 [VPN Gate CSV](http://www.vpngate.net/cn/?mobile=2) 中的 `Speed`、`Ping`、`Score` 与地区代码，优先筛选 `JP/KR/HK/TW/SG` 且带宽 `>= 10Mbps` 的 UDP 节点，并在 `data-ciphers` 中加入 `AES-128-GCM` / `CHACHA20-POLY1305`。<br>4. **实测 RTT 延迟排序**：记录每个节点完成 HTTPS `generate_204` 的真实毫秒级 RTT，按延迟从低到高排序并截取 Top 25 优质节点。<br>5. **高可用代理组 (`url-test` + `fallback`)**：新增 [Mihomo 自动测速组与故障转移组](https://wiki.metacubex.one/en/config/proxy-groups/)（`⚡ 自动优选 (最快)`、`🛡️ 故障转移 (稳定)`、`🌐 WARP 前置池`），断联时毫秒级自动切换。 |
| `workers/subscription-worker.js` | 1. **URL 动态参数覆盖**：支持在订阅链接后附加 `?endpoint=优选IP:端口`、`?mtu=1380`、`?dialer=pool`（将所有 OpenVPN 节点的 `dialer-proxy` 动态切换至自动测速的 `🌐 WARP 前置池`）或 `?awg=0`（关闭 AmneziaWG 混淆以兼容旧客户端）。<br>2. **Cloudflare KV 边缘缓存加速**：启用 300 秒边缘缓存（可通过 `?nocache=1` 强制刷新）与 `Profile-Update-Interval: 1` 标头。 |
| `tools/warp-probe/cmd/warp-probe/main.go` | 1. **多 Endpoint 自动回退探测**：当默认 `engage.cloudflareclient.com` 解析或握手失败时，自动回退尝试备用 Anycast IP。<br>2. **按实测速度排序端口**：记录每个 UDP 端口的握手与 HTTPS 响应耗时，将最快的 UDP 端口排在 `verified_ports` 首位。 |
| `tests/test_vpngate_optimizer.py` | 同步扩充单元测试，覆盖 CSV 元数据提取、实测延迟排序、AmneziaWG 参数注入及多策略组生成。 |
| `.github/workflows/vpngate.yml` | 将探测并发数 `VPNGATE_PROBE_WORKERS` 提升至 `8`，并更新 YAML 结构断言以校验新增的自动测速组与故障转移组。 |

## 二、 订阅链接进阶参数用法（无需重新跑 GitHub Actions）

更新 `workers/subscription-worker.js` 到 Cloudflare Worker 后，你可以在客户端（如 Clash Mi / Clash Verge Rev / Karing）的订阅地址后直接拼接参数来解决本地网络连不上或慢的问题：

1. **开启 WARP 前置池自动切换 + 本地优选 Endpoint（强烈推荐）**：
   ```text
   https://你的自定义域名/vpngate/你的TOKEN?dialer=pool&endpoint=162.159.193.1:2408
   ```
   - `dialer=pool`：让所有 OpenVPN 节点通过 `🌐 WARP 前置池`（`url-test` 自动测速组）转发，某个 WARP IP 被阻断时自动无缝切换到其他优选 IP 或端口。
   - `endpoint=IP:PORT`：可用 [XIU2/CloudflareSpeedTest](https://github.com/XIU2/CloudflareSpeedTest) 或 [warp-endpoint-optimizer](https://github.com/Leizhenpeng/warp-endpoint-optimizer) 在本地测出延迟最低的 WARP IP:端口直接替换。
2. **兼容不支持 AmneziaWG 的旧版客户端**：
   ```text
   https://你的自定义域名/vpngate/你的TOKEN?awg=0
   ```
