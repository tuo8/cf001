# Cloudflare 优选 IP 自动测速与更新工具

原有 CFST 优选 IP 与 hosts 更新功能保持不变。另新增独立的代理订阅优选器：解析常见订阅格式，按真实连通性、延迟和下载速度筛选节点，输出 Clash YAML。

## 代理订阅优选器

1. 打开仓库 **Settings → Secrets and variables → Actions**，新增 repository secret `SUBSCRIPTION_URL`（完整订阅 URL）。不要把真实订阅链接或凭据提交到仓库。
2. 打开 **Actions → Subscription Optimizer → Run workflow**，可选填区域代码（如 `SIN,NRT`）及排名方式；也会每 6 小时自动运行。
3. **仓库目前是公开的**。为避免泄露代理账号密码，工作流会跳过公开仓库的配置 artifact 上传。需要下载配置时，请先将仓库改为 **Private**，再运行工作流；随后从 run 的 **Artifacts** 下载 `clash-mi-subscription-*`（保留 1 天）。

详细说明见 [`docs/subscription-optimizer.md`](docs/subscription-optimizer.md)。配置含代理认证参数，不要公开分享。

**兼容性提示：** 解析支持 Clash YAML、Base64 订阅及常见 SS/VMess/VLESS/Trojan/SOCKS/HTTP/Hysteria2 URI 的常见字段。协议扩展和供应商私有格式可能需要适配。地区筛选基于节点名称标签。真实测速需要 Mihomo 核心。

---
