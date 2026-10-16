# 订阅优选器

本功能独立于 CFST IP 测速/hosts 流程，不修改原有 hourly.yml 或 CFST 脚本。

## 配置
在 Settings → Secrets and variables → Actions 添加 repository secret `SUBSCRIPTION_URL`，值为订阅 URL。不要提交订阅链接或凭据。可选 variables：`SUBSCRIPTION_TOP_N`（默认 30）、`DOWNLOAD_TEST_URL`。

Actions → Subscription Optimizer → Run workflow 可手动运行；计划任务每 6 小时执行。

## 输出安全
Clash YAML 作为保留 1 天的 Actions artifact，不写入仓库或 GitHub Pages。Artifact 可访问性取决于仓库权限；生成配置内含代理认证信息，不要公开分享。

## 限制
支持 Clash YAML、Base64 订阅及常见 SS、VMess、VLESS、Trojan、SOCKS、HTTP、Hysteria2 URI 的常见参数。复杂 Reality、插件、SSR 或供应商私有格式可能需要扩展。真实测速要求 Mihomo；只有通过代理连通性和下载测试的节点才进入配置。地区按节点名称标签判断，并非 GeoIP 证明。parse-only 仅用于格式测试，不代表节点可用。

## 本地运行
```bash
python -m pip install -r requirements-subscription.txt
export SUBSCRIPTION_URL='实际订阅地址'
export MIHOMO_PATH=/path/to/mihomo
python scripts/subscription_optimizer.py --region SIN,NRT --sort balanced --top 30 --output /tmp/clash-mi.yaml
```
