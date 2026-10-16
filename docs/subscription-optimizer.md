# 订阅优选器

本功能独立于 CFST IP 测速/hosts 流程，不修改原有 hourly.yml 或 CFST 脚本。

## 配置
在 Settings → Secrets and variables → Actions 添加 repository secret `SUBSCRIPTION_URL`，值支持单个订阅 URL，也支持多个订阅 URL **每行一个**。不要提交订阅链接或凭据。可选 variables：`SUBSCRIPTION_TOP_N`（默认 30）、`DOWNLOAD_TEST_URL`。

Actions → Subscription Optimizer → Run workflow 可手动运行；计划任务每 6 小时执行。工作流先运行解析单元测试，再下载 Mihomo 核心并逐个测试节点。

多个订阅会合并节点，并按节点配置去重；空行和以 `#` 开头的注释行会被忽略。\n\n## 输出与安全
生成的 Clash YAML 含有代理认证参数。**当前仓库为公开仓库**，因此工作流刻意跳过 artifact 上传，避免任何人下载到你的代理凭据。若要在 Actions 页面下载配置，请先在 GitHub 仓库 Settings → General → Danger Zone 中将仓库设为 **Private**，再重新运行工作流。配置不会提交到仓库，也不会发布到 GitHub Pages。私有仓库中的 artifact 默认保留 1 天，仍不要分享给无权访问的人。

## 限制
支持 Clash YAML、Base64 订阅及常见 SS、VMess、VLESS、Trojan、SOCKS、HTTP、Hysteria2 URI 的常见参数。复杂 Reality、插件、SSR 或供应商私有格式可能需要扩展。 像 `https://bestcf.pages.dev/vps789/top20.txt` 这类 `域名/IP:端口#备注` 列表是 Cloudflare 优选候选地址，不是代理订阅：它不包含 UUID、密码、协议和传输参数，不能单独转换成可用代理节点。工作流会识别并提示这种格式；若要用这类候选地址，需要另行提供基础 Clash 节点模板，并实现将候选地址写入模板的功能。真实测速要求 Mihomo；只有通过代理连通性和下载测试的节点才进入配置。地区按节点名称标签判断，并非 GeoIP 证明。parse-only 仅用于格式测试，不代表节点可用。

## 本地运行
```bash
python -m pip install -r requirements-subscription.txt
export SUBSCRIPTION_URL='https://provider-one.example/subscription\nhttps://provider-two.example/subscription'
export MIHOMO_PATH=/path/to/mihomo
python scripts/subscription_optimizer.py --region SIN,NRT --sort balanced --top 30 --output /tmp/clash-mi.yaml
```
