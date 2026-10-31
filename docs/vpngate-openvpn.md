# VPN Gate OpenVPN 筛选

数据源为 VPN Gate 官方 CSV API。每次 workflow 运行时重新拉取当前列表快照，解码 OpenVPN 配置，提取 remote/proto/CA 和可选证书、TLS key、cipher、auth、compression。只保留包含有效 remote、port、CA 的 TCP/UDP profile，认证使用官方共享账号 vpn/vpn。

筛选与更新策略：
- 以本次官网 CSV 返回的原始列表顺序处理全部解析有效节点，不使用 Ping、Speed 或延迟排序，不限制候选数量。
- Mihomo 实际启动每个候选 OpenVPN 节点，通过 mixed-port 发起 HTTPS 请求，确认真实出站连通性。
- 连通性失败的节点不写入订阅；所有连通性检查通过的节点全部写入订阅，不设 20 个或其他数量上限；失败节点不写入订阅。
- 不执行 Ping 测试、延迟测量、下载测速或大文件下载。
- 每小时 UTC 第 17 分钟重新拉取官网快照；支持手动触发。

VPN Gate 官方 CSV 未提供单个节点的最后更新时间字段，所以不能准确给节点标注或按节点更新时间排序。项目按每次获取时的最新官网快照更新；不把 Uptime 字段误当成更新时间。无节点通过时任务失败，不发布空配置、不覆盖旧 KV。全量检查耗时会随官网有效节点数量增加；GitHub Actions 当前单次运行超时为 90 分钟，超时中止时不会发布不完整结果。
