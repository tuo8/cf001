# VPN Gate OpenVPN 筛选

数据源为 VPN Gate 官方 CSV API。解码 `OpenVPN_Config`，提取 remote/proto/CA 和可选证书、TLS key、cipher、auth、compression。只保留有 remote、port、CA 的 TCP/UDP profile，认证使用官方共享账号 vpn/vpn。

官方 Ping/Speed 只用于候选排序。Mihomo 实际启动后通过 mixed-port 做 HTTPS 延迟和下载测试；最终节点必须连续通过两次独立 5 MiB 下载精测。按实测延迟升序、下载速度降序输出。无节点通过时任务失败，不发布空配置、不覆盖旧 KV。
