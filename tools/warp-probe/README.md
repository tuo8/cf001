# WARP handshake probe

This is an isolated, user-space WARP diagnostic. It does not publish a subscription
or modify the existing VPN Gate workflow.

The probe reads the existing VPNGATE_WARP_CONFIG GitHub Actions secret without
printing it. It uses the MIT-licensed MetaCubeX WireGuard-Go device and an
independently implemented UDP Bind adapter that applies the configured three-byte
WARP reserved value to outbound datagrams and strips it from inbound datagrams.

It reads last_handshake_time_sec from WireGuard UAPI and requires a nonzero value.
It then uses the AmneziaWG-Go user-space netstack to make DNS-resolved HTTPS
requests through the tunnel only. There is no host-network fallback.

The ports that pass both checks are exported as the verified_ports GitHub Actions
output. A successful probe validates the GitHub Actions runner's WARP tunnel; it
does not prove that the iPhone's Clash Mi tunnel is working.

The probe is intentionally separate from the VPN Gate publishing workflow until
its real-run behavior has been verified.
