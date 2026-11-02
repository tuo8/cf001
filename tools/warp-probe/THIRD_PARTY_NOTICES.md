# Third-party notices

The WARP probe depends on:

- MetaCubeX/wireguard-go, MIT License:
  https://github.com/MetaCubeX/wireguard-go
- AmneziaWG-Go, MIT License:
  https://github.com/amnezia-vpn/amneziawg-go

The probe does not import the GPL-3.0-licensed sing-wireguard package. Its UDP
reserved-byte adapter is independently implemented against the MIT
WireGuard-Go conn.Bind interface.
