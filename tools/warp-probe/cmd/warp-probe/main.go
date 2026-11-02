package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"
	"github.com/metacubex/wireguard-go/conn"
	"github.com/metacubex/wireguard-go/device"
)

var defaultReserved = [3]byte{211, 165, 3}
var candidatePorts = []int{2408, 500, 1701, 4500}

type warpConfig struct {
	privateKey    []byte
	peerPublicKey []byte
	ipv4          netip.Addr
	endpoint      string
	port          int
	mtu           int
	keepalive     int
	reserved      [3]byte
}

func stringField(fields map[string]json.RawMessage, name string) string {
	var value string
	_ = json.Unmarshal(fields[name], &value)
	return value
}

func intField(fields map[string]json.RawMessage, name string) int {
	var value int
	_ = json.Unmarshal(fields[name], &value)
	return value
}

func parseConfig(raw string) (warpConfig, error) {
	var input map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &input); err != nil {
		return warpConfig{}, errors.New("VPNGATE_WARP_CONFIG must be valid JSON")
	}
	privateKey, err := base64.StdEncoding.Strict().DecodeString(stringField(input, "private_key"))
	if err != nil || len(privateKey) != 32 {
		return warpConfig{}, errors.New("WARP private_key must be base64-encoded 32 bytes")
	}
	peerPublicKey, err := base64.StdEncoding.Strict().DecodeString(stringField(input, "peer_public_key"))
	if err != nil || len(peerPublicKey) != 32 {
		return warpConfig{}, errors.New("WARP peer_public_key must be base64-encoded 32 bytes")
	}

	ipText := strings.TrimSpace(stringField(input, "ipv4"))
	var localIP netip.Addr
	if prefix, parseErr := netip.ParsePrefix(ipText); parseErr == nil {
		localIP = prefix.Addr()
	} else if addr, addrErr := netip.ParseAddr(ipText); addrErr == nil {
		localIP = addr
	} else {
		return warpConfig{}, errors.New("WARP ipv4 must be a valid IPv4 address or prefix")
	}
	if !localIP.Is4() {
		return warpConfig{}, errors.New("WARP ipv4 must be IPv4")
	}

	endpoint := strings.TrimSpace(stringField(input, "endpoint"))
	if endpoint == "" {
		endpoint = "engage.cloudflareclient.com"
	}
	if strings.ContainsAny(endpoint, " \t\r\n") {
		return warpConfig{}, errors.New("WARP endpoint contains whitespace")
	}

	port := intField(input, "port")
	if port == 0 {
		port = 2408
	}
	if port < 1 || port > 65535 {
		return warpConfig{}, errors.New("WARP port is outside 1..65535")
	}
	mtu := intField(input, "mtu")
	if mtu == 0 {
		mtu = 1280
	}
	if mtu < 576 || mtu > 9000 {
		return warpConfig{}, errors.New("WARP MTU is outside 576..9000")
	}
	keepalive := intField(input, "keepalive")
	if keepalive == 0 {
		keepalive = 25
	}
	if keepalive < 0 || keepalive > 65535 {
		return warpConfig{}, errors.New("WARP keepalive is outside 0..65535")
	}

	reserved := defaultReserved
	if rawReserved, exists := input["reserved"]; exists {
		if string(rawReserved) == "null" {
			reserved = [3]byte{}
		} else {
			var values []int
			if err := json.Unmarshal(rawReserved, &values); err != nil || len(values) != 3 {
				return warpConfig{}, errors.New("WARP reserved must be a three-byte integer array")
			}
			for i, value := range values {
				if value < 0 || value > 255 {
					return warpConfig{}, errors.New("WARP reserved byte is outside 0..255")
				}
				reserved[i] = byte(value)
			}
		}
	}

	return warpConfig{
		privateKey: privateKey, peerPublicKey: peerPublicKey, ipv4: localIP,
		endpoint: endpoint, port: port, mtu: mtu, keepalive: keepalive,
		reserved: reserved,
	}, nil
}

func portCandidates(config warpConfig) []int {
	seen := make(map[int]bool)
	ports := make([]int, 0, len(candidatePorts)+1)
	for _, port := range append([]int{config.port}, candidatePorts...) {
		if port > 0 && port <= 65535 && !seen[port] {
			seen[port] = true
			ports = append(ports, port)
		}
	}
	return ports
}

type wgEndpoint struct {
	addr netip.AddrPort
}

func (e *wgEndpoint) ClearSrc()           {}
func (e *wgEndpoint) SrcToString() string { return "" }
func (e *wgEndpoint) DstToString() string { return e.addr.String() }
func (e *wgEndpoint) DstIP() netip.Addr   { return e.addr.Addr() }
func (e *wgEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }
func (e *wgEndpoint) DstToBytes() []byte {
	value, _ := e.addr.MarshalBinary()
	return value
}

type reservedBind struct {
	mu       sync.RWMutex
	udp      *net.UDPConn
	reserved [3]byte
}

func newReservedBind(reserved [3]byte) *reservedBind {
	return &reservedBind{reserved: reserved}
}

func (b *reservedBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.udp != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{Port: int(port)})
	if err != nil {
		return nil, 0, err
	}
	b.udp = udp
	actualPort := uint16(udp.LocalAddr().(*net.UDPAddr).Port)
	return []conn.ReceiveFunc{b.receive}, actualPort, nil
}

func (b *reservedBind) receive(packets [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
	if len(packets) == 0 || len(sizes) == 0 || len(endpoints) == 0 {
		return 0, errors.New("WireGuard receive buffers are empty")
	}
	b.mu.RLock()
	udp := b.udp
	b.mu.RUnlock()
	if udp == nil {
		return 0, net.ErrClosed
	}
	n, remote, err := udp.ReadFromUDP(packets[0])
	if err != nil {
		return 0, err
	}
	clearReserved(packets[0][:n])
	addr := remote.AddrPort()
	if addr.Addr().Is4In6() {
		addr = netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
	}
	sizes[0] = n
	endpoints[0] = &wgEndpoint{addr: addr}
	return 1, nil
}

func (b *reservedBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.udp == nil {
		return nil
	}
	err := b.udp.Close()
	b.udp = nil
	return err
}

func (b *reservedBind) SetMark(uint32) error { return nil }

func (b *reservedBind) Send(packets [][]byte, endpoint conn.Endpoint) error {
	target, ok := endpoint.(*wgEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	b.mu.RLock()
	udp := b.udp
	b.mu.RUnlock()
	if udp == nil {
		return net.ErrClosed
	}
	for _, packet := range packets {
		out := append([]byte(nil), packet...)
		setReserved(out, b.reserved)
		if _, err := udp.WriteToUDP(out, net.UDPAddrFromAddrPort(target.addr)); err != nil {
			return err
		}
	}
	return nil
}

func (b *reservedBind) ParseEndpoint(value string) (conn.Endpoint, error) {
	addr, err := netip.ParseAddrPort(value)
	if err != nil {
		return nil, err
	}
	if addr.Addr().Is4In6() {
		addr = netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
	}
	return &wgEndpoint{addr: addr}, nil
}

func (b *reservedBind) BatchSize() int { return 1 }

func setReserved(packet []byte, reserved [3]byte) {
	if len(packet) > 3 {
		copy(packet[1:4], reserved[:])
	}
}

func clearReserved(packet []byte) {
	if len(packet) > 3 {
		packet[1], packet[2], packet[3] = 0, 0, 0
	}
}

func parseHandshakeTime(uapi string) (int64, bool) {
	for _, line := range strings.Split(uapi, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok && key == "last_handshake_time_sec" {
			seconds, err := strconv.ParseInt(value, 10, 64)
			return seconds, err == nil
		}
	}
	return 0, false
}

func parseCounter(uapi, name string) uint64 {
	for _, line := range strings.Split(uapi, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok && key == name {
			number, err := strconv.ParseUint(value, 10, 64)
			if err == nil {
				return number
			}
		}
	}
	return 0
}

func waitHandshake(ctx context.Context, wg *device.Device) (int64, error) {
	delay := 2 * time.Millisecond
	for {
		status, err := wg.IpcGet()
		if err == nil {
			if seconds, ok := parseHandshakeTime(status); ok && seconds > 0 {
				return seconds, nil
			}
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return 0, fmt.Errorf("WireGuard handshake was not confirmed before timeout: %w", ctx.Err())
		case <-timer.C:
		}
		if delay < 50*time.Millisecond {
			delay *= 2
			if delay > 50*time.Millisecond {
				delay = 50 * time.Millisecond
			}
		}
	}
}

type probeResult struct {
	port      int
	handshake int64
	url       string
	status    int
	txBytes   uint64
	rxBytes   uint64
}

func probePort(config warpConfig, port int) (probeResult, error) {
	outer, err := net.ResolveUDPAddr("udp", net.JoinHostPort(config.endpoint, strconv.Itoa(port)))
	if err != nil {
		return probeResult{}, fmt.Errorf("resolve WARP endpoint: %w", err)
	}
	outerAddr := outer.AddrPort()
	if !outerAddr.IsValid() {
		return probeResult{}, errors.New("WARP endpoint did not resolve to a valid UDP address")
	}

	tunDevice, tunnelNet, err := netstack.CreateNetTUN(
		[]netip.Addr{config.ipv4},
		[]netip.Addr{netip.MustParseAddr("1.1.1.1")},
		config.mtu,
	)
	if err != nil {
		return probeResult{}, fmt.Errorf("create user-space network stack: %w", err)
	}

	bind := newReservedBind(config.reserved)
	wg := device.NewDevice(newTUNBridge(tunDevice), bind, device.NewLogger(device.LogLevelSilent, "warp-probe"), 0)
	defer wg.Close()

	uapi := fmt.Sprintf(
		"private_key=%s\npublic_key=%s\nendpoint=%s\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=%d\n\n",
		hex.EncodeToString(config.privateKey),
		hex.EncodeToString(config.peerPublicKey),
		outerAddr.String(),
		config.keepalive,
	)
	if err := wg.IpcSet(uapi); err != nil {
		return probeResult{}, fmt.Errorf("configure WireGuard device: %w", err)
	}
	if err := wg.Up(); err != nil {
		return probeResult{}, fmt.Errorf("start WireGuard device: %w", err)
	}

	handshakeCtx, cancelHandshake := context.WithTimeout(context.Background(), 8*time.Second)
	handshake, err := waitHandshake(handshakeCtx, wg)
	cancelHandshake()
	if err != nil {
		return probeResult{}, err
	}

	url, status, err := checkHTTPS(tunnelNet)
	if err != nil {
		return probeResult{}, fmt.Errorf("handshake confirmed at %d, but HTTPS through WARP failed: %w", handshake, err)
	}
	finalStatus, err := wg.IpcGet()
	if err != nil {
		return probeResult{}, fmt.Errorf("read WireGuard transfer counters: %w", err)
	}
	return probeResult{
		port: port, handshake: handshake, url: url, status: status,
		txBytes: parseCounter(finalStatus, "tx_bytes"),
		rxBytes: parseCounter(finalStatus, "rx_bytes"),
	}, nil
}

func checkHTTPS(tunnelNet *netstack.Net) (string, int, error) {
	transport := &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			return tunnelNet.DialContext(ctx, "tcp", address)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   7 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var lastErr error
	for _, target := range []string{
		"https://cp.cloudflare.com/generate_204",
		"https://www.gstatic.com/generate_204",
	} {
		response, err := client.Get(target)
		if err != nil {
			lastErr = err
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		_ = response.Body.Close()
		if response.StatusCode == http.StatusOK || response.StatusCode == http.StatusNoContent {
			return target, response.StatusCode, nil
		}
		lastErr = fmt.Errorf("%s returned HTTP %d", target, response.StatusCode)
	}
	if lastErr == nil {
		lastErr = errors.New("no HTTPS connectivity endpoint was tested")
	}
	return "", 0, lastErr
}

func writeGitHubOutput(ports []int) error {
	path := os.Getenv("GITHUB_OUTPUT")
	if path == "" {
		return nil
	}
	values := make([]string, 0, len(ports))
	for _, port := range ports {
		values = append(values, strconv.Itoa(port))
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, writeErr := fmt.Fprintf(file, "verified_ports=%s\n", strings.Join(values, ","))
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func run() error {
	raw := os.Getenv("VPNGATE_WARP_CONFIG")
	if raw == "" {
		return errors.New("VPNGATE_WARP_CONFIG is missing; refusing to continue")
	}
	config, err := parseConfig(raw)
	if err != nil {
		return err
	}
	if override := os.Getenv("VPNGATE_WARP_PORT"); override != "" {
		port, parseErr := strconv.Atoi(override)
		if parseErr != nil || port < 1 || port > 65535 {
			return errors.New("VPNGATE_WARP_PORT must be between 1 and 65535")
		}
		config.port = port
	}

	verified := make([]int, 0, len(candidatePorts))
	for _, port := range portCandidates(config) {
		result, probeErr := probePort(config, port)
		if probeErr != nil {
			fmt.Printf("WARP probe FAIL: UDP port %d: %v\n", port, probeErr)
			continue
		}
		verified = append(verified, port)
		fmt.Printf(
			"WARP handshake PASS: UDP port %d; last_handshake_time_sec=%d; tx_bytes=%d; rx_bytes=%d\n",
			result.port, result.handshake, result.txBytes, result.rxBytes,
		)
		fmt.Printf("WARP HTTPS data-plane PASS: %s returned HTTP %d\n", result.url, result.status)
	}
	if len(verified) == 0 {
		return errors.New("no candidate UDP port passed both WireGuard handshake and in-tunnel HTTPS; refusing VPN Gate checks and publication")
	}
	values := make([]string, 0, len(verified))
	for _, port := range verified {
		values = append(values, strconv.Itoa(port))
	}
	fmt.Printf("WARP_PROBE_VERIFIED_PORTS=%s\n", strings.Join(values, ","))
	return writeGitHubOutput(verified)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
