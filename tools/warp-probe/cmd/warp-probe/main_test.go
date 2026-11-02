package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/metacubex/wireguard-go/conn"
)

func TestParseConfigAndReservedDefaults(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	raw := fmt.Sprintf("{\"private_key\":%q,\"peer_public_key\":%q,\"ipv4\":\"172.16.0.2/32\",\"port\":2408}", key, key)
	config, err := parseConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if config.ipv4.String() != "172.16.0.2" {
		t.Fatalf("unexpected local IPv4: %s", config.ipv4)
	}
	if config.reserved != defaultReserved {
		t.Fatalf("unexpected default reserved bytes: %v", config.reserved)
	}
	if config.mtu != 1280 || config.keepalive != 25 {
		t.Fatalf("unexpected defaults: MTU=%d keepalive=%d", config.mtu, config.keepalive)
	}
}

func TestParseConfigRejectsInvalidReserved(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	raw := fmt.Sprintf("{\"private_key\":%q,\"peer_public_key\":%q,\"ipv4\":\"172.16.0.2\",\"reserved\":[1,2,999]}", key, key)
	if _, err := parseConfig(raw); err == nil {
		t.Fatal("expected invalid reserved byte to be rejected")
	}
}

func TestPortCandidatesConfiguredFirstAndDeduplicated(t *testing.T) {
	config := warpConfig{port: 500}
	got := portCandidates(config)
	want := []int{500, 2408, 1701, 4500}
	if len(got) != len(want) {
		t.Fatalf("ports=%v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ports=%v, want %v", got, want)
		}
	}
}

func TestParseHandshakeTime(t *testing.T) {
	if seconds, ok := parseHandshakeTime("last_handshake_time_sec=0\n"); !ok || seconds != 0 {
		t.Fatalf("zero handshake parse = %d, %v", seconds, ok)
	}
	if seconds, ok := parseHandshakeTime("public_key=abc\nlast_handshake_time_sec=1793637000\n"); !ok || seconds != 1793637000 {
		t.Fatalf("nonzero handshake parse = %d, %v", seconds, ok)
	}
	if _, ok := parseHandshakeTime("last_handshake_time_sec=not-a-time\n"); ok {
		t.Fatal("malformed handshake time must be rejected")
	}
}

func TestReservedBindRoundTrip(t *testing.T) {
	remote, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()

	reserved := [3]byte{211, 165, 3}
	bind := newReservedBind(reserved)
	receivers, port, err := bind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer bind.Close()

	target := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)}
	incoming := []byte{1, 8, 8, 8, 9}
	if _, err := remote.WriteToUDP(incoming, target); err != nil {
		t.Fatal(err)
	}

	packets := [][]byte{make([]byte, 1500)}
	sizes := []int{0}
	endpoints := []conn.Endpoint{nil}
	count, err := receivers[0](packets, sizes, endpoints)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 || sizes[0] != len(incoming) {
		t.Fatalf("receive count=%d size=%d", count, sizes[0])
	}
	if !bytes.Equal(packets[0][:sizes[0]], []byte{1, 0, 0, 0, 9}) {
		t.Fatalf("incoming reserved bytes were not stripped: %v", packets[0][:sizes[0]])
	}

	outgoing := []byte{1, 0, 0, 0, 7}
	if err := bind.Send([][]byte{outgoing}, endpoints[0]); err != nil {
		t.Fatal(err)
	}
	if err := remote.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	n, _, err := remote.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buffer[:n], []byte{1, 211, 165, 3, 7}) {
		t.Fatalf("outgoing reserved bytes were not applied: %v", buffer[:n])
	}
}

func TestReservedHelpersIgnoreShortPackets(t *testing.T) {
	short := []byte{1, 2, 3}
	setReserved(short, [3]byte{9, 8, 7})
	clearReserved(short)
	if !bytes.Equal(short, []byte{1, 2, 3}) {
		t.Fatalf("short packet unexpectedly changed: %v", short)
	}
}
