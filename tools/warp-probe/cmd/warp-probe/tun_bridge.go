package main

import (
	"os"
	"sync"

	amneziaTun "github.com/amnezia-vpn/amneziawg-go/tun"
	wireguardTun "github.com/metacubex/wireguard-go/tun"
)

type tunBridge struct {
	base      amneziaTun.Device
	events    chan wireguardTun.Event
	done      chan struct{}
	closeOnce sync.Once
}

func newTUNBridge(base amneziaTun.Device) *tunBridge {
	bridge := &tunBridge{
		base:   base,
		events: make(chan wireguardTun.Event, 16),
		done:   make(chan struct{}),
	}
	go func() {
		defer close(bridge.events)
		source := base.Events()
		for {
			select {
			case event, ok := <-source:
				if !ok {
					return
				}
				select {
				case bridge.events <- wireguardTun.Event(event):
				case <-bridge.done:
					return
				}
			case <-bridge.done:
				return
			}
		}
	}()
	return bridge
}

func (b *tunBridge) File() *os.File { return b.base.File() }

func (b *tunBridge) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	return b.base.Read(bufs, sizes, offset)
}

func (b *tunBridge) Write(bufs [][]byte, offset int) (int, error) {
	return b.base.Write(bufs, offset)
}

func (b *tunBridge) MTU() (int, error) { return b.base.MTU() }
func (b *tunBridge) Name() (string, error) { return b.base.Name() }
func (b *tunBridge) Events() <-chan wireguardTun.Event { return b.events }

func (b *tunBridge) Close() error {
	b.closeOnce.Do(func() { close(b.done) })
	return b.base.Close()
}

func (b *tunBridge) BatchSize() int { return b.base.BatchSize() }
