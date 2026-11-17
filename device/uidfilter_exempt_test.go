package device

import (
	"net/netip"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn/bindtest"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
	"github.com/amnezia-vpn/amneziawg-go/v3/uidfilter"
)

type denyAll struct{}

func (denyAll) Allow(string, string, int, string, int) bool { return false }

// A device on a netstack tun carries a multihop inner tunnel, whose sockets the
// platform cannot name an owner for, so it must skip the uid filter.
func TestNetstackDeviceIsUIDFilterExempt(t *testing.T) {
	tunDev, _, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.0.0.2")}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	binds := bindtest.NewChannelBinds()
	dev := NewDevice(tunDev, binds[0], NewLogger(LogLevelError, ""), func(StatusCode) {})
	defer dev.Close()
	if !dev.tun.uidExempt {
		t.Error("device on a netstack tun is not uid filter exempt")
	}

	plain := NewDevice(tuntest.NewChannelTUN().TUN(), binds[1], NewLogger(LogLevelError, ""), func(StatusCode) {})
	defer plain.Close()
	if plain.tun.uidExempt {
		t.Error("device on a plain tun is uid filter exempt")
	}
}

// With a filter that denies everything, packets read from the tun are dropped,
// unless the device is exempt.
func TestUIDFilterExemptDeviceSkipsGate(t *testing.T) {
	if !uidfilter.Supported {
		t.Skip("the uid filter gate is compiled out off Android")
	}
	goroutineLeakCheck(t)
	uidfilter.Set(denyAll{})
	t.Cleanup(func() { uidfilter.Set(nil) })

	pair := genTestPair(t, true)
	msg := tuntest.Ping(pair[0].ip, pair[1].ip)

	pair[1].tun.Outbound <- msg
	select {
	case <-pair[0].tun.Inbound:
		t.Fatal("packet passed a deny-all filter")
	case <-time.After(time.Second):
	}

	// The tun reader reads the flag only after the next packet arrives on the
	// channel, so the send below orders this write before that read.
	pair[1].dev.tun.uidExempt = true
	pair[1].tun.Outbound <- msg
	select {
	case got := <-pair[0].tun.Inbound:
		if string(got) != string(msg) {
			t.Error("exempt packet did not transit correctly")
		}
	case <-time.After(6 * time.Second):
		t.Error("exempt device did not skip the filter")
	}
}
