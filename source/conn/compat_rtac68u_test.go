//go:build rtac68u

package conn

import (
	"bytes"
	"net/netip"
	"testing"
	"time"
)

// Exercise the actual non-batch socket path in both directions, including
// replying to the endpoint created from a received packet's control messages.
func TestRTAC68UUDPExchange(t *testing.T) {
	a := NewStdNetBind().(*StdNetBind)
	b := NewStdNetBind().(*StdNetBind)
	af, _, err := a.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	bf, port, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if a.BatchSize() != 1 || b.BatchSize() != 1 {
		t.Fatal("legacy sockets must advertise a single packet")
	}
	if a.ipv4PC != nil || b.ipv4PC != nil || a.ipv4TxOffload || b.ipv4RxOffload {
		t.Fatal("legacy sockets must not use batch I/O or offload")
	}
	a.ipv4.SetReadDeadline(time.Now().Add(5 * time.Second))
	b.ipv4.SetReadDeadline(time.Now().Add(5 * time.Second))
	ep := &StdNetEndpoint{AddrPort: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)}
	receive := func(fn ReceiveFunc, want []byte) Endpoint {
		t.Helper()
		bufs := [][]byte{make([]byte, 2048)}
		sizes := make([]int, 1)
		eps := make([]Endpoint, 1)
		n, err := fn(bufs, sizes, eps)
		if err != nil {
			t.Fatal(err)
		}
		if n != 1 || !bytes.Equal(bufs[0][:sizes[0]], want) {
			t.Fatalf("UDP payload mismatch: packets=%d sizes=%v", n, sizes)
		}
		return eps[0]
	}
	for _, size := range []int{1, 148, 1420} {
		payload := bytes.Repeat([]byte{byte(size)}, size)
		if err := a.Send([][]byte{payload}, ep); err != nil {
			t.Fatal(err)
		}
		replyTo := receive(bf[0], payload)
		if err := b.Send([][]byte{payload}, replyTo); err != nil {
			t.Fatal(err)
		}
		receive(af[0], payload)
	}
}
