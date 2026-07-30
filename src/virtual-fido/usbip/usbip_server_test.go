package usbip

import (
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bulwarkid/virtual-fido/util"
)

// nullDevice is a minimal USBIPDevice; the connection-lifecycle tests never
// reach message handling, so the methods are no-ops.
type nullDevice struct{}

func (nullDevice) HandleMessage(uint32, func([]byte), uint32, []byte, []byte) {}
func (nullDevice) RemoveWaitingRequest(uint32) bool                           { return false }
func (nullDevice) BusID() string                                              { return "2-2" }
func (nullDevice) DeviceSummary() USBIPDeviceSummary                          { return USBIPDeviceSummary{} }

// Regression: a dropped connection (detach/EOF) must end the command loop, not
// spin re-reading a dead socket. Before the fix handleCommands recovered the
// read panic but stayed in its for-loop, burning CPU forever and never freeing
// the vhci port. The loop must now return promptly.
func TestHandleCommandsReturnsOnClosedConnection(t *testing.T) {
	server, client := net.Pipe()
	conn := newUSBIPConnection(NewUSBIPServer(nil), server)
	client.Close() // peer (kernel vhci side) drops the connection

	done := make(chan struct{})
	go func() {
		conn.handleCommands(nullDevice{})
		close(done)
	}()

	select {
	case <-done:
		// returned cleanly
	case <-time.After(2 * time.Second):
		t.Fatal("handleCommands did not return on a closed connection (spin regression)")
	}
}

// Regression: the OP_REP_DEVLIST reply holds a slice, which binary.Write cannot
// encode. util.ToBE discarded that error, so the reply went out as ZERO bytes
// and every `usbip list -r` hung forever waiting for it. The encoding must be
// non-empty and exactly the size the kernel expects.
func TestOpRepDevlistEncodesNonEmpty(t *testing.T) {
	const (
		controlHeaderLen = 8   // version u16 + command u16 + status u32
		numDevicesLen    = 4   // u32
		summaryHeaderLen = 312 // path[256] + busid[32] + 3×u32 + 3×u16 + 6×u8
		deviceIfaceLen   = 4   // class, subclass, protocol, padding
	)

	reply := newOpRepDevlist([]USBIPDevice{nullDevice{}})
	got := reply.toBytes()

	want := controlHeaderLen + numDevicesLen + summaryHeaderLen + deviceIfaceLen
	if len(got) != want {
		t.Errorf("devlist encoded to %d bytes, want %d", len(got), want)
	}
	if len(got) == 0 {
		t.Fatal("devlist encoded to zero bytes - this is the hang regression")
	}

	// The device count must actually reach the wire.
	if n := binary.BigEndian.Uint32(got[controlHeaderLen : controlHeaderLen+4]); n != 1 {
		t.Errorf("encoded NumDevices = %d, want 1", n)
	}

	// And an empty server must still emit a well-formed, non-empty reply.
	if empty := newOpRepDevlist(nil).toBytes(); len(empty) != controlHeaderLen+numDevicesLen {
		t.Errorf("empty devlist encoded to %d bytes, want %d", len(empty), controlHeaderLen+numDevicesLen)
	}
}

// The kernel's struct usbip_usb_interface is four bytes. It was three, so every
// device entry was short by one and the client mis-parsed the stream.
func TestDeviceInterfaceWireSize(t *testing.T) {
	if got := len(util.ToBE(USBIPDeviceInterface{})); got != 4 {
		t.Errorf("USBIPDeviceInterface encodes to %d bytes, want 4", got)
	}
}

// Connections are served concurrently, so a device must never be handed to two
// importers at once - they would drive the same HandleMessage /
// RemoveWaitingRequest state simultaneously.
func TestClaimDeviceIsExclusive(t *testing.T) {
	server := NewUSBIPServer([]USBIPDevice{nullDevice{}})

	if !server.claimDevice("2-2") {
		t.Fatal("first claim was refused, want granted")
	}
	if server.claimDevice("2-2") {
		t.Error("second claim was granted while the device was held, want refused")
	}
	// A different device is unaffected.
	if !server.claimDevice("3-3") {
		t.Error("claim of an unrelated device was refused, want granted")
	}

	server.releaseDevice("2-2")
	if !server.claimDevice("2-2") {
		t.Error("claim after release was refused; the device leaked")
	}
}

// The claim set is touched from every connection goroutine, so it must be
// race-free. Run with -race for this to mean anything.
func TestClaimDeviceConcurrent(t *testing.T) {
	server := NewUSBIPServer([]USBIPDevice{nullDevice{}})

	const goroutines = 50
	var granted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if server.claimDevice("2-2") {
				granted.Add(1)
			}
		}()
	}
	wg.Wait()

	if got := granted.Load(); got != 1 {
		t.Errorf("%d goroutines got the claim, want exactly 1", got)
	}
}

// A zero-value server (not built through NewUSBIPServer) must not panic on the
// nil map.
func TestClaimDeviceZeroValueServer(t *testing.T) {
	var server USBIPServer
	if !server.claimDevice("2-2") {
		t.Error("claim on a zero-value server was refused, want granted")
	}
}

// Same guarantee for the outer control loop, whose header read was previously
// unwrapped and would propagate the panic instead of returning.
func TestHandleReturnsOnClosedConnection(t *testing.T) {
	server, client := net.Pipe()
	conn := newUSBIPConnection(NewUSBIPServer(nil), server)
	client.Close()

	done := make(chan struct{})
	go func() {
		conn.handle()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handle did not return on a closed connection (spin regression)")
	}
}
