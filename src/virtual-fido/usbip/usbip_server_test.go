package usbip

import (
	"net"
	"testing"
	"time"
)

// nullDevice is a minimal USBIPDevice; the connection-lifecycle tests never
// reach message handling, so the methods are no-ops.
type nullDevice struct{}

func (nullDevice) HandleMessage(uint32, func([]byte), uint32, []byte, []byte) {}
func (nullDevice) RemoveWaitingRequest(uint32) bool                          { return false }
func (nullDevice) BusID() string                                            { return "2-2" }
func (nullDevice) DeviceSummary() USBIPDeviceSummary                        { return USBIPDeviceSummary{} }

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
