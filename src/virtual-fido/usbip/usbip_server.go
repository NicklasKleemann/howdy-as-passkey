package usbip

import (
	"net"
	"strings"
	"sync"
	"syscall"

	"github.com/bulwarkid/virtual-fido/util"
)

var usbipLogger = util.NewLogger("[USBIP] ", util.LogLevelTrace)
var errLogger = util.NewLogger("[ERR] ", util.LogLevelEnabled)

type USBIPServer struct {
	devices []USBIPDevice

	// Connections are served concurrently, so a device must not be importable
	// twice: two importers would drive the same HandleMessage /
	// RemoveWaitingRequest state at once. importMu guards the claim set.
	importMu sync.Mutex
	imported map[string]bool
}

func NewUSBIPServer(devices []USBIPDevice) *USBIPServer {
	server := new(USBIPServer)
	server.devices = devices
	server.imported = make(map[string]bool)
	return server
}

// claimDevice reserves a device for a single connection, reporting false if
// another connection already holds it.
func (server *USBIPServer) claimDevice(busID string) bool {
	server.importMu.Lock()
	defer server.importMu.Unlock()
	if server.imported == nil {
		server.imported = make(map[string]bool)
	}
	if server.imported[busID] {
		return false
	}
	server.imported[busID] = true
	return true
}

// releaseDevice hands a device back once its connection is finished.
func (server *USBIPServer) releaseDevice(busID string) {
	server.importMu.Lock()
	delete(server.imported, busID)
	server.importMu.Unlock()
}

func (server *USBIPServer) Start() {
	usbipLogger.Println("Starting USBIP server...")
	listener, err := net.Listen("tcp", ":3240")
	util.CheckErr(err, "Could not create listener")
	for {
		connection, err := listener.Accept()
		if err != nil {
			usbipLogger.Printf("Connection accept error: %v", err)
			continue
		}
		if !strings.HasPrefix(connection.RemoteAddr().String(), "127.0.0.1") {
			usbipLogger.Printf("Connection attempted from non-local address: %s", connection.RemoteAddr().String())
			connection.Close()
			continue
		}
		usbipConn := newUSBIPConnection(server, connection)
		// Serve each connection on its own goroutine. handle() blocks for the
		// entire lifetime of an imported device, so running it inline pinned the
		// accept loop: while the authenticator was attached, every other client
		// sat unaccepted in the TCP backlog forever. That made `usbip list -r`
		// and `usbip attach` hang instead of failing, which is actively
		// misleading when diagnosing an unrelated problem.
		go util.Try(func() {
			usbipConn.handle()
		}, func(err interface{}) {
			errLogger.Printf("%v", err)
		})
	}
}

func (server *USBIPServer) getDevice(busID string) USBIPDevice {
	var device USBIPDevice = nil
	for _, other := range server.devices {
		if other.BusID() == busID {
			device = other
			break
		}
	}
	return device
}

type usbipConnection struct {
	responseMutex *sync.Mutex
	conn          net.Conn
	server        *USBIPServer
}

func newUSBIPConnection(server *USBIPServer, conn net.Conn) *usbipConnection {
	usbipConn := new(usbipConnection)
	usbipConn.responseMutex = &sync.Mutex{}
	usbipConn.conn = conn
	usbipConn.server = server
	return usbipConn
}

func (conn *usbipConnection) handle() {
	// Always release the socket when the handler ends, so a detach or a dropped
	// peer cannot leave the vhci side holding a half-open connection.
	//
	// (Note: a port rendering as "unknown host, remote port and remote busid" in
	// `usbip port` is NOT a symptom of this. That is just usbip failing to read
	// its bookkeeping file under /run/vhci_hcd, which is root-owned and absent
	// on a stock system while this bridge runs unprivileged. It is cosmetic.)
	defer conn.conn.Close()
	for {
		// A read failure here means the peer (the kernel vhci side) dropped the
		// connection on detach/EOF. Stop reading and return instead of letting
		// the panic spin the loop on a dead socket.
		if !conn.alive(func() {
			header := util.ReadBE[usbipControlHeader](conn.conn)
			usbipLogger.Printf("[CONTROL MESSAGE] %#v\n\n", header)
			if header.Command == usbipCommandOpReqDevlist {
				reply := newOpRepDevlist(conn.server.devices)
				usbipLogger.Printf("[OP_REP_DEVLIST] %#v\n\n", reply)
				// Not util.ToBE: this reply holds a slice, which
				// binary.Write cannot encode. See toBytes.
				conn.writeResponse(reply.toBytes())
			} else if header.Command == usbipCommandOpReqImport {
				busIDData := util.Read(conn.conn, 32)
				busID := util.CStringToString(busIDData)
				device := conn.server.getDevice(busID)
				if device == nil {
					// Device not found
					reply := opRepImportError(1)
					conn.writeResponse(util.ToBE(reply))
					return
				}
				if !conn.server.claimDevice(busID) {
					// Another connection is already driving this device. Refuse
					// rather than let two importers race its message state -
					// possible now that connections are served concurrently.
					usbipLogger.Printf("Device %s already imported, refusing", busID)
					reply := opRepImportError(1)
					conn.writeResponse(util.ToBE(reply))
					return
				}
				defer conn.server.releaseDevice(busID)
				reply := newOpRepImport(device)
				usbipLogger.Printf("[OP_REP_IMPORT] %s\n\n", reply)
				conn.writeResponse(util.ToBE(reply))
				conn.handleCommands(device)
			} else {
				usbipLogger.Printf("Unknown Command Code: %d", header.Command)
			}
		}) {
			return
		}
	}
}

func (conn *usbipConnection) handleCommands(device USBIPDevice) {
	for {
		// On a dropped connection the read panics; break the loop and return
		// rather than spinning (the old behavior re-read the dead socket forever,
		// burning CPU and never freeing the port).
		if !conn.alive(func() {
			header := util.ReadBE[usbipMessageHeader](conn.conn)
			usbipLogger.Printf("[MESSAGE HEADER] %s\n\n", header)
			if header.Command == usbipCmdSubmit {
				conn.handleCommandSubmit(device, header)
			} else if header.Command == usbipCmdUnlink {
				conn.handleCommandUnlink(device, header)
			} else {
				usbipLogger.Printf("Unsupported Command: %#v\n\n", header)
			}
		}) {
			return
		}
	}
}

// alive runs fn and reports whether it completed without a panic. A panic here
// means a read/write on the connection failed (peer dropped it); the caller
// must stop looping rather than retry a dead socket.
func (conn *usbipConnection) alive(fn func()) bool {
	ok := true
	util.Try(fn, func(err interface{}) {
		errLogger.Printf("connection closed, ending handler: %v", err)
		ok = false
	})
	return ok
}

func (conn *usbipConnection) handleCommandSubmit(device USBIPDevice, header usbipMessageHeader) {
	command := util.ReadBE[usbipCommandSubmitBody](conn.conn)
	usbipLogger.Printf("[COMMAND SUBMIT] %s\n\n", command)
	transferBuffer := make([]byte, command.TransferBufferLength)
	if header.Direction == usbipDirOut && command.TransferBufferLength > 0 {
		_, err := conn.conn.Read(transferBuffer)
		util.CheckErr(err, "Could not read transfer buffer")
	}
	// Getting the reponse may not be immediate, so we need a callback
	onReturnSubmit := func(response []byte) {
		if response != nil {
			copy(transferBuffer, response)
		}
		replyHeader := header.replyHeader()
		replyBody := usbipReturnSubmitBody{
			Status:          0,
			ActualLength:    uint32(len(transferBuffer)),
			StartFrame:      0,
			NumberOfPackets: 0,
			ErrorCount:      0,
			Padding:         0,
		}
		usbipLogger.Printf("[RETURN SUBMIT] %v %#v\n\n", replyHeader, replyBody)
		reply := util.Concat(util.ToBE(replyHeader), util.ToBE(replyBody))
		if header.Direction == usbipDirIn {
			usbipLogger.Printf("[RETURN SUBMIT] DATA: %#v\n\n", transferBuffer)
			reply = append(reply, transferBuffer...)
		}
		conn.writeResponse(reply)
	}
	device.HandleMessage(header.SequenceNumber, onReturnSubmit, header.Endpoint, command.SetupBytes[:], transferBuffer)
}

func (conn *usbipConnection) handleCommandUnlink(device USBIPDevice, header usbipMessageHeader) {
	unlink := util.ReadBE[usbipCommandUnlinkBody](conn.conn)
	usbipLogger.Printf("[COMMAND UNLINK] %#v\n\n", unlink)
	var status int32
	if device.RemoveWaitingRequest(unlink.UnlinkSequenceNumber) {
		status = -int32(syscall.ECONNRESET)
	} else {
		status = -int32(syscall.ENOENT)
	}
	replyHeader := header.replyHeader()
	replyBody := usbipReturnUnlinkBody{
		Status:  status,
		Padding: [24]byte{},
	}
	reply := util.Concat(
		util.ToBE(replyHeader),
		util.ToBE(replyBody),
	)
	conn.writeResponse(reply)
}

func (conn *usbipConnection) writeResponse(data []byte) {
	conn.responseMutex.Lock()
	util.Write(conn.conn, data)
	conn.responseMutex.Unlock()
}
