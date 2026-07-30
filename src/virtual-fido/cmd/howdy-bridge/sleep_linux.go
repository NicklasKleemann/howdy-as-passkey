//go:build linux

package main

import (
	"fmt"
	"os"
	"sync"

	"github.com/godbus/dbus/v5"
)

// Suspend coordination.
//
// vhci_hcd refuses to suspend while any USB/IP port is connected: its suspend
// callback bails out with -EBUSY and the kernel logs
//
//	vhci_hcd vhci_hcd.0: We have 1 active connection. Do not suspend.
//	vhci_hcd vhci_hcd.0: PM: failed to suspend: error -16
//
// So with the authenticator attached the machine can never enter s2idle at all.
// The desktop keeps retrying on its idle timer, every attempt fails, and the
// laptop stays awake until the battery is flat.
//
// The fix: hold a logind "delay" inhibitor. When logind announces an imminent
// suspend we detach the device and drop the lock, which lets the suspend
// proceed; on resume we re-attach and re-arm.
//
// This has to be an inhibitor rather than a /usr/lib/systemd/system-sleep hook.
// systemd-sleep freezes user.slice *before* it runs those hooks, so by that
// point this process is already frozen and a hook that tries to reach the user
// session deadlocks the suspend outright. PrepareForSleep, by contrast, is
// delivered while userspace is still running.

const (
	loginService = "org.freedesktop.login1"
	loginPath    = dbus.ObjectPath("/org/freedesktop/login1")
	loginManager = "org.freedesktop.login1.Manager"
	prepareSleep = loginManager + ".PrepareForSleep"
)

var (
	sleepMu      sync.Mutex
	sleepPending bool
)

// Seams for tests: the sleep state machine is the part most likely to break,
// and exercising it must not require a system bus or a real vhci device.
var (
	detachForSuspend    = detachAllPorts
	reattachAfterResume = attachDevice
)

// suspendPending reports whether a suspend has been announced and has not yet
// completed. The attach watchdog consults this so it cannot re-attach into the
// window between our detach and the kernel actually going down - doing so would
// put the port back and block the suspend all over again.
func suspendPending() bool {
	sleepMu.Lock()
	defer sleepMu.Unlock()
	return sleepPending
}

func setSuspendPending(pending bool) {
	sleepMu.Lock()
	sleepPending = pending
	sleepMu.Unlock()
}

// startSleepCoordinator watches logind for suspend transitions for the life of
// the process.
//
// Best-effort by design: if the system bus or logind is unreachable the bridge
// still authenticates normally, the machine just cannot suspend while the
// authenticator is attached - which is exactly the behaviour before this
// existed. A broken bus must not take the authenticator down with it.
func startSleepCoordinator() {
	conn, err := dbus.SystemBus()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[bridge] suspend coordination disabled: no system bus: %s\n", err)
		return
	}

	if err := conn.AddMatchSignal(
		dbus.WithMatchInterface(loginManager),
		dbus.WithMatchMember("PrepareForSleep"),
		dbus.WithMatchObjectPath(loginPath),
	); err != nil {
		fmt.Fprintf(os.Stderr, "[bridge] suspend coordination disabled: %s\n", err)
		return
	}

	signals := make(chan *dbus.Signal, 8)
	conn.Signal(signals)

	lock := takeSleepInhibitor(conn)
	go handleSleepSignals(signals, lock, func() *os.File { return takeSleepInhibitor(conn) })
}

// handleSleepSignals drives the detach/re-attach cycle. logind emits
// PrepareForSleep(true) before suspending and PrepareForSleep(false) after
// resuming. reinhibit re-acquires the delay lock after a resume; it is a
// parameter rather than a direct call so the state machine stays testable
// without a bus connection. Returns when signals is closed.
func handleSleepSignals(signals <-chan *dbus.Signal, lock *os.File, reinhibit func() *os.File) {
	for sig := range signals {
		if sig.Name != prepareSleep || len(sig.Body) != 1 {
			continue
		}
		goingDown, ok := sig.Body[0].(bool)
		if !ok {
			continue
		}

		if goingDown {
			// Order matters: detach first, then release the lock. logind
			// proceeds the instant the last delay inhibitor is gone, so
			// dropping it early would race the detach.
			setSuspendPending(true)
			detachForSuspend()
			if lock != nil {
				lock.Close()
				lock = nil
			}
			continue
		}

		// Resumed. Re-arm the inhibitor before re-attaching, so a second
		// suspend arriving right behind this one is still covered.
		lock = reinhibit()
		setSuspendPending(false)
		reattachAfterResume()
	}
}

// takeSleepInhibitor asks logind for a delay lock on sleep and returns the file
// whose closure releases it.
//
// "delay" rather than "block": we are not trying to prevent suspend, only to
// postpone it for the few milliseconds a detach takes. logind caps this at
// InhibitDelayMaxSec (5s by default) and suspends regardless once it expires,
// so a wedged bridge can never keep the machine awake.
func takeSleepInhibitor(conn *dbus.Conn) *os.File {
	var fd dbus.UnixFD
	err := conn.Object(loginService, loginPath).Call(
		loginManager+".Inhibit", 0,
		"sleep",
		"howdy-passkey-bridge",
		"detach the virtual FIDO authenticator so vhci_hcd permits suspend",
		"delay",
	).Store(&fd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[bridge] could not take sleep inhibitor: %s\n", err)
		return nil
	}
	return os.NewFile(uintptr(fd), "logind-sleep-inhibitor")
}
