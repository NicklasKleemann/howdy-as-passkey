//go:build linux

package main

import (
	"os"
	"testing"

	"github.com/godbus/dbus/v5"
)

// sleepSignal builds the PrepareForSleep signal logind emits: true just before
// suspending, false just after resuming.
func sleepSignal(goingDown bool) *dbus.Signal {
	return &dbus.Signal{
		Path: loginPath,
		Name: prepareSleep,
		Body: []any{goingDown},
	}
}

// stubSleepActions swaps the usbip-backed actions for counters and restores
// them when the test ends.
func stubSleepActions(t *testing.T, detaches, attaches *int) {
	t.Helper()
	origDetach, origAttach := detachForSuspend, reattachAfterResume
	detachForSuspend = func() { *detaches++ }
	reattachAfterResume = func() { *attaches++ }
	t.Cleanup(func() {
		detachForSuspend, reattachAfterResume = origDetach, origAttach
		setSuspendPending(false)
	})
}

// drain runs the state machine to completion over a fixed set of signals.
func drain(lock *os.File, reinhibit func() *os.File, sigs ...*dbus.Signal) {
	ch := make(chan *dbus.Signal, len(sigs))
	for _, s := range sigs {
		ch <- s
	}
	close(ch)
	handleSleepSignals(ch, lock, reinhibit)
}

func TestSleepSignalDetachesAndHoldsPending(t *testing.T) {
	var detaches, attaches int
	stubSleepActions(t, &detaches, &attaches)

	drain(nil, func() *os.File { return nil }, sleepSignal(true))

	if detaches != 1 {
		t.Errorf("detaches = %d, want 1", detaches)
	}
	if attaches != 0 {
		t.Errorf("attaches = %d, want 0 (nothing has resumed yet)", attaches)
	}
	// The watchdog must see this and skip re-attaching, otherwise the port
	// comes back and vhci_hcd refuses the suspend again.
	if !suspendPending() {
		t.Error("suspendPending = false after PrepareForSleep(true), want true")
	}
}

func TestSleepResumeReattachesAndClearsPending(t *testing.T) {
	var detaches, attaches, reinhibits int
	stubSleepActions(t, &detaches, &attaches)

	drain(nil,
		func() *os.File { reinhibits++; return nil },
		sleepSignal(true), sleepSignal(false))

	if detaches != 1 || attaches != 1 {
		t.Errorf("detaches = %d, attaches = %d, want 1 and 1", detaches, attaches)
	}
	if reinhibits != 1 {
		t.Errorf("reinhibits = %d, want 1 (lock must be re-armed for the next suspend)", reinhibits)
	}
	if suspendPending() {
		t.Error("suspendPending = true after resume, want false")
	}
}

// The delay lock must be released only after the detach, and it must actually
// be released - logind waits on it up to InhibitDelayMaxSec otherwise.
func TestSleepReleasesInhibitorAfterDetach(t *testing.T) {
	var detaches, attaches int
	stubSleepActions(t, &detaches, &attaches)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %s", err)
	}
	defer r.Close()

	var lockOpenAtDetach bool
	detachForSuspend = func() {
		detaches++
		// Writing succeeds only while the fd is still open.
		_, err := w.Write([]byte{0})
		lockOpenAtDetach = err == nil
	}

	drain(w, func() *os.File { return nil }, sleepSignal(true))

	if !lockOpenAtDetach {
		t.Error("inhibitor was released before the detach ran; logind could suspend mid-detach")
	}
	if _, err := w.Write([]byte{0}); err == nil {
		t.Error("inhibitor still open after PrepareForSleep(true); suspend would stall until the delay expires")
	}
}

func TestSleepIgnoresIrrelevantSignals(t *testing.T) {
	var detaches, attaches int
	stubSleepActions(t, &detaches, &attaches)

	drain(nil, func() *os.File { return nil },
		&dbus.Signal{Path: loginPath, Name: "org.freedesktop.login1.Manager.SessionNew", Body: []any{true}},
		&dbus.Signal{Path: loginPath, Name: prepareSleep, Body: []any{}},      // malformed: no args
		&dbus.Signal{Path: loginPath, Name: prepareSleep, Body: []any{"yes"}}, // malformed: wrong type
	)

	if detaches != 0 || attaches != 0 {
		t.Errorf("detaches = %d, attaches = %d, want 0 and 0", detaches, attaches)
	}
	if suspendPending() {
		t.Error("suspendPending = true, want false (no valid sleep signal was delivered)")
	}
}
