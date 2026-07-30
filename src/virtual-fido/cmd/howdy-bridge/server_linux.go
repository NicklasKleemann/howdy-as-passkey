//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	virtual_fido "github.com/bulwarkid/virtual-fido"
)

// attachPollInterval is how often the watchdog checks the device is still
// attached. Short enough that a suspend/resume drop is restored within seconds,
// long enough to stay invisible.
const attachPollInterval = 5 * time.Second

// runServer starts the USB/IP server for the virtual authenticator, attaches it
// to the local virtual host controller (vhci-hcd) via usbip, then keeps it
// attached for the life of the process.
//
// No sudo: a udev rule (scripts/70-howdy-passkey-vhci.rules) grants the
// "usbip" group write access to the vhci attach/detach sysfs controls, and the
// installing user is added to that group. The whole bridge - attach included -
// runs unprivileged. The only security gate is the Howdy face check on each
// ceremony.
func runServer(client virtual_fido.FIDOClient) {
	// Serve USB/IP on 127.0.0.1:3240. Start never returns under normal
	// operation; if it ever does the device is dead, so exit non-zero and let
	// systemd (Restart=on-failure) bring us back.
	go func() {
		virtual_fido.Start(client)
		fail("usbip server exited unexpectedly")
	}()

	// Let the server bind before the first attach.
	time.Sleep(500 * time.Millisecond)
	attachDevice()

	// vhci_hcd will not let the machine suspend while our device is attached,
	// so hand off to logind: detach on the way down, re-attach on the way back.
	// See sleep_linux.go.
	startSleepCoordinator()

	// Watchdog: a detach or suspend/resume drops the vhci connection and the
	// device disappears, but the server above is still listening, so a fresh
	// `usbip attach` brings it straight back without restarting the process.
	// The loop never returns, which also keeps the process alive.
	for {
		time.Sleep(attachPollInterval)
		if suspendPending() {
			// We detached on purpose and the machine is on its way down.
			// Re-attaching now would re-block the suspend.
			continue
		}
		if deviceAttached() {
			continue
		}
		fmt.Fprintf(os.Stderr, "[bridge] device not attached, re-attaching\n")
		attachDevice()
	}
}

// attachDevice attaches the virtual authenticator to the local vhci-hcd. bus id
// 2-2 matches the device the library exports.
func attachDevice() {
	cmd := exec.Command("usbip", "attach", "-r", "127.0.0.1", "-b", "2-2")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	runErr := cmd.Run()

	attached, known := waitForAttach()
	if !attachSucceeded(runErr, attached, known) {
		fmt.Fprintf(os.Stderr, "[bridge] usbip attach failed: %s\n", runErr)
		fmt.Fprintf(os.Stderr, "[bridge] hint: is the 'usbip' group + udev rule installed, and are you a member? (scripts/setup-env.sh)\n")
		return
	}
	fmt.Fprintf(os.Stderr, "[bridge] attached - virtual authenticator is live\n")
}

// attachSucceeded decides what an `usbip attach` run actually meant.
//
// A non-zero exit is not proof of failure here. After attaching the device,
// usbip calls record_connection(), which writes bookkeeping to
// /run/vhci_hcd/portNN. That path is root-owned and absent on a stock system,
// and this bridge runs unprivileged on purpose (the udev rule grants only the
// vhci attach/detach controls), so the write always fails and usbip returns 1 -
// with the device already attached and fully working. The only casualty is the
// remote-host column of `usbip port`, which is why our device renders as
// "unknown host, remote port and remote busid".
//
// So the kernel is the source of truth. attached reports what `usbip port` saw;
// if that could not be determined (known == false) the exit code is all we
// have, and we trust it.
func attachSucceeded(runErr error, attached bool, known bool) bool {
	if runErr == nil {
		return true
	}
	return known && attached
}

// The kernel publishes the imported device a short moment after usbip writes
// the vhci attach control file, so an immediate `usbip port` can still come
// back empty on a perfectly good attach. Measured at ~300ms on this hardware;
// two seconds is generous without stalling startup when an attach truly failed.
const (
	attachSettleTimeout = 2 * time.Second
	attachSettledPoll   = 100 * time.Millisecond
)

// waitForAttach polls until the kernel publishes the imported device or the
// settle timeout expires, and reports the last state it saw.
func waitForAttach() (attached bool, known bool) {
	deadline := time.Now().Add(attachSettleTimeout)
	for {
		attached, known = portState()
		if known && attached {
			return true, true
		}
		if time.Now().After(deadline) {
			return attached, known
		}
		time.Sleep(attachSettledPoll)
	}
}

// portState reports whether `usbip port` showed a device, and whether it could
// be read at all. A failure to run it leaves both false.
func portState() (attached bool, known bool) {
	out, err := exec.Command("usbip", "port").Output()
	if err != nil {
		return false, false
	}
	return anyPortInUse(string(out)), true
}

// detachAllPorts unbinds every in-use vhci port so the kernel will allow a
// suspend. This bridge is the only usbip consumer on the machine, so anything
// imported is ours to take down.
//
// Failures are logged and skipped rather than fatal: a port we cannot detach
// means this suspend attempt fails, which is no worse than the old behaviour,
// and the next resume re-attaches from a clean slate either way.
func detachAllPorts() {
	out, err := exec.Command("usbip", "port").Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[bridge] usbip port check failed before detach: %s\n", err)
		return
	}
	for _, port := range portsInUse(string(out)) {
		cmd := exec.Command("usbip", "detach", "-p", port)
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "[bridge] usbip detach -p %s failed: %s\n", port, err)
			continue
		}
		fmt.Fprintf(os.Stderr, "[bridge] detached port %s for suspend\n", port)
	}
}

// portsInUse extracts the port numbers from `usbip port` output. Imported
// devices render as "Port 00: <Port in Use> at Full Speed(12Mbps)".
func portsInUse(usbipPortOutput string) []string {
	var ports []string
	for _, line := range strings.Split(usbipPortOutput, "\n") {
		if !strings.Contains(line, "Port in Use") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "Port" {
			continue
		}
		ports = append(ports, strings.TrimSuffix(fields[1], ":"))
	}
	return ports
}

// deviceAttached reports whether a usbip device is currently imported on the
// local vhci. This bridge is the only usbip consumer on the machine, so any
// in-use port means our authenticator is live; none means it dropped and must
// be re-attached.
func deviceAttached() bool {
	out, err := exec.Command("usbip", "port").Output()
	if err != nil {
		// If we can't tell, assume still attached rather than risk a duplicate
		// attach; the next poll retries.
		fmt.Fprintf(os.Stderr, "[bridge] usbip port check failed: %s\n", err)
		return true
	}
	return anyPortInUse(string(out))
}

// anyPortInUse parses `usbip port` output. An imported device renders a
// "Port NN: <Port in Use> ..." line; an empty controller renders none.
func anyPortInUse(usbipPortOutput string) bool {
	for _, line := range strings.Split(usbipPortOutput, "\n") {
		if strings.Contains(line, "Port in Use") {
			return true
		}
	}
	return false
}
