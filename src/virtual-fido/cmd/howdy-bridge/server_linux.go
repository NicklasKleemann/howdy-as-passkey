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

	// Watchdog: a detach or suspend/resume drops the vhci connection and the
	// device disappears, but the server above is still listening, so a fresh
	// `usbip attach` brings it straight back without restarting the process.
	// The loop never returns, which also keeps the process alive.
	for {
		time.Sleep(attachPollInterval)
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
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "[bridge] usbip attach failed: %s\n", err)
		fmt.Fprintf(os.Stderr, "[bridge] hint: is the 'usbip' group + udev rule installed, and are you a member? (scripts/setup-env.sh)\n")
		return
	}
	fmt.Fprintf(os.Stderr, "[bridge] attached - virtual authenticator is live\n")
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
