//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"

	virtual_fido "github.com/bulwarkid/virtual-fido"
)

// runServer starts the USB/IP server for the virtual authenticator, then
// attaches it to the local virtual host controller (vhci-hcd) via usbip.
//
// No sudo: a udev rule (scripts/70-howdy-passkey-vhci.rules) grants the
// "usbip" group write access to the vhci attach/detach sysfs controls, and the
// installing user is added to that group. The whole bridge — attach included —
// runs unprivileged. The only security gate is the Howdy face check on each
// ceremony.
func runServer(client virtual_fido.FIDOClient) {
	wg := &sync.WaitGroup{}
	wg.Add(2)

	go func() {
		defer wg.Done()
		virtual_fido.Start(client) // serves USB/IP on 127.0.0.1:3240
	}()

	go func() {
		defer wg.Done()
		time.Sleep(500 * time.Millisecond) // let the server bind first
		// bus id 2-2 matches the device the library exports.
		cmd := exec.Command("usbip", "attach", "-r", "127.0.0.1", "-b", "2-2")
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "[bridge] usbip attach failed: %s\n", err)
			fmt.Fprintf(os.Stderr, "[bridge] hint: is the 'usbip' group + udev rule installed, and are you a member? (scripts/setup-env.sh)\n")
		} else {
			fmt.Fprintf(os.Stderr, "[bridge] attached — virtual authenticator is live\n")
		}
	}()

	wg.Wait()
}
