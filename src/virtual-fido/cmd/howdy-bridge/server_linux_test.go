//go:build linux

package main

import (
	"errors"
	"strings"
	"testing"
)

func TestAnyPortInUse(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want bool
	}{
		{
			name: "empty controller",
			out:  "Imported USB devices\n====================\n",
			want: false,
		},
		{
			name: "device attached",
			out: "Imported USB devices\n" +
				"====================\n" +
				"Port 00: <Port in Use> at Full Speed(12Mbps)\n" +
				"       unknown vendor : unknown product (0000:0000)\n" +
				"       9-1 -> unknown host, remote port and remote busid\n",
			want: true,
		},
		{
			name: "empty string",
			out:  "",
			want: false,
		},
	}
	for _, c := range cases {
		if got := anyPortInUse(c.out); got != c.want {
			t.Errorf("%s: anyPortInUse = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestAttachSucceeded(t *testing.T) {
	boom := errors.New("exit status 1")
	cases := []struct {
		name     string
		runErr   error
		attached bool
		known    bool
		want     bool
	}{
		{
			name:   "clean exit",
			runErr: nil, attached: true, known: true, want: true,
		},
		{
			// The real-world case: usbip attaches the device, then exits 1
			// because it cannot write /run/vhci_hcd/portNN as a normal user.
			name:   "exit 1 but device is attached",
			runErr: boom, attached: true, known: true, want: true,
		},
		{
			// Must still be reported - this is a genuine failure.
			name:   "exit 1 and nothing attached",
			runErr: boom, attached: false, known: true, want: false,
		},
		{
			// Cannot ask the kernel, so the exit code is all we have.
			name:   "exit 1 and port state unreadable",
			runErr: boom, attached: false, known: false, want: false,
		},
		{
			name:   "clean exit even if port state unreadable",
			runErr: nil, attached: false, known: false, want: true,
		},
	}
	for _, c := range cases {
		if got := attachSucceeded(c.runErr, c.attached, c.known); got != c.want {
			t.Errorf("%s: attachSucceeded = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestPortsInUse(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want []string
	}{
		{
			name: "empty controller",
			out:  "Imported USB devices\n====================\n",
			want: nil,
		},
		{
			name: "single device",
			out: "Imported USB devices\n" +
				"====================\n" +
				"Port 00: <Port in Use> at Full Speed(12Mbps)\n" +
				"       unknown vendor : unknown product (0000:0000)\n" +
				"       9-1 -> unknown host, remote port and remote busid\n",
			want: []string{"00"},
		},
		{
			// Defensive: the bridge attaches one device, but detaching must
			// clear every port or vhci_hcd still refuses to suspend.
			name: "two devices",
			out: "Imported USB devices\n" +
				"====================\n" +
				"Port 00: <Port in Use> at Full Speed(12Mbps)\n" +
				"       9-1 -> unknown host, remote port and remote busid\n" +
				"Port 03: <Port in Use> at High Speed(480Mbps)\n" +
				"       9-2 -> unknown host, remote port and remote busid\n",
			want: []string{"00", "03"},
		},
		{
			name: "empty string",
			out:  "",
			want: nil,
		},
	}
	for _, c := range cases {
		got := portsInUse(c.out)
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: portsInUse = %v, want %v", c.name, got, c.want)
		}
	}
}
