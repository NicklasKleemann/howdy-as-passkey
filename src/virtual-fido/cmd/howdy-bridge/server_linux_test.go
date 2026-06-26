//go:build linux

package main

import "testing"

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
