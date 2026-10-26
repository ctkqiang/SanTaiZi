//go:build !darwin && !linux

package main

import (
	"fmt"
	"os"

	"santaizi/sdk"
)

var _ sdk.Module = (*WifiSecModule)(nil)

// WifiSecModule is the compile-only fallback for platforms where the POSIX
// serial termios transport is unavailable. The framework still discovers the
// module, but execution fails closed with an explicit message instead of
// pretending the ESP co-processor path is supported.
type WifiSecModule struct {
	sdk.BaseModule
}

func (m *WifiSecModule) Info() sdk.ModuleConfig {
	return sdk.ModuleConfig{
		Name:        "wifisec",
		Description: "WiFi security testing via ESP8266/ESP32 co-processor: capability negotiation, scanning, 802.11 frame injection, cross-platform native scanning.",
		Options: []sdk.Option{
			{Name: "serial_port", Type: "string", Required: true, Default: ""},
			{Name: "ssid", Type: "string", Required: false, Default: ""},
			{Name: "bssid", Type: "string", Required: false, Default: ""},
			{Name: "action", Type: "string", Required: false, Default: "scan"},
		},
	}
}

func (m *WifiSecModule) Init(options map[string]string) error {
	m.Config = options
	fmt.Fprintln(os.Stderr, "AUTHORIZED TESTING ONLY: wifisec controls an ESP co-processor and can inject 802.11 management frames. Use it only on networks you own or are explicitly authorized to test.")
	return fmt.Errorf("wifisec: the POSIX serial/termios transport is not available on this platform; build on macOS or Linux, or use the upstream wifisec binary for this host")
}

func (m *WifiSecModule) Run() (string, error) {
	return "", fmt.Errorf("wifisec: unsupported platform")
}

func main() {
	sdk.RunModule(&WifiSecModule{})
}
