// Package main implements the SanTaiZi "vecmap" module.
//
// vecmap is a read-only attack-surface assessment for vector databases. This
// module ports the adapter registry, fingerprinting, schema enumeration,
// bounded record sampling, CVE correlation and ATT&CK reporting from
// github.com/ctkqiang/vecmap without its CLI, TUI or SaaS dependencies.
//
// The read-only iron rule is enforced on every request: only GET/HEAD/OPTIONS
// and read-only POST are allowed, and destructive paths are rejected before a
// socket is opened. Evidence is written to a local SQLite database in WAL
// journal mode using a small pure-Go writer, so the module needs no SQLite
// driver, no CGO and no network dependency beyond the target.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
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
	vecmapName       = "vecmap"
	vecmapUserAgent  = "SanTaiZi-vecmap/1.0 (authorized read-only assessment)"
	vecmapMaxBody    = 1 << 20
	vecmapMaxColls   = 10
	vecmapMaxRecords = 5
	vecmapMaxBudget  = 64
)

var (
	_ sdk.Module = (*VecmapModule)(nil)

	vecVersionRE = regexp.MustCompile(`\d+(?:\.\d+){1,3}`)
	vecStringRE  = regexp.MustCompile(`[A-Za-z0-9_.:/\-]{6,}`)
)

// VecmapModule implements sdk.Module.
type VecmapModule struct {
	sdk.BaseModule
}

// Info advertises the module to the SanTaiZi registry.
func (m *VecmapModule) Info() sdk.ModuleConfig {
	return sdk.ModuleConfig{
		Name:        vecmapName,
		Description: "Vector database attack-surface assessment: fingerprinting, gRPC/REST read-only probing, schema enumeration, bounded record extraction, CVE association, MITRE ATT&CK reporting.",
		CNVD:        "",
		CVE:         "CVE-2024-3829, CVE-2025-64513, CVE-2025-67818, CVE-2026-11500, CVE-2026-25628, CVE-2026-26190, CVE-2026-45829, CVE-2026-69111, CVE-2026-92782",
		Options: []sdk.Option{
			{Name: "target", Type: "string", Required: true, Default: ""},
			{Name: "adapter", Type: "string", Required: false, Default: "auto"},
			{Name: "deep", Type: "bool", Required: false, Default: "false"},
			{Name: "evidence_dir", Type: "string", Required: false, Default: "."},
		},
	}
}

// Init applies defaults and validates configuration before any network I/O.
func (m *VecmapModule) Init(options map[string]string) error {
	m.Config = map[string]string{
		"target":       "",
		"adapter":      "auto",
		"deep":         "false",
		"evidence_dir": ".",
	}
	for key, value := range options {
		m.Config[key] = value
	}

	fmt.Fprintln(os.Stderr, "AUTHORIZED TESTING ONLY: vecmap performs read-only fingerprinting and bounded schema/record sampling against vector databases. Confirm written authorization and scope before running. Destructive paths are hard-denied.")

	target := strings.TrimSpace(m.GetOption("target"))
	if target == "" {
		return fmt.Errorf("vecmap: option \"target\" is required")
	}
	if _, err := parseVecTargets(target); err != nil {
		return err
	}

	adapter := strings.ToLower(strings.TrimSpace(m.GetOption("adapter")))
	if adapter == "" {
		adapter = "auto"
	}
	if !validVecAdapter(adapter) {
		return fmt.Errorf("vecmap: unknown adapter %q (use auto, qdrant, milvus, weaviate, chroma, redis, elasticsearch, opensearch, pgvector, typesense, pinecone or vespa)", adapter)
	}
	m.Config["adapter"] = adapter

	dir := strings.TrimSpace(m.GetOption("evidence_dir"))
	if dir == "" {
		dir = "."
	}
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("vecmap: resolve evidence_dir: %w", err)
	}
	if err := os.MkdirAll(absolute, 0o700); err != nil {
		return fmt.Errorf("vecmap: create evidence_dir: %w", err)
	}
	m.Config["evidence_dir"] = absolute

	return nil
}

// Run scans the target and returns a structured assessment.
func (m *VecmapModule) Run() (string, error) {
	raw := strings.TrimSpace(m.GetOption("target"))
	adapter := strings.ToLower(strings.TrimSpace(m.GetOption("adapter")))
	if adapter == "" {
		adapter = "auto"
	}
	deep := parseVecBool(m.GetOption("deep"))
	evidenceDir := m.GetOption("evidence_dir")

	targets, err := parseVecTargets(raw)
	if err != nil {
		return "", err
	}
	if len(targets) == 0 {
		return "", fmt.Errorf("vecmap: no target could be parsed")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()

	var (
		results  []vecResult
		evidence []vecEvidence
	)

	for _, target := range targets {
		scan := newVecScan(target, adapter, deep)
		result := scan.scan(ctx)
		results = append(results, result)
		evidence = append(evidence, scan.evidence...)
		// A CIDR is a bounded sweep; stop at the first identified vendor so a
		// /24 cannot turn into an unbounded internet scan.
		if len(targets) > 1 && result.vendor != "" {
			break
		}
	}

	path, writeErr := writeVecEvidence(evidenceDir, evidence)
	report := renderVecmapReport(raw, adapter, deep, results, path, writeErr)

	return report, nil
}

// ---------------------------------------------------------------------------
// Targets
// ---------------------------------------------------------------------------

type vecTarget struct {
	raw          string
	scheme       string
	host         string
	port         int
	path         string
	baseURL      string
	explicitPort bool
}

func parseVecTargets(raw string) ([]vecTarget, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("vecmap: empty target")
	}
	if _, network, err := net.ParseCIDR(raw); err == nil {
		return expandVecCIDR(raw, network)
	}

	target, err := parseVecTarget(raw)
	if err != nil {
		return nil, err
	}
	return []vecTarget{target}, nil
}

func parseVecTarget(raw string) (vecTarget, error) {
	original := raw
	if !strings.Contains(raw, "://") {
		if host, port, err := net.SplitHostPort(raw); err == nil {
			raw = "http://" + net.JoinHostPort(host, port)
		} else if strings.Count(raw, ":") > 1 {
			raw = "http://[" + strings.Trim(raw, "[]") + "]"
		} else {
			raw = "http://" + raw
		}
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return vecTarget{}, fmt.Errorf("vecmap: parse target %q: %w", original, err)
	}
	if parsed.User != nil {
		return vecTarget{}, fmt.Errorf("vecmap: credentials in the target URL are not supported; keep credentials out of evidence")
	}
	switch parsed.Scheme {
	case "http", "https", "grpc", "redis", "rediss", "postgres", "postgresql":
	default:
		return vecTarget{}, fmt.Errorf("vecmap: unsupported target scheme %q (http, https, grpc, redis, postgres)", parsed.Scheme)
	}
	if parsed.Hostname() == "" {
		return vecTarget{}, fmt.Errorf("vecmap: target %q has no host", original)
	}

	explicitPort := parsed.Port() != ""
	port := 0
	if value := parsed.Port(); value != "" {
		port, err = strconv.Atoi(value)
		if err != nil || port < 1 || port > 65535 {
			return vecTarget{}, fmt.Errorf("vecmap: invalid port %q", value)
		}
	}

	scheme := parsed.Scheme
	if scheme == "postgresql" {
		scheme = "postgres"
	}
	defaultPort := vecDefaultPort(scheme)
	if port == 0 {
		port = defaultPort
	}

	targetPath := strings.TrimRight(parsed.EscapedPath(), "/")
	if targetPath == "/" {
		targetPath = ""
	}
	base := scheme + "://" + net.JoinHostPort(parsed.Hostname(), strconv.Itoa(port)) + targetPath

	return vecTarget{
		raw:          parsed.String(),
		scheme:       scheme,
		host:         parsed.Hostname(),
		port:         port,
		path:         targetPath,
		baseURL:      base,
		explicitPort: explicitPort,
	}, nil
}

func vecDefaultPort(scheme string) int {
	switch scheme {
	case "https":
		return 443
	case "rediss":
		return 6380
	case "redis":
		return 6379
	case "postgres":
		return 5432
	case "grpc":
		return 19530
	default:
		return 80
	}
}

func expandVecCIDR(raw string, network *net.IPNet) ([]vecTarget, error) {
	ip := network.IP.Mask(network.Mask)
	ones, bits := network.Mask.Size()
	if bits == 0 {
		return nil, fmt.Errorf("vecmap: unsupported CIDR %q", raw)
	}
	hostBits := bits - ones
	if hostBits > 12 {
		return nil, fmt.Errorf("vecmap: CIDR %q is too large for a bounded module scan; use a /20 or narrower scope or a single target", raw)
	}

	targets := make([]vecTarget, 0, 8)
	for i := 0; i < 1<<hostBits && len(targets) < 8; i++ {
		candidate := make(net.IP, len(ip))
		copy(candidate, ip)
		for bit := 0; bit < hostBits; bit++ {
			if i&(1<<bit) != 0 {
				index := len(candidate) - 1 - bit/8
				candidate[index] |= 1 << (bit % 8)
			}
		}
		if bits == 32 && hostBits >= 2 {
			if i == 0 || i == (1<<hostBits)-1 {
				continue
			}
		}
		port := vecDefaultPort("http")
		targets = append(targets, vecTarget{
			raw:          candidate.String(),
			scheme:       "http",
			host:         candidate.String(),
			port:         port,
			baseURL:      "http://" + net.JoinHostPort(candidate.String(), strconv.Itoa(port)),
			explicitPort: false,
		})
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("vecmap: CIDR %q yielded no usable host", raw)
	}
	return targets, nil
}

// ---------------------------------------------------------------------------
// Vendor registry and probe catalog
// ---------------------------------------------------------------------------

type vecVendor struct {
	id      string
	display string
	ports   []int
	grpc    int
}

var vecVendors = []vecVendor{
	{id: "qdrant", display: "Qdrant", ports: []int{6333}, grpc: 6334},
	{id: "milvus", display: "Milvus", ports: []int{19530, 9091}, grpc: 19530},
	{id: "weaviate", display: "Weaviate", ports: []int{8080}, grpc: 50051},
	{id: "chroma", display: "Chroma", ports: []int{8000}},
	{id: "redis", display: "Redis / RediSearch", ports: []int{6379, 6380}},
	{id: "elasticsearch", display: "Elasticsearch", ports: []int{9200}},
	{id: "opensearch", display: "OpenSearch", ports: []int{9200}},
	{id: "pgvector", display: "PostgreSQL + pgvector", ports: []int{5432}},
	{id: "typesense", display: "Typesense", ports: []int{8108}},
	{id: "pinecone", display: "Pinecone", ports: []int{443}},
	{id: "vespa", display: "Vespa", ports: []int{8080, 19071}},
}

func validVecAdapter(adapter string) bool {
	if adapter == "auto" {
		return true
	}
	for _, vendor := range vecVendors {
		if vendor.id == adapter {
			return true
		}
	}
	return false
}

func vecVendorByID(id string) (vecVendor, bool) {
	for _, vendor := range vecVendors {
		if vendor.id == id {
			return vendor, true
		}
	}
	return vecVendor{}, false
}

type vecProbeSpec struct {
	method string
	path   string
	body   any
}

type vecCandidate struct {
	vendor  string
	scheme  string
	port    int
	baseURL string
	probes  []vecProbeSpec
}

func vecFingerprintSpecs(vendor string) []vecProbeSpec {
	switch vendor {
	case "qdrant":
		return []vecProbeSpec{
			{method: http.MethodGet, path: "/"},
			{method: http.MethodGet, path: "/collections"},
			{method: http.MethodGet, path: "/healthz"},
		}
	case "weaviate":
		return []vecProbeSpec{
			{method: http.MethodGet, path: "/v1/meta"},
			{method: http.MethodGet, path: "/v1/.well-known/ready"},
		}
	case "chroma":
		return []vecProbeSpec{
			{method: http.MethodGet, path: "/api/v1/heartbeat"},
			{method: http.MethodGet, path: "/api/v1/version"},
		}
	case "milvus":
		return []vecProbeSpec{
			{method: http.MethodGet, path: "/healthz"},
			{method: http.MethodPost, path: "/v2/vectordb/collections/list", body: map[string]any{"dbName": "default"}},
		}
	case "elasticsearch", "opensearch":
		return []vecProbeSpec{{method: http.MethodGet, path: "/"}}
	case "typesense":
		return []vecProbeSpec{
			{method: http.MethodGet, path: "/health"},
			{method: http.MethodGet, path: "/debug"},
			{method: http.MethodGet, path: "/collections"},
		}
	case "pinecone":
		return []vecProbeSpec{{method: http.MethodGet, path: "/"}}
	case "vespa":
		return []vecProbeSpec{
			{method: http.MethodGet, path: "/state/v1/version"},
			{method: http.MethodGet, path: "/state/v1/health"},
		}
	case "redis":
		return nil
	case "pgvector":
		return nil
	default:
		return []vecProbeSpec{{method: http.MethodGet, path: "/"}}
	}
}

func buildVecCandidates(target vecTarget, adapter string) []vecCandidate {
	var candidates []vecCandidate
	add := func(vendor vecVendor, scheme string, port int) {
		if port <= 0 {
			return
		}
		base := scheme + "://" + net.JoinHostPort(target.host, strconv.Itoa(port)) + target.path
		for _, existing := range candidates {
			if existing.vendor == vendor.id && existing.port == port {
				return
			}
		}
		candidates = append(candidates, vecCandidate{
			vendor:  vendor.id,
			scheme:  scheme,
			port:    port,
			baseURL: base,
			probes:  vecFingerprintSpecs(vendor.id),
		})
	}

	if adapter != "auto" {
		vendor, _ := vecVendorByID(adapter)
		if target.explicitPort {
			add(vendor, vecCandidateScheme(target, adapter, target.port), target.port)
		} else {
			for _, port := range vendor.ports {
				add(vendor, vecCandidateScheme(target, adapter, port), port)
			}
		}
		return candidates
	}

	if target.scheme == "redis" || target.scheme == "rediss" {
		vendor, _ := vecVendorByID("redis")
		add(vendor, target.scheme, target.port)
		return candidates
	}
	if target.scheme == "postgres" {
		vendor, _ := vecVendorByID("pgvector")
		add(vendor, "postgres", target.port)
		return candidates
	}
	if target.scheme == "grpc" {
		for _, id := range []string{"milvus", "qdrant", "weaviate"} {
			vendor, _ := vecVendorByID(id)
			add(vendor, "grpc", target.port)
		}
		return candidates
	}

	for _, vendor := range vecVendors {
		if vendor.id == "pgvector" || vendor.id == "redis" {
			continue
		}
		ports := vendor.ports
		if target.explicitPort {
			ports = []int{target.port}
		}
		for _, port := range ports {
			add(vendor, vecSchemeForPort(target, port), port)
		}
	}

	if !target.explicitPort || target.port == 6379 || target.port == 6380 {
		vendor, _ := vecVendorByID("redis")
		add(vendor, "redis", 6379)
	}
	if !target.explicitPort || target.port == 5432 {
		vendor, _ := vecVendorByID("pgvector")
		add(vendor, "postgres", 5432)
	}

	return candidates
}

func vecCandidateScheme(target vecTarget, adapter string, port int) string {
	switch adapter {
	case "redis":
		if target.scheme == "rediss" {
			return "rediss"
		}
		return "redis"
	case "pgvector":
		return "postgres"
	case "grpc":
		return "grpc"
	default:
		return vecSchemeForPort(target, port)
	}
}

func vecSchemeForPort(target vecTarget, port int) string {
	if port == 443 {
		return "https"
	}
	if target.scheme == "https" && target.explicitPort && port == target.port {
		return "https"
	}
	return "http"
}

// ---------------------------------------------------------------------------
// HTTP evidence chain
// ---------------------------------------------------------------------------

type vecScan struct {
	target   vecTarget
	adapter  string
	deep     bool
	client   *http.Client
	evidence []vecEvidence
	budget   int
	auxCount int
	blocked  int
}

type vecResponse struct {
	method  string
	url     string
	status  int
	header  http.Header
	body    []byte
	err     error
	elapsed time.Duration
}

type vecEvidence struct {
	ts     string
	phase  string
	method string
	path   string
	status int
	detail string
}

func newVecScan(target vecTarget, adapter string, deep bool) *vecScan {
	return &vecScan{
		target:  target,
		adapter: adapter,
		deep:    deep,
		client: &http.Client{
			Timeout: 8 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
	}
}

func (s *vecScan) record(phase, method, rawURL string, status int, detail string) {
	s.evidence = append(s.evidence, vecEvidence{
		ts:     time.Now().UTC().Format(time.RFC3339),
		phase:  phase,
		method: method,
		path:   sanitizeVecText(redactVecURL(rawURL), 300),
		status: status,
		detail: sanitizeVecText(detail, 300),
	})
}

func (s *vecScan) do(ctx context.Context, phase, method, rawURL string, body any, extra map[string]string) *vecResponse {
	method = strings.ToUpper(strings.TrimSpace(method))
	response := &vecResponse{method: method, url: rawURL}

	if vecDestructivePath(rawURL) {
		s.blocked++
		response.err = fmt.Errorf("read-only guard rejected destructive path")
		s.record(phase, method, rawURL, 0, "BLOCKED by read-only guard: "+response.err.Error())
		return response
	}
	if !vecReadOnlyMethod(method) {
		s.blocked++
		response.err = fmt.Errorf("read-only guard rejected method %s", method)
		s.record(phase, method, rawURL, 0, "BLOCKED by read-only guard: "+response.err.Error())
		return response
	}
	if s.budget >= vecmapMaxBudget {
		response.err = fmt.Errorf("request budget exhausted")
		s.record(phase, method, rawURL, 0, "request budget exhausted")
		return response
	}
	s.budget++

	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			response.err = fmt.Errorf("encode request body: %w", err)
			s.record(phase, method, rawURL, 0, response.err.Error())
			return response
		}
	}

	request, err := http.NewRequestWithContext(ctx, method, rawURL, bytes.NewReader(payload))
	if err != nil {
		response.err = err
		s.record(phase, method, rawURL, 0, "request build error: "+err.Error())
		return response
	}
	request.Header.Set("User-Agent", vecmapUserAgent)
	request.Header.Set("Accept", "application/json, text/plain;q=0.9, */*;q=0.8")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	for key, value := range extra {
		request.Header.Set(key, value)
	}

	started := time.Now()
	httpResponse, err := s.client.Do(request)
	response.elapsed = time.Since(started)
	if err != nil {
		response.err = err
		s.record(phase, method, rawURL, 0, "network error: "+err.Error())
		return response
	}
	defer func() {
		_ = httpResponse.Body.Close()
	}()

	response.status = httpResponse.StatusCode
	response.header = httpResponse.Header.Clone()
	data, readErr := io.ReadAll(io.LimitReader(httpResponse.Body, vecmapMaxBody+1))
	if readErr != nil {
		response.err = readErr
		s.record(phase, method, rawURL, response.status, "read error: "+readErr.Error())
		return response
	}
	if len(data) > vecmapMaxBody {
		data = data[:vecmapMaxBody]
	}
	response.body = data

	summary := fmt.Sprintf("HTTP %d %s %s (%d bytes, %d ms)", response.status, method, redactVecURL(rawURL), len(data), response.elapsed.Milliseconds())
	s.record(phase, method, rawURL, response.status, summary)
	return response
}

var vecDestructiveTokens = []string{
	"/management/stop",
	"/delete",
	"/drop",
	"/truncate",
	"/recover",
	"/restore",
	"/snapshots/create",
	"/snapshot/create",
	"/snapshot/upload",
	"/compact",
	"/flush",
	"/optimize",
	"/shutdown",
	"/reset",
	"/upsert",
	"/insert",
	"/update",
	"/write",
	"_delete_by_query",
}

func vecDestructivePath(rawURL string) bool {
	path := rawURL
	if parsed, err := url.Parse(rawURL); err == nil {
		path = parsed.EscapedPath() + "?" + parsed.RawQuery
	}
	lower := strings.ToLower(path)
	for _, token := range vecDestructiveTokens {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}

func vecReadOnlyMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodPost:
		return true
	default:
		return false
	}
}

func redactVecURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	parsed.User = nil
	query := parsed.Query()
	for key := range query {
		lower := strings.ToLower(key)
		if strings.Contains(lower, "key") || strings.Contains(lower, "token") || strings.Contains(lower, "secret") || strings.Contains(lower, "password") {
			query.Set(key, "REDACTED")
		}
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

// ---------------------------------------------------------------------------
// Scan orchestration
// ---------------------------------------------------------------------------

type vecCollection struct {
	Name         string
	Count        int64
	Dimension    int
	Metric       string
	IndexType    string
	Fields       []string
	Sampled      int
	SampleKeys   []string
	namespace    string
	collectionID string
}

type vecResult struct {
	target       vecTarget
	vendor       string
	version      string
	confidence   string
	collections  []vecCollection
	cves         []vecCVE
	grpc         vecGRPCResult
	pg           vecPGResult
	exposed      bool
	authRequired bool
	errors       []string
	attempts     int
	blocked      int
}

func (s *vecScan) scan(ctx context.Context) vecResult {
	result := vecResult{target: s.target}

	if s.target.scheme == "grpc" {
		result.vendor = s.adapter
		if result.vendor == "auto" {
			switch s.target.port {
			case 6334:
				result.vendor = "qdrant"
			case 50051:
				result.vendor = "weaviate"
			case 19530:
				result.vendor = "milvus"
			}
		}
		if result.vendor == "" || result.vendor == "auto" {
			result.vendor = ""
			result.errors = append(result.errors, "gRPC target did not match a known vendor port; no HTTP enumeration is possible on a grpc:// URL")
			result.attempts = s.budget + s.auxCount
			return result
		}
		result.confidence = "low (gRPC endpoint inferred from port; reflection is best-effort)"
		s.auxCount++
		result.grpc = probeVecGRPC(ctx, s.target.host, s.target.port, false)
		s.record("grpc", "REFLECT", net.JoinHostPort(s.target.host, strconv.Itoa(s.target.port)), 0, result.grpc.detail)
		result.attempts = s.budget + s.auxCount
		result.blocked = s.blocked
		return result
	}

	candidates := buildVecCandidates(s.target, s.adapter)
	bestScore := 0
	var best vecCandidate
	var bestVersion string
	var bestEvidence []string

	for _, candidate := range candidates {
		if ctx.Err() != nil {
			break
		}
		score, version, evidence := s.fingerprint(ctx, candidate)
		if score > bestScore {
			bestScore = score
			best = candidate
			bestVersion = version
			bestEvidence = evidence
		}
	}

	if bestScore >= 40 {
		result.vendor = best.vendor
		result.version = bestVersion
		result.confidence = vecConfidence(bestScore)
		s.target.baseURL = best.baseURL
		s.target.port = best.port
		s.target.scheme = best.scheme
		if len(bestEvidence) > 0 {
			s.record("fingerprint", "SUMMARY", best.baseURL, 200, strings.Join(bestEvidence, "; "))
		}
	} else if s.adapter != "auto" {
		result.vendor = s.adapter
		result.confidence = "low (adapter forced; fingerprint inconclusive)"
		result.errors = append(result.errors, "fingerprint did not confirm the selected adapter; enumeration is best-effort")
		if len(candidates) > 0 {
			s.target.baseURL = candidates[0].baseURL
			s.target.port = candidates[0].port
			s.target.scheme = candidates[0].scheme
		}
	} else {
		result.errors = append(result.errors, "no vector-database fingerprint matched the read-only probe catalog")
		result.attempts = s.budget + s.auxCount
		result.blocked = s.blocked
		return result
	}

	if s.target.scheme != "grpc" {
		if s.deep || result.vendor == "qdrant" || result.vendor == "weaviate" || result.vendor == "chroma" ||
			result.vendor == "elasticsearch" || result.vendor == "opensearch" || result.vendor == "typesense" ||
			result.vendor == "milvus" || result.vendor == "redis" || result.vendor == "vespa" || result.vendor == "pinecone" ||
			result.vendor == "pgvector" {
			s.enumerate(ctx, &result)
		}
	}

	if vendor, ok := vecVendorByID(result.vendor); ok {
		if grpcPort := vecGRPCPort(vendor, s.target); grpcPort > 0 {
			s.auxCount++
			grpcTLS := s.target.scheme == "https"
			result.grpc = probeVecGRPC(ctx, s.target.host, grpcPort, grpcTLS)
			if grpcTLS && !result.grpc.reachable {
				s.auxCount++
				result.grpc = probeVecGRPC(ctx, s.target.host, grpcPort, false)
			}
			s.record("grpc", "REFLECT", net.JoinHostPort(s.target.host, strconv.Itoa(grpcPort)), 0, result.grpc.detail)
		}
	}
	if result.vendor == "pgvector" && result.pg.detail == "" {
		s.auxCount++
		result.pg = probeVecPostgres(ctx, s.target.host, s.target.port)
		if result.pg.auth {
			result.authRequired = true
		}
		s.record("postgres", "STARTUP", net.JoinHostPort(s.target.host, strconv.Itoa(s.target.port)), 0, result.pg.detail)
	}

	if result.version != "" {
		result.cves = matchVecCVEs(result.vendor, result.version)
	}

	result.attempts = s.budget + s.auxCount
	result.blocked = s.blocked
	return result
}

func vecConfidence(score int) string {
	switch {
	case score >= 90:
		return "high"
	case score >= 60:
		return "medium"
	default:
		return "low"
	}
}

func vecGRPCPort(vendor vecVendor, target vecTarget) int {
	if vendor.grpc == 0 {
		return 0
	}
	if target.scheme == "grpc" {
		return target.port
	}
	return vendor.grpc
}

func (s *vecScan) fingerprint(ctx context.Context, candidate vecCandidate) (int, string, []string) {
	if candidate.vendor == "redis" {
		return s.fingerprintRedis(ctx, candidate)
	}
	if candidate.vendor == "pgvector" {
		return s.fingerprintPostgres(ctx, candidate)
	}

	score := 0
	version := ""
	var evidence []string
	for _, spec := range candidate.probes {
		rawURL := strings.TrimRight(candidate.baseURL, "/") + spec.path
		response := s.do(ctx, "fingerprint", spec.method, rawURL, spec.body, nil)
		if response.err != nil {
			continue
		}
		localScore, localVersion, localEvidence := scoreVecVendor(candidate.vendor, response)
		if localScore > score {
			score = localScore
		}
		if version == "" && localVersion != "" {
			version = localVersion
		}
		evidence = append(evidence, localEvidence...)
	}
	return score, version, uniqueVecStrings(evidence)
}

func scoreVecVendor(vendor string, response *vecResponse) (int, string, []string) {
	if response == nil || response.err != nil {
		return 0, "", nil
	}
	body := string(response.body)
	lower := strings.ToLower(body)
	contentType := strings.ToLower(response.header.Get("Content-Type"))
	server := strings.ToLower(strings.Join(response.header.Values("Server"), " "))
	jsonMap := decodeVecJSONMap(response.body)

	switch vendor {
	case "qdrant":
		if strings.Contains(lower, "qdrant") {
			return 100, stringField(jsonMap, "version"), []string{"Qdrant marker in response body"}
		}
		if result, ok := jsonMap["result"].(map[string]any); ok {
			if _, ok := result["collections"]; ok {
				return 85, "", []string{"/collections result shape matched"}
			}
		}
		if response.path() == "/healthz" && strings.Contains(lower, "healthz") {
			return 45, "", []string{"/healthz responded"}
		}
	case "weaviate":
		if strings.Contains(lower, "weaviate") {
			return 100, stringField(jsonMap, "version"), []string{"Weaviate marker in response body"}
		}
		if _, ok := jsonMap["version"]; ok {
			if _, host := jsonMap["hostname"]; host {
				return 95, stringField(jsonMap, "version"), []string{"/v1/meta version+hostname"}
			}
			if _, modules := jsonMap["modules"]; modules {
				return 90, stringField(jsonMap, "version"), []string{"/v1/meta modules shape"}
			}
		}
	case "chroma":
		if strings.Contains(lower, "nanosecond") && strings.Contains(lower, "heartbeat") {
			return 100, stringField(jsonMap, "version"), []string{"Chroma heartbeat shape"}
		}
		if strings.Contains(lower, "chroma") {
			return 90, stringField(jsonMap, "version"), []string{"Chroma marker in response body"}
		}
		if _, ok := jsonMap["version"]; ok && strings.Contains(contentType, "json") {
			return 60, stringField(jsonMap, "version"), []string{"version JSON on Chroma probe"}
		}
	case "milvus":
		if strings.Contains(lower, "milvus") {
			return 95, "", []string{"Milvus marker in response body"}
		}
		if response.path() == "/v2/vectordb/collections/list" {
			if _, ok := jsonMap["code"]; ok {
				if _, data := jsonMap["data"]; data {
					return 85, "", []string{"/v2/vectordb/collections/list code+data"}
				}
			}
		}
		if strings.Contains(server, "milvus") {
			return 90, "", []string{"Server header identifies Milvus"}
		}
		if response.path() == "/healthz" && strings.TrimSpace(lower) == "ok" {
			return 40, "", []string{"/healthz returned OK"}
		}
	case "elasticsearch":
		if response.header.Get("X-Elastic-Product") != "" {
			return 100, nestedStringField(jsonMap, "version", "number"), []string{"X-Elastic-Product header"}
		}
		if strings.Contains(lower, "you know, for search") {
			return 100, nestedStringField(jsonMap, "version", "number"), []string{"Elasticsearch tagline"}
		}
		if nestedStringField(jsonMap, "version", "distribution") == "elasticsearch" {
			return 95, nestedStringField(jsonMap, "version", "number"), []string{"version.distribution=elasticsearch"}
		}
	case "opensearch":
		if nestedStringField(jsonMap, "version", "distribution") == "opensearch" || strings.Contains(lower, "opensearch") {
			return 100, nestedStringField(jsonMap, "version", "number"), []string{"OpenSearch distribution marker"}
		}
	case "typesense":
		if strings.Contains(server, "typesense") || strings.Contains(lower, "typesense") {
			return 90, versionFromServer(server, "typesense"), []string{"Typesense server marker"}
		}
		if response.path() == "/debug" {
			if version := stringField(jsonMap, "version"); version != "" {
				return 85, version, []string{"/debug version shape"}
			}
		}
		if _, ok := jsonMap["ok"]; ok && response.path() == "/health" {
			return 70, "", []string{"/health returned ok"}
		}
		if strings.HasPrefix(strings.TrimSpace(body), "[") && strings.Contains(lower, "num_documents") {
			return 75, "", []string{"/collections num_documents shape"}
		}
	case "pinecone":
		if hasVecHeaderPrefix(response.header, "X-Pinecone-") || strings.Contains(lower, "pinecone") {
			return 75, "", []string{"Pinecone header/body marker"}
		}
		if response.status == http.StatusUnauthorized {
			return 35, "", []string{"HTTP 401 on Pinecone probe; authentication may be enforced"}
		}
	case "vespa":
		if strings.Contains(lower, "vespa") {
			return 95, stringField(jsonMap, "version"), []string{"Vespa marker in response body"}
		}
		if response.path() == "/state/v1/version" && stringField(jsonMap, "version") != "" {
			return 90, stringField(jsonMap, "version"), []string{"/state/v1/version shape"}
		}
		if response.path() == "/state/v1/health" && jsonMap["services"] != nil {
			return 75, "", []string{"/state/v1/health services shape"}
		}
	}

	if response.status == http.StatusUnauthorized || response.status == http.StatusForbidden {
		return 25, "", []string{"authentication enforced (" + strconv.Itoa(response.status) + ")"}
	}
	return 0, "", nil
}

func (r *vecResponse) path() string {
	if r == nil {
		return ""
	}
	parsed, err := url.Parse(r.url)
	if err != nil {
		return ""
	}
	return parsed.Path
}

func (s *vecScan) enumerate(ctx context.Context, result *vecResult) {
	switch result.vendor {
	case "qdrant":
		s.enumerateQdrant(ctx, result)
	case "weaviate":
		s.enumerateWeaviate(ctx, result)
	case "chroma":
		s.enumerateChroma(ctx, result)
	case "milvus":
		s.enumerateMilvus(ctx, result)
	case "elasticsearch", "opensearch":
		s.enumerateElastic(ctx, result)
	case "typesense":
		s.enumerateTypesense(ctx, result)
	case "vespa":
		s.enumerateVespa(ctx, result)
	case "redis":
		s.enumerateRedis(ctx, result)
	case "pinecone":
		s.enumeratePinecone(ctx, result)
	case "pgvector":
		s.auxCount++
		result.pg = probeVecPostgres(ctx, s.target.host, s.target.port)
		if result.pg.auth {
			result.authRequired = true
		}
	}
}

// ---------------------------------------------------------------------------
// Vendor enumeration
// ---------------------------------------------------------------------------

func (s *vecScan) base() string {
	return strings.TrimRight(s.target.baseURL, "/")
}

func (s *vecScan) getJSON(ctx context.Context, phase, path string) (map[string]any, *vecResponse) {
	response := s.do(ctx, phase, http.MethodGet, s.base()+path, nil, nil)
	if response.err != nil {
		return nil, response
	}
	return decodeVecJSONMap(response.body), response
}

func (s *vecScan) postJSON(ctx context.Context, phase, path string, body any) (map[string]any, *vecResponse) {
	response := s.do(ctx, phase, http.MethodPost, s.base()+path, body, nil)
	if response.err != nil {
		return nil, response
	}
	return decodeVecJSONMap(response.body), response
}

func (s *vecScan) enumerateQdrant(ctx context.Context, result *vecResult) {
	data, response := s.getJSON(ctx, "enum", "/collections")
	if response != nil && (response.status == http.StatusUnauthorized || response.status == http.StatusForbidden) {
		result.authRequired = true
	}
	names := []string{}
	if list, ok := data["result"].(map[string]any); ok {
		for _, item := range anySlice(list["collections"]) {
			if entry, ok := item.(map[string]any); ok {
				if name := stringField(entry, "name"); name != "" {
					names = append(names, name)
				}
			} else if name, ok := item.(string); ok {
				names = append(names, name)
			}
		}
	}
	if len(names) == 0 {
		for _, item := range anySlice(data["collections"]) {
			if name, ok := item.(string); ok {
				names = append(names, name)
			}
		}
	}

	for _, name := range limitStrings(names, vecmapMaxColls) {
		collection := vecCollection{Name: name}
		detail, response := s.getJSON(ctx, "schema", "/collections/"+url.PathEscape(name))
		if response != nil && response.err == nil {
			if body, ok := detail["result"].(map[string]any); ok {
				collection.Count = int64Field(body, "points_count")
				if config, ok := body["config"].(map[string]any); ok {
					if params, ok := config["params"].(map[string]any); ok {
						if vectors, ok := params["vectors"].(map[string]any); ok {
							collection.Dimension = int(int64Field(vectors, "size"))
							collection.Metric = stringField(vectors, "distance")
							collection.IndexType = "hnsw"
						} else {
							for _, value := range vectors {
								if vectorMap, ok := value.(map[string]any); ok {
									if collection.Dimension == 0 {
										collection.Dimension = int(int64Field(vectorMap, "size"))
										collection.Metric = stringField(vectorMap, "distance")
									}
								}
							}
						}
					}
				}
			}
		}
		if s.deep {
			scroll, scrollResponse := s.postJSON(ctx, "sample", "/collections/"+url.PathEscape(name)+"/points/scroll", map[string]any{
				"limit": vecmapMaxRecords, "with_payload": true, "with_vector": false,
			})
			if scrollResponse != nil && scrollResponse.status == http.StatusOK {
				if body, ok := scroll["result"].(map[string]any); ok {
					if points := anySlice(body["points"]); len(points) > 0 {
						collection.Sampled = len(points)
						result.exposed = true
						keys := map[string]struct{}{}
						for _, point := range points {
							if entry, ok := point.(map[string]any); ok {
								if payload, ok := entry["payload"].(map[string]any); ok {
									for key := range payload {
										keys[key] = struct{}{}
									}
								}
							}
						}
						collection.SampleKeys = sortedKeys(keys)
					}
				}
			}
		}
		result.collections = append(result.collections, collection)
	}
	if len(result.collections) > 0 {
		result.exposed = true
	}
}

func (s *vecScan) enumerateWeaviate(ctx context.Context, result *vecResult) {
	data, response := s.getJSON(ctx, "enum", "/v1/schema")
	if response != nil && (response.status == http.StatusUnauthorized || response.status == http.StatusForbidden) {
		result.authRequired = true
	}
	for _, item := range anySlice(data["classes"]) {
		class, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name := stringField(class, "class")
		if name == "" {
			continue
		}
		collection := vecCollection{
			Name:      name,
			IndexType: stringField(class, "vectorIndexType"),
		}
		if indexConfig, ok := class["vectorIndexConfig"].(map[string]any); ok {
			collection.Metric = stringField(indexConfig, "distance")
			collection.Dimension = int(int64Field(indexConfig, "dimensions"))
		}
		if s.deep {
			objects, objectResponse := s.getJSON(ctx, "sample", "/v1/objects?limit="+strconv.Itoa(vecmapMaxRecords)+"&class="+url.QueryEscape(name))
			if objectResponse != nil && objectResponse.status == http.StatusOK {
				collection.Count = int64Field(objects, "totalResults")
				if items := anySlice(objects["objects"]); len(items) > 0 {
					collection.Sampled = len(items)
					result.exposed = true
					keys := map[string]struct{}{}
					for _, object := range items {
						if entry, ok := object.(map[string]any); ok {
							if properties, ok := entry["properties"].(map[string]any); ok {
								for key := range properties {
									keys[key] = struct{}{}
								}
							}
						}
					}
					collection.SampleKeys = sortedKeys(keys)
				}
			}
		}
		result.collections = append(result.collections, collection)
	}
	if len(result.collections) > 0 {
		result.exposed = true
	}
}

func (s *vecScan) enumerateChroma(ctx context.Context, result *vecResult) {
	basePath := "/api/v1/collections"
	response := s.do(ctx, "enum", http.MethodGet, s.base()+basePath, nil, nil)
	v2 := false
	if response != nil && response.status == http.StatusNotFound {
		basePath = "/api/v2/tenants/default_tenant/databases/default_database/collections"
		response = s.do(ctx, "enum", http.MethodGet, s.base()+basePath, nil, nil)
		v2 = true
	}
	if response != nil && (response.status == http.StatusUnauthorized || response.status == http.StatusForbidden) {
		result.authRequired = true
	}

	items := decodeVecItems(responseBodyOf(response))
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			if name, ok := item.(string); ok {
				entry = map[string]any{"name": name}
			} else {
				continue
			}
		}
		name := stringField(entry, "name")
		id := stringField(entry, "id")
		if name == "" && id == "" {
			continue
		}
		if name == "" {
			name = id
		}
		collection := vecCollection{
			Name:         name,
			collectionID: id,
			Dimension:    int(int64Field(entry, "dimension")),
			namespace:    stringField(entry, "tenant"),
		}
		identifier := id
		if identifier == "" {
			identifier = name
		}
		if response := s.do(ctx, "schema", http.MethodGet, s.base()+basePath+"/"+url.PathEscape(identifier)+"/count", nil, nil); response.err == nil && response.status == http.StatusOK {
			trimmed := strings.TrimSpace(string(response.body))
			if count, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
				collection.Count = count
			}
		}
		if s.deep {
			getPath := basePath + "/" + url.PathEscape(identifier) + "/get"
			if v2 {
				getPath = basePath + "/" + url.PathEscape(identifier) + "/get"
			}
			sample, sampleResponse := s.postJSON(ctx, "sample", getPath, map[string]any{"limit": vecmapMaxRecords, "include": []string{"metadatas", "documents"}})
			if sampleResponse != nil && sampleResponse.status == http.StatusOK {
				ids := anySlice(sample["ids"])
				if len(ids) > 0 {
					collection.Sampled = len(ids)
					result.exposed = true
				}
				keys := map[string]struct{}{}
				for _, metadata := range anySlice(sample["metadatas"]) {
					if entry, ok := metadata.(map[string]any); ok {
						for key := range entry {
							keys[key] = struct{}{}
						}
					}
				}
				collection.SampleKeys = sortedKeys(keys)
			}
		}
		result.collections = append(result.collections, collection)
	}
	if len(result.collections) > 0 {
		result.exposed = true
	}
}

func (s *vecScan) enumerateMilvus(ctx context.Context, result *vecResult) {
	data, response := s.postJSON(ctx, "enum", "/v2/vectordb/collections/list", map[string]any{"dbName": "default"})
	if response != nil && (response.status == http.StatusUnauthorized || response.status == http.StatusForbidden) {
		result.authRequired = true
	}
	var names []string
	for _, item := range anySlice(data["data"]) {
		if name, ok := item.(string); ok {
			names = append(names, name)
		} else if entry, ok := item.(map[string]any); ok {
			if name := firstStringField(entry, "collectionName", "collection_name", "name"); name != "" {
				names = append(names, name)
			}
		}
	}
	for _, name := range limitStrings(names, vecmapMaxColls) {
		collection := vecCollection{Name: name}
		describe, describeResponse := s.postJSON(ctx, "schema", "/v2/vectordb/collections/describe", map[string]any{"dbName": "default", "collectionName": name})
		if describeResponse != nil && describeResponse.status == http.StatusOK {
			if body, ok := describe["data"].(map[string]any); ok {
				collection.Dimension = int(int64Field(body, "dimension"))
				collection.Metric = firstStringField(body, "metricType", "metric_type")
				collection.Count = int64Field(body, "numRows")
				collection.IndexType = "hnsw"
				collection.Fields = stringSliceFromMaps(anySlice(body["fields"]), "name")
			}
		}
		if s.deep {
			query, queryResponse := s.postJSON(ctx, "sample", "/v2/vectordb/entities/query", map[string]any{
				"dbName": "default", "collectionName": name, "filter": "", "outputFields": []string{"*"}, "limit": vecmapMaxRecords,
			})
			if queryResponse != nil && queryResponse.status == http.StatusOK {
				rows := anySlice(query["data"])
				if len(rows) > 0 {
					collection.Sampled = len(rows)
					result.exposed = true
					keys := map[string]struct{}{}
					for _, row := range rows {
						if entry, ok := row.(map[string]any); ok {
							for key := range entry {
								keys[key] = struct{}{}
							}
						}
					}
					collection.SampleKeys = sortedKeys(keys)
				}
			}
		}
		result.collections = append(result.collections, collection)
	}
	if len(result.collections) > 0 {
		result.exposed = true
	}
}

func (s *vecScan) enumerateElastic(ctx context.Context, result *vecResult) {
	response := s.do(ctx, "enum", http.MethodGet, s.base()+"/_cat/indices?format=json&h=index,docs.count,store.size", nil, nil)
	if response.err != nil {
		return
	}
	if response.status == http.StatusUnauthorized || response.status == http.StatusForbidden {
		result.authRequired = true
	}
	items, err := decodeVecJSONArray(response.body)
	if err != nil {
		return
	}
	names := make([]string, 0, len(items))
	counts := map[string]int64{}
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name := stringField(entry, "index")
		if name == "" || strings.HasPrefix(name, ".") {
			continue
		}
		names = append(names, name)
		counts[name] = int64Field(entry, "docs.count")
	}
	for _, name := range limitStrings(names, vecmapMaxColls) {
		collection := vecCollection{Name: name, Count: counts[name], IndexType: "lucene"}
		mapping, mapResponse := s.getJSON(ctx, "schema", "/"+url.PathEscape(name)+"/_mapping")
		if mapResponse != nil && mapResponse.status == http.StatusOK {
			for _, index := range mapping {
				if entry, ok := index.(map[string]any); ok {
					if mappings, ok := entry["mappings"].(map[string]any); ok {
						collection.Fields = nestedFieldNames(mappings)
						collection.Dimension = vectorDimensionFromMapping(mappings)
					}
				}
			}
		}
		if s.deep {
			search, searchResponse := s.getJSON(ctx, "sample", "/"+url.PathEscape(name)+"/_search?size="+strconv.Itoa(vecmapMaxRecords)+"&track_total_hits=true")
			if searchResponse != nil && searchResponse.status == http.StatusOK {
				if hits, ok := search["hits"].(map[string]any); ok {
					if total, ok := hits["total"].(map[string]any); ok {
						collection.Count = int64Field(total, "value")
					}
					if rows := anySlice(hits["hits"]); len(rows) > 0 {
						collection.Sampled = len(rows)
						result.exposed = true
						keys := map[string]struct{}{}
						for _, row := range rows {
							if entry, ok := row.(map[string]any); ok {
								if source, ok := entry["_source"].(map[string]any); ok {
									for key := range source {
										keys[key] = struct{}{}
									}
								}
							}
						}
						collection.SampleKeys = sortedKeys(keys)
					}
				}
			}
		}
		result.collections = append(result.collections, collection)
	}
	if len(result.collections) > 0 {
		result.exposed = true
	}
}

func (s *vecScan) enumerateTypesense(ctx context.Context, result *vecResult) {
	response := s.do(ctx, "enum", http.MethodGet, s.base()+"/collections", nil, nil)
	if response.err != nil {
		return
	}
	if response.status == http.StatusUnauthorized || response.status == http.StatusForbidden {
		result.authRequired = true
	}
	items, err := decodeVecJSONArray(response.body)
	if err != nil {
		return
	}
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name := stringField(entry, "name")
		if name == "" {
			continue
		}
		collection := vecCollection{
			Name:      name,
			Count:     int64Field(entry, "num_documents"),
			IndexType: "hnsw",
		}
		for _, field := range anySlice(entry["fields"]) {
			fieldMap, ok := field.(map[string]any)
			if !ok {
				continue
			}
			collection.Fields = append(collection.Fields, stringField(fieldMap, "name"))
			if dimension := int(int64Field(fieldMap, "num_dim")); dimension > 0 && collection.Dimension == 0 {
				collection.Dimension = dimension
			}
		}
		if s.deep {
			searchPath := "/collections/" + url.PathEscape(name) + "/documents/search?q=*&limit=" + strconv.Itoa(vecmapMaxRecords)
			search, searchResponse := s.getJSON(ctx, "sample", searchPath)
			if searchResponse != nil && searchResponse.status == http.StatusOK {
				if hits := anySlice(search["hits"]); len(hits) > 0 {
					collection.Sampled = len(hits)
					result.exposed = true
					keys := map[string]struct{}{}
					for _, hit := range hits {
						if wrapper, ok := hit.(map[string]any); ok {
							if document, ok := wrapper["document"].(map[string]any); ok {
								for key := range document {
									keys[key] = struct{}{}
								}
							}
						}
					}
					collection.SampleKeys = sortedKeys(keys)
				}
			}
		}
		result.collections = append(result.collections, collection)
	}
	if len(result.collections) > 0 {
		result.exposed = true
	}
}

func (s *vecScan) enumerateVespa(ctx context.Context, result *vecResult) {
	version, response := s.getJSON(ctx, "version", "/state/v1/version")
	if response != nil && response.status == http.StatusOK {
		result.version = stringField(version, "version")
	}
	if s.deep {
		search, searchResponse := s.getJSON(ctx, "sample", "/search/?yql=select%20*%20from%20sources%20*%20where%20true%3B&hits="+strconv.Itoa(vecmapMaxRecords))
		if searchResponse != nil && searchResponse.status == http.StatusOK {
			collection := vecCollection{Name: "vespa-documents"}
			if root, ok := search["root"].(map[string]any); ok {
				collection.Count = int64Field(root, "totalCount")
				if children := anySlice(root["children"]); len(children) > 0 {
					collection.Sampled = len(children)
					result.exposed = true
					keys := map[string]struct{}{}
					for _, child := range children {
						if entry, ok := child.(map[string]any); ok {
							if fields, ok := entry["fields"].(map[string]any); ok {
								for key := range fields {
									keys[key] = struct{}{}
								}
							}
						}
					}
					collection.SampleKeys = sortedKeys(keys)
				}
			}
			result.collections = append(result.collections, collection)
		}
	}
	if len(result.collections) > 0 {
		result.exposed = true
	}
}

func (s *vecScan) enumeratePinecone(ctx context.Context, result *vecResult) {
	stats, response := s.postJSON(ctx, "schema", "/describe_index_stats", map[string]any{})
	if response == nil {
		return
	}
	if response.status == http.StatusUnauthorized || response.status == http.StatusForbidden {
		result.authRequired = true
		return
	}
	if response.status != http.StatusOK {
		return
	}
	collection := vecCollection{
		Name:      "pinecone-index",
		Dimension: int(int64Field(stats, "dimension")),
		Count:     int64Field(stats, "totalVectorCount"),
		IndexType: "hnsw",
	}
	if namespaces, ok := stats["namespaces"].(map[string]any); ok {
		collection.namespace = strings.Join(sortedKeysFromMap(namespaces), ",")
	}
	result.collections = append(result.collections, collection)
	result.exposed = collection.Count > 0 || collection.Dimension > 0
}

// ---------------------------------------------------------------------------
// Redis / RediSearch (RESP)
// ---------------------------------------------------------------------------

func (s *vecScan) fingerprintRedis(ctx context.Context, candidate vecCandidate) (int, string, []string) {
	secure := s.target.scheme == "rediss" || strings.HasPrefix(candidate.baseURL, "rediss://")
	s.auxCount++
	client, err := dialVecRedis(ctx, candidate.baseURL, secure)
	if err != nil {
		s.record("fingerprint", "TCP", candidate.baseURL, 0, "redis dial: "+err.Error())
		return 0, "", nil
	}
	defer client.close()
	defer func() {
		s.auxCount += client.count
	}()

	pong, err := client.command("PING")
	if err != nil {
		lower := strings.ToLower(err.Error())
		s.record("fingerprint", "RESP", candidate.baseURL, 0, "PING: "+err.Error())
		if strings.Contains(lower, "noauth") || strings.Contains(lower, "wrongpass") {
			return 45, "", []string{"Redis endpoint requires authentication"}
		}
		return 0, "", nil
	}
	if strings.ToUpper(strings.TrimSpace(fmt.Sprint(pong))) != "PONG" {
		return 0, "", nil
	}
	info, _ := client.command("INFO", "server")
	version := redisInfoValue(info, "redis_version")
	s.record("fingerprint", "RESP", candidate.baseURL, 200, "PING=PONG redis_version="+version)
	return 100, version, []string{"RESP PING returned PONG", "redis_version=" + version}
}

func (s *vecScan) enumerateRedis(ctx context.Context, result *vecResult) {
	s.auxCount++
	client, err := dialVecRedis(ctx, s.target.baseURL, s.target.scheme == "rediss")
	if err != nil {
		result.errors = append(result.errors, "redis: "+err.Error())
		return
	}
	defer client.close()
	defer func() {
		s.auxCount += client.count
	}()

	indexes, err := client.command("FT._LIST")
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "noauth") || strings.Contains(strings.ToLower(err.Error()), "wrongpass") {
			result.authRequired = true
		}
		result.errors = append(result.errors, "RediSearch FT._LIST: "+err.Error())
		return
	}
	for _, item := range anySlice(indexes) {
		name := fmt.Sprint(item)
		collection := vecCollection{Name: name, IndexType: "redisearch"}
		info, infoErr := client.command("FT.INFO", name)
		if infoErr == nil {
			fields := respPairs(info)
			collection.Count = parseInt64(fields["num_docs"])
			collection.Dimension = redisVectorDimension(info)
			collection.Metric = redisVectorMetric(info)
			collection.Fields = redisFieldNames(info)
		}
		if s.deep {
			search, searchErr := client.command("FT.SEARCH", name, "*", "LIMIT", "0", strconv.Itoa(vecmapMaxRecords))
			if searchErr == nil {
				if items, ok := search.([]any); ok && len(items) > 1 {
					collection.Sampled = (len(items) - 1) / 2
					if collection.Sampled < 1 {
						collection.Sampled = 1
					}
					result.exposed = true
				}
			}
		}
		result.collections = append(result.collections, collection)
	}
	if len(result.collections) > 0 {
		result.exposed = true
	}
}

type vecRedis struct {
	conn  net.Conn
	rd    *bufio.Reader
	count int
}

func dialVecRedis(ctx context.Context, rawURL string, secure bool) (*vecRedis, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		port = "6379"
	}
	address := net.JoinHostPort(host, port)
	dialer := &net.Dialer{Timeout: 4 * time.Second}
	var conn net.Conn
	if secure {
		conn, err = tls.DialWithDialer(dialer, "tcp", address, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", address)
	}
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	return &vecRedis{conn: conn, rd: bufio.NewReader(conn)}, nil
}

func (r *vecRedis) close() {
	if r != nil && r.conn != nil {
		_ = r.conn.Close()
	}
}

func (r *vecRedis) command(args ...string) (any, error) {
	r.count++
	var builder strings.Builder
	builder.WriteString("*")
	builder.WriteString(strconv.Itoa(len(args)))
	builder.WriteString("\r\n")
	for _, arg := range args {
		builder.WriteString("$")
		builder.WriteString(strconv.Itoa(len(arg)))
		builder.WriteString("\r\n")
		builder.WriteString(arg)
		builder.WriteString("\r\n")
	}
	if _, err := io.WriteString(r.conn, builder.String()); err != nil {
		return nil, err
	}
	return readVecRESP(r.rd)
}

func readVecRESP(reader *bufio.Reader) (any, error) {
	return readVecRESPDepth(reader, 0)
}

func readVecRESPDepth(reader *bufio.Reader, depth int) (any, error) {
	if depth > 32 {
		return nil, fmt.Errorf("RESP nesting exceeds 32 levels")
	}
	prefix, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	lineBytes, err := reader.ReadSlice('\n')
	if err != nil {
		return nil, err
	}
	line := strings.TrimSuffix(strings.TrimSuffix(string(lineBytes), "\n"), "\r")
	switch prefix {
	case '+':
		return line, nil
	case '-':
		return nil, fmt.Errorf("%s", line)
	case ':':
		return strconv.ParseInt(line, 10, 64)
	case '$':
		length, err := strconv.Atoi(line)
		if err != nil {
			return nil, err
		}
		if length < 0 {
			return nil, nil
		}
		if length > 8<<20 {
			return nil, fmt.Errorf("RESP bulk length %d exceeds the 8 MiB limit", length)
		}
		buffer := make([]byte, length+2)
		if _, err := io.ReadFull(reader, buffer); err != nil {
			return nil, err
		}
		return string(buffer[:length]), nil
	case '*':
		count, err := strconv.Atoi(line)
		if err != nil {
			return nil, err
		}
		if count < 0 {
			return nil, nil
		}
		if count > 10000 {
			return nil, fmt.Errorf("RESP array count %d exceeds the 10000-item limit", count)
		}
		items := make([]any, 0, count)
		for i := 0; i < count; i++ {
			item, err := readVecRESPDepth(reader, depth+1)
			if err != nil {
				return nil, err
			}
			items = append(items, item)
		}
		return items, nil
	default:
		return nil, fmt.Errorf("unsupported RESP prefix %q", prefix)
	}
}

func redisInfoValue(value any, key string) string {
	text := fmt.Sprint(value)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, key+":") {
			return strings.TrimSpace(strings.TrimPrefix(line, key+":"))
		}
	}
	return ""
}

func respPairs(value any) map[string]string {
	result := map[string]string{}
	items, ok := value.([]any)
	if !ok {
		return result
	}
	for i := 0; i+1 < len(items); i += 2 {
		key := strings.ToLower(fmt.Sprint(items[i]))
		result[key] = fmt.Sprint(items[i+1])
	}
	return result
}

func redisVectorDimension(value any) int {
	found, ok := respFindValue(value, "DIM")
	if !ok {
		return 0
	}
	dimension, _ := strconv.Atoi(fmt.Sprint(found))
	return dimension
}

func redisVectorMetric(value any) string {
	found, ok := respFindValue(value, "DISTANCE_METRIC")
	if !ok {
		return ""
	}
	return fmt.Sprint(found)
}

func respFindValue(value any, key string) (any, bool) {
	items, ok := value.([]any)
	if !ok {
		return nil, false
	}
	for index, item := range items {
		if index+1 < len(items) && strings.EqualFold(fmt.Sprint(item), key) {
			return items[index+1], true
		}
		if found, ok := respFindValue(item, key); ok {
			return found, true
		}
	}
	return nil, false
}

func redisFieldNames(value any) []string {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	var names []string
	for i := 0; i+1 < len(items); i++ {
		if !strings.EqualFold(fmt.Sprint(items[i]), "ATTRIBUTES") {
			continue
		}
		for _, attribute := range anySlice(items[i+1]) {
			fields := respPairs(attribute)
			if name := fields["identifier"]; name != "" {
				names = append(names, name)
			}
		}
	}
	return names
}

// ---------------------------------------------------------------------------
// PostgreSQL / pgvector reachability
// ---------------------------------------------------------------------------

type vecPGResult struct {
	reachable bool
	auth      bool
	detail    string
}

func probeVecPostgres(ctx context.Context, host string, port int) vecPGResult {
	dialer := &net.Dialer{Timeout: 4 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return vecPGResult{detail: "PostgreSQL TCP dial failed: " + err.Error()}
	}
	defer func() {
		_ = conn.Close()
	}()
	_ = conn.SetDeadline(time.Now().Add(6 * time.Second))

	sslRequest := make([]byte, 8)
	binary.BigEndian.PutUint32(sslRequest[0:4], 8)
	binary.BigEndian.PutUint32(sslRequest[4:8], 80877103)
	if _, err := conn.Write(sslRequest); err != nil {
		return vecPGResult{detail: "PostgreSQL SSLRequest write failed: " + err.Error()}
	}
	answer := make([]byte, 1)
	if _, err := io.ReadFull(conn, answer); err != nil {
		return vecPGResult{detail: "PostgreSQL SSLRequest read failed: " + err.Error()}
	}
	if answer[0] == 'S' {
		return vecPGResult{reachable: true, detail: "PostgreSQL wire endpoint requires TLS; pgvector enumeration needs credentials"}
	}
	if answer[0] != 'N' {
		return vecPGResult{detail: "PostgreSQL wire endpoint returned an unexpected SSL answer"}
	}

	user := "postgres"
	body := make([]byte, 0, 64)
	body = binary.BigEndian.AppendUint32(body, 196608)
	body = append(body, []byte("user\x00"+user+"\x00database\x00postgres\x00\x00")...)
	startup := make([]byte, 4)
	binary.BigEndian.PutUint32(startup, uint32(4+len(body)))
	startup = append(startup, body...)
	if _, err := conn.Write(startup); err != nil {
		return vecPGResult{detail: "PostgreSQL startup write failed: " + err.Error()}
	}

	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return vecPGResult{reachable: true, detail: "PostgreSQL accepted TCP but returned no startup response"}
	}
	messageType := header[0]
	length := int(binary.BigEndian.Uint32(header[1:5]))
	if length < 4 || length > 4096 {
		return vecPGResult{reachable: true, detail: "PostgreSQL startup response length was unreasonable"}
	}
	payload := make([]byte, length-4)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return vecPGResult{reachable: true, detail: "PostgreSQL startup response was truncated"}
	}

	switch messageType {
	case 'R':
		authType := 0
		if len(payload) >= 4 {
			authType = int(binary.BigEndian.Uint32(payload[:4]))
		}
		return vecPGResult{reachable: true, auth: true, detail: fmt.Sprintf("PostgreSQL authentication requested (type %d); pgvector enumeration needs credentials", authType)}
	case 'E':
		return vecPGResult{reachable: true, detail: "PostgreSQL returned an ErrorResponse: " + sanitizeVecText(string(payload), 160)}
	default:
		return vecPGResult{reachable: true, detail: fmt.Sprintf("PostgreSQL startup message type %q received", messageType)}
	}
}

func (s *vecScan) fingerprintPostgres(ctx context.Context, candidate vecCandidate) (int, string, []string) {
	s.auxCount++
	parsed, err := url.Parse(candidate.baseURL)
	if err != nil {
		return 0, "", nil
	}
	port, _ := strconv.Atoi(parsed.Port())
	probe := probeVecPostgres(ctx, parsed.Hostname(), port)
	s.record("fingerprint", "STARTUP", candidate.baseURL, 0, probe.detail)
	if probe.reachable {
		return 50, "", []string{"PostgreSQL wire endpoint (pgvector extension unconfirmed): " + probe.detail}
	}
	return 0, "", nil
}

// ---------------------------------------------------------------------------
// gRPC HTTP/2 reflection probe
// ---------------------------------------------------------------------------

type vecGRPCResult struct {
	port       int
	reachable  bool
	reflection bool
	services   []string
	detail     string
}

func probeVecGRPC(ctx context.Context, host string, port int, useTLS bool) vecGRPCResult {
	result := vecGRPCResult{port: port}
	address := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: 3 * time.Second}

	var conn net.Conn
	var err error
	if useTLS {
		conn, err = tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
			ServerName: host,
			NextProtos: []string{"h2"},
			MinVersion: tls.VersionTLS12,
		})
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", address)
	}
	if err != nil {
		result.detail = "gRPC port " + strconv.Itoa(port) + " unreachable: " + err.Error()
		return result
	}
	defer func() {
		_ = conn.Close()
	}()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	result.reachable = true

	if _, err := io.WriteString(conn, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"); err != nil {
		result.detail = "HTTP/2 preface write failed"
		return result
	}
	if err := writeVecH2Frame(conn, 0x4, 0, 0, nil); err != nil {
		result.detail = "HTTP/2 SETTINGS write failed"
		return result
	}

	gotSettings := false
	for i := 0; i < 4; i++ {
		frameType, flags, streamID, payload, err := readVecH2Frame(conn)
		if err != nil {
			break
		}
		switch frameType {
		case 0x4:
			gotSettings = true
			if flags&0x1 == 0 {
				_ = writeVecH2Frame(conn, 0x4, 0x1, 0, nil)
			}
		case 0x6:
			_ = writeVecH2Frame(conn, 0x6, 0x1, 0, payload)
		case 0x0, 0x1:
			if streamID == 1 {
				i = 4
			}
		}
		if gotSettings {
			break
		}
	}
	if !gotSettings {
		result.detail = "gRPC port accepted TCP but no HTTP/2 SETTINGS arrived; not a confirmed gRPC endpoint"
		return result
	}

	authority := net.JoinHostPort(host, strconv.Itoa(port))
	headerBlock := make([]byte, 0, 128)
	headerBlock = append(headerBlock, 0x83) // :method POST
	if useTLS {
		headerBlock = append(headerBlock, 0x87) // :scheme https
	} else {
		headerBlock = append(headerBlock, 0x86) // :scheme http
	}
	headerBlock = appendVecHPACKLiteral(headerBlock, 0x04, "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo")
	headerBlock = appendVecHPACKLiteral(headerBlock, 0x01, authority)
	headerBlock = append(headerBlock, 0x0F, 0x10) // content-type (static index 31)
	headerBlock = appendVecHPACKString(headerBlock, "application/grpc")
	headerBlock = appendVecHPACKLiteral(headerBlock, 0x00, "te")
	headerBlock = appendVecHPACKString(headerBlock, "trailers")
	headerBlock = appendVecHPACKLiteral(headerBlock, 0x00, "user-agent")
	headerBlock = appendVecHPACKString(headerBlock, "SanTaiZi-vecmap/1.0")

	grpcRequest := []byte{0x00, 0x00, 0x00, 0x00, 0x02, 0x3A, 0x00}
	if err := writeVecH2Frame(conn, 0x1, 0x4, 1, headerBlock); err != nil {
		result.detail = "gRPC HEADERS write failed"
		return result
	}
	if err := writeVecH2Frame(conn, 0x0, 0x1, 1, grpcRequest); err != nil {
		result.detail = "gRPC DATA write failed"
		return result
	}

	headersSeen := false
	var data bytes.Buffer
	for i := 0; i < 12; i++ {
		frameType, flags, streamID, payload, err := readVecH2Frame(conn)
		if err != nil {
			break
		}
		switch frameType {
		case 0x4:
			if flags&0x1 == 0 {
				_ = writeVecH2Frame(conn, 0x4, 0x1, 0, nil)
			}
		case 0x6:
			_ = writeVecH2Frame(conn, 0x6, 0x1, 0, payload)
		case 0x1:
			if streamID == 1 {
				headersSeen = true
			}
		case 0x0:
			if streamID == 1 {
				data.Write(payload)
			}
		case 0x3, 0x7:
			i = 12
		}
	}

	if data.Len() > 0 {
		result.reflection = true
		result.services = extractVecGRPCServices(data.Bytes())
	}
	if result.reflection {
		result.detail = "gRPC/HTTP2 reflection endpoint responded"
		if len(result.services) > 0 {
			result.detail += "; services=" + strings.Join(result.services, ",")
		}
	} else if headersSeen {
		result.detail = "gRPC/HTTP2 response headers received; reflection payload was not decoded"
	} else {
		result.detail = "gRPC/HTTP2 SETTINGS received; reflection response not observed"
	}
	return result
}

func writeVecH2Frame(writer io.Writer, frameType, flags byte, streamID uint32, payload []byte) error {
	header := []byte{
		byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload)),
		frameType, flags,
		byte(streamID >> 24), byte(streamID >> 16), byte(streamID >> 8), byte(streamID),
	}
	if _, err := writer.Write(header); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := writer.Write(payload)
	return err
}

func readVecH2Frame(reader io.Reader) (byte, byte, uint32, []byte, error) {
	header := make([]byte, 9)
	if _, err := io.ReadFull(reader, header); err != nil {
		return 0, 0, 0, nil, err
	}
	length := int(header[0])<<16 | int(header[1])<<8 | int(header[2])
	if length < 0 || length > 1<<20 {
		return 0, 0, 0, nil, fmt.Errorf("HTTP/2 frame length %d exceeds limit", length)
	}
	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(reader, payload); err != nil {
			return 0, 0, 0, nil, err
		}
	}
	streamID := uint32(header[5]&0x7F)<<24 | uint32(header[6])<<16 | uint32(header[7])<<8 | uint32(header[8])
	return header[3], header[4], streamID, payload, nil
}

func appendVecHPACKLiteral(dst []byte, nameIndex byte, value string) []byte {
	dst = append(dst, nameIndex)
	return appendVecHPACKString(dst, value)
}

func appendVecHPACKString(dst []byte, value string) []byte {
	length := len(value)
	if length < 127 {
		dst = append(dst, byte(length))
	} else {
		dst = append(dst, 127)
		remaining := length - 127
		for remaining >= 128 {
			dst = append(dst, byte(remaining&0x7f)|0x80)
			remaining >>= 7
		}
		dst = append(dst, byte(remaining))
	}
	return append(dst, value...)
}

func extractVecGRPCServices(payload []byte) []string {
	seen := map[string]struct{}{}
	for _, match := range vecStringRE.FindAllString(string(payload), -1) {
		lower := strings.ToLower(match)
		if strings.Contains(lower, "reflection") || strings.Contains(lower, "milvus") ||
			strings.Contains(lower, "qdrant") || strings.Contains(lower, "weaviate") ||
			strings.Contains(lower, "grpc.health") {
			seen[match] = struct{}{}
		}
	}
	return sortedKeys(seen)
}

// ---------------------------------------------------------------------------
// CVE correlation
// ---------------------------------------------------------------------------

type vecRange struct {
	min          string
	max          string
	maxExclusive bool
}

type vecCVE struct {
	ID        string
	Vendor    string
	Title     string
	Severity  string
	CVSS      float64
	Fixed     string
	TTP       string
	CNVD      string
	Reference string
	Ranges    []vecRange
}

var vecCVEs = []vecCVE{
	{
		ID: "CVE-2024-3829", Vendor: "qdrant", Title: "Arbitrary file read/write via snapshot restore", Severity: "CRITICAL", CVSS: 9.8,
		Fixed: "1.9.0", TTP: "T1190", Reference: "https://github.com/advisories/GHSA-7m75-x27w-r52r",
		Ranges: []vecRange{{max: "1.8.9"}},
	},
	{
		ID: "CVE-2026-25628", Vendor: "qdrant", Title: "Arbitrary file append via /logger endpoint", Severity: "HIGH", CVSS: 8.1,
		Fixed: "1.16.0", TTP: "T1190", Reference: "https://nvd.nist.gov/vuln/detail/CVE-2026-25628",
		Ranges: []vecRange{{min: "1.9.3", max: "1.15.5"}},
	},
	{
		ID: "GHSA-frc7-44gm-99qq", Vendor: "qdrant", Title: "Unauthenticated internal gRPC in distributed mode", Severity: "HIGH", CVSS: 8.1,
		Fixed: "1.20.0", TTP: "T1190", Reference: "https://github.com/advisories/GHSA-frc7-44gm-99qq",
		Ranges: []vecRange{{max: "1.19.9"}},
	},
	{
		ID: "GHSA-3gph-6c29-p29v", Vendor: "qdrant", Title: "Internal gRPC accepts read-only keys and JWTs", Severity: "HIGH", CVSS: 7.5,
		Fixed: "1.19.2", TTP: "T1078", Reference: "https://github.com/advisories/GHSA-3gph-6c29-p29v",
		Ranges: []vecRange{{min: "1.18.0", max: "1.19.1"}},
	},
	{
		ID: "CVE-2025-64513", Vendor: "milvus", Title: "Milvus Proxy authentication bypass", Severity: "CRITICAL", CVSS: 9.8,
		Fixed: "2.4.24 / 2.5.21 / 2.6.5", TTP: "T1190", Reference: "https://nvd.nist.gov/vuln/detail/CVE-2025-64513",
		Ranges: []vecRange{{max: "2.4.23"}, {min: "2.5.0", max: "2.5.20"}, {min: "2.6.0", max: "2.6.4"}},
	},
	{
		ID: "CVE-2026-26190", Vendor: "milvus", Title: "Default-exposed port 9091 bypasses authentication", Severity: "HIGH", CVSS: 8.7,
		Fixed: "2.5.27 / 2.6.10", TTP: "T1190", Reference: "https://nvd.nist.gov/vuln/detail/CVE-2026-26190",
		Ranges: []vecRange{{max: "2.5.26"}, {min: "2.6.0", max: "2.6.9"}},
	},
	{
		ID: "CVE-2026-69111", Vendor: "milvus", Title: "Unauthenticated management endpoint denial of service", Severity: "HIGH", CVSS: 8.7,
		Fixed: "2.6.23", TTP: "T1190", Reference: "https://nvd.nist.gov/vuln/detail/CVE-2026-69111",
		Ranges: []vecRange{{max: "2.6.22"}, {min: "3.0.0", max: "3.0.0"}},
	},
	{
		ID: "CVE-2025-67818", Vendor: "weaviate", Title: "Path traversal in backup restore (ZipSlip)", Severity: "HIGH", CVSS: 7.2,
		Fixed: "1.30.20 / 1.31.19 / 1.32.16 / 1.33.4", TTP: "T1190", Reference: "https://nvd.nist.gov/vuln/detail/CVE-2025-67818",
		Ranges: []vecRange{{max: "1.30.19"}, {min: "1.31.0", max: "1.31.18"}, {min: "1.32.0", max: "1.32.15"}, {min: "1.33.0", max: "1.33.3"}},
	},
	{
		ID: "CVE-2025-67819", Vendor: "weaviate", Title: "Path traversal in shard movement (arbitrary file read)", Severity: "HIGH", CVSS: 8.7,
		Fixed: "1.30.20 / 1.31.19 / 1.32.16 / 1.33.4", TTP: "T1005", Reference: "https://github.com/advisories/GHSA-hmmh-292h-3364",
		Ranges: []vecRange{{min: "1.30.0", max: "1.30.19"}, {min: "1.31.0", max: "1.31.18"}, {min: "1.32.0", max: "1.32.15"}, {min: "1.33.0", max: "1.33.3"}},
	},
	{
		ID: "CVE-2026-11500", Vendor: "weaviate", Title: "Static API key validation flaw leads to authorization bypass", Severity: "MEDIUM", CVSS: 5.0,
		Fixed: "1.38.0-rc.0", TTP: "T1078", Reference: "https://nvd.nist.gov/vuln/detail/CVE-2026-11500",
		Ranges: []vecRange{{max: "1.37.7"}},
	},
	{
		ID: "CVE-2026-45829", Vendor: "chroma", Title: "Pre-authentication code injection via trust_remote_code", Severity: "CRITICAL", CVSS: 9.8,
		Fixed: "none listed", TTP: "T1190", Reference: "https://nvd.nist.gov/vuln/detail/CVE-2026-45829",
		Ranges: []vecRange{{min: "1.0.0", max: "1.5.9"}},
	},
	{
		ID: "CVE-2026-45831", Vendor: "chroma", Title: "RBAC does not verify tenant and collection ownership", Severity: "HIGH", CVSS: 7.5,
		Fixed: "none listed", TTP: "T1078", Reference: "https://nvd.nist.gov/vuln/detail/CVE-2026-45831",
		Ranges: []vecRange{{min: "0.5.0", max: "1.5.9"}},
	},
	{
		ID: "CVE-2026-92782", Vendor: "chroma", Title: "Collection ID parsing bypasses tenant isolation", Severity: "HIGH", CVSS: 8.6,
		Fixed: "none listed", TTP: "T1213", Reference: "https://nvd.nist.gov/vuln/detail/CVE-2026-92782",
		Ranges: []vecRange{{max: "1.5.9"}},
	},
	{
		ID: "CVE-2026-85664", Vendor: "chroma", Title: "Unbounded HNSW parameters exhaust memory", Severity: "HIGH", CVSS: 7.5,
		Fixed: "none listed", TTP: "T1190", Reference: "https://nvd.nist.gov/vuln/detail/CVE-2026-85664",
		Ranges: []vecRange{{max: "1.5.9"}},
	},
	{
		ID: "CVE-2026-47216", Vendor: "typesense", Title: "Unauthenticated denial of service in /multi_search", Severity: "HIGH", CVSS: 8.7,
		Fixed: "29.1 / 30.2", TTP: "T1190", Reference: "https://github.com/typesense/typesense/security/advisories/GHSA-fpx5-8c99-247j",
		Ranges: []vecRange{{max: "29.1", maxExclusive: true}, {min: "30.0", max: "30.2", maxExclusive: true}},
	},
	{
		ID: "CVE-2026-47225", Vendor: "typesense", Title: "Search cache isolation flaw with scoped API keys", Severity: "MEDIUM", CVSS: 5.0,
		Fixed: "29.1 / 30.2", TTP: "T1078", Reference: "https://github.com/typesense/typesense/security/advisories/GHSA-97x4-gm45-jpcw",
		Ranges: []vecRange{{max: "29.1", maxExclusive: true}, {min: "30.0", max: "30.2", maxExclusive: true}},
	},
	{
		ID: "CVE-2022-0543", Vendor: "redis", Title: "Lua sandbox escape in Debian-packaged Redis", Severity: "CRITICAL", CVSS: 10.0,
		Fixed: "distribution update", TTP: "T1190", CNVD: "", Reference: "https://nvd.nist.gov/vuln/detail/CVE-2022-0543",
		Ranges: []vecRange{{min: "5.0.0", max: "6.2.99"}},
	},
}

func matchVecCVEs(vendor, version string) []vecCVE {
	parsed, ok := parseVecVersion(version)
	if !ok {
		return nil
	}
	var matches []vecCVE
	for _, entry := range vecCVEs {
		if entry.Vendor != vendor {
			continue
		}
		for _, versionRange := range entry.Ranges {
			if vecInRange(parsed, versionRange) {
				matches = append(matches, entry)
				break
			}
		}
	}
	return matches
}

func vecInRange(version [3]int, versionRange vecRange) bool {
	if versionRange.min != "" {
		minimum, ok := parseVecVersion(versionRange.min)
		if ok && vecCompareVersions(version, minimum) < 0 {
			return false
		}
	}
	if versionRange.max != "" {
		maximum, ok := parseVecVersion(versionRange.max)
		if ok {
			comparison := vecCompareVersions(version, maximum)
			if versionRange.maxExclusive && comparison >= 0 {
				return false
			}
			if !versionRange.maxExclusive && comparison > 0 {
				return false
			}
		}
	}
	return true
}

func parseVecVersion(value string) ([3]int, bool) {
	match := vecVersionRE.FindString(strings.TrimSpace(value))
	if match == "" {
		return [3]int{}, false
	}
	segments := strings.Split(match, ".")
	var parsed [3]int
	for i := 0; i < len(segments) && i < 3; i++ {
		number, err := strconv.Atoi(segments[i])
		if err != nil {
			return [3]int{}, false
		}
		parsed[i] = number
	}
	return parsed, true
}

func vecCompareVersions(left, right [3]int) int {
	for i := 0; i < 3; i++ {
		if left[i] < right[i] {
			return -1
		}
		if left[i] > right[i] {
			return 1
		}
	}
	return 0
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

func renderVecmapReport(raw, adapter string, deep bool, results []vecResult, evidencePath string, writeErr error) string {
	lines := []string{
		"vecmap — VECTOR DATABASE ATTACK-SURFACE ASSESSMENT",
		"=================================================",
		"Input: " + sanitizeVecText(redactVecURL(raw), 200),
		"Adapter: " + adapter,
		"Mode: " + vecModeLine(deep),
		fmt.Sprintf("Targets evaluated: %d (bounded CIDR sweep stops at the first identified vendor)", len(results)),
		"",
	}

	for index, result := range results {
		if len(results) > 1 {
			lines = append(lines, fmt.Sprintf("[%d] %s", index+1, result.target.baseURL))
		}
		lines = append(lines,
			"Target: "+sanitizeVecText(result.target.baseURL, 200),
			"Vendor: "+vecVendorLine(result),
			"Version: "+vecVersionLine(result),
			"Authentication: "+vecAuthLine(result),
			"Unauthenticated read surface: "+vecExposureLine(result),
		)
		if result.grpc.port > 0 {
			lines = append(lines, "gRPC: "+vecGRPCLine(result.grpc))
		}
		if result.pg.detail != "" {
			lines = append(lines, "PostgreSQL/pgvector: "+sanitizeVecText(result.pg.detail, 220))
		}
		lines = append(lines, "", "Collections / indexes:")
		if len(result.collections) == 0 {
			lines = append(lines, "  (none enumerated — authentication, adapter mismatch or empty deployment)")
		} else {
			lines = append(lines, "  NAME | COUNT | DIM | METRIC | INDEX | SAMPLED | SAMPLE KEYS")
			for _, collection := range limitVecCollections(result.collections, vecmapMaxColls) {
				lines = append(lines, fmt.Sprintf("  %s | %s | %s | %s | %s | %s | %s",
					sanitizeVecText(collection.Name, 60),
					countOrUnknown(collection.Count),
					dimensionOrUnknown(collection.Dimension),
					orDash(collection.Metric),
					orDash(collection.IndexType),
					sampledOrDash(collection.Sampled),
					orDash(strings.Join(collection.SampleKeys, ",")),
				))
			}
		}

		lines = append(lines, "", "CVE / CNVD correlation:")
		if len(result.cves) == 0 {
			if result.version == "" {
				lines = append(lines, "  not assessed — version unknown; no guess was made from a product name")
			} else {
				lines = append(lines, "  no built-in advisory range matched the observed version")
			}
		} else {
			for _, entry := range result.cves {
				cnvd := ""
				if entry.CNVD != "" {
					cnvd = " / " + entry.CNVD
				}
				lines = append(lines, fmt.Sprintf("  - %s%s (CVSS %.1f, %s): %s; fixed: %s", entry.ID, cnvd, entry.CVSS, entry.Severity, entry.Title, entry.Fixed))
			}
		}

		lines = append(lines, "", "ATT&CK:")
		for _, item := range vecATTACK(result) {
			lines = append(lines, "  - "+item)
		}

		if len(result.errors) > 0 {
			lines = append(lines, "", "Notes:")
			for _, note := range result.errors {
				lines = append(lines, "  - "+sanitizeVecText(note, 220))
			}
		}
		lines = append(lines,
			"",
			fmt.Sprintf("Read-only guard: %d requests issued, %d destructive request(s) rejected before execution.", result.attempts, result.blocked),
		)
		if index != len(results)-1 {
			lines = append(lines, "")
		}
	}

	lines = append(lines, "", "Evidence:")
	if writeErr != nil {
		lines = append(lines, "  write failed: "+sanitizeVecText(writeErr.Error(), 220))
	} else {
		lines = append(lines, "  "+evidencePath+" (SQLite, WAL journal mode)")
	}
	lines = append(lines,
		"  Every HTTP/TCP/gRPC probe above is persisted locally with redacted URLs; no body content or credentials are stored.",
		"",
		"Safety: vector-database enumeration is read-only. No delete, drop, upsert, insert, update, snapshot-create, compact, flush or management-stop path was invoked.",
		"Authorized testing only. Version evidence and record counts cover only the endpoints that answered during this run.",
	)
	return strings.Join(lines, "\n")
}

func vecModeLine(deep bool) string {
	if deep {
		return "deep (schema enumeration + bounded record sampling, max 5 records/collection)"
	}
	return "standard (fingerprint + read-only schema enumeration; pass deep=true for bounded sampling)"
}

func vecVendorLine(result vecResult) string {
	if result.vendor == "" {
		return "unknown (no fingerprint matched)"
	}
	if display, ok := vecVendorByID(result.vendor); ok {
		return display.display + " (confidence: " + result.confidence + ")"
	}
	return result.vendor
}

func vecVersionLine(result vecResult) string {
	if result.version == "" {
		return "unknown / not exposed by the read-only surface"
	}
	return sanitizeVecText(result.version, 60)
}

func vecAuthLine(result vecResult) string {
	if result.authRequired {
		return "enforced (401/403 observed)"
	}
	return "not enforced or not observable from the read-only surface"
}

func vecExposureLine(result vecResult) string {
	if result.exposed {
		return "YES — collections and/or records were readable without credentials"
	}
	if result.vendor == "" {
		return "UNKNOWN"
	}
	if result.authRequired {
		return "NO (authentication wall on the probed endpoints)"
	}
	return "NO (no unauthenticated collection/record data returned)"
}

func vecGRPCLine(result vecGRPCResult) string {
	state := "reachable"
	if result.reflection {
		state = "reflection responded"
	} else if !result.reachable {
		state = "unreachable"
	}
	line := fmt.Sprintf("%s (port %d)", state, result.port)
	if len(result.services) > 0 {
		line += "; services=" + strings.Join(result.services, ",")
	}
	if result.detail != "" {
		line += " — " + result.detail
	}
	return line
}

func vecATTACK(result vecResult) []string {
	items := []string{
		"T1595 Active Scanning (Reconnaissance) — bounded read-only probes against the vector surface. https://attack.mitre.org/techniques/T1595/",
		"T1595.002 Active Scanning: Vulnerability Scanning (Reconnaissance) — read-only CVE correlation against the observed version. https://attack.mitre.org/techniques/T1595/002/",
		"T1592 Gather Victim Host Information (Reconnaissance) — product, version, schema and deployment metadata read from responses. https://attack.mitre.org/techniques/T1592/",
	}
	if result.exposed {
		items = append(items, "T1213 Data from Information Repositories (Collection) — collection metadata and bounded records were readable without credentials. https://attack.mitre.org/techniques/T1213/")
	}
	if len(result.cves) > 0 {
		items = append(items, "T1190 Exploit Public-Facing Application (Initial Access) — a public advisory range matches the observed version; validate under separate authorization. https://attack.mitre.org/techniques/T1190/")
	}
	for _, entry := range result.cves {
		if entry.TTP == "T1078" {
			items = append(items, "T1078 Valid Accounts (Defense Evasion / Persistence) — the matched advisory is an authentication/authorization bypass. https://attack.mitre.org/techniques/T1078/")
			break
		}
	}
	if result.grpc.reflection {
		items = append(items, "T1046 Network Service Discovery (Discovery) — gRPC reflection exposed service names. https://attack.mitre.org/techniques/T1046/")
	}
	return uniqueVecStrings(items)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func decodeVecItems(body []byte) []any {
	if array, err := decodeVecJSONArray(body); err == nil {
		return array
	}
	data := decodeVecJSONMap(body)
	if items := anySlice(data["collections"]); len(items) > 0 {
		return items
	}
	if items := anySlice(data["data"]); len(items) > 0 {
		return items
	}
	return nil
}

func responseBodyOf(response *vecResponse) []byte {
	if response == nil {
		return nil
	}
	return response.body
}

func decodeVecJSONMap(body []byte) map[string]any {
	var value map[string]any
	if err := json.Unmarshal(body, &value); err != nil {
		return map[string]any{}
	}
	return value
}

func decodeVecJSONArray(body []byte) ([]any, error) {
	var value []any
	if err := json.Unmarshal(body, &value); err != nil {
		return nil, err
	}
	return value, nil
}

func anySlice(value any) []any {
	result, _ := value.([]any)
	return result
}

func stringField(value map[string]any, key string) string {
	if value == nil {
		return ""
	}
	item, ok := value[key]
	if !ok {
		return ""
	}
	switch typed := item.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	case float64:
		if typed == float64(int64(typed)) {
			return strconv.FormatInt(int64(typed), 10)
		}
		return strconv.FormatFloat(typed, 'f', -1, 64)
	default:
		return ""
	}
}

func nestedStringField(value map[string]any, outer, inner string) string {
	nested, ok := value[outer].(map[string]any)
	if !ok {
		return ""
	}
	return stringField(nested, inner)
}

func firstStringField(value map[string]any, keys ...string) string {
	for _, key := range keys {
		if result := stringField(value, key); result != "" {
			return result
		}
	}
	return ""
}

func int64Field(value map[string]any, key string) int64 {
	item, ok := value[key]
	if !ok {
		return 0
	}
	switch typed := item.(type) {
	case float64:
		return int64(typed)
	case int64:
		return typed
	case json.Number:
		number, _ := typed.Int64()
		return number
	case string:
		number, _ := strconv.ParseInt(strings.TrimSpace(typed), 10, 64)
		return number
	default:
		return 0
	}
}

func parseInt64(value string) int64 {
	number, _ := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	return number
}

func sortedKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedKeysFromMap(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func uniqueVecStrings(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func limitStrings(values []string, limit int) []string {
	if len(values) <= limit {
		return values
	}
	return values[:limit]
}

func limitVecCollections(values []vecCollection, limit int) []vecCollection {
	if len(values) <= limit {
		return values
	}
	return values[:limit]
}

func stringSliceFromMaps(values []any, key string) []string {
	var result []string
	for _, value := range values {
		if entry, ok := value.(map[string]any); ok {
			if name := stringField(entry, key); name != "" {
				result = append(result, name)
			}
		}
	}
	return result
}

func nestedFieldNames(mappings map[string]any) []string {
	properties, ok := mappings["properties"].(map[string]any)
	if !ok {
		return nil
	}
	keys := sortedKeysFromMap(properties)
	return keys
}

func vectorDimensionFromMapping(mappings map[string]any) int {
	properties, ok := mappings["properties"].(map[string]any)
	if !ok {
		return 0
	}
	for _, value := range properties {
		entry, ok := value.(map[string]any)
		if !ok {
			continue
		}
		if dimension := int(int64Field(entry, "dims")); dimension > 0 {
			return dimension
		}
		if dimension := int(int64Field(entry, "dimension")); dimension > 0 {
			return dimension
		}
		if parameters, ok := entry["index_options"].(map[string]any); ok {
			if dimension := int(int64Field(parameters, "dims")); dimension > 0 {
				return dimension
			}
		}
	}
	return 0
}

func hasVecHeaderPrefix(headers http.Header, prefix string) bool {
	lowerPrefix := strings.ToLower(prefix)
	for key := range headers {
		if strings.HasPrefix(strings.ToLower(key), lowerPrefix) {
			return true
		}
	}
	return false
}

func versionFromServer(server, marker string) string {
	index := strings.Index(server, marker)
	if index < 0 {
		return ""
	}
	return vecVersionRE.FindString(server[index+len(marker):])
}

func countOrUnknown(value int64) string {
	if value <= 0 {
		return "?"
	}
	return strconv.FormatInt(value, 10)
}

func dimensionOrUnknown(value int) string {
	if value <= 0 {
		return "?"
	}
	return strconv.Itoa(value)
}

func sampledOrDash(value int) string {
	if value <= 0 {
		return "-"
	}
	return strconv.Itoa(value)
}

func orDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func sanitizeVecText(value string, max int) string {
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

func parseVecBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on", "y":
		return true
	default:
		return false
	}
}

// ---------------------------------------------------------------------------
// Pure-Go SQLite (WAL) evidence writer
// ---------------------------------------------------------------------------

const vecSQLitePageSize = 65536

var vecEvidenceSchema = "CREATE TABLE evidence (id INTEGER PRIMARY KEY, ts TEXT NOT NULL, phase TEXT, method TEXT, path TEXT, status INTEGER, detail TEXT)"

func writeVecEvidence(dir string, rows []vecEvidence) (string, error) {
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	suffix := make([]byte, 2)
	if _, err := rand.Read(suffix); err != nil {
		copy(suffix, []byte{0, 1})
	}
	name := "vecmap-evidence-" + time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(suffix) + ".sqlite"
	path := filepath.Join(dir, name)

	// Keep the leaf page inside its capacity; detail is already bounded.
	if len(rows) > 90 {
		rows = rows[:90]
	}
	schemaRecord := encodeVecSQLiteRecord([]any{"table", "evidence", "evidence", int64(2), vecEvidenceSchema})
	pageOneCells := [][]byte{encodeVecSQLiteCell(1, schemaRecord)}
	cells := make([][]byte, 0, len(rows))
	for index, row := range rows {
		record := encodeVecSQLiteRecord([]any{
			nil,
			row.ts,
			row.phase,
			row.method,
			row.path,
			int64(row.status),
			sanitizeVecText(row.detail, 300),
		})
		cells = append(cells, encodeVecSQLiteCell(int64(index+1), record))
	}

	pageOneCells = fitVecSQLiteCells(pageOneCells, 100)
	cells = fitVecSQLiteCells(cells, 0)
	pageOne := buildVecSQLiteLeaf(pageOneCells, true)
	header := make([]byte, 100)
	copy(header, "SQLite format 3\x00")
	binary.BigEndian.PutUint16(header[16:], 1) // 65536-byte page size is encoded as 1
	header[18], header[19] = 2, 2              // WAL journal mode (write/read version)
	header[21], header[22], header[23] = 64, 32, 32
	binary.BigEndian.PutUint32(header[24:], 1) // change counter
	binary.BigEndian.PutUint32(header[28:], 2) // database size in pages
	binary.BigEndian.PutUint32(header[40:], 1) // schema cookie
	binary.BigEndian.PutUint32(header[44:], 4) // schema format
	binary.BigEndian.PutUint32(header[56:], 1) // UTF-8
	binary.BigEndian.PutUint32(header[92:], 1) // version-valid-for
	binary.BigEndian.PutUint32(header[96:], 3046000)
	copy(pageOne, header)

	if len(cells) == 0 {
		cells = [][]byte{encodeVecSQLiteCell(1, encodeVecSQLiteRecord([]any{nil, time.Now().UTC().Format(time.RFC3339), "session", "NONE", "no probes recorded", int64(0), "empty run"}))}
	}
	pageTwo := buildVecSQLiteLeaf(cells, false)

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = file.Close()
	}()
	if _, err := file.Write(pageOne); err != nil {
		return "", err
	}
	if _, err := file.Write(pageTwo); err != nil {
		return "", err
	}
	return path, nil
}

func fitVecSQLiteCells(cells [][]byte, reserved int) [][]byte {
	limit := vecSQLitePageSize - reserved - 200
	for len(cells) > 0 {
		total := 0
		for _, cell := range cells {
			total += len(cell) + 2
		}
		if total <= limit {
			return cells
		}
		cells = cells[:len(cells)-1]
	}
	return cells
}

func buildVecSQLiteLeaf(cells [][]byte, pageOne bool) []byte {
	page := make([]byte, vecSQLitePageSize)
	headerOffset := 0
	if pageOne {
		headerOffset = 100
	}
	page[headerOffset] = 0x0D // table b-tree leaf
	binary.BigEndian.PutUint16(page[headerOffset+3:], uint16(len(cells)))
	position := vecSQLitePageSize
	for index, cell := range cells {
		position -= len(cell)
		copy(page[position:], cell)
		binary.BigEndian.PutUint16(page[headerOffset+8+2*index:], uint16(position))
	}
	if position == vecSQLitePageSize {
		position = 0
	}
	binary.BigEndian.PutUint16(page[headerOffset+5:], uint16(position))
	return page
}

func encodeVecSQLiteCell(rowID int64, payload []byte) []byte {
	cell := appendVecVarint(nil, uint64(len(payload)))
	cell = appendVecVarint(cell, uint64(rowID))
	return append(cell, payload...)
}

func encodeVecSQLiteRecord(values []any) []byte {
	serials := make([]uint64, 0, len(values))
	body := make([]byte, 0, 128)
	for _, value := range values {
		switch typed := value.(type) {
		case nil:
			serials = append(serials, 0)
		case int64:
			serials = append(serials, 6)
			var buffer [8]byte
			binary.BigEndian.PutUint64(buffer[:], uint64(typed))
			body = append(body, buffer[:]...)
		case string:
			serials = append(serials, uint64(13+2*len(typed)))
			body = append(body, []byte(typed)...)
		default:
			serials = append(serials, 0)
		}
	}
	headerSize := 0
	var header []byte
	for {
		candidate := appendVecVarint(nil, uint64(headerSize))
		for _, serial := range serials {
			candidate = appendVecVarint(candidate, serial)
		}
		if len(candidate) == headerSize {
			header = candidate
			break
		}
		headerSize = len(candidate)
	}
	return append(header, body...)
}

func appendVecVarint(dst []byte, value uint64) []byte {
	if value <= 0x7f {
		return append(dst, byte(value))
	}
	var buffer [9]byte
	count := 0
	for value > 0 {
		buffer[count] = byte(value & 0x7f)
		value >>= 7
		count++
	}
	for index := count - 1; index >= 0; index-- {
		current := buffer[index]
		if index != 0 {
			current |= 0x80
		}
		dst = append(dst, current)
	}
	return dst
}

func main() {
	sdk.RunModule(&VecmapModule{})
}
