// Package main implements the SanTaiZi "php2shell" module.
//
// The module is a passive, GET-only exposure analyzer for the PHP2Shell bug
// class (CVE-2026-109618 / CVE-2026-109619). It ports the triage model from
// github.com/ctkqiang/PHP2ShellPOC2026: root plus random canary probes,
// evidence separation, branch fix floors, access-state classification and
// ATT&CK mapping. The upstream POST/multipart POC is deliberately not ported;
// this module never sends a state-changing request.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"santaizi/sdk"
)

const (
	php2shellName      = "php2shell"
	php2shellUserAgent = "SanTaiZi-php2shell/1.0 (authorized passive triage)"
	php2shellMaxBody   = 512 * 1024
)

var (
	_ sdk.Module = (*PHP2ShellModule)(nil)

	phpHeaderVersionRE = regexp.MustCompile(`(?i)\bPHP/(\d+\.\d+(?:\.\d+)?)`)
	phpBodyVersionRE   = regexp.MustCompile(`(?i)PHP\s+Version\s*[:=]?\s*(\d+\.\d+(?:\.\d+)?)`)
	phpTitleRE         = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	phpPasswordRE      = regexp.MustCompile(`(?i)<input[^>]+type=["']password["']`)
	phpLoginTextRE     = regexp.MustCompile(`(?i)\b(sign in|log in|login|connexion|anmelden|accedi|inloggen|登录|登入)\b`)
	phpLoginPathRE     = regexp.MustCompile(`(?i)/(?:login|log-in|signin|sign-in|auth|sso|cas|oauth|session|connexion|anmelden|entrar|accedi|inloggen)(?:[/?]|$)`)
	phpVersionNumberRE = regexp.MustCompile(`\d+(?:\.\d+){1,3}`)
)

// PHP2ShellModule implements sdk.Module.
type PHP2ShellModule struct {
	sdk.BaseModule
}

// Info advertises the module to the SanTaiZi registry.
func (m *PHP2ShellModule) Info() sdk.ModuleConfig {
	return sdk.ModuleConfig{
		Name:        php2shellName,
		Description: "Passive exposure analyzer for the PHP2Shell bug class (CVE-2026-109618 / CVE-2026-109619). Triage-only.",
		CNVD:        "",
		CVE:         "CVE-2026-109618, CVE-2026-109619",
		Options: []sdk.Option{
			{Name: "target", Type: "string", Required: true, Default: ""},
			{Name: "scope", Type: "string", Required: false, Default: ""},
			{Name: "require_scope", Type: "bool", Required: false, Default: "false"},
			{Name: "exploit", Type: "bool", Required: false, Default: "false"},
		},
	}
}

// Init applies defaults, enforces the scope gate and prints the authorization
// boundary before any network traffic.
func (m *PHP2ShellModule) Init(options map[string]string) error {
	m.Config = map[string]string{
		"target":        "",
		"scope":         "",
		"require_scope": "false",
		"exploit":       "false",
	}
	for key, value := range options {
		m.Config[key] = value
	}

	fmt.Fprintln(os.Stderr, "AUTHORIZED TESTING ONLY: php2shell performs ordinary GET requests against the supplied target. Confirm written authorization, program scope and rate limits first.")

	target := strings.TrimSpace(m.GetOption("target"))
	if target == "" {
		return fmt.Errorf("php2shell: option \"target\" is required")
	}
	normalized, err := normalizePHP2ShellTarget(target)
	if err != nil {
		return err
	}
	m.Config["target"] = normalized

	if parseBoolOption(m.GetOption("require_scope")) && strings.TrimSpace(m.GetOption("scope")) == "" {
		return fmt.Errorf("php2shell: require_scope=true but no scope identifier was supplied; refusing to run")
	}

	return nil
}

// Run performs the passive triage scan and returns a structured report.
func (m *PHP2ShellModule) Run() (string, error) {
	target, err := normalizePHP2ShellTarget(m.GetOption("target"))
	if err != nil {
		return "", err
	}
	scope := strings.TrimSpace(m.GetOption("scope"))
	exploitRequested := parseBoolOption(m.GetOption("exploit"))

	if parseBoolOption(m.GetOption("require_scope")) && scope == "" {
		return "", fmt.Errorf("php2shell: refuse to run without an authorized scope identifier")
	}

	parsed, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("php2shell: parse target: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	token := randomToken()
	probes := buildPHP2ShellProbes(parsed, token)
	client := newPHP2ShellClient()

	results := make([]*phpProbe, 0, len(probes))
	for _, item := range probes {
		if ctx.Err() != nil {
			break
		}
		results = append(results, fetchPHPProbe(ctx, client, item.role, item.rawURL))
		time.Sleep(120 * time.Millisecond)
	}

	root := findProbe(results, "root")
	access := classifyPHPAccess(results, root, token)
	env := analyzePHPEnvironment(results, access)
	version, precision, source, phpDetected := extractPHPVersion(results)
	verdict := assessPHP2Shell(version, precision, source, phpDetected, access, env)

	return renderPHP2ShellReport(target, scope, token, results, access, env, verdict, precision, source, phpDetected, exploitRequested), nil
}

type phpProbeSpec struct {
	role   string
	rawURL string
}

type phpProbe struct {
	role      string
	rawURL    string
	status    int
	header    http.Header
	body      []byte
	title     string
	err       error
	elapsed   time.Duration
	truncated bool
}

type phpAccess struct {
	state  string
	reason string
}

type phpEnvironment struct {
	server         string
	via            string
	edge           string
	cdn            string
	waf            string
	hosting        string
	sapi           string
	sapiRationale  string
	frameworks     []string
	blockPage      string
	blockPageQuote string
}

type phpVerdict struct {
	status     string
	label      string
	answer     string
	reason     string
	confidence string
	version    string
	branch     string
	fixFloor   string
	exposure   string
	exposed    bool
}

func buildPHP2ShellProbes(target *url.URL, token string) []phpProbeSpec {
	origin := target.Scheme + "://" + target.Host + "/"
	specs := []phpProbeSpec{{role: "root", rawURL: target.String()}}

	// A canary belongs beside the target script, not underneath it: for
	// /app/index.php the control path is /app/php2shell-<token>.txt.
	basePath := ""
	escapedPath := target.EscapedPath()
	switch {
	case escapedPath == "" || escapedPath == "/":
	case strings.HasSuffix(escapedPath, "/"):
		basePath = strings.TrimPrefix(strings.TrimSuffix(escapedPath, "/"), "/") + "/"
	default:
		directory := path.Dir(escapedPath)
		if directory != "/" && directory != "." {
			basePath = strings.TrimPrefix(directory, "/") + "/"
		}
	}
	specs = append(specs,
		phpProbeSpec{role: "control-text", rawURL: origin + basePath + "php2shell-" + token + ".txt"},
		phpProbeSpec{role: "control-php", rawURL: origin + basePath + "php2shell-" + token + ".php"},
	)
	if escapedPath == "" || escapedPath == "/" {
		specs = append(specs, phpProbeSpec{role: "index", rawURL: origin + "index.php"})
	}
	return specs
}

func newPHP2ShellClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func fetchPHPProbe(ctx context.Context, client *http.Client, role, rawURL string) *phpProbe {
	probe := &phpProbe{role: role, rawURL: rawURL}
	started := time.Now()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		probe.err = err
		return probe
	}
	request.Header.Set("User-Agent", php2shellUserAgent)
	request.Header.Set("Accept", "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8")

	response, err := client.Do(request)
	probe.elapsed = time.Since(started)
	if err != nil {
		probe.err = err
		return probe
	}
	defer func() {
		_ = response.Body.Close()
	}()

	probe.status = response.StatusCode
	probe.header = response.Header.Clone()

	body, readErr := io.ReadAll(io.LimitReader(response.Body, php2shellMaxBody+1))
	if readErr != nil {
		probe.err = readErr
		return probe
	}
	if len(body) > php2shellMaxBody {
		body = body[:php2shellMaxBody]
		probe.truncated = true
	}
	probe.body = body
	probe.title = extractHTMLTitle(body)
	return probe
}

func extractHTMLTitle(body []byte) string {
	match := phpTitleRE.FindSubmatch(body)
	if len(match) < 2 {
		return ""
	}
	return sanitizePHPEvidence(string(match[1]), 120)
}

func classifyPHPAccess(probes []*phpProbe, root *phpProbe, token string) phpAccess {
	if len(probes) == 0 || root == nil {
		return phpAccess{state: "unknown", reason: "no probe was completed"}
	}

	allErrors := true
	for _, probe := range probes {
		if probe.err == nil {
			allErrors = false
			break
		}
	}
	if allErrors {
		return phpAccess{state: "unreachable", reason: "no usable response from the target"}
	}

	if root.err != nil {
		return phpAccess{state: "unreachable", reason: "the root probe failed: " + sanitizePHPEvidence(root.err.Error(), 180)}
	}

	controls := make([]*phpProbe, 0, len(probes))
	for _, probe := range probes {
		if probe.role != "root" && probe.role != "index" {
			controls = append(controls, probe)
		}
	}

	if root.status == http.StatusTooManyRequests || (anyRateLimited(probes) && onlyRateLimitedOrErrors(probes)) {
		return phpAccess{state: "rate_limited", reason: "the origin returned HTTP 429 (Rate Limit); the scan rate was too high or the edge is throttling"}
	}

	if deniedPHPAccess(root.status) {
		for _, control := range controls {
			if deniedPHPAccess(control.status) {
				return phpAccess{
					state:  "blocked",
					reason: fmt.Sprintf("every probe, including a random control path, returned HTTP %d; the edge denied the scanner before the application answered", root.status),
				}
			}
		}
		for _, control := range controls {
			if control.status == http.StatusNotFound {
				return phpAccess{
					state:  "restricted",
					reason: fmt.Sprintf("the root returned HTTP %d but a random control path returned 404; this is path-level access control, not a blanket edge block", root.status),
				}
			}
		}
		return phpAccess{state: "restricted", reason: fmt.Sprintf("the root returned HTTP %d and the control path behaved differently; the application is reachable but this path is protected", root.status)}
	}

	if isPHPAuthWall(root) {
		return phpAccess{state: "auth_wall", reason: "the site redirects to, or renders, an authentication page; PHP may exist but the surface is behind a login"}
	}

	for _, control := range controls {
		if soft404PHP(root, control, token) {
			return phpAccess{
				state:  "soft_404",
				reason: fmt.Sprintf("a random nonexistent path returned HTTP %d with content similar to the root; catch-all/soft-404 routing makes path status codes untrustworthy", control.status),
			}
		}
	}

	if root.status >= 500 {
		return phpAccess{state: "server_error", reason: "the origin returned HTTP 5xx on the root probe; the application is unhealthy, not necessarily unpatched"}
	}

	return phpAccess{state: "open", reason: "application responded normally"}
}

func anyRateLimited(probes []*phpProbe) bool {
	for _, probe := range probes {
		if probe.status == http.StatusTooManyRequests {
			return true
		}
	}
	return false
}

func onlyRateLimitedOrErrors(probes []*phpProbe) bool {
	for _, probe := range probes {
		if probe.err != nil {
			continue
		}
		if probe.status != http.StatusTooManyRequests {
			return false
		}
	}
	return true
}

func deniedPHPAccess(status int) bool {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusProxyAuthRequired, http.StatusUnavailableForLegalReasons:
		return true
	default:
		return false
	}
}

func isPHPAuthWall(probe *phpProbe) bool {
	if probe == nil || probe.err != nil {
		return false
	}
	if probe.status >= 300 && probe.status < 400 {
		if phpLoginPathRE.MatchString(probe.header.Get("Location")) {
			return true
		}
	}
	if phpLoginTextRE.MatchString(probe.title) {
		return true
	}
	return phpPasswordRE.Match(probe.body)
}

func soft404PHP(root, control *phpProbe, token string) bool {
	if root == nil || control == nil || control.err != nil || control.status != http.StatusOK {
		return false
	}
	if len(control.body) == 0 {
		return false
	}
	if strings.Contains(string(control.body), token) {
		return true
	}
	return bodySimilarity(root.body, control.body) >= 0.80
}

func bodySimilarity(left, right []byte) float64 {
	const sample = 64 * 1024
	if len(left) > sample {
		left = left[:sample]
	}
	if len(right) > sample {
		right = right[:sample]
	}
	if len(left) == 0 || len(right) == 0 {
		return 0
	}

	a := shingleSet(left)
	b := shingleSet(right)
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	intersection := 0
	for item := range a {
		if _, ok := b[item]; ok {
			intersection++
		}
	}
	union := len(a) + len(b) - intersection
	if union == 0 {
		return 0
	}
	return float64(intersection) / float64(union)
}

func shingleSet(body []byte) map[string]struct{} {
	normalized := make([]byte, 0, len(body))
	space := false
	for _, char := range body {
		switch {
		case char == ' ' || char == '\n' || char == '\r' || char == '\t':
			space = true
		case char >= 32 && char <= 126:
			if space && len(normalized) > 0 {
				normalized = append(normalized, ' ')
			}
			space = false
			normalized = append(normalized, char)
		}
	}
	set := make(map[string]struct{})
	const width = 4
	for i := 0; i+width <= len(normalized); i++ {
		set[string(normalized[i:i+width])] = struct{}{}
	}
	return set
}

func analyzePHPEnvironment(probes []*phpProbe, access phpAccess) phpEnvironment {
	headers := make(http.Header)
	for _, probe := range probes {
		if probe.err != nil {
			continue
		}
		for key, values := range probe.header {
			if len(values) > 0 && headers.Get(key) == "" {
				headers.Set(key, strings.Join(values, ", "))
			}
		}
	}
	bodies := phpProbeBodies(probes)

	env := phpEnvironment{
		server: sanitizePHPEvidence(headers.Get("Server"), 160),
		via:    sanitizePHPEvidence(headers.Get("Via"), 160),
	}
	env.edge = detectPHPEdge(headers, env.server)
	env.cdn = detectPHPCDN(headers, env.server, env.via)
	env.frameworks = detectPHPFrameworks(headers, bodies)
	env.blockPage, env.blockPageQuote = detectPHPBlockPage(probes, bodies)
	env.waf = detectPHPWAF(headers, bodies, env.blockPage, access.state)
	env.hosting = detectPHPHosting(headers, env.server)
	env.sapi, env.sapiRationale = detectPHPSAPI(headers, env.server, env.cdn, bodies, access)
	return env
}

func phpProbeBodies(probes []*phpProbe) string {
	var parts []string
	for _, probe := range probes {
		if probe.err != nil || len(probe.body) == 0 {
			continue
		}
		limit := len(probe.body)
		if limit > 4096 {
			limit = 4096
		}
		parts = append(parts, string(probe.body[:limit]))
	}
	return strings.Join(parts, "\n")
}

func detectPHPEdge(headers http.Header, server string) string {
	lower := strings.ToLower(server)
	switch {
	case strings.Contains(lower, "openresty"):
		return "openresty"
	case strings.Contains(lower, "cloudflare"):
		return "cloudflare"
	case strings.Contains(lower, "akamaighost"):
		return "akamai"
	case strings.Contains(lower, "litespeed"):
		return "litespeed"
	case strings.Contains(lower, "nginx"):
		return "nginx"
	case strings.Contains(lower, "apache"):
		return "apache"
	case strings.Contains(lower, "microsoft-iis"), strings.Contains(lower, "iis"):
		return "iis"
	case strings.Contains(lower, "envoy"):
		return "envoy"
	case strings.Contains(lower, "caddy"):
		return "caddy"
	case strings.Contains(lower, "traefik"):
		return "traefik"
	case strings.Contains(lower, "haproxy"):
		return "haproxy"
	case headers.Get("X-Varnish") != "":
		return "varnish"
	case hasPHPHeaderPrefix(headers, "X-Kong-"):
		return "kong"
	case hasPHPHeaderPrefix(headers, "X-Apisix-"), strings.Contains(lower, "apisix"):
		return "apisix"
	case headers.Get("X-Envoy-Upstream-Service-Time") != "":
		return "envoy"
	case strings.Contains(lower, "awselb"):
		return "aws-elb"
	case strings.Contains(lower, "google frontend"), lower == "gws":
		return "google"
	default:
		return ""
	}
}

func detectPHPCDN(headers http.Header, server, via string) string {
	lowerServer := strings.ToLower(server)
	lowerVia := strings.ToLower(via)
	switch {
	case headers.Get("CF-Ray") != "", strings.Contains(lowerServer, "cloudflare"):
		return "cloudflare"
	case headers.Get("X-Amz-Cf-Id") != "", strings.Contains(lowerVia, "cloudfront"), strings.Contains(strings.ToLower(headers.Get("X-Cache")), "cloudfront"):
		return "cloudfront"
	case headers.Get("X-Fastly-Request-Id") != "", strings.Contains(strings.ToLower(headers.Get("X-Served-By")), "fastly"), strings.Contains(lowerVia, "fastly"):
		return "fastly"
	case hasPHPHeaderPrefix(headers, "X-Akamai-"), headers.Get("Akamai-Grn") != "", strings.Contains(lowerServer, "akamai"):
		return "akamai"
	case headers.Get("X-Azure-Ref") != "", headers.Get("X-Msedge-Ref") != "":
		return "azure-front-door"
	case hasPHPHeaderPrefix(headers, "X-Goog-"), strings.Contains(lowerVia, "google"):
		return "google-cloud-cdn"
	case hasPHPHeaderPrefix(headers, "X-Bunny-"), strings.Contains(lowerServer, "bunny"):
		return "bunny"
	case headers.Get("Eagleid") != "", headers.Get("Ali-Swift-Global-Savetime") != "":
		return "alibaba-cloud"
	case headers.Get("X-Nws-Log-Uuid") != "", strings.Contains(lowerServer, "tencent"):
		return "tencent-cloud"
	case hasPHPHeaderPrefix(headers, "X-Vercel-"), strings.Contains(lowerServer, "vercel"):
		return "vercel"
	case headers.Get("X-Nf-Request-Id") != "", strings.Contains(lowerServer, "netlify"):
		return "netlify"
	case hasPHPHeaderPrefix(headers, "X-Kinsta-"):
		return "kinsta"
	case headers.Get("X-Wp-Engine") != "", strings.Contains(lowerServer, "wp engine"):
		return "wp-engine"
	case headers.Get("X-Varnish") != "" && headers.Get("X-Cache") != "":
		return "fastly"
	default:
		return ""
	}
}

func detectPHPWAF(headers http.Header, bodies, blockPage, accessState string) string {
	lowerBodies := strings.ToLower(bodies)
	if blockPage != "" && blockPage != "unidentified" {
		return strings.ToLower(blockPage)
	}
	switch {
	case blockPage == "ovhcloud":
		return "ovhcloud"
	case headers.Get("CF-Ray") != "", headers.Get("CF-Mitigated") != "", strings.Contains(strings.ToLower(headers.Get("Server")), "cloudflare"):
		return "cloudflare"
	case headers.Get("X-Sucuri-Id") != "", strings.Contains(lowerBodies, "sucuri website firewall"):
		return "sucuri"
	case headers.Get("X-Iinfo") != "", strings.Contains(strings.ToLower(headers.Get("X-Cdn")), "incapsula"), strings.Contains(lowerBodies, "incapsula"):
		return "imperva"
	case headers.Get("Akamai-Grn") != "":
		return "akamai"
	case headers.Get("X-Amzn-Waf-Action") != "", strings.Contains(lowerBodies, "aws waf"), strings.Contains(lowerBodies, "request blocked by aws"):
		return "aws-waf"
	case headers.Get("X-Wa-Info") != "", strings.Contains(lowerBodies, "the requested url was rejected"):
		return "f5-big-ip"
	case strings.Contains(strings.ToLower(headers.Get("Server")), "modsecurity"), strings.Contains(lowerBodies, "not acceptable"):
		return "modsecurity"
	case strings.Contains(lowerBodies, "wordfence"):
		return "wordfence"
	case strings.Contains(lowerBodies, "fortiweb"):
		return "fortiweb"
	case strings.Contains(lowerBodies, "barra_counter_session"):
		return "barracuda"
	case accessState == "blocked":
		return "unidentified edge control"
	case accessState == "rate_limited":
		return "rate limiter"
	default:
		return ""
	}
}

func detectPHPHosting(headers http.Header, server string) string {
	lowerServer := strings.ToLower(server)
	switch {
	case headers.Get("X-Ovh-Webhosting-Id") != "":
		return "OVHcloud"
	case hasPHPHeaderPrefix(headers, "X-Cpanel-"), strings.Contains(lowerServer, "cpanel"):
		return "cPanel"
	case strings.Contains(strings.ToLower(headers.Get("X-Powered-By")), "plesklin"), strings.Contains(lowerServer, "plesk"):
		return "Plesk"
	case headers.Get("X-Wp-Engine") != "", strings.Contains(lowerServer, "wp engine"):
		return "WP Engine"
	case hasPHPHeaderPrefix(headers, "X-Kinsta-"):
		return "Kinsta"
	case hasPHPHeaderPrefix(headers, "X-Vercel-"):
		return "Vercel"
	case headers.Get("X-Nf-Request-Id") != "":
		return "Netlify"
	case hasPHPHeaderPrefix(headers, "X-Render-"):
		return "Render"
	case headers.Get("Fly-Request-Id") != "":
		return "Fly.io"
	case strings.Contains(lowerServer, "heroku"):
		return "Heroku"
	case hasPHPHeaderPrefix(headers, "X-Cloudways-"):
		return "Cloudways"
	case hasPHPHeaderPrefix(headers, "X-Platformsh-"):
		return "Platform.sh"
	case hasPHPHeaderPrefix(headers, "X-Acquia-"):
		return "Acquia"
	case hasPHPHeaderPrefix(headers, "X-Pantheon-"):
		return "Pantheon"
	default:
		return ""
	}
}

func detectPHPFrameworks(headers http.Header, bodies string) []string {
	lowerBodies := strings.ToLower(bodies)
	var found []string
	if strings.Contains(lowerBodies, "wp-content") || strings.Contains(lowerBodies, "wp-includes") || strings.Contains(strings.ToLower(headers.Get("X-Powered-By")), "wordpress") {
		found = append(found, "WordPress")
	}
	if strings.Contains(lowerBodies, "drupal") || strings.Contains(strings.ToLower(headers.Get("X-Generator")), "drupal") {
		found = append(found, "Drupal")
	}
	if strings.Contains(lowerBodies, "joomla") || strings.Contains(strings.ToLower(headers.Get("X-Content-Encoded-By")), "joomla") {
		found = append(found, "Joomla")
	}
	if strings.Contains(lowerBodies, "laravel_session") || strings.Contains(strings.ToLower(headers.Get("Set-Cookie")), "laravel_session") {
		found = append(found, "Laravel")
	}
	if strings.Contains(lowerBodies, "symfony") || strings.Contains(strings.ToLower(headers.Get("Set-Cookie")), "symfony") {
		found = append(found, "Symfony")
	}
	if strings.Contains(lowerBodies, "codeigniter") || strings.Contains(strings.ToLower(headers.Get("Set-Cookie")), "ci_session") {
		found = append(found, "CodeIgniter")
	}
	if strings.Contains(lowerBodies, "thinkphp") || strings.Contains(strings.ToLower(headers.Get("Set-Cookie")), "think_lang") {
		found = append(found, "ThinkPHP")
	}
	if strings.Contains(lowerBodies, "yii") || strings.Contains(strings.ToLower(headers.Get("Set-Cookie")), "yii_session") {
		found = append(found, "Yii")
	}
	if strings.Contains(strings.ToLower(headers.Get("Set-Cookie")), "cakephp") {
		found = append(found, "CakePHP")
	}
	return found
}

func detectPHPBlockPage(probes []*phpProbe, bodies string) (string, string) {
	lower := strings.ToLower(bodies)
	switch {
	case strings.Contains(lower, "ovhcloud"):
		return "OVHcloud", "OVHcloud block page"
	case strings.Contains(lower, "attention required") && strings.Contains(lower, "cloudflare"):
		return "Cloudflare", "Attention Required! | Cloudflare"
	case strings.Contains(lower, "sucuri website firewall"):
		return "Sucuri", "Sucuri Website Firewall"
	case strings.Contains(lower, "incapsula"):
		return "Imperva", "Incapsula incident ID"
	case strings.Contains(lower, "aws waf"), strings.Contains(lower, "request blocked by aws"):
		return "AWS WAF", "Request blocked by AWS WAF"
	case strings.Contains(lower, "the requested url was rejected"):
		return "F5 BIG-IP", "The requested URL was rejected"
	case strings.Contains(lower, "wordfence"):
		return "Wordfence", "Wordfence firewall"
	case strings.Contains(lower, "modsecurity"):
		return "ModSecurity", "ModSecurity"
	default:
		for _, probe := range probes {
			if probe.err == nil && deniedPHPAccess(probe.status) {
				quote := probe.title
				if quote == "" {
					quote = sanitizePHPEvidence(string(probe.body), 100)
				}
				return "unidentified", quote
			}
		}
		return "", ""
	}
}

func detectPHPSAPI(headers http.Header, server, cdn string, bodies string, access phpAccess) (string, string) {
	lowerServer := strings.ToLower(server)
	php := phpSurfaceDetected(headers, bodies)

	if !php && access.state != "open" {
		return "unknown", "the edge answered before the origin; the SAPI is not observable from this response"
	}
	switch {
	case strings.Contains(lowerServer, "litespeed"):
		return "litespeed", "LiteSpeed SAPI — affected per the PHP advisory"
	case strings.Contains(lowerServer, "apache") && cdn == "":
		return "mod_php (likely)", "Apache server header with no CDN in front — the highest-risk setup per the PHP team"
	case strings.Contains(lowerServer, "apache"):
		return "mod_php (possible)", "Apache behind " + cdn + "; the origin SAPI is unconfirmed from outside"
	case strings.Contains(lowerServer, "openresty"):
		return "php-fpm (possible)", "openresty is nginx-based and commonly proxies to PHP-FPM; worker affinity is unconfirmed"
	case strings.Contains(lowerServer, "nginx"), headers.Get("X-Fastcgi-Cache") != "":
		return "php-fpm (likely)", "nginx/fastcgi fingerprint — FPM is affected but needs same-worker request pairing"
	case strings.Contains(lowerServer, "iis"):
		return "php-cgi (possible)", "IIS front end with PHP markers — CGI/FastCGI SAPI, worker model unconfirmed"
	case strings.Contains(lowerServer, "caddy"), strings.Contains(lowerServer, "traefik"), strings.Contains(lowerServer, "envoy"):
		if php {
			return "php-fpm (possible)", "reverse-proxy front end with PHP markers — usually proxies to FPM"
		}
	}
	return "unknown", "no SAPI fingerprint exposed"
}

func phpSurfaceDetected(headers http.Header, bodies string) bool {
	if phpHeaderVersionRE.MatchString(headers.Get("X-Powered-By")) || phpHeaderVersionRE.MatchString(headers.Get("Server")) {
		return true
	}
	lower := strings.ToLower(bodies)
	if strings.Contains(lower, "phpinfo()") || strings.Contains(lower, "php version") || strings.Contains(lower, "phpsessid") {
		return true
	}
	if strings.Contains(lower, "wp-content") || strings.Contains(lower, ".php") {
		return true
	}
	return false
}

func extractPHPVersion(probes []*phpProbe) (string, string, string, bool) {
	detected := false
	bestVersion := ""
	bestSource := ""

	for _, probe := range probes {
		if probe.err != nil {
			continue
		}
		if phpSurfaceDetected(probe.header, string(probe.body)) {
			detected = true
		}
		headerNames := []string{"X-Powered-By", "Server"}
		for _, name := range headerNames {
			value := probe.header.Get(name)
			if match := phpHeaderVersionRE.FindStringSubmatch(value); len(match) == 2 {
				if bestVersion == "" || morePrecisePHPVersion(match[1], bestVersion) {
					bestVersion = match[1]
					bestSource = strings.ToLower(name)
				}
			}
		}
		for key, values := range probe.header {
			for _, value := range values {
				if match := phpHeaderVersionRE.FindStringSubmatch(value); len(match) == 2 {
					if bestVersion == "" || morePrecisePHPVersion(match[1], bestVersion) {
						bestVersion = match[1]
						bestSource = strings.ToLower(key)
					}
				}
			}
		}
		if match := phpBodyVersionRE.FindStringSubmatch(string(probe.body)); len(match) == 2 {
			if bestVersion == "" || morePrecisePHPVersion(match[1], bestVersion) {
				bestVersion = match[1]
				bestSource = "response body"
			}
		}
		if strings.Contains(strings.ToLower(string(probe.body)), "phpinfo()") {
			detected = true
		}
	}

	precision := "minor"
	if bestVersion != "" {
		precision = versionPrecision(bestVersion)
	}
	return bestVersion, precision, bestSource, detected
}

func versionPrecision(version string) string {
	if strings.Count(version, ".") >= 2 {
		return "patch"
	}
	return "minor"
}

func morePrecisePHPVersion(candidate, current string) bool {
	return current == "" || (versionPrecision(candidate) == "patch" && versionPrecision(current) != "patch")
}

func assessPHP2Shell(version, precision, source string, phpDetected bool, access phpAccess, env phpEnvironment) phpVerdict {
	switch access.state {
	case "blocked", "unreachable", "rate_limited", "server_error":
		if version != "" {
			verdict := versionedPHPVerdict(version, precision, source, access, env, " — observed on an error response; "+access.reason)
			verdict.confidence = "low"
			return verdict
		}
		return phpVerdict{
			status:     "inconclusive",
			label:      "INCONCLUSIVE",
			answer:     "UNKNOWN",
			reason:     access.reason + " — exposure is unverified, not absent",
			confidence: "low",
			exposure:   "n/a",
		}
	case "restricted":
		if version != "" {
			verdict := versionedPHPVerdict(version, precision, source, access, env, " — root path restricted; "+access.reason)
			verdict.confidence = "low"
			return verdict
		}
		return phpVerdict{
			status:     "inconclusive",
			label:      "INCONCLUSIVE",
			answer:     "UNKNOWN",
			reason:     access.reason + " — the interpreter could not be assessed",
			confidence: "low",
			exposure:   "n/a",
		}
	case "auth_wall":
		if version == "" {
			return phpVerdict{
				status:     "inconclusive",
				label:      "INCONCLUSIVE",
				answer:     "UNKNOWN",
				reason:     access.reason + " — assess the authenticated surface only with authorization",
				confidence: "low",
				exposure:   "n/a",
			}
		}
	case "soft_404":
		if version == "" {
			return phpVerdict{
				status:     "inconclusive",
				label:      "INCONCLUSIVE",
				answer:     "UNKNOWN",
				reason:     access.reason + " — no version header was exposed, so exposure is unverified",
				confidence: "low",
				exposure:   "n/a",
			}
		}
	}

	if version == "" {
		if phpDetected {
			confidence := "low"
			if access.state == "open" {
				confidence = "medium"
			}
			return phpVerdict{
				status:     "unknown",
				label:      "UNVERIFIED",
				answer:     "UNKNOWN",
				reason:     "PHP is present but no version was exposed — exposure is unconfirmed; read the version host-side or from an approved diagnostic page",
				confidence: confidence,
				exposure:   "n/a",
			}
		}
		confidence := "low"
		if access.state == "open" {
			confidence = "medium"
		}
		return phpVerdict{
			status:     "no_php",
			label:      "NO PHP OBSERVED",
			answer:     "NO",
			reason:     "no PHP markers were observed on the reachable paths and the control path behaved normally — no PHP surface found on this route (this is not proof that other vhosts are PHP-free)",
			confidence: confidence,
			exposure:   "0.0",
		}
	}

	return versionedPHPVerdict(version, precision, source, access, env, "")
}

func versionedPHPVerdict(version, precision, source string, access phpAccess, env phpEnvironment, caveat string) phpVerdict {
	verdict := versionedPHPVerdictInner(version, precision, source, access, env, caveat)
	verdict.version = version
	return verdict
}

func versionedPHPVerdictInner(version, precision, source string, access phpAccess, _ phpEnvironment, caveat string) phpVerdict {
	branch := versionBranch(version)
	floor, hasFloor := phpFixedReleases[branch]
	parsed, ok := parsePHPVersion(version)
	if !ok {
		return phpVerdict{
			status:     "unknown",
			label:      "UNVERIFIED",
			answer:     "UNKNOWN",
			reason:     "a PHP version string was observed but could not be parsed (" + sanitizePHPEvidence(version, 40) + ")",
			confidence: "low",
			exposure:   "n/a",
		}
	}

	confidence := "medium"
	if precision == "minor" {
		confidence = "low"
	} else if access.state == "open" {
		if strings.Contains(source, "powered-by") || strings.Contains(source, "server") || strings.Contains(source, "body") {
			confidence = "high"
		}
	}

	if precision == "minor" {
		if phpEOLBranches[branch] {
			return phpVerdict{
				status:     "eol",
				label:      "END-OF-LIFE",
				answer:     "YES",
				reason:     "PHP branch " + branch + " is end-of-life — no upstream fix exists; only distro backports or an upgrade will clear this" + caveat,
				confidence: confidence,
				branch:     branch,
				exposure:   "10.0",
				exposed:    true,
			}
		}
		return phpVerdict{
			status:     "unknown",
			label:      "UNVERIFIED",
			answer:     "UNKNOWN",
			reason:     "only a branch-level version (" + version + ") was exposed; the patch level is unknown — compare against " + floorString(floor, hasFloor) + " host-side" + caveat,
			confidence: "low",
			branch:     branch,
			fixFloor:   floorString(floor, hasFloor),
			exposure:   "n/a",
		}
	}

	if hasFloor {
		if comparePHPVersions(parsed, floor) >= 0 {
			return phpVerdict{
				status:     "patched",
				label:      "PATCHED",
				answer:     "NO",
				reason:     "PHP " + version + " is at or above the " + branch + " fix level (" + floorString(floor, true) + ")" + caveat,
				confidence: confidence,
				branch:     branch,
				fixFloor:   floorString(floor, true),
				exposure:   "0.0",
			}
		}
		return phpVerdict{
			status:     "vulnerable",
			label:      "VULNERABLE",
			answer:     "YES",
			reason:     "PHP " + version + " is below the " + branch + " fix level (" + floorString(floor, true) + ") — update now" + caveat,
			confidence: confidence,
			branch:     branch,
			fixFloor:   floorString(floor, true),
			exposure:   "9.8",
			exposed:    true,
		}
	}

	if phpEOLBranches[branch] {
		return phpVerdict{
			status:     "eol",
			label:      "END-OF-LIFE",
			answer:     "YES",
			reason:     "PHP " + version + " (branch " + branch + ") is end-of-life — no upstream fix exists; only distro backports or an upgrade will clear this" + caveat,
			confidence: confidence,
			branch:     branch,
			exposure:   "10.0",
			exposed:    true,
		}
	}

	if branchNewerThanTable(branch) {
		return phpVerdict{
			status:     "unknown",
			label:      "UNVERIFIED",
			answer:     "UNKNOWN",
			reason:     "PHP " + version + " is newer than this module's fix table (8.5.x) — verify against the current PHP release notes" + caveat,
			confidence: "low",
			branch:     branch,
			exposure:   "n/a",
		}
	}

	return phpVerdict{
		status:     "eol",
		label:      "END-OF-LIFE",
		answer:     "YES",
		reason:     "PHP " + version + " (branch " + branch + ") is outside the supported fix table — treat as end-of-life until a vendor advisory says otherwise" + caveat,
		confidence: confidence,
		branch:     branch,
		exposure:   "10.0",
		exposed:    true,
	}
}

var phpFixedReleases = map[string][3]int{
	"8.2": {8, 2, 35},
	"8.3": {8, 3, 36},
	"8.4": {8, 4, 27},
	"8.5": {8, 5, 12},
}

var phpEOLBranches = map[string]bool{
	"5.0": true, "5.1": true, "5.2": true, "5.3": true, "5.4": true, "5.5": true, "5.6": true,
	"7.0": true, "7.1": true, "7.2": true, "7.3": true, "7.4": true,
	"8.0": true, "8.1": true,
}

func versionBranch(version string) string {
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return version
	}
	return parts[0] + "." + parts[1]
}

func parsePHPVersion(version string) ([3]int, bool) {
	match := phpVersionNumberRE.FindString(version)
	if match == "" {
		return [3]int{}, false
	}
	segments := strings.Split(match, ".")
	var parsed [3]int
	for i := 0; i < len(segments) && i < 3; i++ {
		value, err := strconv.Atoi(segments[i])
		if err != nil {
			return [3]int{}, false
		}
		parsed[i] = value
	}
	return parsed, true
}

func comparePHPVersions(left, right [3]int) int {
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

func branchNewerThanTable(branch string) bool {
	parsed, ok := parsePHPVersion(branch + ".0")
	if !ok {
		return false
	}
	return comparePHPVersions(parsed, [3]int{8, 5, 0}) > 0
}

func floorString(floor [3]int, ok bool) string {
	if !ok {
		return "the branch fix level"
	}
	return fmt.Sprintf("%d.%d.%d", floor[0], floor[1], floor[2])
}

func renderPHP2ShellReport(target, scope, token string, probes []*phpProbe, access phpAccess, env phpEnvironment, verdict phpVerdict, precision, source string, phpDetected, exploitRequested bool) string {
	lines := []string{
		"PHP2Shell — PASSIVE EXPOSURE TRIAGE",
		"=================================",
		"Target: " + sanitizePHPEvidence(redactPHPURL(target), 200),
		"Scope: " + scopeLine(scope),
		"Verdict: " + verdict.answer + " (" + verdict.label + ")",
		"Reason: " + verdict.reason,
		"Confidence: " + verdict.confidence,
		"Exposure severity: " + verdict.exposure + "  (separate from exploit friction)",
		fmt.Sprintf("PHP version: %s", versionLine(verdict, precision, source, phpDetected)),
		"SAPI: " + env.sapi + " — " + env.sapiRationale,
		"Access: " + access.state + " — " + access.reason,
		"Edge: " + orUnknown(env.edge) + " | CDN: " + orUnknown(env.cdn) + " | WAF: " + orUnknown(env.waf) + " | Hosting: " + orUnknown(env.hosting),
		"Framework context: " + listOrUnknown(env.frameworks),
		"",
		"Evidence:",
	}
	for _, probe := range probes {
		lines = append(lines, "  "+describePHPProbe(probe))
	}
	if source != "" {
		lines = append(lines, "  [version] source="+source+" value="+sanitizePHPEvidence(verdict.version, 40))
	}
	if env.blockPage != "" {
		quote := env.blockPageQuote
		if quote == "" {
			quote = "(no page message captured)"
		}
		lines = append(lines, "  [block-page] vendor="+env.blockPage+" message="+sanitizePHPEvidence(quote, 140))
	}

	friction := phpFriction(env, access)
	lines = append(lines,
		"",
		"Exploit friction: "+listOrNone(friction),
		"Request profile: GET only; root + random canaries"+(func() string {
			if strings.Contains(target, "index.php") {
				return "; no extra path appended"
			}
			return "; /index.php included when the target is a site root"
		})()+" (canary token "+token+")",
	)

	if exploitRequested {
		lines = append(lines,
			"Exploit gate: REQUESTED but withheld — this module is triage-only.",
			"  The upstream POST/multipart POC is destructive and is not ported here. Run it only from the upstream tool,",
			"  in an authorized lab, after reading the POC contract and accepting the disruption risk.",
		)
	} else {
		lines = append(lines, "Exploit gate: closed (default). No POST or multipart request was sent.")
	}

	lines = append(lines, "", "ATT&CK assessment path:")
	for _, item := range phpAssessmentTechniques(verdict, env) {
		lines = append(lines, "  - "+item)
	}
	if verdict.exposed {
		lines = append(lines, "", "ATT&CK kill chain (only because exposure was confirmed):")
		for _, item := range phpKillChainTechniques() {
			lines = append(lines, "  - "+item)
		}
	} else {
		lines = append(lines, "", "ATT&CK kill chain: not printed — exposure was not confirmed.")
	}

	lines = append(lines,
		"",
		"Safety: this module performed GET requests only. It did not send a payload, POST body, multipart form or state-changing verb.",
		"Authorized testing only. A NO verdict covers only the routes and version evidence observed.",
	)
	return strings.Join(lines, "\n")
}

func describePHPProbe(probe *phpProbe) string {
	if probe.err != nil {
		return fmt.Sprintf("[%s] GET %s -> ERROR %s", probe.role, sanitizePHPEvidence(redactPHPURL(probe.rawURL), 160), sanitizePHPEvidence(probe.err.Error(), 120))
	}
	contentType := sanitizePHPEvidence(probe.header.Get("Content-Type"), 80)
	if contentType == "" {
		contentType = "unknown"
	}
	line := fmt.Sprintf("[%s] GET %s -> %d (%s, %s, %d ms)", probe.role, sanitizePHPEvidence(redactPHPURL(probe.rawURL), 160), probe.status, contentType, byteCount(len(probe.body)), probe.elapsed.Milliseconds())
	if probe.title != "" {
		line += " title=" + strconv.Quote(probe.title)
	}
	if probe.truncated {
		line += " [body truncated]"
	}
	return line
}

func phpFriction(env phpEnvironment, access phpAccess) []string {
	var friction []string
	if env.waf != "" {
		friction = append(friction, "WAF/edge control: "+env.waf)
	}
	if env.cdn != "" {
		friction = append(friction, "CDN in front: "+env.cdn)
	}
	if access.state == "auth_wall" {
		friction = append(friction, "authentication wall")
	}
	if access.state == "rate_limited" {
		friction = append(friction, "rate limiting")
	}
	if access.state == "soft_404" {
		friction = append(friction, "soft-404/catch-all routing")
	}
	if access.state == "blocked" || access.state == "restricted" {
		friction = append(friction, "edge/path denial")
	}
	if strings.Contains(strings.ToLower(env.sapi), "fpm") {
		friction = append(friction, "FPM worker affinity required for the upstream POC")
	}
	return friction
}

func phpAssessmentTechniques(verdict phpVerdict, env phpEnvironment) []string {
	items := []string{
		"T1595 Active Scanning (Reconnaissance) — ordinary GET requests; no payloads and no state-changing verbs. This scan is visible in web logs. https://attack.mitre.org/techniques/T1595/",
		"T1592 Gather Victim Host Information (Reconnaissance) — response headers, server/edge fingerprint, cookies and framework markers were read passively. https://attack.mitre.org/techniques/T1592/",
	}
	if env.cdn != "" {
		items = append(items,
			"T1596 Search Open Technical Databases (Reconnaissance) — certificate transparency, historical DNS and scan data can reveal the origin behind "+env.cdn+". https://attack.mitre.org/techniques/T1596/",
			"T1590 Gather Victim Network Information (Reconnaissance) — map the origin and confirm it only accepts traffic from the CDN range. https://attack.mitre.org/techniques/T1590/",
		)
	} else if verdict.status == "unknown" || verdict.status == "inconclusive" {
		items = append(items, "T1596 Search Open Technical Databases (Reconnaissance) — corroborate the host and find side assets that expose the same interpreter. https://attack.mitre.org/techniques/T1596/")
	}
	if verdict.status == "no_php" {
		items = append(items, "T1046 Network Service Discovery (Discovery, next step) — an authorized port/service scan may find other web tiers or development servers. https://attack.mitre.org/techniques/T1046/")
	}
	return items
}

func phpKillChainTechniques() []string {
	return []string{
		"T1190 Exploit Public-Facing Application (Initial Access) — one crafted request reaches the parser before application code. https://attack.mitre.org/techniques/T1190/",
		"T1059.004 Command and Scripting Interpreter: Unix Shell (Execution) — confirmed exploit paths run commands as the web worker. https://attack.mitre.org/techniques/T1059/004/",
		"T1505.003 Server Software Component: Web Shell (Persistence) — a long-lived worker makes a webshell drop trivial. https://attack.mitre.org/techniques/T1505/003/",
		"T1005 Data from Local System (Collection) — the disclosure variant leaks process memory: env vars, cloud keys, session material. https://attack.mitre.org/techniques/T1005/",
		"T1082 System Information Discovery (Discovery) — post-exploitation recon blends into ordinary app traffic. https://attack.mitre.org/techniques/T1082/",
		"T1071.001 Application Layer Protocol: Web Protocols (Command and Control) — C2 and exfil blend into HTTPS egress. https://attack.mitre.org/techniques/T1071/001/",
	}
}

func versionLine(verdict phpVerdict, precision, source string, phpDetected bool) string {
	if verdict.status == "no_php" {
		return "none observed (PHP markers absent on reachable routes)"
	}
	if verdict.status == "unknown" && verdict.branch == "" {
		return "present, version hidden (PHP markers observed; no version header/body evidence)"
	}
	if verdict.branch == "" {
		return "not established"
	}
	if precision == "minor" {
		return verdict.branch + " (branch only; patch level unverified)"
	}
	if source == "" {
		return verdict.version + " (source not recorded)"
	}
	if !phpDetected {
		return verdict.version + " (source: " + source + ")"
	}
	return verdict.version + " (source: " + source + ", precision: " + precision + ")"
}

func scopeLine(scope string) string {
	if scope == "" {
		return "not supplied (operator attests authorization)"
	}
	return sanitizePHPEvidence(scope, 80) + " (authorized identifier; this module does not expand it into a network scope)"
}

func listOrUnknown(items []string) string {
	if len(items) == 0 {
		return "unknown"
	}
	return strings.Join(items, ", ")
}

func listOrNone(items []string) string {
	if len(items) == 0 {
		return "none observed"
	}
	return strings.Join(items, "; ")
}

func orUnknown(value string) string {
	if value == "" {
		return "unknown"
	}
	return value
}

func byteCount(size int) string {
	if size >= 1024 {
		return fmt.Sprintf("%.1f KiB", float64(size)/1024)
	}
	return fmt.Sprintf("%d B", size)
}

func sanitizePHPEvidence(value string, max int) string {
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

func redactPHPURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
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

func hasPHPHeaderPrefix(headers http.Header, prefix string) bool {
	lowerPrefix := strings.ToLower(prefix)
	for key := range headers {
		if strings.HasPrefix(strings.ToLower(key), lowerPrefix) {
			return true
		}
	}
	return false
}

func randomToken() string {
	buffer := make([]byte, 4)
	if _, err := rand.Read(buffer); err != nil {
		return fmt.Sprintf("%08x", time.Now().UnixNano())
	}
	return hex.EncodeToString(buffer)
}

func findProbe(probes []*phpProbe, role string) *phpProbe {
	for _, probe := range probes {
		if probe.role == role {
			return probe
		}
	}
	return nil
}

func normalizePHP2ShellTarget(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("php2shell: empty target")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("php2shell: parse target: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("php2shell: unsupported scheme %q (http/https only)", parsed.Scheme)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("php2shell: target has no host")
	}
	if parsed.User != nil {
		return "", fmt.Errorf("php2shell: credentials in the target URL are not supported; use an authorized header out of band")
	}
	return parsed.String(), nil
}

func parseBoolOption(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on", "y":
		return true
	default:
		return false
	}
}

func main() {
	sdk.RunModule(&PHP2ShellModule{})
}
