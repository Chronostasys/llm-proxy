package anthropic

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"llm-proxy/internal/config"
)

func TestApplyDisguiseHeaders_StripsStainless(t *testing.T) {
	provider := config.ProviderConfig{
		UpstreamAPIKey: "test-key",
		Disguise:       config.DisguiseConfig{Enabled: true},
	}

	h := make(http.Header)
	h.Set("X-Stainless-Lang", "js")
	h.Set("X-Stainless-Runtime", "node")
	h.Set("X-Stainless-Runtime-Version", "v24.3.0")
	h.Set("X-Stainless-Arch", "x64")
	h.Set("X-Stainless-OS", "Linux")
	h.Set("X-Stainless-Package-Version", "0.74.0")
	h.Set("X-Stainless-Retry-Count", "0")
	h.Set("X-Stainless-Timeout", "3000")

	ApplyHeaders(h, provider)

	for _, key := range []string{
		"X-Stainless-Lang", "X-Stainless-Runtime", "X-Stainless-Runtime-Version",
		"X-Stainless-Arch", "X-Stainless-OS", "X-Stainless-Package-Version",
		"X-Stainless-Retry-Count", "X-Stainless-Timeout",
	} {
		if h.Get(key) != "" {
			t.Errorf("header %q should have been removed, got %q", key, h.Get(key))
		}
	}
}

// TestApplyDisguiseHeaders_WhitelistStripsUnknownHeaders verifies that ANY
// header not on the explicit allowlist gets stripped, regardless of name.
// This is the core guarantee: future Claude Code versions may add arbitrary
// headers, but they will never leak through.
func TestApplyDisguiseHeaders_WhitelistStripsUnknownHeaders(t *testing.T) {
	provider := config.ProviderConfig{
		UpstreamAPIKey: "test-key",
		Disguise:       config.DisguiseConfig{Enabled: true},
	}

	// Simulate a future Claude Code version that adds headers we've never seen.
	h := make(http.Header)
	h.Set("User-Agent", "claude-cli/99.0.0 (external, sdk-cli)")
	h.Set("X-Stainless-Lang", "js")
	h.Set("X-Stainless-Package-Version", "99.99.0")
	h.Set("x-app", "cli")
	h.Set("anthropic-dangerous-direct-browser-access", "true")
	h.Set("X-Client-Name", "claude-code")
	h.Set("X-Client-Version", "1.0.26")
	h.Set("X-Unknown-Future-Header", "some-value")
	h.Set("X-Claude-Session-Id", "abc-123")
	h.Set("X-Telemetry-Id", "xyz")
	h.Set("Some-Random-New-Header", "anything")
	// These should survive (on whitelist)
	h.Set("Content-Type", "application/json")
	h.Set("Accept", "application/json")
	h.Set("Anthropic-Version", "2023-06-01")
	h.Set("Anthropic-Beta", "interleaved-thinking-2025-05-14")

	ApplyHeaders(h, provider)

	// Verify all unknown headers are gone.
	unknownHeaders := []string{
		"X-Stainless-Lang", "X-Stainless-Package-Version",
		"x-app", "anthropic-dangerous-direct-browser-access",
		"X-Client-Name", "X-Client-Version",
		"X-Unknown-Future-Header", "X-Claude-Session-Id",
		"X-Telemetry-Id", "Some-Random-New-Header",
	}
	for _, key := range unknownHeaders {
		if v := h.Get(key); v != "" {
			t.Errorf("unknown header %q should be stripped, got %q", key, v)
		}
	}

	// Verify whitelisted headers survive.
	if v := h.Get("Content-Type"); v != "application/json" {
		t.Errorf("Content-Type should survive, got %q", v)
	}
	if v := h.Get("Accept"); v != "application/json" {
		t.Errorf("Accept should survive, got %q", v)
	}
	if v := h.Get("Anthropic-Version"); v != "2023-06-01" {
		t.Errorf("Anthropic-Version should survive, got %q", v)
	}
	if v := h.Get("Anthropic-Beta"); v != "interleaved-thinking-2025-05-14" {
		t.Errorf("Anthropic-Beta should survive (cleaned), got %q", v)
	}

	// Verify no claude-cli in UA.
	ua := h.Get("User-Agent")
	if strings.Contains(ua, "claude") {
		t.Errorf("User-Agent should not contain 'claude': %q", ua)
	}
}

// TestApplyDisguiseHeaders_FullSimulation simulates a complete Claude Code
// request with all known + unknown fingerprints and verifies clean output.
func TestApplyDisguiseHeaders_FullSimulation(t *testing.T) {
	provider := config.ProviderConfig{
		UpstreamAPIKey: "sk-ant-real-key",
		UpstreamHeaders: map[string]string{
			"anthropic-version": "2023-06-01",
		},
		Disguise: config.DisguiseConfig{Enabled: true},
	}

	// Simulate exact headers from Claude Code 2.1.51 capture + future additions.
	h := make(http.Header)
	h.Set("Accept", "application/json")
	h.Set("Authorization", "Bearer client-token") // proxy auth, must be removed
	h.Set("Content-Type", "application/json")
	h.Set("User-Agent", "claude-cli/2.1.114 (external, sdk-cli)")
	h.Set("X-Stainless-Arch", "x64")
	h.Set("X-Stainless-Lang", "js")
	h.Set("X-Stainless-OS", "Linux")
	h.Set("X-Stainless-Package-Version", "0.74.0")
	h.Set("X-Stainless-Retry-Count", "0")
	h.Set("X-Stainless-Runtime", "node")
	h.Set("X-Stainless-Runtime-Version", "v24.3.0")
	h.Set("X-Stainless-Timeout", "3000")
	h.Set("anthropic-beta", "claude-code-20250219,interleaved-thinking-2025-05-14,prompt-caching-scope-2026-01-05")
	h.Set("anthropic-dangerous-direct-browser-access", "true")
	h.Set("anthropic-version", "2023-06-01")
	h.Set("x-app", "cli")
	h.Set("Accept-Encoding", "gzip, deflate, br, zstd")

	ApplyHeaders(h, provider)

	// Must NOT be present.
	forbidden := []string{
		"Authorization", "X-Stainless-Arch", "X-Stainless-Lang",
		"X-Stainless-OS", "X-Stainless-Package-Version",
		"X-Stainless-Retry-Count", "X-Stainless-Runtime",
		"X-Stainless-Runtime-Version", "X-Stainless-Timeout",
		"x-app", "anthropic-dangerous-direct-browser-access",
	}
	for _, key := range forbidden {
		if v := h.Get(key); v != "" {
			t.Errorf("forbidden header %q leaked: %q", key, v)
		}
	}

	// Must be present and correct.
	if v := h.Get("x-api-key"); v != "sk-ant-real-key" {
		t.Errorf("x-api-key = %q, want upstream key", v)
	}
	if v := h.Get("anthropic-version"); v != "2023-06-01" {
		t.Errorf("anthropic-version = %q, want 2023-06-01", v)
	}
	if v := h.Get("Content-Type"); v != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", v)
	}

	// anthropic-beta should have claude-code flags removed.
	beta := h.Get("anthropic-beta")
	if strings.Contains(beta, "claude-code") {
		t.Errorf("anthropic-beta still contains claude-code: %q", beta)
	}
	if !strings.Contains(beta, "interleaved-thinking") {
		t.Errorf("anthropic-beta should preserve non-code flags: %q", beta)
	}

	// User-Agent must look like a browser.
	ua := h.Get("User-Agent")
	if strings.Contains(ua, "claude") {
		t.Errorf("User-Agent still contains 'claude': %q", ua)
	}
	if !strings.Contains(ua, "Chrome") {
		t.Errorf("User-Agent should be Chrome-like: %q", ua)
	}

	// Accept-Encoding must not have zstd.
	ae := h.Get("Accept-Encoding")
	if strings.Contains(ae, "zstd") {
		t.Errorf("Accept-Encoding still contains zstd: %q", ae)
	}
}
func TestApplyDisguiseHeaders_StripsClaudeCodeIdentity(t *testing.T) {
	provider := config.ProviderConfig{
		UpstreamAPIKey: "test-key",
		Disguise:       config.DisguiseConfig{Enabled: true},
	}

	h := make(http.Header)
	h.Set("x-app", "cli")
	h.Set("anthropic-dangerous-direct-browser-access", "true")

	ApplyHeaders(h, provider)

	if v := h.Get("x-app"); v != "" {
		t.Errorf("x-app should be removed, got %q", v)
	}
	if v := h.Get("anthropic-dangerous-direct-browser-access"); v != "" {
		t.Errorf("anthropic-dangerous-direct-browser-access should be removed, got %q", v)
	}
}

func TestApplyDisguiseHeaders_ReplacesUserAgent(t *testing.T) {
	provider := config.ProviderConfig{
		UpstreamAPIKey: "test-key",
		Disguise:       config.DisguiseConfig{Enabled: true},
	}

	h := make(http.Header)
	h.Set("User-Agent", "claude-cli/2.1.51 (external, sdk-cli)")

	ApplyHeaders(h, provider)

	ua := h.Get("User-Agent")
	if strings.Contains(ua, "claude-cli") {
		t.Errorf("User-Agent still contains claude-cli: %q", ua)
	}
	if ua == "" {
		t.Error("User-Agent should not be empty")
	}
	// Should use default Chrome UA
	if !strings.Contains(ua, "Chrome") {
		t.Errorf("User-Agent should be Chrome-like, got %q", ua)
	}
}

func TestApplyDisguiseHeaders_CustomUserAgent(t *testing.T) {
	provider := config.ProviderConfig{
		UpstreamAPIKey: "test-key",
		Disguise: config.DisguiseConfig{
			Enabled:   true,
			UserAgent: "MyBot/1.0",
		},
	}

	h := make(http.Header)
	h.Set("User-Agent", "claude-cli/2.1.51 (external, sdk-cli)")

	ApplyHeaders(h, provider)

	if got := h.Get("User-Agent"); got != "MyBot/1.0" {
		t.Errorf("User-Agent = %q, want %q", got, "MyBot/1.0")
	}
}

func TestApplyDisguiseHeaders_CleansAnthropicBeta(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "removes claude-code flag",
			input: "claude-code-20250219,interleaved-thinking-2025-05-14,prompt-caching-scope-2026-01-05",
			want:  "interleaved-thinking-2025-05-14,prompt-caching-scope-2026-01-05",
		},
		{
			name:  "removes multiple claude-code flags",
			input: "claude-code-20250219,claude-code-v2-20250301,interleaved-thinking-2025-05-14",
			want:  "interleaved-thinking-2025-05-14",
		},
		{
			name:  "no claude-code flags",
			input: "interleaved-thinking-2025-05-14,prompt-caching-2024-07-31",
			want:  "interleaved-thinking-2025-05-14,prompt-caching-2024-07-31",
		},
		{
			name:  "all claude-code flags",
			input: "claude-code-20250219",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := config.ProviderConfig{
				UpstreamAPIKey: "test-key",
				Disguise:       config.DisguiseConfig{Enabled: true},
			}

			h := make(http.Header)
			h.Set("anthropic-beta", tt.input)
			ApplyHeaders(h, provider)

			got := h.Get("anthropic-beta")
			if got != tt.want {
				t.Errorf("anthropic-beta = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestApplyDisguiseHeaders_StripsZstd(t *testing.T) {
	provider := config.ProviderConfig{
		UpstreamAPIKey: "test-key",
		Disguise:       config.DisguiseConfig{Enabled: true},
	}

	h := make(http.Header)
	h.Set("Accept-Encoding", "gzip, deflate, br, zstd")

	ApplyHeaders(h, provider)

	ae := h.Get("Accept-Encoding")
	if strings.Contains(ae, "zstd") {
		t.Errorf("Accept-Encoding should not contain zstd: %q", ae)
	}
	if !strings.Contains(ae, "gzip") || !strings.Contains(ae, "br") {
		t.Errorf("Accept-Encoding should preserve other encodings: %q", ae)
	}
}

func TestApplyDisguiseHeaders_AddsBrowserHeaders(t *testing.T) {
	provider := config.ProviderConfig{
		UpstreamAPIKey: "test-key",
		Disguise:       config.DisguiseConfig{Enabled: true},
	}

	h := make(http.Header)
	ApplyHeaders(h, provider)

	if h.Get("Accept-Language") == "" {
		t.Error("Accept-Language should be set")
	}
	if h.Get("Sec-Fetch-Dest") == "" {
		t.Error("Sec-Fetch-Dest should be set")
	}
	if h.Get("Sec-Fetch-Mode") == "" {
		t.Error("Sec-Fetch-Mode should be set")
	}
	if h.Get("Sec-Fetch-Site") == "" {
		t.Error("Sec-Fetch-Site should be set")
	}
}

func TestApplyDisguiseHeaders_PreservesExistingBrowserHeaders(t *testing.T) {
	provider := config.ProviderConfig{
		UpstreamAPIKey: "test-key",
		Disguise:       config.DisguiseConfig{Enabled: true},
	}

	h := make(http.Header)
	h.Set("Accept-Language", "zh-CN,zh;q=0.9")

	ApplyHeaders(h, provider)

	if got := h.Get("Accept-Language"); got != "zh-CN,zh;q=0.9" {
		t.Errorf("Accept-Language should not be overwritten: got %q", got)
	}
}

func TestApplyDisguiseHeaders_Disabled(t *testing.T) {
	provider := config.ProviderConfig{
		UpstreamAPIKey: "test-key",
		Disguise:       config.DisguiseConfig{Enabled: false},
	}

	h := make(http.Header)
	h.Set("User-Agent", "claude-cli/2.1.51 (external, sdk-cli)")
	h.Set("X-Stainless-Lang", "js")
	h.Set("x-app", "cli")

	ApplyHeaders(h, provider)

	// When disabled, fingerprints should pass through untouched
	if got := h.Get("User-Agent"); got != "claude-cli/2.1.51 (external, sdk-cli)" {
		t.Errorf("User-Agent should be preserved when disguise disabled: got %q", got)
	}
	if h.Get("X-Stainless-Lang") != "js" {
		t.Errorf("X-Stainless-Lang should be preserved when disguise disabled")
	}
	if h.Get("x-app") != "cli" {
		t.Errorf("x-app should be preserved when disguise disabled")
	}
}

func TestDisguiseBody_StripsMetadata(t *testing.T) {
	body := `{"model":"glm-5-turbo","max_tokens":32000,"stream":true,"messages":[],"metadata":{"user_id":"user_abc123_account__session_uuid"},"tools":[]}`
	rc := io.NopCloser(strings.NewReader(body))

	result := DisguiseBody(rc)
	defer result.Close()

	out, _ := io.ReadAll(result)
	s := string(out)

	if strings.Contains(s, "metadata") {
		t.Errorf("metadata should be stripped from body, got: %s", s)
	}
	if strings.Contains(s, "user_id") {
		t.Errorf("user_id should be stripped from body, got: %s", s)
	}
	if !strings.Contains(s, `"model"`) {
		t.Error("other fields should be preserved")
	}
	if !strings.Contains(s, `"stream"`) {
		t.Error("other fields should be preserved")
	}
}

func TestDisguiseBody_NilBody(t *testing.T) {
	result := DisguiseBody(nil)
	if result != nil {
		t.Error("nil body should return nil")
	}
}

func TestDisguiseBody_NonJSONBody(t *testing.T) {
	body := io.NopCloser(strings.NewReader("this is not json"))
	result := DisguiseBody(body)
	defer result.Close()

	out, _ := io.ReadAll(result)
	if string(out) != "this is not json" {
		t.Errorf("non-JSON body should pass through unchanged, got: %s", string(out))
	}
}

func TestDisguiseBody_EmptyBody(t *testing.T) {
	body := io.NopCloser(strings.NewReader(""))
	result := DisguiseBody(body)
	defer result.Close()

	out, _ := io.ReadAll(result)
	if string(out) != "" {
		t.Errorf("empty body should pass through unchanged, got: %q", string(out))
	}
}

func TestDisguiseBody_NoMetadata(t *testing.T) {
	body := `{"model":"glm-5-turbo","max_tokens":32000}`
	rc := io.NopCloser(strings.NewReader(body))
	result := DisguiseBody(rc)
	defer result.Close()

	out, _ := io.ReadAll(result)
	s := string(out)
	if !strings.Contains(s, `"model"`) {
		t.Error("body fields should be preserved when no metadata present")
	}
}

func TestCleanAnthropicBeta(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"a,b,c", "a,b,c"},
		{"claude-code-20250219,b", "b"},
			{"a,claude-code-20250219", "a"},
			{"claude-code-20250219", ""},
			{"claude-code-20250219,claude-code-v2,a", "a"},
		{"", ""},
	}
	for _, tt := range tests {
		got := cleanAnthropicBeta(tt.input)
		if got != tt.want {
			t.Errorf("cleanAnthropicBeta(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestStripZstd(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"gzip, deflate, br, zstd", "gzip, deflate, br"},
		{"gzip, zstd, br", "gzip, br"},
		{"zstd", ""},
		{"gzip, deflate", "gzip, deflate"},
		{"", ""},
	}
	for _, tt := range tests {
		got := stripZstd(tt.input)
		if got != tt.want {
			t.Errorf("stripZstd(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
