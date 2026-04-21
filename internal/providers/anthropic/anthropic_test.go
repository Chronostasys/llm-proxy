package anthropic

import (
	"net/http"
	"testing"

	"llm-proxy/internal/config"
)

// exactDisguiseHeaders is the full set of headers that applyDisguiseHeaders must produce.
var exactDisguiseHeaders = map[string]string{
	"Accept":                              "application/json",
	"Content-Type":                        "application/json",
	"User-Agent":                          "claude-cli/2.1.51 (external, sdk-cli)",
	"X-Stainless-Arch":                    "x64",
	"X-Stainless-Lang":                    "js",
	"X-Stainless-OS":                      "Linux",
	"X-Stainless-Package-Version":         "0.74.0",
	"X-Stainless-Retry-Count":             "0",
	"X-Stainless-Runtime":                 "node",
	"X-Stainless-Runtime-Version":         "v24.3.0",
	"X-Stainless-Timeout":                 "3000",
	"anthropic-beta":                      "claude-code-20250219,interleaved-thinking-2025-05-14,prompt-caching-scope-2026-01-05",
	"anthropic-dangerous-direct-browser-access": "true",
	"anthropic-version":                   "2023-06-01",
	"x-app":                               "cli",
	"Accept-Encoding":                     "gzip, deflate, br, zstd",
	"x-api-key":                           "sk-test-upstream-key",
}

func TestApplyDisguiseHeaders_ExactFingerprint(t *testing.T) {
	provider := config.ProviderConfig{
		UpstreamAPIKey: "sk-test-upstream-key",
		Disguise:       config.DisguiseConfig{Enabled: true},
	}

	h := make(http.Header)
	// Simulate a client that sends completely different headers.
	h.Set("User-Agent", "MyRandomClient/3.0")
	h.Set("X-Custom-Header", "should-be-gone")
	h.Set("Accept-Language", "zh-CN")
	h.Set("X-Forwarded-For", "1.2.3.4")

	ApplyHeaders(h, provider)

	// Must have exactly the right number of headers (no extras).
	if len(h) != len(exactDisguiseHeaders) {
		t.Errorf("got %d headers, want %d", len(h), len(exactDisguiseHeaders))
		for k, v := range h {
			t.Logf("  %s: %s", k, v)
		}
	}

	// Every expected header must match exactly.
	for key, want := range exactDisguiseHeaders {
		got := h.Get(key)
		if got != want {
			t.Errorf("header %q = %q, want %q", key, got, want)
		}
	}
}

func TestApplyDisguiseHeaders_NoExtraHeadersLeak(t *testing.T) {
	provider := config.ProviderConfig{
		UpstreamAPIKey: "key",
		Disguise:       config.DisguiseConfig{Enabled: true},
	}

	h := make(http.Header)
	// Throw every possible header at it.
	h.Set("X-Stainless-Lang", "js")
	h.Set("x-app", "cli")
	h.Set("X-Client-Name", "claude-code")
	h.Set("X-Client-Version", "1.0.26")
	h.Set("X-Future-Unknown-Header", "anything")
	h.Set("Authorization", "Bearer old-token")
	h.Set("Cookie", "session=abc")
	h.Set("Sec-Fetch-Dest", "document")
	h.Set("Accept-Language", "en")
	h.Set("X-Real-Ip", "10.0.0.1")

	ApplyHeaders(h, provider)

	// None of the originals should survive.
	forbidden := []string{
		"X-Client-Name", "X-Client-Version", "X-Future-Unknown-Header",
		"Authorization", "Cookie", "Sec-Fetch-Dest", "Accept-Language",
		"X-Real-Ip",
	}
	for _, key := range forbidden {
		if v := h.Get(key); v != "" {
			t.Errorf("forbidden header %q leaked: %q", key, v)
		}
	}
}

func TestApplyDisguiseHeaders_Disabled(t *testing.T) {
	provider := config.ProviderConfig{
		UpstreamAPIKey: "test-key",
		Disguise:       config.DisguiseConfig{Enabled: false},
	}

	h := make(http.Header)
	h.Set("User-Agent", "MyClient/1.0")
	h.Set("X-Custom", "keep-me")
	h.Set("Accept", "text/html")

	ApplyHeaders(h, provider)

	// When disabled, original headers pass through (minus auth).
	if got := h.Get("User-Agent"); got != "MyClient/1.0" {
		t.Errorf("User-Agent should be preserved when disabled: got %q", got)
	}
	if got := h.Get("X-Custom"); got != "keep-me" {
		t.Errorf("X-Custom should be preserved when disabled: got %q", got)
	}
	if got := h.Get("Accept"); got != "text/html" {
		t.Errorf("Accept should be preserved when disabled: got %q", got)
	}
}

func TestApplyDisguiseHeaders_UpstreamHeadersOverridden(t *testing.T) {
	// upstream_headers should NOT override the disguise fingerprint.
	// The disguise wipes everything and hard-codes the values.
	provider := config.ProviderConfig{
		UpstreamAPIKey: "sk-key",
		UpstreamHeaders: map[string]string{
			"anthropic-version": "2024-01-01", // wrong version
		},
		Disguise: config.DisguiseConfig{Enabled: true},
	}

	h := make(http.Header)
	ApplyHeaders(h, provider)

	// Disguise must override to the hard-coded value.
	if got := h.Get("anthropic-version"); got != "2023-06-01" {
		t.Errorf("anthropic-version = %q, want 2023-06-01 (disguise overrides upstream_headers)", got)
	}
}
