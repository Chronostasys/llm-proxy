package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"llm-proxy/internal/config"
)

func TestBuildUpstreamRequest_DisguiseAddsBetaTrue(t *testing.T) {
	provider := config.ProviderConfig{
		Type:            config.ProviderTypeAnthropic,
		UpstreamBaseURL: "https://api.anthropic.com",
		UpstreamAPIKey:  "sk-test",
		Disguise:        config.DisguiseConfig{Enabled: true},
	}

	req := httptest.NewRequest(http.MethodPost, "/anthropic/v1/messages", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer proxy-token")

	target, _ := buildUpstreamURL(provider.UpstreamBaseURL, "/v1/messages", "")
	upstream, err := buildUpstreamRequest(req, target, provider)
	if err != nil {
		t.Fatalf("buildUpstreamRequest() error = %v", err)
	}

	if got := upstream.URL.Query().Get("beta"); got != "true" {
		t.Errorf("query beta = %q, want %q", got, "true")
	}
}

func TestBuildUpstreamRequest_DisguisePreservesExistingQuery(t *testing.T) {
	provider := config.ProviderConfig{
		Type:            config.ProviderTypeAnthropic,
		UpstreamBaseURL: "https://api.anthropic.com",
		UpstreamAPIKey:  "sk-test",
		Disguise:        config.DisguiseConfig{Enabled: true},
	}

	req := httptest.NewRequest(http.MethodPost, "/anthropic/v1/messages?stream=true", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer proxy-token")

	target, _ := buildUpstreamURL(provider.UpstreamBaseURL, "/v1/messages", "stream=true")
	upstream, err := buildUpstreamRequest(req, target, provider)
	if err != nil {
		t.Fatalf("buildUpstreamRequest() error = %v", err)
	}

	if got := upstream.URL.Query().Get("beta"); got != "true" {
		t.Errorf("query beta = %q, want %q", got, "true")
	}
	if got := upstream.URL.Query().Get("stream"); got != "true" {
		t.Errorf("query stream should be preserved, got %q", got)
	}
}

func TestBuildUpstreamRequest_NoDisguiseNoBeta(t *testing.T) {
	provider := config.ProviderConfig{
		Type:            config.ProviderTypeAnthropic,
		UpstreamBaseURL: "https://api.anthropic.com",
		UpstreamAPIKey:  "sk-test",
		Disguise:        config.DisguiseConfig{Enabled: false},
	}

	req := httptest.NewRequest(http.MethodPost, "/anthropic/v1/messages", strings.NewReader(`{}`))
	req.Header.Set("x-api-key", "proxy-token")

	target, _ := buildUpstreamURL(provider.UpstreamBaseURL, "/v1/messages", "")
	upstream, err := buildUpstreamRequest(req, target, provider)
	if err != nil {
		t.Fatalf("buildUpstreamRequest() error = %v", err)
	}

	if got := upstream.URL.Query().Get("beta"); got != "" {
		t.Errorf("query beta should not be injected when disguise disabled, got %q", got)
	}
}

func TestBuildUpstreamRequest_DisguiseCompleteFingerprint(t *testing.T) {
	provider := config.ProviderConfig{
		Type:            config.ProviderTypeAnthropic,
		UpstreamBaseURL: "https://api.anthropic.com",
		UpstreamAPIKey:  "sk-test-key",
		Disguise:        config.DisguiseConfig{Enabled: true},
	}

	req := httptest.NewRequest(http.MethodPost, "/anthropic/v1/messages", strings.NewReader(`{"model":"claude-sonnet-4-5"}`))
	req.Header.Set("Authorization", "Bearer proxy-token")
	req.Header.Set("User-Agent", "MyClient/1.0")
	req.Header.Set("X-Custom", "should-be-gone")

	target, _ := buildUpstreamURL(provider.UpstreamBaseURL, "/v1/messages", "")
	upstream, err := buildUpstreamRequest(req, target, provider)
	if err != nil {
		t.Fatalf("buildUpstreamRequest() error = %v", err)
	}

	h := upstream.Header

	// Must have Claude Code UA.
	if got := h.Get("User-Agent"); got != "claude-cli/2.1.51 (external, sdk-cli)" {
		t.Errorf("User-Agent = %q, want Claude Code UA", got)
	}
	// Must have x-api-key (not Authorization).
	if got := h.Get("x-api-key"); got != "sk-test-key" {
		t.Errorf("x-api-key = %q, want upstream key", got)
	}
	if got := h.Get("Authorization"); got != "" {
		t.Errorf("Authorization should be empty, got %q", got)
	}
	// Must have Stainless headers.
	if got := h.Get("X-Stainless-Lang"); got != "js" {
		t.Errorf("X-Stainless-Lang = %q, want js", got)
	}
	if got := h.Get("X-Stainless-Package-Version"); got != "0.74.0" {
		t.Errorf("X-Stainless-Package-Version = %q, want 0.74.0", got)
	}
	// Must have Claude Code identity headers.
	if got := h.Get("x-app"); got != "cli" {
		t.Errorf("x-app = %q, want cli", got)
	}
	if got := h.Get("anthropic-dangerous-direct-browser-access"); got != "true" {
		t.Errorf("anthropic-dangerous-direct-browser-access = %q, want true", got)
	}
	// Must have beta flags.
	if got := h.Get("anthropic-beta"); !strings.Contains(got, "claude-code-20250219") {
		t.Errorf("anthropic-beta should contain claude-code flag: %q", got)
	}
	// Custom header must be gone.
	if got := h.Get("X-Custom"); got != "" {
		t.Errorf("X-Custom should be stripped, got %q", got)
	}
}

func TestBuildUpstreamURL_OriginalBehavior(t *testing.T) {
	// Verify original URL building is unchanged (no beta stripping).
	target, err := buildUpstreamURL("https://api.anthropic.com", "/v1/messages", "beta=true")
	if err != nil {
		t.Fatalf("buildUpstreamURL() error = %v", err)
	}
	if got := target.String(); got != "https://api.anthropic.com/v1/messages?beta=true" {
		t.Fatalf("target.String() = %q, want beta=true preserved", got)
	}
}
