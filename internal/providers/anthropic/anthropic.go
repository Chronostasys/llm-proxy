package anthropic

import (
	"net/http"

	"llm-proxy/internal/config"
)

func ApplyHeaders(headers http.Header, provider config.ProviderConfig) {
	headers.Del("Authorization")
	headers.Set("x-api-key", provider.UpstreamAPIKey)
	applyStaticHeaders(headers, provider.UpstreamHeaders)

	if provider.Disguise.Enabled {
		applyDisguiseHeaders(headers, provider.UpstreamAPIKey)
	}
}

func applyStaticHeaders(headers http.Header, values map[string]string) {
	for key, value := range values {
		headers.Set(key, value)
	}
}

// applyDisguiseHeaders wipes every header and replaces them with the exact
// fingerprint of a genuine Claude Code CLI request. Values are hard-coded
// from a real mitmproxy capture — no user configuration needed.
//
// Captured from: claude-cli/2.1.51, Anthropic SDK 0.74.0, Node.js v24.3.0.
func applyDisguiseHeaders(headers http.Header, apiKey string) {
	// Nuke everything.
	for key := range headers {
		delete(headers, key)
	}

	// Rebuild with the exact Claude Code CLI fingerprint.
	headers.Set("Accept", "application/json")
	headers.Set("Content-Type", "application/json")
	headers.Set("User-Agent", "claude-cli/2.1.51 (external, sdk-cli)")
	headers.Set("X-Stainless-Arch", "x64")
	headers.Set("X-Stainless-Lang", "js")
	headers.Set("X-Stainless-OS", "Linux")
	headers.Set("X-Stainless-Package-Version", "0.74.0")
	headers.Set("X-Stainless-Retry-Count", "0")
	headers.Set("X-Stainless-Runtime", "node")
	headers.Set("X-Stainless-Runtime-Version", "v24.3.0")
	headers.Set("X-Stainless-Timeout", "3000")
	headers.Set("anthropic-beta", "claude-code-20250219,interleaved-thinking-2025-05-14,prompt-caching-scope-2026-01-05")
	headers.Set("anthropic-dangerous-direct-browser-access", "true")
	headers.Set("anthropic-version", "2023-06-01")
	headers.Set("x-app", "cli")
	headers.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	headers.Set("x-api-key", apiKey)
}
