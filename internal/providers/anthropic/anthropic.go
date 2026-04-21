package anthropic

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"llm-proxy/internal/config"
)

// DefaultDisguiseUserAgent is used when disguise is enabled but no custom
// User-Agent is configured. Matches a recent Chrome on Windows.
const DefaultDisguiseUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"

func ApplyHeaders(headers http.Header, provider config.ProviderConfig) {
	headers.Del("Authorization")
	headers.Set("x-api-key", provider.UpstreamAPIKey)
	applyStaticHeaders(headers, provider.UpstreamHeaders)

	if provider.Disguise.Enabled {
		applyDisguiseHeaders(headers, provider.Disguise)
	}
}

func applyStaticHeaders(headers http.Header, values map[string]string) {
	for key, value := range values {
		headers.Set(key, value)
	}
}

// applyDisguiseHeaders removes every fingerprint that identifies the caller as
// Claude Code (or any Stainless-generated SDK) and replaces them with values
// that match a typical Anthropic web-console or browser-based client.
func applyDisguiseHeaders(headers http.Header, disguise config.DisguiseConfig) {
	// 1. Strip all X-Stainless-* headers — the single biggest fingerprint.
	for key := range headers {
		if strings.HasPrefix(strings.ToLower(key), "x-stainless-") {
			delete(headers, key)
		}
	}

	// 2. Strip Claude Code identity headers.
	headers.Del("x-app")
	headers.Del("anthropic-dangerous-direct-browser-access")

	// 3. Clean anthropic-beta: remove claude-code-* flags that only Claude Code sends.
	if beta := headers.Get("anthropic-beta"); beta != "" {
		if cleaned := cleanAnthropicBeta(beta); cleaned != "" {
			headers.Set("anthropic-beta", cleaned)
		} else {
			headers.Del("anthropic-beta")
		}
	}

	// 4. Replace User-Agent with a browser-like string.
	ua := disguise.UserAgent
	if ua == "" {
		ua = DefaultDisguiseUserAgent
	}
	headers.Set("User-Agent", ua)

	// 5. Strip zstd from Accept-Encoding — very uncommon outside Node.js.
	if ae := headers.Get("Accept-Encoding"); ae != "" {
		headers.Set("Accept-Encoding", stripZstd(ae))
	}

	// 6. Add browser-typical headers that Claude Code omits.
	if headers.Get("Accept-Language") == "" {
		headers.Set("Accept-Language", "en-US,en;q=0.9")
	}
	if headers.Get("Sec-Fetch-Dest") == "" {
		headers.Set("Sec-Fetch-Dest", "empty")
	}
	if headers.Get("Sec-Fetch-Mode") == "" {
		headers.Set("Sec-Fetch-Mode", "cors")
	}
	if headers.Get("Sec-Fetch-Site") == "" {
		headers.Set("Sec-Fetch-Site", "same-origin")
	}
}

// cleanAnthropicBeta removes claude-code-* beta flags and returns the rest.
func cleanAnthropicBeta(beta string) string {
	parts := strings.Split(beta, ",")
	var kept []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if !strings.HasPrefix(p, "claude-code-") {
			kept = append(kept, p)
		}
	}
	return strings.Join(kept, ",")
}

// stripZstd removes the zstd token from an Accept-Encoding header value.
func stripZstd(ae string) string {
	parts := strings.Split(ae, ",")
	var kept []string
	for _, p := range parts {
		if strings.TrimSpace(p) != "zstd" {
			kept = append(kept, p)
		}
	}
	return strings.Join(kept, ",")
}

// DisguiseBody transforms the request body to remove Claude Code fingerprints.
// It strips the "metadata" field (which contains a user_id encoded with the
// Claude Code session format) and returns the modified body reader.
// Returns nil if the body is not JSON or cannot be parsed.
func DisguiseBody(body io.ReadCloser) io.ReadCloser {
	if body == nil {
		return body
	}

	raw, err := io.ReadAll(body)
	body.Close()
	if err != nil {
		return io.NopCloser(bytes.NewReader(raw))
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		// Not valid JSON — return as-is (e.g. SSE stream body, empty).
		return io.NopCloser(bytes.NewReader(raw))
	}

	// Strip metadata — contains "user_id" with Claude Code session encoding.
	delete(obj, "metadata")

	out, err := json.Marshal(obj)
	if err != nil {
		return io.NopCloser(bytes.NewReader(raw))
	}
	return io.NopCloser(bytes.NewReader(out))
}
