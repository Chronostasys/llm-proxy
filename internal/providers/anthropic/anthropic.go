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

// allowedHeaders is the whitelist of headers that are legitimate for Anthropic
// API requests. Everything else is a fingerprint and gets stripped.
var allowedHeaders = map[string]bool{
	"content-type":     true,
	"accept":           true,
	"accept-encoding":  true,
	"accept-language":  true,
	"anthropic-version": true,
	"anthropic-beta":   true,
	"x-api-key":        true, // set by proxy
}

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

// applyDisguiseHeaders uses a whitelist approach: wipe every header that is
// not on the Anthropic API allowlist, then inject browser-like values for
// User-Agent, Accept-Encoding, Accept-Language, and Sec-Fetch-*.
// This is robust against any future headers Claude Code might add.
func applyDisguiseHeaders(headers http.Header, disguise config.DisguiseConfig) {
	// 1. Save the values we want to keep from the whitelist.
	saved := make(map[string][]string)
	for key, values := range headers {
		if allowedHeaders[strings.ToLower(key)] {
			saved[key] = values
		}
	}

	// 2. Nuke everything.
	for key := range headers {
		delete(headers, key)
	}

	// 3. Restore whitelisted headers.
	for key, values := range saved {
		for _, v := range values {
			headers.Add(key, v)
		}
	}

	// 4. Clean anthropic-beta: remove claude-code-* flags.
	if beta := headers.Get("anthropic-beta"); beta != "" {
		if cleaned := cleanAnthropicBeta(beta); cleaned != "" {
			headers.Set("anthropic-beta", cleaned)
		} else {
			headers.Del("anthropic-beta")
		}
	}

	// 5. Strip zstd from Accept-Encoding (uncommon outside Node.js).
	if ae := headers.Get("Accept-Encoding"); ae != "" {
		headers.Set("Accept-Encoding", stripZstd(ae))
	}
	if headers.Get("Accept-Encoding") == "" {
		headers.Set("Accept-Encoding", "gzip, deflate, br")
	}

	// 6. Inject browser-like User-Agent.
	ua := disguise.UserAgent
	if ua == "" {
		ua = DefaultDisguiseUserAgent
	}
	headers.Set("User-Agent", ua)

	// 7. Add browser-typical headers.
	if headers.Get("Accept-Language") == "" {
		headers.Set("Accept-Language", "en-US,en;q=0.9")
	}
	headers.Set("Sec-Fetch-Dest", "empty")
	headers.Set("Sec-Fetch-Mode", "cors")
	headers.Set("Sec-Fetch-Site", "same-origin")
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
		return io.NopCloser(bytes.NewReader(raw))
	}

	delete(obj, "metadata")

	out, err := json.Marshal(obj)
	if err != nil {
		return io.NopCloser(bytes.NewReader(raw))
	}
	return io.NopCloser(bytes.NewReader(out))
}
