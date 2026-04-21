package proxy

import (
	"testing"
)

func TestBuildUpstreamURL_StripsBetaQuery(t *testing.T) {
	target, err := buildUpstreamURL("https://api.anthropic.com", "/v1/messages", "beta=true")
	if err != nil {
		t.Fatalf("buildUpstreamURL() error = %v", err)
	}
	if got := target.String(); got != "https://api.anthropic.com/v1/messages" {
		t.Fatalf("target.String() = %q, want no query params", got)
	}
}

func TestBuildUpstreamURL_StripsBetaKeepsOthers(t *testing.T) {
	target, err := buildUpstreamURL("https://api.anthropic.com", "/v1/messages", "beta=true&stream=true")
	if err != nil {
		t.Fatalf("buildUpstreamURL() error = %v", err)
	}
	expected := "https://api.anthropic.com/v1/messages?stream=true"
	if got := target.String(); got != expected {
		t.Fatalf("target.String() = %q, want %q", got, expected)
	}
}

func TestBuildUpstreamURL_PreservesNormalQuery(t *testing.T) {
	target, err := buildUpstreamURL("https://api.openai.com", "/v1/chat/completions", "stream=true")
	if err != nil {
		t.Fatalf("buildUpstreamURL() error = %v", err)
	}
	if got := target.String(); got != "https://api.openai.com/v1/chat/completions?stream=true" {
		t.Fatalf("target.String() = %q, want %q", got, "https://api.openai.com/v1/chat/completions?stream=true")
	}
}

func TestBuildUpstreamURL_EmptyQuery(t *testing.T) {
	target, err := buildUpstreamURL("https://api.anthropic.com", "/v1/messages", "")
	if err != nil {
		t.Fatalf("buildUpstreamURL() error = %v", err)
	}
	if got := target.String(); got != "https://api.anthropic.com/v1/messages" {
		t.Fatalf("target.String() = %q, want %q", got, "https://api.anthropic.com/v1/messages")
	}
}

func TestSanitizeQuery(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"beta only", "beta=true", ""},
		{"beta with other", "beta=true&stream=true", "stream=true"},
		{"other only", "stream=true", "stream=true"},
		{"no beta", "a=1&b=2", "a=1&b=2"},
		{"beta=false", "beta=false", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := sanitizeQuery(tt.in)
			if got != tt.want {
				t.Errorf("sanitizeQuery(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
