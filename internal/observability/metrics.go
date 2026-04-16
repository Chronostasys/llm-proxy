package observability

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"sync"
)

type Metrics struct {
	mu                sync.RWMutex
	requestsTotal     uint64
	responsesByStatus map[int]uint64
}

func NewMetrics() *Metrics {
	return &Metrics{
		responsesByStatus: make(map[int]uint64),
	}
}

func (m *Metrics) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder := &metricsRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)

		m.mu.Lock()
		m.requestsTotal++
		m.responsesByStatus[recorder.status]++
		m.mu.Unlock()
	})
}

func (m *Metrics) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("format") == "prometheus" {
			w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
			_ = m.writePrometheus(w)
			return
		}
		payload := m.snapshot()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(payload)
	})
}

func (m *Metrics) writePrometheus(w http.ResponseWriter) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, _ = fmt.Fprintf(w, "# HELP llm_proxy_requests_total Total number of proxy requests.\n")
	_, _ = fmt.Fprintf(w, "# TYPE llm_proxy_requests_total counter\n")
	_, _ = fmt.Fprintf(w, "llm_proxy_requests_total %d\n\n", m.requestsTotal)

	_, _ = fmt.Fprintf(w, "# HELP llm_proxy_responses_total Total number of responses by status code.\n")
	_, _ = fmt.Fprintf(w, "# TYPE llm_proxy_responses_total counter\n")

	statuses := make([]int, 0, len(m.responsesByStatus))
	for status := range m.responsesByStatus {
		statuses = append(statuses, status)
	}
	sort.Ints(statuses)
	for _, status := range statuses {
		_, _ = fmt.Fprintf(w, "llm_proxy_responses_total{status=\"%d\"} %d\n", status, m.responsesByStatus[status])
	}

	return nil
}

func (m *Metrics) snapshot() map[string]any {
	m.mu.RLock()
	defer m.mu.RUnlock()

	statuses := make(map[string]uint64, len(m.responsesByStatus))
	for status, count := range m.responsesByStatus {
		statuses[strconv.Itoa(status)] = count
	}

	return map[string]any{
		"requests_total":      m.requestsTotal,
		"responses_by_status": statuses,
	}
}

type metricsRecorder struct {
	http.ResponseWriter
	status int
}

func (r *metricsRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *metricsRecorder) Flush() {
	flusher, ok := r.ResponseWriter.(http.Flusher)
	if ok {
		flusher.Flush()
	}
}
