package health

import (
	"net/http"
)

// TokenChecker reports whether a usable Thalassa token is available.
type TokenChecker interface {
	HasValidCachedToken() bool
}

// Handler serves liveness and readiness probes.
type Handler struct {
	Tokens TokenChecker
}

// Register mounts /healthz and /readyz on mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("/healthz", h.Live)
	mux.HandleFunc("/readyz", h.Ready)
}

// Live always succeeds when the process is up.
func (h *Handler) Live(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// Ready succeeds when a cached Thalassa token is present and unexpired.
// The refresh skew does not fail readiness. Warm the token on startup and
// refresh it in the background so an idle Service stays Ready.
func (h *Handler) Ready(w http.ResponseWriter, _ *http.Request) {
	if h == nil || h.Tokens == nil || !h.Tokens.HasValidCachedToken() {
		http.Error(w, "token not ready", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}
