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

// Ready succeeds only when a valid cached Thalassa token is present.
// Callers should warm the token on startup so readiness reflects auth readiness.
func (h *Handler) Ready(w http.ResponseWriter, _ *http.Request) {
	if h == nil || h.Tokens == nil || !h.Tokens.HasValidCachedToken() {
		http.Error(w, "token not ready", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}
