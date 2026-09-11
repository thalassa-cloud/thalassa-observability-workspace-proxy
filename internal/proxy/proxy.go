package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/thalassa-cloud/thalassa-observability-workspace-proxy/internal/wif"
)

// Handler is an HTTP reverse proxy that injects a Thalassa bearer token.
type Handler struct {
	Upstream     *url.URL
	TokenSource  wif.TokenSource
	Timeout      time.Duration
	MaxBodyBytes int64
	Logger       *slog.Logger

	proxy *httputil.ReverseProxy
}

// New creates a reverse proxy bound to a single upstream host (no open proxy).
func New(upstream *url.URL, tokens wif.TokenSource, timeout time.Duration, maxBodyBytes int64, logger *slog.Logger) (*Handler, error) {
	if upstream == nil {
		return nil, fmt.Errorf("upstream is required")
	}
	if tokens == nil {
		return nil, fmt.Errorf("token source is required")
	}
	if timeout <= 0 {
		return nil, fmt.Errorf("timeout must be positive")
	}
	if logger == nil {
		logger = slog.Default()
	}

	h := &Handler{
		Upstream:     upstream,
		TokenSource:  tokens,
		Timeout:      timeout,
		MaxBodyBytes: maxBodyBytes,
		Logger:       logger,
	}

	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(h.Upstream)
			pr.Out.Host = h.Upstream.Host
			// Prevent credential confusion: never forward client Authorization.
			pr.Out.Header.Del("Authorization")
			if token, ok := pr.In.Context().Value(ctxTokenKey{}).(string); ok && token != "" {
				pr.Out.Header.Set("Authorization", "Bearer "+token)
			}
			pr.SetXForwarded()
		},
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ResponseHeaderTimeout: timeout,
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			h.Logger.Error("upstream request failed", "error", err.Error(), "path", r.URL.Path)
			http.Error(w, "bad gateway", http.StatusBadGateway)
		},
	}
	h.proxy = rp
	return h, nil
}

type ctxTokenKey struct{}

// ServeHTTP obtains a Thalassa token, then proxies the request upstream.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.proxy == nil {
		http.Error(w, "proxy not configured", http.StatusInternalServerError)
		return
	}

	if h.MaxBodyBytes > 0 && r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, h.MaxBodyBytes)
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.Timeout)
	defer cancel()

	token, err := h.TokenSource.Token(ctx)
	if err != nil {
		h.Logger.Error("token exchange failed", "error", err.Error())
		http.Error(w, "unable to authenticate to upstream", http.StatusBadGateway)
		return
	}
	if strings.TrimSpace(token) == "" {
		http.Error(w, "unable to authenticate to upstream", http.StatusBadGateway)
		return
	}

	r = r.WithContext(context.WithValue(ctx, ctxTokenKey{}, token))
	h.proxy.ServeHTTP(w, r)
}
