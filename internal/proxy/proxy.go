package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
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
		Transport: &upstreamTransport{
			base: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				ResponseHeaderTimeout: timeout,
			},
			tokens: tokens,
			logger: logger,
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

	if err := bufferRequestBody(w, r, h.MaxBodyBytes); err != nil {
		return
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

// bufferRequestBody keeps the body so an upstream 401 can be retried once.
func bufferRequestBody(w http.ResponseWriter, r *http.Request, maxBytes int64) error {
	if r.Body == nil || r.Body == http.NoBody {
		return nil
	}
	reader := r.Body
	if maxBytes > 0 {
		reader = http.MaxBytesReader(w, r.Body, maxBytes)
	}
	data, err := io.ReadAll(reader)
	closeErr := reader.Close()
	if err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return err
		}
		http.Error(w, "bad request", http.StatusBadRequest)
		return err
	}
	if closeErr != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return closeErr
	}
	r.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	}
	body, err := r.GetBody()
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return err
	}
	r.Body = body
	r.ContentLength = int64(len(data))
	r.TransferEncoding = nil
	r.Header.Set("Content-Length", strconv.Itoa(len(data)))
	return nil
}

// upstreamTransport retries once when the workspace gateway rejects the bearer.
type upstreamTransport struct {
	base   http.RoundTripper
	tokens wif.TokenSource
	logger *slog.Logger
}

func (t *upstreamTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t == nil || t.base == nil {
		return nil, fmt.Errorf("upstream transport is not configured")
	}
	resp, err := t.base.RoundTrip(req)
	if err != nil || resp == nil || resp.StatusCode != http.StatusUnauthorized {
		return resp, err
	}
	rejected := bearerValue(req.Header.Get("Authorization"))
	if rejected == "" || t.tokens == nil {
		return resp, nil
	}

	t.tokens.Invalidate(rejected)
	drainBody(resp.Body)
	if t.logger != nil {
		t.logger.Warn("upstream rejected bearer; refreshing token", "path", req.URL.Path)
	}

	fresh, err := t.tokens.Token(req.Context())
	if err != nil {
		return nil, fmt.Errorf("refresh bearer after upstream unauthorized: %w", err)
	}
	fresh = strings.TrimSpace(fresh)
	if fresh == "" {
		return nil, fmt.Errorf("refresh bearer after upstream unauthorized: empty token")
	}

	retry, err := replayBody(req)
	if err != nil {
		return nil, err
	}
	retry.Header.Set("Authorization", "Bearer "+fresh)
	retryResp, err := t.base.RoundTrip(retry)
	if err != nil || retryResp == nil {
		return retryResp, err
	}
	if retryResp.StatusCode == http.StatusUnauthorized {
		t.tokens.Invalidate(fresh)
	}
	return retryResp, nil
}

func replayBody(req *http.Request) (*http.Request, error) {
	retry := req.Clone(req.Context())
	if req.Body == nil || req.Body == http.NoBody || req.ContentLength == 0 {
		retry.Body = nil
		return retry, nil
	}
	if req.GetBody == nil {
		return nil, fmt.Errorf("cannot retry request body")
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, fmt.Errorf("retry request body: %w", err)
	}
	retry.Body = body
	return retry, nil
}

func bearerValue(header string) string {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, prefix))
}

func drainBody(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(body, 1<<20))
	_ = body.Close()
}
