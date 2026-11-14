package wif

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	grantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	subjectTokenTypeID     = "urn:ietf:params:oauth:token-type:id_token"

	// refreshFailureBackoff spaces exchange attempts after a failed refresh
	// while a cached token is still inside its real lifetime.
	refreshFailureBackoff = 5 * time.Second

	// defaultExchangeTimeout bounds a shared refresh when the caller context
	// and the HTTP client have no deadline.
	defaultExchangeTimeout = 15 * time.Second
)

// TokenSource provides Thalassa Cloud bearer tokens obtained via WIF exchange.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
	// Invalidate drops a cached bearer after upstream rejects it.
	// A token that does not match the cache is left in place.
	Invalidate(token string)
}

// ExchangeClient exchanges a Kubernetes subject token for a Thalassa access token.
type ExchangeClient struct {
	APIURL           string
	OrganisationID   string
	ServiceAccountID string
	SubjectTokenFile string
	RefreshSkew      time.Duration
	HTTPClient       *http.Client
	Now              func() time.Time

	mu             sync.Mutex
	cached         string
	expiresAt      time.Time
	refreshRetryAt time.Time
	inflight       *exchangeCall
}

type exchangeCall struct {
	done  chan struct{}
	token string
	err   error
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	TokenType   string `json:"token_type"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// Token returns a cached bearer token or performs a fresh exchange.
// Concurrent callers share one exchange. A failed refresh returns the cached
// token while it is still before expiresAt.
func (c *ExchangeClient) Token(ctx context.Context) (string, error) {
	if c == nil {
		return "", fmt.Errorf("wif exchange client is nil")
	}
	if err := c.validate(); err != nil {
		return "", err
	}
	if ctx == nil {
		ctx = context.Background()
	}

	c.mu.Lock()
	now := c.now()
	if token, ok := c.reusableLocked(now); ok {
		c.mu.Unlock()
		return token, nil
	}
	if c.inflight != nil {
		call := c.inflight
		c.mu.Unlock()
		return waitExchange(ctx, call)
	}
	call := &exchangeCall{done: make(chan struct{})}
	c.inflight = call
	c.mu.Unlock()

	go func() {
		fetchCtx, cancel := exchangeContext(ctx)
		defer cancel()
		token, expiresIn, err := c.fetch(fetchCtx)
		c.complete(call, token, expiresIn, err)
	}()
	return waitExchange(ctx, call)
}

// exchangeContext keeps the caller's deadline and ignores cancellation.
// One disconnected client then does not abort the shared refresh.
func exchangeContext(ctx context.Context) (context.Context, context.CancelFunc) {
	detached := context.WithoutCancel(ctx)
	if deadline, ok := ctx.Deadline(); ok {
		return context.WithDeadline(detached, deadline)
	}
	return context.WithTimeout(detached, defaultExchangeTimeout)
}

// Invalidate drops the cached bearer when it matches token.
func (c *ExchangeClient) Invalidate(token string) {
	if c == nil {
		return
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cached == token {
		c.cached = ""
		c.expiresAt = time.Time{}
		c.refreshRetryAt = time.Time{}
	}
}

// HasValidCachedToken reports whether a cached token is present and unexpired.
// The refresh skew starts an early exchange and does not, by itself, drop readiness.
func (c *ExchangeClient) HasValidCachedToken() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.unexpiredLocked(c.now())
	return ok
}

// RunRefreshLoop refreshes the Thalassa token before the refresh skew until ctx ends.
// It does not depend on proxied traffic, so readiness stays up for an idle Service.
func (c *ExchangeClient) RunRefreshLoop(ctx context.Context) {
	if c == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		wait := c.nextRefreshDelay()
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if _, err := c.Token(ctx); err != nil && !c.HasValidCachedToken() {
			slog.Default().Warn("background token refresh failed", "error", err.Error())
		}
	}
}

// nextRefreshDelay returns how long to wait before the next background exchange.
func (c *ExchangeClient) nextRefreshDelay() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	if now.Before(c.refreshRetryAt) {
		return c.refreshRetryAt.Sub(now)
	}
	if c.cached == "" || !now.Before(c.expiresAt) {
		return refreshFailureBackoff
	}
	refreshAt := c.expiresAt.Add(-c.refreshSkew())
	if now.Before(refreshAt) {
		return refreshAt.Sub(now)
	}
	// Already inside the skew window. Retry soon without a tight loop.
	return refreshFailureBackoff
}

func (c *ExchangeClient) fetch(ctx context.Context) (string, int64, error) {
	subjectToken, err := c.readSubjectToken()
	if err != nil {
		return "", 0, err
	}
	return c.exchange(ctx, subjectToken)
}

func (c *ExchangeClient) complete(call *exchangeCall, token string, expiresIn int64, fetchErr error) {
	c.mu.Lock()
	if c.inflight == call {
		c.inflight = nil
	}
	if fetchErr == nil {
		if err := c.storeLocked(c.now(), token, expiresIn); err != nil {
			fetchErr = err
		} else {
			call.token = token
			c.mu.Unlock()
			close(call.done)
			return
		}
	}
	if cached, ok := c.unexpiredLocked(c.now()); ok {
		c.refreshRetryAt = c.now().Add(refreshFailureBackoff)
		slog.Default().Warn("token refresh failed; using cached token", "error", fetchErr.Error())
		call.token = cached
		c.mu.Unlock()
		close(call.done)
		return
	}
	if fetchErr == nil {
		fetchErr = fmt.Errorf("token exchange failed")
	}
	call.err = fetchErr
	c.mu.Unlock()
	close(call.done)
}

func waitExchange(ctx context.Context, call *exchangeCall) (string, error) {
	select {
	case <-ctx.Done():
		return "", fmt.Errorf("token exchange canceled: %w", ctx.Err())
	case <-call.done:
		if call.err != nil {
			return "", call.err
		}
		if strings.TrimSpace(call.token) == "" {
			return "", fmt.Errorf("token exchange returned empty access_token")
		}
		return call.token, nil
	}
}

// reusableLocked returns the cache when it is outside the refresh skew,
// or when a recent refresh failure still has an unexpired token.
func (c *ExchangeClient) reusableLocked(now time.Time) (string, bool) {
	token, ok := c.unexpiredLocked(now)
	if !ok {
		return "", false
	}
	if now.Before(c.expiresAt.Add(-c.refreshSkew())) || now.Before(c.refreshRetryAt) {
		return token, true
	}
	return "", false
}

func (c *ExchangeClient) unexpiredLocked(now time.Time) (string, bool) {
	if c.cached == "" || !now.Before(c.expiresAt) {
		return "", false
	}
	return c.cached, true
}

func (c *ExchangeClient) storeLocked(now time.Time, token string, expiresIn int64) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return fmt.Errorf("token exchange returned empty access_token")
	}
	deadline, err := expiryDeadline(now, expiresIn)
	if err != nil {
		return err
	}
	c.cached = token
	c.expiresAt = deadline
	c.refreshRetryAt = time.Time{}
	return nil
}

func expiryDeadline(now time.Time, expiresIn int64) (time.Time, error) {
	if expiresIn <= 0 {
		return time.Time{}, fmt.Errorf("token exchange returned non-positive expires_in")
	}
	const maxSeconds = int64(time.Duration(1<<63-1) / time.Second)
	if expiresIn > maxSeconds {
		return time.Time{}, fmt.Errorf("token exchange expires_in out of range")
	}
	return now.Add(time.Duration(expiresIn) * time.Second), nil
}

func (c *ExchangeClient) validate() error {
	if strings.TrimSpace(c.APIURL) == "" {
		return fmt.Errorf("api url is required")
	}
	if strings.TrimSpace(c.OrganisationID) == "" {
		return fmt.Errorf("organisation id is required")
	}
	if strings.TrimSpace(c.ServiceAccountID) == "" {
		return fmt.Errorf("service account id is required")
	}
	if strings.TrimSpace(c.SubjectTokenFile) == "" {
		return fmt.Errorf("subject token file is required")
	}
	return nil
}

func (c *ExchangeClient) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *ExchangeClient) refreshSkew() time.Duration {
	if c.RefreshSkew > 0 {
		return c.RefreshSkew
	}
	return time.Minute
}

func (c *ExchangeClient) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

func (c *ExchangeClient) readSubjectToken() (string, error) {
	raw, err := os.ReadFile(c.SubjectTokenFile)
	if err != nil {
		return "", fmt.Errorf("read subject token file: %w", err)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", fmt.Errorf("subject token file is empty")
	}
	return token, nil
}

func (c *ExchangeClient) exchange(ctx context.Context, subjectToken string) (string, int64, error) {
	endpoint := strings.TrimRight(c.APIURL, "/") + "/oidc/token"
	form := url.Values{}
	form.Set("grant_type", grantTypeTokenExchange)
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", subjectTokenTypeID)
	form.Set("organisation_id", c.OrganisationID)
	form.Set("service_account_id", c.ServiceAccountID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("create token exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("token exchange request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", 0, fmt.Errorf("read token exchange response: %w", err)
	}

	var parsed tokenResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", 0, fmt.Errorf("decode token exchange response (status %d): %w", resp.StatusCode, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := parsed.Error
		if parsed.ErrorDesc != "" {
			msg = parsed.Error + ": " + parsed.ErrorDesc
		}
		if msg == "" {
			msg = fmt.Sprintf("unexpected status %d", resp.StatusCode)
		}
		return "", 0, fmt.Errorf("token exchange failed: %s", msg)
	}

	if strings.TrimSpace(parsed.AccessToken) == "" {
		return "", 0, fmt.Errorf("token exchange returned empty access_token")
	}
	return parsed.AccessToken, parsed.ExpiresIn, nil
}
