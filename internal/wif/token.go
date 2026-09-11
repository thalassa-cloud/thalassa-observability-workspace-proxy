package wif

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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
)

// TokenSource provides Thalassa Cloud bearer tokens obtained via WIF exchange.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
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

	mu        sync.Mutex
	cached    string
	expiresAt time.Time
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	TokenType   string `json:"token_type"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// Token returns a cached bearer token or performs a fresh exchange.
func (c *ExchangeClient) Token(ctx context.Context) (string, error) {
	if c == nil {
		return "", fmt.Errorf("wif exchange client is nil")
	}
	if err := c.validate(); err != nil {
		return "", err
	}

	now := c.now()
	c.mu.Lock()
	if c.cached != "" && now.Before(c.expiresAt.Add(-c.refreshSkew())) {
		token := c.cached
		c.mu.Unlock()
		return token, nil
	}
	c.mu.Unlock()

	subjectToken, err := c.readSubjectToken()
	if err != nil {
		return "", err
	}

	accessToken, expiresIn, err := c.exchange(ctx, subjectToken)
	if err != nil {
		return "", err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.cached = accessToken
	if expiresIn <= 0 {
		expiresIn = int64((time.Hour).Seconds())
	}
	c.expiresAt = now.Add(time.Duration(expiresIn) * time.Second)
	return c.cached, nil
}

// HasValidCachedToken reports whether a non-expired cached token exists.
func (c *ExchangeClient) HasValidCachedToken() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cached != "" && c.now().Before(c.expiresAt.Add(-c.refreshSkew()))
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
