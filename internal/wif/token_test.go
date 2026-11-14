package wif

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestExchangeClientToken(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       any
		subject    string
		wantErr    string
		wantToken  string
		wantCalls  int32
		secondCall bool
	}{
		{
			name:      "successful exchange",
			status:    http.StatusOK,
			body:      map[string]any{"access_token": "tok-1", "expires_in": 3600, "token_type": "Bearer"},
			subject:   "k8s-jwt",
			wantToken: "tok-1",
			wantCalls: 1,
		},
		{
			name:       "uses cache on second call",
			status:     http.StatusOK,
			body:       map[string]any{"access_token": "tok-cached", "expires_in": 3600},
			subject:    "k8s-jwt",
			wantToken:  "tok-cached",
			wantCalls:  1,
			secondCall: true,
		},
		{
			name:      "empty subject token file",
			status:    http.StatusOK,
			body:      map[string]any{"access_token": "tok"},
			subject:   "   ",
			wantErr:   "subject token file is empty",
			wantCalls: 0,
		},
		{
			name:      "exchange error response",
			status:    http.StatusUnauthorized,
			body:      map[string]any{"error": "invalid_grant", "error_description": "no match"},
			subject:   "k8s-jwt",
			wantErr:   "token exchange failed",
			wantCalls: 1,
		},
		{
			name:      "empty access token",
			status:    http.StatusOK,
			body:      map[string]any{"access_token": ""},
			subject:   "k8s-jwt",
			wantErr:   "empty access_token",
			wantCalls: 1,
		},
		{
			name:      "non-positive expires_in",
			status:    http.StatusOK,
			body:      map[string]any{"access_token": "tok", "expires_in": 0},
			subject:   "k8s-jwt",
			wantErr:   "non-positive expires_in",
			wantCalls: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				require.Equal(t, http.MethodPost, r.Method)
				require.Equal(t, "/oidc/token", r.URL.Path)
				require.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
				require.NoError(t, r.ParseForm())
				require.Equal(t, grantTypeTokenExchange, r.Form.Get("grant_type"))
				require.Equal(t, subjectTokenTypeID, r.Form.Get("subject_token_type"))
				require.Equal(t, "org-1", r.Form.Get("organisation_id"))
				require.Equal(t, "sa-1", r.Form.Get("service_account_id"))
				if tt.subject != "" && tt.subject != "   " {
					require.Equal(t, tt.subject, r.Form.Get("subject_token"))
				}

				w.WriteHeader(tt.status)
				require.NoError(t, json.NewEncoder(w).Encode(tt.body))
			}))
			t.Cleanup(srv.Close)

			tokenFile := filepath.Join(t.TempDir(), "token")
			require.NoError(t, os.WriteFile(tokenFile, []byte(tt.subject), 0o600))

			now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
			client := &ExchangeClient{
				APIURL:           srv.URL,
				OrganisationID:   "org-1",
				ServiceAccountID: "sa-1",
				SubjectTokenFile: tokenFile,
				RefreshSkew:      time.Minute,
				HTTPClient:       srv.Client(),
				Now:              func() time.Time { return now },
			}

			tok, err := client.Token(context.Background())
			if tt.wantErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.wantErr)
				require.Equal(t, tt.wantCalls, calls.Load())
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantToken, tok)

			if tt.secondCall {
				tok2, err := client.Token(context.Background())
				require.NoError(t, err)
				require.Equal(t, tt.wantToken, tok2)
			}
			require.Equal(t, tt.wantCalls, calls.Load())
			require.True(t, client.HasValidCachedToken())
		})
	}
}

func TestExchangeClientRefreshesNearExpiry(t *testing.T) {
	var calls atomic.Int32
	tokens := []string{"tok-1", "tok-2"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(calls.Add(1))
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": tokens[n-1],
			"expires_in":   120,
		})
	}))
	t.Cleanup(srv.Close)

	tokenFile := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("k8s-jwt"), 0o600))

	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	client := &ExchangeClient{
		APIURL:           srv.URL,
		OrganisationID:   "org-1",
		ServiceAccountID: "sa-1",
		SubjectTokenFile: tokenFile,
		RefreshSkew:      time.Minute,
		HTTPClient:       srv.Client(),
		Now:              func() time.Time { return now },
	}

	tok1, err := client.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, "tok-1", tok1)

	now = now.Add(90 * time.Second)
	require.True(t, client.HasValidCachedToken())
	tok2, err := client.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, "tok-2", tok2)
	require.Equal(t, int32(2), calls.Load())
}

func TestExchangeClientUsesCachedTokenWhenRefreshFailsInsideSkew(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "tok-1",
				"expires_in":   120,
			})
			return
		}
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	tokenFile := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("k8s-jwt"), 0o600))

	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	client := &ExchangeClient{
		APIURL:           srv.URL,
		OrganisationID:   "org-1",
		ServiceAccountID: "sa-1",
		SubjectTokenFile: tokenFile,
		RefreshSkew:      time.Minute,
		HTTPClient:       srv.Client(),
		Now:              func() time.Time { return now },
	}

	tok1, err := client.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, "tok-1", tok1)

	now = now.Add(90 * time.Second)
	tok2, err := client.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, "tok-1", tok2)
	require.True(t, client.HasValidCachedToken())
	require.Equal(t, int32(2), calls.Load())

	tok3, err := client.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, "tok-1", tok3)
	require.Equal(t, int32(2), calls.Load())

	now = now.Add(refreshFailureBackoff)
	_, err = client.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, int32(3), calls.Load())

	now = now.Add(40 * time.Second)
	_, err = client.Token(context.Background())
	require.Error(t, err)
	require.False(t, client.HasValidCachedToken())
}

func TestExchangeClientInvalidateDropsMatchingToken(t *testing.T) {
	var calls atomic.Int32
	tokens := []string{"tok-1", "tok-2"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(calls.Add(1))
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": tokens[n-1],
			"expires_in":   3600,
		})
	}))
	t.Cleanup(srv.Close)

	tokenFile := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("k8s-jwt"), 0o600))

	client := &ExchangeClient{
		APIURL:           srv.URL,
		OrganisationID:   "org-1",
		ServiceAccountID: "sa-1",
		SubjectTokenFile: tokenFile,
		RefreshSkew:      time.Minute,
		HTTPClient:       srv.Client(),
	}

	tok, err := client.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, "tok-1", tok)

	client.Invalidate("other")
	require.True(t, client.HasValidCachedToken())
	tok, err = client.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, "tok-1", tok)
	require.Equal(t, int32(1), calls.Load())

	client.Invalidate("tok-1")
	require.False(t, client.HasValidCachedToken())
	tok, err = client.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, "tok-2", tok)
	require.Equal(t, int32(2), calls.Load())
}

func TestExchangeClientSingleflight(t *testing.T) {
	var calls atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		once.Do(func() { close(started) })
		<-release
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "tok-shared",
			"expires_in":   3600,
		})
	}))
	t.Cleanup(srv.Close)

	tokenFile := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("k8s-jwt"), 0o600))
	client := &ExchangeClient{
		APIURL:           srv.URL,
		OrganisationID:   "org-1",
		ServiceAccountID: "sa-1",
		SubjectTokenFile: tokenFile,
		RefreshSkew:      time.Minute,
		HTTPClient:       srv.Client(),
	}

	const n = 8
	errCh := make(chan error, n)
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tok, err := client.Token(context.Background())
			if err != nil {
				errCh <- err
				return
			}
			if tok != "tok-shared" {
				errCh <- errors.New("unexpected token " + tok)
			}
		}()
	}

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("exchange did not start")
	}
	close(release)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		require.NoError(t, err)
	}
	require.Equal(t, int32(1), calls.Load())
}

func TestExchangeClientMissingFile(t *testing.T) {
	client := &ExchangeClient{
		APIURL:           "https://api.example",
		OrganisationID:   "org-1",
		ServiceAccountID: "sa-1",
		SubjectTokenFile: filepath.Join(t.TempDir(), "missing"),
	}
	_, err := client.Token(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "read subject token file")
}

func TestNextRefreshDelay(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	client := &ExchangeClient{
		RefreshSkew: time.Minute,
		Now:         func() time.Time { return now },
	}

	require.Equal(t, refreshFailureBackoff, client.nextRefreshDelay())

	client.mu.Lock()
	client.cached = "tok-1"
	client.expiresAt = now.Add(10 * time.Minute)
	client.mu.Unlock()
	require.Equal(t, 9*time.Minute, client.nextRefreshDelay())

	now = now.Add(9*time.Minute + time.Second)
	require.True(t, client.HasValidCachedToken())
	require.Equal(t, refreshFailureBackoff, client.nextRefreshDelay())

	client.mu.Lock()
	client.refreshRetryAt = now.Add(3 * time.Second)
	client.mu.Unlock()
	require.Equal(t, 3*time.Second, client.nextRefreshDelay())
}

func TestExchangeClientRefreshLoopRefreshesWithoutTraffic(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "tok-" + strconv.FormatInt(int64(n), 10),
			"expires_in":   2,
		})
	}))
	t.Cleanup(srv.Close)

	tokenFile := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("k8s-jwt"), 0o600))

	client := &ExchangeClient{
		APIURL:           srv.URL,
		OrganisationID:   "org-1",
		ServiceAccountID: "sa-1",
		SubjectTokenFile: tokenFile,
		RefreshSkew:      time.Second,
		HTTPClient:       srv.Client(),
	}

	tok, err := client.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, "tok-1", tok)
	require.True(t, client.HasValidCachedToken())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go client.RunRefreshLoop(ctx)

	require.Eventually(t, func() bool {
		return calls.Load() >= 2 && client.HasValidCachedToken()
	}, 5*time.Second, 50*time.Millisecond)

	tok, err = client.Token(context.Background())
	require.NoError(t, err)
	require.NotEqual(t, "tok-1", tok)
	require.True(t, client.HasValidCachedToken())
}

func TestReadyStaysTrueInsideSkewWithoutTraffic(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "tok-1",
			"expires_in":   120,
		})
	}))
	t.Cleanup(srv.Close)

	tokenFile := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("k8s-jwt"), 0o600))

	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	client := &ExchangeClient{
		APIURL:           srv.URL,
		OrganisationID:   "org-1",
		ServiceAccountID: "sa-1",
		SubjectTokenFile: tokenFile,
		RefreshSkew:      time.Minute,
		HTTPClient:       srv.Client(),
		Now:              func() time.Time { return now },
	}

	_, err := client.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, int32(1), calls.Load())

	// Enter the refresh skew without another Token() call. Readiness must stay up.
	now = now.Add(90 * time.Second)
	require.True(t, client.HasValidCachedToken())
	require.Equal(t, refreshFailureBackoff, client.nextRefreshDelay())
	require.Equal(t, int32(1), calls.Load())
}
