package proxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type staticToken string

func (s staticToken) Token(context.Context) (string, error) {
	return string(s), nil
}

func (staticToken) Invalidate(string) {}

type errToken struct{ err error }

func (e errToken) Token(context.Context) (string, error) {
	return "", e.err
}

func (errToken) Invalidate(string) {}

type scriptedToken struct {
	mu          sync.Mutex
	tokens      []string
	errOnCall   int
	calls       int
	invalidated []string
}

func (s *scriptedToken) Token(context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.errOnCall > 0 && s.calls == s.errOnCall {
		return "", errors.New("exchange down")
	}
	if s.calls > len(s.tokens) {
		return "", errors.New("no token")
	}
	return s.tokens[s.calls-1], nil
}

func (s *scriptedToken) Invalidate(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.invalidated = append(s.invalidated, token)
}

func TestHandlerInjectsBearerAndStripsClientAuth(t *testing.T) {
	var gotAuth string
	var gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(upstream.Close)

	u, err := url.Parse(upstream.URL)
	require.NoError(t, err)

	h, err := New(u, staticToken("thalassa-token"), time.Second, 0, slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/workspace/obsw-1/api/v1/push", nil)
	req.Header.Set("Authorization", "Bearer client-should-not-leak")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	require.Equal(t, "Bearer thalassa-token", gotAuth)
	require.Equal(t, "/workspace/obsw-1/api/v1/push", gotPath)
	require.Equal(t, "ok", rr.Body.String())
}

func TestHandlerTokenFailure(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called")
	}))
	t.Cleanup(upstream.Close)

	u, err := url.Parse(upstream.URL)
	require.NoError(t, err)

	h, err := New(u, errToken{err: context.DeadlineExceeded}, time.Second, 0, slog.Default())
	require.NoError(t, err)

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/query", nil))
	require.Equal(t, http.StatusBadGateway, rr.Code)
}

func TestHandlerRetriesOnceAfterUpstreamUnauthorized(t *testing.T) {
	var mu sync.Mutex
	var auths []string
	var bodies []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			http.Error(w, "read", http.StatusInternalServerError)
			return
		}
		mu.Lock()
		auths = append(auths, r.Header.Get("Authorization"))
		bodies = append(bodies, string(body))
		mu.Unlock()
		if r.Header.Get("Authorization") == "Bearer old" {
			http.Error(w, "expired", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(upstream.Close)

	u, err := url.Parse(upstream.URL)
	require.NoError(t, err)
	tokens := &scriptedToken{tokens: []string{"old", "new"}}
	h, err := New(u, tokens, time.Second, 1<<20, slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/push", strings.NewReader("payload"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	require.Equal(t, "ok", rr.Body.String())
	require.Equal(t, []string{"Bearer old", "Bearer new"}, auths)
	require.Equal(t, []string{"payload", "payload"}, bodies)
	require.Equal(t, []string{"old"}, tokens.invalidated)
}

func TestHandlerRefreshFailureAfterUnauthorized(t *testing.T) {
	var calls int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		http.Error(w, "expired", http.StatusUnauthorized)
	}))
	t.Cleanup(upstream.Close)

	u, err := url.Parse(upstream.URL)
	require.NoError(t, err)
	tokens := &scriptedToken{tokens: []string{"old"}, errOnCall: 2}
	h, err := New(u, tokens, time.Second, 0, slog.Default())
	require.NoError(t, err)

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/query", nil))
	require.Equal(t, http.StatusBadGateway, rr.Code)
	require.Equal(t, 1, calls)
	require.Equal(t, []string{"old"}, tokens.invalidated)
}

func TestHandlerRejectsOversizedBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called")
	}))
	t.Cleanup(upstream.Close)

	u, err := url.Parse(upstream.URL)
	require.NoError(t, err)
	h, err := New(u, staticToken("thalassa-token"), time.Second, 4, slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/push", strings.NewReader("too-big"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	require.Equal(t, http.StatusRequestEntityTooLarge, rr.Code)
}

func TestNewValidation(t *testing.T) {
	u, err := url.Parse("https://prometheus.example")
	require.NoError(t, err)

	_, err = New(nil, staticToken("t"), time.Second, 0, nil)
	require.Error(t, err)

	_, err = New(u, nil, time.Second, 0, nil)
	require.Error(t, err)

	_, err = New(u, staticToken("t"), 0, 0, nil)
	require.Error(t, err)
}
