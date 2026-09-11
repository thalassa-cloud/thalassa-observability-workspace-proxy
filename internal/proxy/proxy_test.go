package proxy

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type staticToken string

func (s staticToken) Token(context.Context) (string, error) {
	return string(s), nil
}

type errToken struct{ err error }

func (e errToken) Token(context.Context) (string, error) {
	return "", e.err
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
