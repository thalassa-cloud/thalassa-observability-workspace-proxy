package health

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

type checker bool

func (c checker) HasValidCachedToken() bool { return bool(c) }

func TestHandler(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		ready      checker
		wantStatus int
	}{
		{name: "live always ok", path: "/healthz", ready: false, wantStatus: http.StatusOK},
		{name: "ready when token cached", path: "/readyz", ready: true, wantStatus: http.StatusOK},
		{name: "not ready without token", path: "/readyz", ready: false, wantStatus: http.StatusServiceUnavailable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mux := http.NewServeMux()
			h := &Handler{Tokens: tt.ready}
			h.Register(mux)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, tt.path, nil))
			require.Equal(t, tt.wantStatus, rr.Code)
		})
	}
}
