package authz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	authv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

type stubReviewer struct {
	err error
}

func (s stubReviewer) Authorize(context.Context, string) error {
	return s.err
}

func TestMiddleware(t *testing.T) {
	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	tests := []struct {
		name       string
		mode       string
		reviewer   Reviewer
		authHeader string
		wantStatus int
	}{
		{
			name:       "none allows without auth",
			mode:       ModeNone,
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "tokenreview rejects missing bearer",
			mode:       ModeTokenReview,
			reviewer:   stubReviewer{},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "tokenreview rejects invalid prefix",
			mode:       ModeTokenReview,
			reviewer:   stubReviewer{},
			authHeader: "Basic abc",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "tokenreview allows valid token",
			mode:       ModeTokenReview,
			reviewer:   stubReviewer{},
			authHeader: "Bearer good-token",
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "rbac denies when reviewer fails",
			mode:       ModeRBAC,
			reviewer:   stubReviewer{err: context.Canceled},
			authHeader: "Bearer good-token",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "nil reviewer rejects",
			mode:       ModeTokenReview,
			reviewer:   nil,
			authHeader: "Bearer good-token",
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mw := &Middleware{Mode: tt.mode, Reviewer: tt.reviewer}
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			rr := httptest.NewRecorder()
			mw.Wrap(okHandler).ServeHTTP(rr, req)
			require.Equal(t, tt.wantStatus, rr.Code)
		})
	}
}

func TestK8sReviewerTokenReviewAndRBAC(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		authOK  bool
		allowed bool
		wantErr string
	}{
		{
			name:   "tokenreview success",
			mode:   ModeTokenReview,
			authOK: true,
		},
		{
			name:    "tokenreview unauthenticated",
			mode:    ModeTokenReview,
			authOK:  false,
			wantErr: "token is not authenticated",
		},
		{
			name:    "rbac allowed",
			mode:    ModeRBAC,
			authOK:  true,
			allowed: true,
		},
		{
			name:    "rbac denied",
			mode:    ModeRBAC,
			authOK:  true,
			allowed: false,
			wantErr: "rbac denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewSimpleClientset()
			client.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
				return true, &authv1.TokenReview{
					Status: authv1.TokenReviewStatus{
						Authenticated: tt.authOK,
						User: authv1.UserInfo{
							Username: "system:serviceaccount:ns:client",
							UID:      "uid-1",
							Groups:   []string{"system:serviceaccounts"},
						},
					},
				}, nil
			})
			client.PrependReactor("create", "subjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
				return true, &authzv1.SubjectAccessReview{
					Status: authzv1.SubjectAccessReviewStatus{
						Allowed: tt.allowed,
						Reason:  "policy",
					},
				}, nil
			})

			rev := &K8sReviewer{
				Client: client,
				Config: Config{
					Mode:             tt.mode,
					Audience:         "https://proxy.example",
					ResourceAPIGroup: "",
					Resource:         "services",
					Verb:             "proxy",
					Namespace:        "observability",
				},
			}
			err := rev.Authorize(context.Background(), "k8s-token")
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestBearerToken(t *testing.T) {
	tok, ok := bearerToken("Bearer abc")
	require.True(t, ok)
	require.Equal(t, "abc", tok)

	_, ok = bearerToken("bearer abc")
	require.False(t, ok)

	_, ok = bearerToken("Bearer ")
	require.False(t, ok)
}
