package authz

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	authv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	ModeNone        = "none"
	ModeTokenReview = "tokenreview"
	ModeRBAC        = "rbac"
)

// Reviewer validates Kubernetes bearer tokens and optional RBAC.
//
// Authorize returns a *StatusError so the middleware can choose the HTTP status.
// A plain error is treated as a backend failure (HTTP 503).
type Reviewer interface {
	Authorize(ctx context.Context, token string) error
}

// StatusError is an authorization result with a fixed HTTP status.
// The message is for logs. The middleware writes a generic response body.
type StatusError struct {
	Status int
	Err    error
}

// Error returns the underlying message.
func (e *StatusError) Error() string {
	if e == nil {
		return "authorization error"
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	return http.StatusText(e.Status)
}

// Unwrap returns the cause.
func (e *StatusError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// Config configures inbound authorization behavior.
type Config struct {
	Mode             string
	Audience         string
	ResourceAPIGroup string
	Resource         string
	ResourceName     string
	Verb             string
	Namespace        string
}

// Middleware wraps a handler with inbound auth checks.
type Middleware struct {
	Mode     string
	Reviewer Reviewer
}

// Wrap returns an http.Handler that enforces inbound auth before next.
func (m *Middleware) Wrap(next http.Handler) http.Handler {
	if m == nil || m.Mode == "" || m.Mode == ModeNone {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r.Header.Get("Authorization"))
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if m.Reviewer == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if err := m.Reviewer.Authorize(r.Context(), token); err != nil {
			writeAuthzError(w, err)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// K8sReviewer uses TokenReview and optionally SubjectAccessReview.
type K8sReviewer struct {
	Client kubernetes.Interface
	Config Config
}

// Authorize validates the token and, in rbac mode, checks SAR.
func (k *K8sReviewer) Authorize(ctx context.Context, token string) error {
	if k == nil || k.Client == nil {
		return statusError(http.StatusServiceUnavailable, errors.New("kubernetes client is required"))
	}
	if strings.TrimSpace(token) == "" {
		return statusError(http.StatusUnauthorized, errors.New("token is required"))
	}

	tr := &authv1.TokenReview{
		Spec: authv1.TokenReviewSpec{
			Token: token,
		},
	}
	if k.Config.Audience != "" {
		tr.Spec.Audiences = []string{k.Config.Audience}
	}

	res, err := k.Client.AuthenticationV1().TokenReviews().Create(ctx, tr, metav1.CreateOptions{})
	if err != nil {
		return statusError(http.StatusServiceUnavailable, fmt.Errorf("token review failed: %w", err))
	}
	if !res.Status.Authenticated {
		return statusError(http.StatusUnauthorized, errors.New("token is not authenticated"))
	}

	if k.Config.Mode != ModeRBAC {
		return nil
	}

	sar := &authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User:   res.Status.User.Username,
			Groups: res.Status.User.Groups,
			UID:    res.Status.User.UID,
			Extra:  toExtra(res.Status.User.Extra),
			ResourceAttributes: &authzv1.ResourceAttributes{
				Namespace: k.Config.Namespace,
				Verb:      k.Config.Verb,
				Group:     k.Config.ResourceAPIGroup,
				Resource:  k.Config.Resource,
				Name:      k.Config.ResourceName,
			},
		},
	}
	sarRes, err := k.Client.AuthorizationV1().SubjectAccessReviews().Create(ctx, sar, metav1.CreateOptions{})
	if err != nil {
		return statusError(http.StatusServiceUnavailable, fmt.Errorf("subject access review failed: %w", err))
	}
	if !sarRes.Status.Allowed {
		reason := sarRes.Status.Reason
		if reason == "" {
			reason = "access denied"
		}
		return statusError(http.StatusForbidden, fmt.Errorf("rbac denied: %s", reason))
	}
	return nil
}

func writeAuthzError(w http.ResponseWriter, err error) {
	status := http.StatusServiceUnavailable
	var se *StatusError
	if errors.As(err, &se) {
		switch se.Status {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusServiceUnavailable:
			status = se.Status
		}
	}
	http.Error(w, authzBody(status), status)
}

func authzBody(status int) string {
	switch status {
	case http.StatusUnauthorized:
		return "unauthorized"
	case http.StatusForbidden:
		return "forbidden"
	default:
		return "authorization unavailable"
	}
}

func statusError(status int, err error) error {
	return &StatusError{Status: status, Err: err}
}

func bearerToken(header string) (string, bool) {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return "", false
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	if token == "" {
		return "", false
	}
	return token, true
}

func toExtra(in map[string]authv1.ExtraValue) map[string]authzv1.ExtraValue {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]authzv1.ExtraValue, len(in))
	for k, v := range in {
		out[k] = authzv1.ExtraValue(v)
	}
	return out
}
