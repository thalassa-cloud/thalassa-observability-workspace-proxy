package authz

import (
	"context"
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
type Reviewer interface {
	Authorize(ctx context.Context, token string) error
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
			http.Error(w, "forbidden", http.StatusForbidden)
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
		return fmt.Errorf("kubernetes client is required")
	}
	if strings.TrimSpace(token) == "" {
		return fmt.Errorf("token is required")
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
		return fmt.Errorf("token review failed: %w", err)
	}
	if !res.Status.Authenticated {
		return fmt.Errorf("token is not authenticated")
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
		return fmt.Errorf("subject access review failed: %w", err)
	}
	if !sarRes.Status.Allowed {
		reason := sarRes.Status.Reason
		if reason == "" {
			reason = "access denied"
		}
		return fmt.Errorf("rbac denied: %s", reason)
	}
	return nil
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
