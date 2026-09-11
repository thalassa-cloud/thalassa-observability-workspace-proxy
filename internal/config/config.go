package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	InboundAuthNone        = "none"
	InboundAuthTokenReview = "tokenreview"
	InboundAuthRBAC        = "rbac"

	DefaultThalassaAPIURL  = "https://api.thalassa.cloud"
	DefaultListenAddress   = "127.0.0.1:8080"
	DefaultMetricsAddress  = "127.0.0.1:9090"
	DefaultTokenSkew       = 60 * time.Second
	DefaultUpstreamTimeout = 60 * time.Second
)

// Config holds validated runtime configuration for the auth proxy.
type Config struct {
	ListenAddress string
	Upstream      *url.URL

	ThalassaAPIURL   string
	OrganisationID   string
	ServiceAccountID string
	SubjectTokenFile string
	TokenRefreshSkew time.Duration

	InboundAuth  string
	AuthAudience string

	RBACResourceAPIGroup string
	RBACResource         string
	RBACVerb             string
	RBACNamespace        string
	RBACResourceName     string

	TLSCertFile string
	TLSKeyFile  string

	UpstreamTimeout time.Duration
	MaxBodyBytes    int64

	MetricsAddress string
}

// Validate fails closed when required fields are missing or inconsistent.
func (c *Config) Validate() error {
	if strings.TrimSpace(c.ListenAddress) == "" {
		return fmt.Errorf("listen-address is required")
	}
	if c.Upstream == nil {
		return fmt.Errorf("upstream is required")
	}
	if c.Upstream.Scheme != "http" && c.Upstream.Scheme != "https" {
		return fmt.Errorf("upstream scheme must be http or https")
	}
	if c.Upstream.Host == "" {
		return fmt.Errorf("upstream host is required")
	}
	if strings.TrimSpace(c.ThalassaAPIURL) == "" {
		return fmt.Errorf("thalassa-api-url is required")
	}
	if _, err := url.ParseRequestURI(c.ThalassaAPIURL); err != nil {
		return fmt.Errorf("thalassa-api-url is invalid: %w", err)
	}
	if strings.TrimSpace(c.OrganisationID) == "" {
		return fmt.Errorf("organisation-id is required")
	}
	if strings.TrimSpace(c.ServiceAccountID) == "" {
		return fmt.Errorf("service-account-id is required")
	}
	if strings.TrimSpace(c.SubjectTokenFile) == "" {
		return fmt.Errorf("subject-token-file is required")
	}
	if c.TokenRefreshSkew < 0 {
		return fmt.Errorf("token-refresh-skew must be non-negative")
	}
	if c.UpstreamTimeout <= 0 {
		return fmt.Errorf("upstream-timeout must be positive")
	}
	if c.MaxBodyBytes < 0 {
		return fmt.Errorf("max-body-bytes must be non-negative")
	}

	switch c.InboundAuth {
	case InboundAuthNone, InboundAuthTokenReview, InboundAuthRBAC:
	default:
		return fmt.Errorf("inbound-auth must be one of %s, %s, %s", InboundAuthNone, InboundAuthTokenReview, InboundAuthRBAC)
	}

	if c.InboundAuth == InboundAuthTokenReview || c.InboundAuth == InboundAuthRBAC {
		if strings.TrimSpace(c.AuthAudience) == "" {
			return fmt.Errorf("auth-audience is required when inbound-auth is %s", c.InboundAuth)
		}
	}
	if c.InboundAuth == InboundAuthRBAC {
		if strings.TrimSpace(c.RBACResource) == "" {
			return fmt.Errorf("rbac-resource is required when inbound-auth is rbac")
		}
		if strings.TrimSpace(c.RBACVerb) == "" {
			return fmt.Errorf("rbac-verb is required when inbound-auth is rbac")
		}
	}

	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return fmt.Errorf("tls-cert-file and tls-key-file must both be set or both be empty")
	}

	return nil
}

// EnvOr returns the environment variable value if set, otherwise fallback.
func EnvOr(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}
