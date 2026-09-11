package config

import (
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestConfigValidate(t *testing.T) {
	upstream, err := url.Parse("https://prometheus.nl-01.thalassa.cloud")
	require.NoError(t, err)

	valid := func() Config {
		return Config{
			ListenAddress:    "127.0.0.1:8080",
			Upstream:         upstream,
			ThalassaAPIURL:   DefaultThalassaAPIURL,
			OrganisationID:   "org-1",
			ServiceAccountID: "sa-1",
			SubjectTokenFile: "/var/run/secrets/tokens/oidc",
			TokenRefreshSkew: DefaultTokenSkew,
			InboundAuth:      InboundAuthNone,
			UpstreamTimeout:  DefaultUpstreamTimeout,
			MaxBodyBytes:     0,
			MetricsAddress:   DefaultMetricsAddress,
		}
	}

	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{
			name: "valid none",
		},
		{
			name: "missing listen",
			mutate: func(c *Config) {
				c.ListenAddress = ""
			},
			wantErr: "listen-address is required",
		},
		{
			name: "missing upstream",
			mutate: func(c *Config) {
				c.Upstream = nil
			},
			wantErr: "upstream is required",
		},
		{
			name: "invalid inbound auth",
			mutate: func(c *Config) {
				c.InboundAuth = "bogus"
			},
			wantErr: "inbound-auth must be one of",
		},
		{
			name: "tokenreview requires audience",
			mutate: func(c *Config) {
				c.InboundAuth = InboundAuthTokenReview
				c.AuthAudience = ""
			},
			wantErr: "auth-audience is required",
		},
		{
			name: "rbac requires resource and verb",
			mutate: func(c *Config) {
				c.InboundAuth = InboundAuthRBAC
				c.AuthAudience = "https://proxy.example"
				c.RBACResource = ""
				c.RBACVerb = "get"
			},
			wantErr: "rbac-resource is required",
		},
		{
			name: "tls mismatch",
			mutate: func(c *Config) {
				c.TLSCertFile = "/cert.pem"
			},
			wantErr: "tls-cert-file and tls-key-file must both be set",
		},
		{
			name: "valid rbac",
			mutate: func(c *Config) {
				c.InboundAuth = InboundAuthRBAC
				c.AuthAudience = "https://proxy.example"
				c.RBACResource = "services"
				c.RBACVerb = "proxy"
				c.RBACNamespace = "observability"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := valid()
			if tt.mutate != nil {
				tt.mutate(&cfg)
			}
			err := cfg.Validate()
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestEnvOr(t *testing.T) {
	t.Setenv("TEST_CFG_ENV", "from-env")
	require.Equal(t, "from-env", EnvOr("TEST_CFG_ENV", "fallback"))
	require.Equal(t, "fallback", EnvOr("TEST_CFG_ENV_MISSING", "fallback"))
	require.Equal(t, time.Minute, DefaultTokenSkew)
}
