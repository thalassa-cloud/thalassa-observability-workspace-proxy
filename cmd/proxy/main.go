package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/thalassa-cloud/thalassa-observability-workspace-proxy/internal/authz"
	"github.com/thalassa-cloud/thalassa-observability-workspace-proxy/internal/config"
	"github.com/thalassa-cloud/thalassa-observability-workspace-proxy/internal/health"
	"github.com/thalassa-cloud/thalassa-observability-workspace-proxy/internal/metrics"
	"github.com/thalassa-cloud/thalassa-observability-workspace-proxy/internal/proxy"
	"github.com/thalassa-cloud/thalassa-observability-workspace-proxy/internal/wif"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func main() {
	os.Exit(run())
}

func run() int {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := parseFlags(os.Args[1:])
	if err != nil {
		logger.Error("invalid configuration", "error", err.Error())
		return 2
	}
	if err := cfg.Validate(); err != nil {
		logger.Error("invalid configuration", "error", err.Error())
		return 2
	}

	tokenClient := &wif.ExchangeClient{
		APIURL:           cfg.ThalassaAPIURL,
		OrganisationID:   cfg.OrganisationID,
		ServiceAccountID: cfg.ServiceAccountID,
		SubjectTokenFile: cfg.SubjectTokenFile,
		RefreshSkew:      cfg.TokenRefreshSkew,
		HTTPClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Warm token so readiness can pass and first requests avoid cold exchange latency.
	if _, err := tokenClient.Token(ctx); err != nil {
		logger.Warn("initial token exchange failed; readiness will stay down until success", "error", err.Error())
	} else {
		logger.Info("initial token exchange succeeded")
	}

	proxyHandler, err := proxy.New(cfg.Upstream, tokenClient, cfg.UpstreamTimeout, cfg.MaxBodyBytes, logger)
	if err != nil {
		logger.Error("create proxy", "error", err.Error())
		return 1
	}

	var inbound http.Handler = proxyHandler
	if cfg.InboundAuth != config.InboundAuthNone {
		reviewer, err := newK8sReviewer(cfg)
		if err != nil {
			logger.Error("configure inbound auth", "error", err.Error())
			return 1
		}
		inbound = (&authz.Middleware{
			Mode:     cfg.InboundAuth,
			Reviewer: reviewer,
		}).Wrap(proxyHandler)
		logger.Info("inbound auth enabled", "mode", cfg.InboundAuth)
	}

	mux := http.NewServeMux()
	(&health.Handler{Tokens: tokenClient}).Register(mux)

	collector := metrics.New(nil)
	mux.Handle("/", collector.Middleware(inbound))

	srv := &http.Server{
		Addr:              cfg.ListenAddress,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       cfg.UpstreamTimeout + 10*time.Second,
		WriteTimeout:      cfg.UpstreamTimeout + 10*time.Second,
		IdleTimeout:       120 * time.Second,
	}

	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", metrics.Handler())
	metricsSrv := &http.Server{
		Addr:              cfg.MetricsAddress,
		Handler:           metricsMux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 2)
	go func() {
		logger.Info("listening", "addr", cfg.ListenAddress, "upstream", cfg.Upstream.String(), "tls", cfg.TLSCertFile != "")
		var serveErr error
		if cfg.TLSCertFile != "" {
			serveErr = srv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			serveErr = srv.ListenAndServe()
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errCh <- serveErr
		}
	}()
	go func() {
		logger.Info("metrics listening", "addr", cfg.MetricsAddress)
		if serveErr := metricsSrv.ListenAndServe(); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errCh <- serveErr
		}
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutting down")
	case err := <-errCh:
		logger.Error("server failed", "error", err.Error())
		return 1
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	_ = metricsSrv.Shutdown(shutdownCtx)
	return 0
}

func parseFlags(args []string) (config.Config, error) {
	fs := flag.NewFlagSet("observability-workspace-proxy", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	listenAddress := fs.String(
		"listen-address",
		config.EnvOr("LISTEN_ADDRESS", config.DefaultListenAddress),
		"Address to listen on for proxied traffic",
	)
	upstreamRaw := fs.String(
		"upstream",
		config.EnvOr("UPSTREAM", ""),
		"Upstream workspace gateway base URL (scheme + host)",
	)
	thalassaAPIURL := fs.String(
		"thalassa-api-url",
		config.EnvOr("THALASSA_API_URL", config.DefaultThalassaAPIURL),
		"Thalassa Cloud API base URL",
	)
	organisationID := fs.String(
		"organisation-id",
		config.EnvOr("THALASSA_ORGANISATION_ID", ""),
		"Thalassa organisation ID",
	)
	serviceAccountID := fs.String(
		"service-account-id",
		config.EnvOr("THALASSA_SERVICE_ACCOUNT_ID", ""),
		"Thalassa service account ID to impersonate",
	)
	subjectTokenFile := fs.String(
		"subject-token-file",
		config.EnvOr("THALASSA_SUBJECT_TOKEN_FILE", ""),
		"Path to projected Kubernetes SA JWT",
	)
	tokenRefreshSkew := fs.Duration(
		"token-refresh-skew",
		config.DefaultTokenSkew,
		"Refresh cached Thalassa token this long before expiry",
	)
	inboundAuth := fs.String(
		"inbound-auth",
		config.EnvOr("INBOUND_AUTH", config.InboundAuthNone),
		"Inbound auth mode: none|tokenreview|rbac",
	)
	authAudience := fs.String(
		"auth-audience",
		config.EnvOr("AUTH_AUDIENCE", ""),
		"Expected audience for inbound TokenReview",
	)
	rbacAPIGroup := fs.String(
		"rbac-resource-api-group",
		config.EnvOr("RBAC_RESOURCE_API_GROUP", ""),
		"SAR resource API group",
	)
	rbacResource := fs.String(
		"rbac-resource",
		config.EnvOr("RBAC_RESOURCE", ""),
		"SAR resource",
	)
	rbacVerb := fs.String(
		"rbac-verb",
		config.EnvOr("RBAC_VERB", ""),
		"SAR verb",
	)
	rbacNamespace := fs.String(
		"rbac-namespace",
		config.EnvOr("RBAC_NAMESPACE", ""),
		"SAR namespace (optional)",
	)
	rbacResourceName := fs.String(
		"rbac-resource-name",
		config.EnvOr("RBAC_RESOURCE_NAME", ""),
		"SAR resource name (optional)",
	)
	tlsCertFile := fs.String(
		"tls-cert-file",
		config.EnvOr("TLS_CERT_FILE", ""),
		"TLS certificate file",
	)
	tlsKeyFile := fs.String(
		"tls-key-file",
		config.EnvOr("TLS_KEY_FILE", ""),
		"TLS private key file",
	)
	upstreamTimeout := fs.Duration(
		"upstream-timeout",
		config.DefaultUpstreamTimeout,
		"Timeout for upstream requests and token exchange",
	)
	maxBodyBytes := fs.Int64(
		"max-body-bytes",
		0,
		"Max request body size in bytes (0 = unlimited)",
	)
	metricsAddress := fs.String(
		"metrics-address",
		config.EnvOr("METRICS_ADDRESS", config.DefaultMetricsAddress),
		"Address for /metrics",
	)

	if err := fs.Parse(args); err != nil {
		return config.Config{}, err
	}

	cfg := config.Config{
		ListenAddress:        *listenAddress,
		ThalassaAPIURL:       strings.TrimRight(*thalassaAPIURL, "/"),
		OrganisationID:       *organisationID,
		ServiceAccountID:     *serviceAccountID,
		SubjectTokenFile:     *subjectTokenFile,
		TokenRefreshSkew:     *tokenRefreshSkew,
		InboundAuth:          strings.ToLower(strings.TrimSpace(*inboundAuth)),
		AuthAudience:         *authAudience,
		RBACResourceAPIGroup: *rbacAPIGroup,
		RBACResource:         *rbacResource,
		RBACVerb:             *rbacVerb,
		RBACNamespace:        *rbacNamespace,
		RBACResourceName:     *rbacResourceName,
		TLSCertFile:          *tlsCertFile,
		TLSKeyFile:           *tlsKeyFile,
		UpstreamTimeout:      *upstreamTimeout,
		MaxBodyBytes:         *maxBodyBytes,
		MetricsAddress:       *metricsAddress,
	}

	if strings.TrimSpace(*upstreamRaw) != "" {
		u, err := url.Parse(*upstreamRaw)
		if err != nil {
			return config.Config{}, fmt.Errorf("parse upstream: %w", err)
		}
		if u.Path != "" && u.Path != "/" {
			return config.Config{}, fmt.Errorf("upstream must be a base URL without path (got %q)", u.Path)
		}
		u.Path = ""
		u.RawQuery = ""
		u.Fragment = ""
		cfg.Upstream = u
	}

	return cfg, nil
}

func newK8sReviewer(cfg config.Config) (*authz.K8sReviewer, error) {
	restCfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("in-cluster kubernetes config: %w", err)
	}
	client, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("kubernetes client: %w", err)
	}
	return &authz.K8sReviewer{
		Client: client,
		Config: authz.Config{
			Mode:             cfg.InboundAuth,
			Audience:         cfg.AuthAudience,
			ResourceAPIGroup: cfg.RBACResourceAPIGroup,
			Resource:         cfg.RBACResource,
			ResourceName:     cfg.RBACResourceName,
			Verb:             cfg.RBACVerb,
			Namespace:        cfg.RBACNamespace,
		},
	}, nil
}
