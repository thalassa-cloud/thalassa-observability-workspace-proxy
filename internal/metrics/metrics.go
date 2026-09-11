package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Collector holds proxy instrumentation.
type Collector struct {
	requestsTotal   *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec
}

// New registers metrics on the given registerer (defaults to prometheus.DefaultRegisterer).
func New(reg prometheus.Registerer) *Collector {
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}
	factory := promauto.With(reg)
	return &Collector{
		requestsTotal: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "observability_proxy_requests_total",
			Help: "Total HTTP requests handled by the proxy.",
		}, []string{"code", "method"}),
		requestDuration: factory.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "observability_proxy_request_duration_seconds",
			Help:    "Request latency in seconds.",
			Buckets: prometheus.DefBuckets,
		}, []string{"code", "method"}),
	}
}

// Handler returns the Prometheus scrape handler.
func Handler() http.Handler {
	return promhttp.Handler()
}

// Middleware records request metrics around next.
func (c *Collector) Middleware(next http.Handler) http.Handler {
	if c == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		code := strconv.Itoa(rw.status)
		c.requestsTotal.WithLabelValues(code, r.Method).Inc()
		c.requestDuration.WithLabelValues(code, r.Method).Observe(time.Since(start).Seconds())
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}
