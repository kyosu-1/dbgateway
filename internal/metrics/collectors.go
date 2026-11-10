package metrics

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/kyosu-1/dbgateway/internal/audit"
	"github.com/kyosu-1/dbgateway/internal/gateway"
	"github.com/kyosu-1/dbgateway/internal/notify"
)

// poolCollector exports connection pool statistics at scrape time.
type poolCollector struct {
	stats func() []gateway.PoolStats
}

var (
	poolLabels    = []string{"database", "pool"}
	poolConnsDesc = prometheus.NewDesc(namespace+"_db_pool_connections",
		"Open connections of a database connection pool, by state (in_use or idle).",
		append(poolLabels, "state"), nil)
	poolMaxDesc = prometheus.NewDesc(namespace+"_db_pool_max_connections",
		"Maximum connections of a database connection pool (0: unlimited).", poolLabels, nil)
	poolWaitsDesc = prometheus.NewDesc(namespace+"_db_pool_waits_total",
		"Connection acquisitions that had to wait because the pool had no idle connection.", poolLabels, nil)
	poolWaitSecondsDesc = prometheus.NewDesc(namespace+"_db_pool_wait_seconds_total",
		"Total time spent waiting for a connection.", poolLabels, nil)
)

func (c *poolCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- poolConnsDesc
	ch <- poolMaxDesc
	ch <- poolWaitsDesc
	ch <- poolWaitSecondsDesc
}

func (c *poolCollector) Collect(ch chan<- prometheus.Metric) {
	for _, s := range c.stats() {
		pool := oneOf(s.Pool, "read", "replica", "write")
		ch <- prometheus.MustNewConstMetric(poolConnsDesc, prometheus.GaugeValue, float64(s.InUse), s.Database, pool, "in_use")
		ch <- prometheus.MustNewConstMetric(poolConnsDesc, prometheus.GaugeValue, float64(s.Idle), s.Database, pool, "idle")
		ch <- prometheus.MustNewConstMetric(poolMaxDesc, prometheus.GaugeValue, float64(s.Max), s.Database, pool)
		ch <- prometheus.MustNewConstMetric(poolWaitsDesc, prometheus.CounterValue, float64(s.WaitCount), s.Database, pool)
		ch <- prometheus.MustNewConstMetric(poolWaitSecondsDesc, prometheus.CounterValue, s.WaitDuration.Seconds(), s.Database, pool)
	}
}

// notifyCollector exports the notification dispatcher's counters.
type notifyCollector struct {
	stats func() notify.Stats
}

var (
	notifyEventsDesc = prometheus.NewDesc(namespace+"_notification_events_total",
		"Events offered to notifications, by result: published (queued) or dropped (queue full or shutting down).",
		[]string{"result"}, nil)
	notifyDeliveriesDesc = prometheus.NewDesc(namespace+"_notification_deliveries_total",
		"Notification deliveries (Slack posts, webhook requests), by result: delivered, failed (after retries) or skipped.",
		[]string{"result"}, nil)
)

func (c *notifyCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- notifyEventsDesc
	ch <- notifyDeliveriesDesc
}

func (c *notifyCollector) Collect(ch chan<- prometheus.Metric) {
	s := c.stats()
	ch <- prometheus.MustNewConstMetric(notifyEventsDesc, prometheus.CounterValue, float64(s.Published), "published")
	ch <- prometheus.MustNewConstMetric(notifyEventsDesc, prometheus.CounterValue, float64(s.Dropped), "dropped")
	ch <- prometheus.MustNewConstMetric(notifyDeliveriesDesc, prometheus.CounterValue, float64(s.Delivered), "delivered")
	ch <- prometheus.MustNewConstMetric(notifyDeliveriesDesc, prometheus.CounterValue, float64(s.Failed), "failed")
	ch <- prometheus.MustNewConstMetric(notifyDeliveriesDesc, prometheus.CounterValue, float64(s.Skipped), "skipped")
}

// forwarderCollector exports the audit forwarders' counters.
type forwarderCollector struct {
	stats func() []audit.ForwarderStats
}

var forwardedDesc = prometheus.NewDesc(namespace+"_audit_forwarded_records_total",
	"Audit records forwarded best effort (e.g. OTLP), by result: sent, dropped (queue full) or failed.",
	[]string{"forwarder", "result"}, nil)

func (c *forwarderCollector) Describe(ch chan<- *prometheus.Desc) { ch <- forwardedDesc }

func (c *forwarderCollector) Collect(ch chan<- prometheus.Metric) {
	for _, s := range c.stats() {
		ch <- prometheus.MustNewConstMetric(forwardedDesc, prometheus.CounterValue, float64(s.Sent), s.Name, "sent")
		ch <- prometheus.MustNewConstMetric(forwardedDesc, prometheus.CounterValue, float64(s.Dropped), s.Name, "dropped")
		ch <- prometheus.MustNewConstMetric(forwardedDesc, prometheus.CounterValue, float64(s.Failed), s.Name, "failed")
	}
}
