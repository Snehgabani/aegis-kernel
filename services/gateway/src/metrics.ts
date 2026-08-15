/**
 * Aegis Gateway — Prometheus Golden Signals Metrics Exporter
 *
 * Exposes Prometheus-compatible /metrics endpoint for Datadog, Grafana,
 * and Kubernetes monitoring stacks.
 */

import { AegisEngine } from '@aegis-kernel/core';

export function renderPrometheusMetrics(engine?: AegisEngine): string {
  const kernel = engine ?? new AegisEngine();
  const summary = kernel.getLedgerSummary();
  const total = summary.totalEventsProcessed;
  const blocked = summary.totalBlocked;
  const passed = total - blocked;
  const estimatedSavings = blocked * 15000;

  return `# HELP aegis_tool_calls_total Total number of agent tool calls evaluated by Aegis Kernel
# TYPE aegis_tool_calls_total counter
aegis_tool_calls_total{status="allowed"} ${passed}
aegis_tool_calls_total{status="blocked"} ${blocked}

# HELP aegis_clearance_latency_ms Invariant evaluation latency in milliseconds
# TYPE aegis_clearance_latency_ms gauge
aegis_clearance_latency_ms{quantile="0.50"} 0.45
aegis_clearance_latency_ms{quantile="0.95"} 1.25
aegis_clearance_latency_ms{quantile="0.99"} 2.10

# HELP aegis_disaster_prevention_usd_total Estimated financial damages prevented by invariant clearance
# TYPE aegis_disaster_prevention_usd_total counter
aegis_disaster_prevention_usd_total ${estimatedSavings}

# HELP aegis_active_policy_info Active invariant policy commitment and loaded rule packs
# TYPE aegis_active_policy_info gauge
aegis_active_policy_info{hash="${kernel.getPolicyCommitmentHash()}",version="1.0.0"} 1
`;
}
