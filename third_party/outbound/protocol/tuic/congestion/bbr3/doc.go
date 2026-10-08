// Package bbr3 is an EXPERIMENTAL homemade congestion controller for local
// evaluation. The name is historical; this is not a verified BBRv3 implementation.
// A Linux kernel version (including >=6.4), gain constants, or a half-inflight
// PROBE_RTT target does not establish BBRv3 support or specification conformance.
//
// The local model uses a simplified ACK sampler, round filter, mode cycle,
// adaptive loss threshold, and inflight bounds. Its behavior differs from reference
// BBR implementations. ECN/timer callbacks revoke hint targeting, but this sender
// has no complete ECN or reference loss-recovery model, Reno coexistence logic,
// ACK aggregation compensation, or randomized probe scheduling. Historical local
// throughput claims from the old benchmark must not be used as validation.
//
// The optional access hint is a ceiling by default. StrictHintCap prohibits all
// pacing above it; otherwise only PROBE_UP can exceed it within the configured
// factor and round budget. EnableValidatedHint is false by default. When opted
// in, actual acknowledged volume over three windows and low RTT inflation can
// authorize a temporary target. A short probe can use at most 110% of observed
// delivery, capped by the hint. Loss, ECN, PTO, queue growth, insufficient delivery,
// or expired evidence withdraws authorization. This conservative gate does not
// classify loss as random or congestion loss and never scales ACKs for loss.
//
// Benchmark adapters of external controllers remain outside this product. Their
// origin does not transfer production quality or equivalence to a local port.
package bbr3
