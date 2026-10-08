import type { TFunction } from 'i18next'
import type { LatencyProbeResult, NodeLatencyProbeResult } from '~/apis'

export type LatencyMethod = 'handshake' | 'http'
export type LatencyTone = 'good' | 'fair' | 'poor' | 'failed' | 'muted'

export interface LatencySlotView {
  method: LatencyMethod
  /** Short text shown on the card, e.g. "102 ms" or "失败". */
  text: string
  /** Tooltip text, e.g. "TLS 102 ms" or "HTTP 失败: timeout". */
  detail: string
  tone: LatencyTone
  loading: boolean
  /** Warning or note attached to a successful result, e.g. a handshake answered locally. */
  warning?: string
}

export interface LatencyView {
  slots: [LatencySlotView, LatencySlotView]
  /** Card text, handshake first: "102 ms, 525 ms". */
  text: string
  /** Tooltip: "TLS 102 ms, HTTP 525 ms". */
  tooltip: string
}

export interface LatencyLoading {
  handshake?: boolean
  http?: boolean
}

/** What a probe measured, as reported by the server (`probe.method`). */
export type LatencyProbeKind = 'TLS' | 'TCP' | 'QUIC' | 'HTTP'

/** Label used before the server reported which handshake ran. */
const DEFAULT_LABEL: Record<LatencyMethod, LatencyProbeKind> = { handshake: 'TLS', http: 'HTTP' }

export function latencyProbeKind(method: LatencyMethod, probe?: LatencyProbeResult | null): LatencyProbeKind {
  const kind = probe?.method?.toUpperCase()
  if (method === 'handshake' && (kind === 'TLS' || kind === 'TCP' || kind === 'QUIC')) return kind
  return DEFAULT_LABEL[method]
}

/**
 * Upper bounds (exclusive) for green and yellow, per probe kind, in ms. A TLS
 * handshake over TCP costs two round trips; a TCP connect or QUIC handshake one.
 */
export const LATENCY_THRESHOLDS: Record<LatencyProbeKind, [good: number, fair: number]> = {
  TLS: [200, 500],
  TCP: [100, 250],
  QUIC: [100, 250],
  HTTP: [400, 1000],
}

export const LATENCY_TONE_CLASS: Record<LatencyTone, string> = {
  good: 'text-emerald-600 dark:text-emerald-400',
  fair: 'text-amber-600 dark:text-amber-400',
  poor: 'text-red-600 dark:text-red-400',
  failed: 'text-red-600 dark:text-red-400',
  muted: 'text-muted-foreground',
}

export function latencyTone(kind: LatencyProbeKind, latencyMs: number): LatencyTone {
  const [good, fair] = LATENCY_THRESHOLDS[kind]
  if (latencyMs < good) return 'good'
  if (latencyMs < fair) return 'fair'
  return 'poor'
}

/** Returns the probe of one method; results from older servers only carry the legacy HTTP fields. */
export function latencyProbe(result: NodeLatencyProbeResult | undefined, method: LatencyMethod) {
  if (!result) return undefined
  const probe = result[method]
  if (probe) return probe
  if (method === 'http' && result.handshake === undefined && result.http === undefined && result.testedAt) {
    return {
      ok: result.alive,
      latencyMs: result.latencyMs,
      message: result.message,
      testedAt: result.testedAt,
      method: 'HTTP',
      pending: false,
      supported: true,
    } satisfies LatencyProbeResult
  }
  return undefined
}

export function describeLatencySlot(
  method: LatencyMethod,
  probe: LatencyProbeResult | null | undefined,
  t: TFunction,
  loading = false,
): LatencySlotView {
  const label = latencyProbeKind(method, probe)
  if (loading || (probe?.pending && !probe.testedAt)) {
    const testing = t('latency.testing')
    return { method, text: '…', detail: `${label} ${testing}`, tone: 'muted', loading: true }
  }
  if (!probe || (!probe.testedAt && probe.supported !== false)) {
    const notTested = t('latency.notTested')
    return { method, text: '-', detail: `${label} ${notTested}`, tone: 'muted', loading: false }
  }
  if (probe.supported === false) {
    return {
      method,
      text: t('latency.notApplicableShort'),
      detail: probe.message
        ? `${label} ${t('latency.notApplicable')}: ${probe.message}`
        : `${label} ${t('latency.notApplicable')}`,
      tone: 'muted',
      loading: false,
    }
  }
  if (probe.ok && typeof probe.latencyMs === 'number') {
    const text = `${probe.latencyMs} ms`
    const warning = probe.message || undefined
    return {
      method,
      text,
      detail: warning ? `${label} ${text} ⚠ ${warning}` : `${label} ${text}`,
      tone: latencyTone(label, probe.latencyMs),
      loading: false,
      warning,
    }
  }
  const failed = t('latency.failed')
  return {
    method,
    text: failed,
    detail: probe.message ? `${label} ${failed}: ${probe.message}` : `${label} ${failed}`,
    tone: 'failed',
    loading: false,
  }
}

/**
 * Formats a node's handshake and HTTP results, e.g. card "102 ms, 失败" with
 * tooltip "TLS 102 ms, HTTP 失败: HTTP 404". Returns undefined when there is nothing
 * to show.
 */
export function formatLatency(
  result: NodeLatencyProbeResult | undefined,
  t: TFunction,
  loading: LatencyLoading = {},
): LatencyView | undefined {
  const handshake = latencyProbe(result, 'handshake')
  const http = latencyProbe(result, 'http')
  const handshakeLoading = Boolean(loading.handshake || handshake?.pending)
  const httpLoading = Boolean(loading.http || http?.pending)
  if (!handshake && !http && !handshakeLoading && !httpLoading) {
    return undefined
  }
  const slots: [LatencySlotView, LatencySlotView] = [
    describeLatencySlot('handshake', handshake, t, handshakeLoading),
    describeLatencySlot('http', http, t, httpLoading),
  ]
  return {
    slots,
    text: slots.map((slot) => slot.text).join(', '),
    tooltip: slots.map((slot) => slot.detail).join(', '),
  }
}

/** True when the node has a successful HTTP measurement. */
export function hasMeasuredLatency(result?: NodeLatencyProbeResult) {
  const http = latencyProbe(result, 'http')
  return Boolean(http?.ok && Number.isFinite(http.latencyMs))
}

/** Plain-text label for places that cannot render a badge. */
export function formatLatencyLabel(result: NodeLatencyProbeResult | undefined, t: TFunction) {
  return formatLatency(result, t)?.text
}

/** testedAt of each method when a test was requested; a slot shows loading until it changes. */
export interface LatencyBaseline {
  handshake: string | null
  http: string | null
  refs: number
}

export function latencyLoadingState(
  baseline: LatencyBaseline | undefined,
  result: NodeLatencyProbeResult | undefined,
): LatencyLoading {
  return {
    handshake: Boolean(
      result?.handshake?.pending || (baseline && (result?.handshake?.testedAt ?? null) === baseline.handshake),
    ),
    http: Boolean(result?.http?.pending || (baseline && (result?.http?.testedAt ?? null) === baseline.http)),
  }
}
