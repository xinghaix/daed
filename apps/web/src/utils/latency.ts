import type { TFunction } from 'i18next'
import type { LatencyProbeResult, NodeLatencyProbeResult } from '~/apis'

export type LatencyMethod = 'ping' | 'http'
export type LatencyTone = 'good' | 'fair' | 'poor' | 'failed' | 'muted'

export interface LatencySlotView {
  method: LatencyMethod
  /** Short text shown on the card, e.g. "102 ms" or "失败". */
  text: string
  /** Tooltip text, e.g. "PING 102 ms" or "HTTP 失败: timeout". */
  detail: string
  tone: LatencyTone
  loading: boolean
}

export interface LatencyView {
  slots: [LatencySlotView, LatencySlotView]
  /** Card text, PING first: "102 ms, 525 ms". */
  text: string
  /** Tooltip: "PING 102 ms, HTTP 525 ms". */
  tooltip: string
}

export interface LatencyLoading {
  ping?: boolean
  http?: boolean
}

const METHOD_LABEL: Record<LatencyMethod, string> = { ping: 'PING', http: 'HTTP' }

/** Upper bounds (exclusive) for green and yellow, per method, in ms. */
export const LATENCY_THRESHOLDS: Record<LatencyMethod, [good: number, fair: number]> = {
  ping: [100, 250],
  http: [400, 1000],
}

export const LATENCY_TONE_CLASS: Record<LatencyTone, string> = {
  good: 'text-emerald-600 dark:text-emerald-400',
  fair: 'text-amber-600 dark:text-amber-400',
  poor: 'text-red-600 dark:text-red-400',
  failed: 'text-red-600 dark:text-red-400',
  muted: 'text-muted-foreground',
}

export function latencyTone(method: LatencyMethod, latencyMs: number): LatencyTone {
  const [good, fair] = LATENCY_THRESHOLDS[method]
  if (latencyMs < good) return 'good'
  if (latencyMs < fair) return 'fair'
  return 'poor'
}

/** Returns the probe of one method; results from older servers only carry the legacy HTTP fields. */
export function latencyProbe(result: NodeLatencyProbeResult | undefined, method: LatencyMethod) {
  if (!result) return undefined
  const probe = result[method]
  if (probe) return probe
  if (method === 'http' && result.ping === undefined && result.http === undefined && result.testedAt) {
    return {
      ok: result.alive,
      latencyMs: result.latencyMs,
      message: result.message,
      testedAt: result.testedAt,
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
  const label = METHOD_LABEL[method]
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
      detail: `${label} ${t('latency.notApplicable')}`,
      tone: 'muted',
      loading: false,
    }
  }
  if (probe.ok && typeof probe.latencyMs === 'number') {
    const text = `${probe.latencyMs} ms`
    return { method, text, detail: `${label} ${text}`, tone: latencyTone(method, probe.latencyMs), loading: false }
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
 * Formats a node's PING and HTTP results, e.g. card "102 ms, 失败" with tooltip
 * "PING 102 ms, HTTP 失败: HTTP 404". Returns undefined when there is nothing
 * to show.
 */
export function formatLatency(
  result: NodeLatencyProbeResult | undefined,
  t: TFunction,
  loading: LatencyLoading = {},
): LatencyView | undefined {
  const ping = latencyProbe(result, 'ping')
  const http = latencyProbe(result, 'http')
  const pingLoading = Boolean(loading.ping || ping?.pending)
  const httpLoading = Boolean(loading.http || http?.pending)
  if (!ping && !http && !pingLoading && !httpLoading) {
    return undefined
  }
  const slots: [LatencySlotView, LatencySlotView] = [
    describeLatencySlot('ping', ping, t, pingLoading),
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
  ping: string | null
  http: string | null
  refs: number
}

export function latencyLoadingState(
  baseline: LatencyBaseline | undefined,
  result: NodeLatencyProbeResult | undefined,
): LatencyLoading {
  return {
    ping: Boolean(result?.ping?.pending || (baseline && (result?.ping?.testedAt ?? null) === baseline.ping)),
    http: Boolean(result?.http?.pending || (baseline && (result?.http?.testedAt ?? null) === baseline.http)),
  }
}
