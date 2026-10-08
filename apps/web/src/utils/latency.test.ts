import type { TFunction } from 'i18next'
import type { NodeLatencyProbeResult } from '~/apis'
import { formatLatency, formatLatencyLabel, hasMeasuredLatency, latencyLoadingState, latencyTone } from './latency'

const zh: Record<string, string> = {
  'latency.failed': '失败',
  'latency.testing': '测试中…',
  'latency.notTested': '未测试',
  'latency.notApplicable': '不适用（仅 UDP 协议）',
  'latency.notApplicableShort': 'N/A',
}
const t = ((key: string) => zh[key] ?? key) as unknown as TFunction

const at = '2026-10-08T10:00:00+08:00'
const ok = (latencyMs: number) => ({ ok: true, latencyMs, testedAt: at, pending: false, supported: true })
const failed = (message?: string) => ({ ok: false, message, testedAt: at, pending: false, supported: true })

function node(partial: Partial<NodeLatencyProbeResult>): NodeLatencyProbeResult {
  return { id: '1', alive: true, testedAt: at, ...partial }
}

describe('formatLatency', () => {
  it('shows PING then HTTP', () => {
    const view = formatLatency(node({ ping: ok(102), http: ok(525) }), t)
    expect(view?.text).toBe('102 ms, 525 ms')
    expect(view?.tooltip).toBe('PING 102 ms, HTTP 525 ms')
  })

  it('shows a failed method in its slot with the reason in the tooltip', () => {
    const view = formatLatency(node({ ping: ok(102), http: failed('HTTP 404') }), t)
    expect(view?.text).toBe('102 ms, 失败')
    expect(view?.tooltip).toBe('PING 102 ms, HTTP 失败: HTTP 404')
    expect(view?.slots[1].tone).toBe('failed')
  })

  it('omits the colon when there is no reason', () => {
    expect(formatLatency(node({ ping: failed(), http: ok(80) }), t)?.tooltip).toBe('PING 失败, HTTP 80 ms')
  })

  it('marks PING as not applicable for UDP-only nodes', () => {
    const view = formatLatency(
      node({ ping: { ok: false, testedAt: at, pending: false, supported: false }, http: ok(300) }),
      t,
    )
    expect(view?.text).toBe('N/A, 300 ms')
    expect(view?.tooltip).toBe('PING 不适用（仅 UDP 协议）, HTTP 300 ms')
  })

  it('shows loading per slot and keeps finished slots', () => {
    const view = formatLatency(node({ ping: ok(90), http: { ...ok(500), pending: true } }), t)
    expect(view?.slots.map((s) => s.loading)).toEqual([false, true])
    expect(view?.text).toBe('90 ms, …')
    expect(view?.tooltip).toBe('PING 90 ms, HTTP 测试中…')
  })

  it('shows loading before any result exists', () => {
    const view = formatLatency(undefined, t, { ping: true, http: true })
    expect(view?.slots.every((s) => s.loading)).toBe(true)
  })

  it('returns nothing for untested nodes', () => {
    expect(formatLatency(undefined, t)).toBeUndefined()
    expect(formatLatencyLabel(undefined, t)).toBeUndefined()
  })

  it('reads legacy results as HTTP', () => {
    const view = formatLatency({ id: '1', alive: false, testedAt: at, message: 'timeout' }, t)
    expect(view?.text).toBe('-, 失败')
    expect(view?.tooltip).toBe('PING 未测试, HTTP 失败: timeout')
    expect(hasMeasuredLatency({ id: '1', alive: true, testedAt: at, latencyMs: 120 })).toBe(true)
  })

  it('shows dae runtime results (HTTP only) with PING untested', () => {
    const view = formatLatency(node({ ping: null, http: ok(250) }), t)
    expect(view?.text).toBe('-, 250 ms')
  })
})

describe('latencyTone', () => {
  it('uses per-method thresholds', () => {
    expect(latencyTone('ping', 99)).toBe('good')
    expect(latencyTone('ping', 100)).toBe('fair')
    expect(latencyTone('ping', 250)).toBe('poor')
    expect(latencyTone('http', 399)).toBe('good')
    expect(latencyTone('http', 999)).toBe('fair')
    expect(latencyTone('http', 1000)).toBe('poor')
  })
})

describe('latencyLoadingState', () => {
  const baseline = { ping: at, http: at, refs: 1 }
  it('loads until each method reports a new result', () => {
    const later = '2026-10-08T10:00:05+08:00'
    expect(latencyLoadingState(baseline, node({ ping: ok(1), http: ok(2) }))).toEqual({ ping: true, http: true })
    expect(latencyLoadingState(baseline, node({ ping: { ...ok(1), testedAt: later }, http: ok(2) }))).toEqual({
      ping: false,
      http: true,
    })
    expect(latencyLoadingState(undefined, node({ ping: ok(1), http: ok(2) }))).toEqual({ ping: false, http: false })
    expect(latencyLoadingState({ ping: null, http: null, refs: 1 }, undefined)).toEqual({ ping: true, http: true })
  })
})
