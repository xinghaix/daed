import type { TFunction } from 'i18next'
import type { NodeLatencyProbeResult } from '~/apis'
import { formatLatency, formatLatencyLabel, hasMeasuredLatency, latencyLoadingState, latencyTone } from './latency'

const zh: Record<string, string> = {
  'latency.failed': '失败',
  'latency.testing': '测试中…',
  'latency.notTested': '未测试',
  'latency.notApplicable': '不适用',
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
  it('shows the handshake then HTTP', () => {
    const view = formatLatency(node({ handshake: ok(102), http: ok(525) }), t)
    expect(view?.text).toBe('102 ms, 525 ms')
    expect(view?.tooltip).toBe('TLS 102 ms, HTTP 525 ms')
  })

  it('shows a failed method in its slot with the reason in the tooltip', () => {
    const view = formatLatency(node({ handshake: ok(102), http: failed('HTTP 404') }), t)
    expect(view?.text).toBe('102 ms, 失败')
    expect(view?.tooltip).toBe('TLS 102 ms, HTTP 失败: HTTP 404')
    expect(view?.slots[1].tone).toBe('failed')
  })

  it('shows warnings on successful results in the tooltip', () => {
    const view = formatLatency(
      node({ handshake: { ...ok(1), message: 'suspiciously low for public address 203.0.113.1' }, http: ok(500) }),
      t,
    )
    expect(view?.text).toBe('1 ms, 500 ms')
    expect(view?.tooltip).toBe('TLS 1 ms ⚠ suspiciously low for public address 203.0.113.1, HTTP 500 ms')
    expect(view?.slots[0].warning).toContain('suspiciously')
  })

  it('omits the colon when there is no reason', () => {
    expect(formatLatency(node({ handshake: failed(), http: ok(80) }), t)?.tooltip).toBe('TLS 失败, HTTP 80 ms')
  })

  it('marks the handshake as not applicable with the reason', () => {
    const view = formatLatency(
      node({
        handshake: { ok: false, message: 'obfuscated QUIC', testedAt: at, pending: false, supported: false },
        http: ok(300),
      }),
      t,
    )
    expect(view?.text).toBe('N/A, 300 ms')
    expect(view?.tooltip).toBe('TLS 不适用: obfuscated QUIC, HTTP 300 ms')
  })

  it('labels the handshake with the method the server ran', () => {
    const quic = formatLatency(node({ handshake: { ...ok(80), method: 'QUIC' }, http: ok(300) }), t)
    expect(quic?.tooltip).toBe('QUIC 80 ms, HTTP 300 ms')
    const reality = formatLatency(node({ handshake: { ...ok(40), method: 'TCP' }, http: ok(300) }), t)
    expect(reality?.tooltip).toBe('TCP 40 ms, HTTP 300 ms')
    expect(reality?.text).toBe('40 ms, 300 ms')
    expect(reality?.slots[0].tone).toBe('good')
    // Unknown or missing methods fall back to TLS.
    expect(formatLatency(node({ handshake: { ...ok(5), method: '' } }), t)?.tooltip).toBe('TLS 5 ms, HTTP 未测试')
  })

  it('shows loading per slot and keeps finished slots', () => {
    const view = formatLatency(node({ handshake: ok(90), http: { ...ok(500), pending: true } }), t)
    expect(view?.slots.map((s) => s.loading)).toEqual([false, true])
    expect(view?.text).toBe('90 ms, …')
    expect(view?.tooltip).toBe('TLS 90 ms, HTTP 测试中…')
  })

  it('shows loading before any result exists', () => {
    const view = formatLatency(undefined, t, { handshake: true, http: true })
    expect(view?.slots.every((s) => s.loading)).toBe(true)
  })

  it('returns nothing for untested nodes', () => {
    expect(formatLatency(undefined, t)).toBeUndefined()
    expect(formatLatencyLabel(undefined, t)).toBeUndefined()
  })

  it('reads legacy results as HTTP', () => {
    const view = formatLatency({ id: '1', alive: false, testedAt: at, message: 'timeout' }, t)
    expect(view?.text).toBe('-, 失败')
    expect(view?.tooltip).toBe('TLS 未测试, HTTP 失败: timeout')
    expect(hasMeasuredLatency({ id: '1', alive: true, testedAt: at, latencyMs: 120 })).toBe(true)
  })

  it('shows dae runtime results (HTTP only) with the handshake untested', () => {
    const view = formatLatency(node({ handshake: null, http: ok(250) }), t)
    expect(view?.text).toBe('-, 250 ms')
  })
})

describe('latencyTone', () => {
  it('uses per-kind thresholds', () => {
    expect(latencyTone('TCP', 99)).toBe('good')
    expect(latencyTone('TCP', 100)).toBe('fair')
    expect(latencyTone('QUIC', 250)).toBe('poor')
    expect(latencyTone('TLS', 199)).toBe('good')
    expect(latencyTone('TLS', 499)).toBe('fair')
    expect(latencyTone('TLS', 500)).toBe('poor')
    expect(latencyTone('HTTP', 399)).toBe('good')
    expect(latencyTone('HTTP', 999)).toBe('fair')
    expect(latencyTone('HTTP', 1000)).toBe('poor')
  })
})

describe('latencyLoadingState', () => {
  const baseline = { handshake: at, http: at, refs: 1 }
  it('loads until each method reports a new result', () => {
    const later = '2026-10-08T10:00:05+08:00'
    expect(latencyLoadingState(baseline, node({ handshake: ok(1), http: ok(2) }))).toEqual({
      handshake: true,
      http: true,
    })
    expect(latencyLoadingState(baseline, node({ handshake: { ...ok(1), testedAt: later }, http: ok(2) }))).toEqual({
      handshake: false,
      http: true,
    })
    expect(latencyLoadingState(undefined, node({ handshake: ok(1), http: ok(2) }))).toEqual({
      handshake: false,
      http: false,
    })
    expect(latencyLoadingState({ handshake: null, http: null, refs: 1 }, undefined)).toEqual({
      handshake: true,
      http: true,
    })
  })
})
