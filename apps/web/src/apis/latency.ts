import type { QueryClient } from '@tanstack/react-query'
import type { GQLClient } from '~/contexts'
import type { LatencyBaseline } from '~/utils/latency'
import { useStore } from '@nanostores/react'
import { useQueryClient } from '@tanstack/react-query'
import { atom } from 'nanostores'
import { useCallback } from 'react'
import { QUERY_KEY_NODE_LATENCY } from '~/constants'
import { useGQLQueryClient } from '~/contexts'
import { latencyLoadingState } from '~/utils/latency'

/** Result of one probe method (PING or HTTP). */
export interface LatencyProbeResult {
  ok: boolean
  latencyMs?: number | null
  message?: string | null
  testedAt?: string | null
  /** The method is being measured; the other fields hold the previous result. */
  pending: boolean
  /** False when the method does not apply, e.g. PING for UDP-only protocols. */
  supported: boolean
}

export interface NodeLatencyProbeResult {
  id: string
  /** latencyMs/alive/testedAt/message mirror the HTTP probe. */
  latencyMs?: number | null
  alive: boolean
  testedAt: string
  message?: string | null
  testing?: boolean
  ping?: LatencyProbeResult | null
  http?: LatencyProbeResult | null
}

const PROBE_FIELDS = 'ok latencyMs message testedAt pending supported'
export const NODE_LATENCY_FIELDS = `
  id
  latencyMs
  alive
  testedAt
  message
  testing
  ping { ${PROBE_FIELDS} }
  http { ${PROBE_FIELDS} }
`

export type LatencyTestTarget =
  | { kind: 'all' }
  | { kind: 'nodes'; ids: string[] }
  | { kind: 'subscription'; id: string }
  | { kind: 'group'; id: string }

export function latencyTargetKey(target: LatencyTestTarget) {
  switch (target.kind) {
    case 'all':
      return 'all'
    case 'nodes':
      return `nodes:${target.ids.join(',')}`
    case 'subscription':
      return `subscription:${target.id}`
    case 'group':
      return `group:${target.id}`
  }
}

export const latencyBaselinesAtom = atom<Record<string, LatencyBaseline>>({})
/** Running tests by target key (counts overlapping clicks). */
export const latencyActiveTargetsAtom = atom<Record<string, number>>({})

const POLL_INTERVAL_MS = 1_000

let activePolls = 0
let pollTimer: ReturnType<typeof setInterval> | undefined
let pollInFlight = false

async function fetchCachedLatencies(gqlClient: GQLClient) {
  const data = await gqlClient.request<{ nodeLatencies: NodeLatencyProbeResult[] }>(
    `
      query CachedNodeLatencies {
        nodeLatencies(cachedOnly: true) {
          ${NODE_LATENCY_FIELDS}
        }
      }
    `,
  )
  return data.nodeLatencies
}

function startPolling(gqlClient: GQLClient, queryClient: QueryClient) {
  activePolls++
  if (pollTimer) return
  pollTimer = setInterval(() => {
    if (pollInFlight) return
    pollInFlight = true
    fetchCachedLatencies(gqlClient)
      .then((results) => queryClient.setQueryData(QUERY_KEY_NODE_LATENCY, results))
      .catch(() => {})
      .finally(() => {
        pollInFlight = false
      })
  }, POLL_INTERVAL_MS)
}

function stopPolling() {
  activePolls = Math.max(0, activePolls - 1)
  if (activePolls === 0 && pollTimer) {
    clearInterval(pollTimer)
    pollTimer = undefined
  }
}

function adjustCount(store: typeof latencyActiveTargetsAtom, key: string, delta: number) {
  const next = { ...store.get() }
  const count = (next[key] ?? 0) + delta
  if (count > 0) next[key] = count
  else delete next[key]
  store.set(next)
}

function markBaselines(ids: string[], current: NodeLatencyProbeResult[] | undefined) {
  const byId = new Map((current ?? []).map((r) => [r.id, r]))
  const next = { ...latencyBaselinesAtom.get() }
  for (const id of ids) {
    const existing = next[id]
    if (existing) {
      next[id] = { ...existing, refs: existing.refs + 1 }
      continue
    }
    const result = byId.get(id)
    next[id] = { ping: result?.ping?.testedAt ?? null, http: result?.http?.testedAt ?? null, refs: 1 }
  }
  latencyBaselinesAtom.set(next)
}

function unmarkBaselines(ids: string[]) {
  const next = { ...latencyBaselinesAtom.get() }
  for (const id of ids) {
    const existing = next[id]
    if (!existing) continue
    if (existing.refs > 1) next[id] = { ...existing, refs: existing.refs - 1 }
    else delete next[id]
  }
  latencyBaselinesAtom.set(next)
}

function mergeResults(queryClient: QueryClient, results: NodeLatencyProbeResult[]) {
  queryClient.setQueryData<NodeLatencyProbeResult[]>(QUERY_KEY_NODE_LATENCY, (previous) => {
    const merged = new Map((previous ?? []).map((r) => [r.id, r]))
    for (const result of results) merged.set(result.id, result)
    return [...merged.values()]
  })
}

async function requestLatencyTest(gqlClient: GQLClient, target: LatencyTestTarget) {
  switch (target.kind) {
    case 'all':
    case 'nodes': {
      const data = await gqlClient.request<{ testNodeLatencies: NodeLatencyProbeResult[] }, { ids?: string[] }>(
        `
          mutation TestNodeLatencies($ids: [ID!]) {
            testNodeLatencies(ids: $ids) {
              ${NODE_LATENCY_FIELDS}
            }
          }
        `,
        target.kind === 'nodes' ? { ids: target.ids } : {},
      )
      return data.testNodeLatencies
    }
    case 'subscription': {
      const data = await gqlClient.request<{ testSubscriptionLatencies: NodeLatencyProbeResult[] }, { id: string }>(
        `
          mutation TestSubscriptionLatencies($id: ID!) {
            testSubscriptionLatencies(id: $id) {
              ${NODE_LATENCY_FIELDS}
            }
          }
        `,
        { id: target.id },
      )
      return data.testSubscriptionLatencies
    }
    case 'group': {
      const data = await gqlClient.request<{ testGroupLatencies: NodeLatencyProbeResult[] }, { id: string }>(
        `
          mutation TestGroupLatencies($id: ID!) {
            testGroupLatencies(id: $id) {
              ${NODE_LATENCY_FIELDS}
            }
          }
        `,
        { id: target.id },
      )
      return data.testGroupLatencies
    }
  }
}

/**
 * Runs manual latency tests. Results stream in while a test runs: cached
 * results are polled every second, and each slot shows a spinner until its
 * method reports a new result.
 */
export function useLatencyTest() {
  const gqlClient = useGQLQueryClient()
  const queryClient = useQueryClient()
  const activeTargets = useStore(latencyActiveTargetsAtom)

  const run = useCallback(
    async (target: LatencyTestTarget, nodeIds: string[] = target.kind === 'nodes' ? target.ids : []) => {
      const key = latencyTargetKey(target)
      const current = queryClient.getQueryData<NodeLatencyProbeResult[]>(QUERY_KEY_NODE_LATENCY)
      const markIds =
        target.kind === 'all' && nodeIds.length === 0 ? (current ?? []).map((r) => r.id) : [...new Set(nodeIds)]
      adjustCount(latencyActiveTargetsAtom, key, 1)
      markBaselines(markIds, current)
      startPolling(gqlClient, queryClient)
      try {
        const results = await requestLatencyTest(gqlClient, target)
        mergeResults(queryClient, results)
        return results
      } finally {
        stopPolling()
        unmarkBaselines(markIds)
        adjustCount(latencyActiveTargetsAtom, key, -1)
      }
    },
    [gqlClient, queryClient],
  )

  const isTesting = useCallback(
    (target: LatencyTestTarget) => !!activeTargets[latencyTargetKey(target)],
    [activeTargets],
  )

  return { run, isTesting }
}

/** Which slots of a node should show a spinner. */
export function useNodeLatencyLoading(nodeId: string, result: NodeLatencyProbeResult | undefined) {
  const baseline = useStore(latencyBaselinesAtom)[nodeId]
  return latencyLoadingState(baseline, result)
}
