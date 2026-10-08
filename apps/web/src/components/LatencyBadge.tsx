import type { NodeLatencyProbeResult } from '~/apis'
import { Loader2, TriangleAlert } from 'lucide-react'
import { Fragment } from 'react'
import { useTranslation } from 'react-i18next'
import { useNodeLatencyLoading } from '~/apis'
import { SimpleTooltip } from '~/components/ui/tooltip'
import { cn } from '~/lib/utils'
import { formatLatency, LATENCY_TONE_CLASS } from '~/utils/latency'

/**
 * Shows a node's handshake (TLS/TCP/QUIC) and HTTP latency as "102 ms, 525 ms", colored per
 * slot, with a spinner for slots being measured and the details (including
 * failure reasons) in a tooltip.
 */
export function LatencyBadge({
  nodeId,
  result,
  className,
}: {
  nodeId: string
  result?: NodeLatencyProbeResult
  className?: string
}) {
  const { t } = useTranslation()
  const loading = useNodeLatencyLoading(nodeId, result)
  const view = formatLatency(result, t, loading)
  if (!view) return null

  return (
    <SimpleTooltip
      label={
        <span className="flex flex-col gap-0.5 text-xs">
          <span>{view.tooltip}</span>
          <span className="text-muted-foreground">{t('latency.legend')}</span>
        </span>
      }
    >
      <span
        className={cn('inline-flex items-center whitespace-nowrap tabular-nums', className)}
        aria-label={view.tooltip}
        data-testid="latency-badge"
      >
        {view.slots.map((slot, index) => (
          <Fragment key={slot.method}>
            {index > 0 && <span className="text-muted-foreground">,&nbsp;</span>}
            {slot.loading ? (
              <Loader2 className="h-3 w-3 animate-spin text-muted-foreground" aria-label={slot.detail} />
            ) : (
              <span className={cn('inline-flex items-center gap-0.5', LATENCY_TONE_CLASS[slot.tone])}>
                {slot.text}
                {slot.warning && <TriangleAlert className="h-3 w-3 text-amber-500" aria-label={slot.warning} />}
              </span>
            )}
          </Fragment>
        ))}
      </span>
    </SimpleTooltip>
  )
}
