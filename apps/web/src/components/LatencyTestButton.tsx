import type { LatencyTestTarget } from '~/apis'
import { Gauge } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { useLatencyTest } from '~/apis'
import { Button } from '~/components/ui/button'
import { SimpleTooltip } from '~/components/ui/tooltip'
import { cn } from '~/lib/utils'

/**
 * Gauge button that runs a PING/HTTP latency test for a node, a
 * subscription, a group or all nodes. nodeIds (when known) lets the affected
 * nodes show a spinner right away.
 */
export function LatencyTestButton({
  target,
  nodeIds,
  label,
  variant = 'card',
  className,
}: {
  target: LatencyTestTarget
  nodeIds?: string[]
  label: React.ReactNode
  /**
   * card: small action on a node/subscription card; badge: tiny hover button
   * in a node badge; toolbar: group card header; section: section header.
   */
  variant?: 'card' | 'badge' | 'toolbar' | 'section'
  className?: string
}) {
  const { t } = useTranslation()
  const { run, isTesting } = useLatencyTest()
  const testing = isTesting(target)

  const onClick = (e: React.MouseEvent) => {
    e.stopPropagation()
    if (testing) return
    run(target, nodeIds).catch((error) => {
      console.error('Failed to test node latencies', error)
      const message = error instanceof Error ? error.message : String(error)
      toast.error(t('latency.testFailed', { message }))
    })
  }

  if (variant === 'toolbar') {
    return (
      <SimpleTooltip label={label}>
        <Button variant="ghost" size="xs" className={className} onClick={onClick} loading={testing}>
          {!testing && <Gauge className="h-4 w-4" />}
        </Button>
      </SimpleTooltip>
    )
  }

  if (variant === 'section') {
    return (
      <SimpleTooltip label={label}>
        <Button variant="ghost" size="icon" className={className} onClick={onClick} loading={testing}>
          {!testing && <Gauge className="h-4 w-4" />}
        </Button>
      </SimpleTooltip>
    )
  }

  return (
    <SimpleTooltip label={label}>
      <Button
        variant="ghost"
        size="xs"
        aria-label={typeof label === 'string' ? label : undefined}
        className={cn(
          variant === 'badge'
            ? 'h-5 w-5 p-0 rounded-full shrink-0 text-muted-foreground hover:text-foreground sm:opacity-0 sm:group-hover:opacity-100 transition-opacity'
            : 'h-6 w-6 p-0 text-muted-foreground hover:text-foreground',
          testing && 'sm:opacity-100',
          className,
        )}
        onClick={onClick}
        onPointerDown={(e) => e.stopPropagation()}
        loading={testing}
      >
        {!testing && <Gauge className={variant === 'badge' ? 'h-3 w-3' : 'h-3.5 w-3.5'} />}
      </Button>
    </SimpleTooltip>
  )
}
