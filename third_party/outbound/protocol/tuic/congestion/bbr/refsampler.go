package bbr

import (
	"time"

	"github.com/olicesx/quic-go/congestion"
)

// RefSampler exposes this package's delivery-rate estimator so a sibling
// congestion controller can share one implementation instead of carrying a
// second, divergent copy.
//
// It is a thin adapter over bandwidthSampler plus the max-bandwidth windowed
// filter, wired exactly the way bbrSender consumes them (bbr_sender.go:427-441):
//
//	sample := sampler.OnCongestionEvent(eventTime, acked, lost, maxBandwidth.GetBest(), bandwidthEstimate(), roundTripCount)
//	if totalBytesAcked changed && (!sample.sampleIsAppLimited || sample.sampleMaxBandwidth > maxBandwidth.GetBest()) {
//		maxBandwidth.Update(sample.sampleMaxBandwidth, roundTripCount)
//	}
//
// The adapter deliberately owns the filter as well: the reference sender feeds
// the same filter from its own round counter, and a caller that re-implemented
// the update rule would be re-introducing the divergence this type exists to
// remove.
//
// It owns the send-record reclamation for the same reason. Removing records
// that can no longer produce a sample is an obligation of the connection-state
// map, not a decision of the caller, so OnCongestionEvent performs it: a
// consumer that forgot would retain one record per send for the life of the
// connection.
type RefSampler struct {
	sampler      *bandwidthSampler
	maxBandwidth *WindowedFilter[Bandwidth, roundTripCount]
}

// RefSample is the exported view of one congestion event's rate sample.
//
// Bandwidth is the resulting estimate (the filter's current best), not the raw
// per-event sample: callers pace from the estimate, and exposing the raw sample
// invites using the unfiltered value by accident.
//
// All bandwidth fields are in THIS package's unit, bits per second (see
// bandwidth.go: BytesPerSecond = 8 * BitsPerSecond). A caller whose own
// Bandwidth is bytes per second must divide by BytesPerSecond; MaxBandwidthBytesPerSecond
// does that conversion in one place so it cannot be forgotten.
type RefSample struct {
	// Bandwidth is the windowed maximum delivery rate.
	Bandwidth Bandwidth
	// RTT is the minimum RTT over the event's acknowledged packets, or zero
	// when the event carried no valid RTT sample.
	RTT time.Duration
	// AppLimited reports whether the sample that produced the estimate came
	// from an app-limited send.
	AppLimited bool
	// ExtraAcked is the ACK-aggregation excess measured at this event.
	ExtraAcked congestion.ByteCount
	// Sample is the raw per-event maximum, before the filter. Diagnostic only.
	Sample Bandwidth
}

// NewRefSampler builds a sampler whose windowed max filter and ACK-height
// tracker both span windowRounds packet-timed rounds.
func NewRefSampler(windowRounds uint64) *RefSampler {
	w := roundTripCount(windowRounds)
	return &RefSampler{
		sampler:      newBandwidthSampler(w),
		maxBandwidth: NewWindowedFilter(w, MaxFilter[Bandwidth]),
	}
}

// OnPacketSent records the connection state a later rate sample needs. It must
// be called for every sent packet, retransmittable or not: the reference
// sampler tracks lastSentPacket even for non-retransmittable sends
// (bandwidth_sampler.go:550-561).
func (r *RefSampler) OnPacketSent(
	sentTime time.Time,
	packetNumber congestion.PacketNumber,
	bytes congestion.ByteCount,
	bytesInFlight congestion.ByteCount,
	isRetransmittable bool,
) {
	r.sampler.OnPacketSent(sentTime, packetNumber, bytes, bytesInFlight, isRetransmittable)
}

// OnCongestionEvent folds one ack/loss vector into the estimate and returns the
// resulting sample. roundTrip must be a monotonically non-decreasing
// packet-timed round counter owned by the caller; it is the filter's time axis.
func (r *RefSampler) OnCongestionEvent(
	ackTime time.Time,
	ackedPackets []congestion.AckedPacketInfo,
	lostPackets []congestion.LostPacketInfo,
	roundTrip uint64,
) RefSample {
	round := roundTripCount(roundTrip)
	totalAckedBefore := r.sampler.TotalBytesAcked()
	// The second bandwidth argument is estBandwidthUpperBound, which only bounds
	// the ACK-aggregation estimate (bandwidth_sampler.go:668). The reference
	// sender passes infBandwidth there, i.e. no bound beyond the running max;
	// passing the filter's current best instead would clamp extraAcked to the
	// previous best and hand callers a wrong MaxAckHeight.
	event := r.sampler.OnCongestionEvent(
		ackTime,
		ackedPackets,
		lostPackets,
		r.maxBandwidth.GetBest(),
		infBandwidth,
		round,
	)
	// Reclamation is NOT driven from this event vector. Estimating the
	// first-outstanding packet number as "highest ack minus the reorder margin",
	// the reference sender's rule (bbr_sender.go:487-492), deletes records for
	// packets that are still outstanding whenever the ack frontier sits more
	// than that margin ahead of a hole; onPacketAcknowledged then skips those
	// packets' delivered bytes (bandwidth_sampler.go:781-784), so a reordering
	// or spurious-loss recovery under-counts delivery and depresses the
	// estimate. Measured with that trim in place, on a lossy path: 1.50 GB
	// delivered against 2.39 GB, max bandwidth 487 KB/s against 1.19 MB/s, cwnd
	// 78 KB against 191 KB.
	//
	// The sampler reclaims by consumption instead. A record is marked when its
	// packet is acked or declared lost, and the queue drops the consumed front
	// (bandwidthSampler.reclaimConsumed), so a record for an outstanding packet
	// is never dropped and the map follows the outstanding window rather than
	// its high-water mark. maxConnectionStateMapSlots stays as the backstop for
	// a caller that stops feeding acks at all.
	if r.sampler.TotalBytesAcked() != totalAckedBefore {
		if !event.sampleIsAppLimited || event.sampleMaxBandwidth > r.maxBandwidth.GetBest() {
			r.maxBandwidth.Update(event.sampleMaxBandwidth, round)
		}
	}
	return RefSample{
		Bandwidth:  r.maxBandwidth.GetBest(),
		RTT:        event.sampleRtt,
		AppLimited: event.sampleIsAppLimited,
		ExtraAcked: event.extraAcked,
		Sample:     event.sampleMaxBandwidth,
	}
}

// MaxBandwidth reports the current windowed maximum delivery rate, in bits per
// second (this package's unit).
func (r *RefSampler) MaxBandwidth() Bandwidth { return r.maxBandwidth.GetBest() }

// MaxBandwidthBytesPerSecond reports the current estimate in bytes per second,
// which is the unit callers outside this package normally pace in. The
// conversion mirrors bbrSender.bandwidthForPacer (bbr_sender.go:522-529).
func (r *RefSampler) MaxBandwidthBytesPerSecond() uint64 {
	return uint64(r.maxBandwidth.GetBest()) / uint64(BytesPerSecond)
}

// MaxAckHeight reports the tracked ACK aggregation height.
func (r *RefSampler) MaxAckHeight() congestion.ByteCount { return r.sampler.MaxAckHeight() }

// TotalBytesAcked reports the congestion-controlled bytes acknowledged so far.
func (r *RefSampler) TotalBytesAcked() congestion.ByteCount { return r.sampler.TotalBytesAcked() }

// TotalBytesLost reports the congestion-controlled bytes lost so far.
func (r *RefSampler) TotalBytesLost() congestion.ByteCount { return r.sampler.TotalBytesLost() }

// OnAppLimited tells the sampler the sender ran out of data, so that sends
// until the next ack of a packet sent after this call produce app-limited
// samples (bandwidth_sampler.go:406-410).
func (r *RefSampler) OnAppLimited() { r.sampler.OnAppLimited() }

// RemoveObsoletePackets drops send records below leastUnacked.
//
// The map bounds itself (see OnCongestionEvent), so this is only for a caller
// that knows the true first-outstanding packet number and wants a tighter
// bound. Do not pass an estimate: dropping a record for a packet that is still
// outstanding makes onPacketAcknowledged skip that packet's delivered bytes,
// which under-counts delivery and depresses the bandwidth estimate.
func (r *RefSampler) RemoveObsoletePackets(leastUnacked congestion.PacketNumber) {
	r.sampler.RemoveObsoletePackets(leastUnacked)
}

// EntrySlotsUsed reports how many send records the connection-state map holds.
// It should track the outstanding window: a value that grows with the number of
// packets ever sent means reclamation has stopped happening.
func (r *RefSampler) EntrySlotsUsed() int {
	return r.sampler.connectionStateMap.EntrySlotsUsed()
}

// EntrySlotsCapacity reports the send-record map's slot capacity, i.e. its
// memory footprint divided by the record size.
func (r *RefSampler) EntrySlotsCapacity() int {
	return r.sampler.connectionStateMap.EntrySlotsCapacity()
}

// EntrySlotsBudget reports the hard slot budget the map enforces on itself when
// reclamation stops happening. Retention should sit near the outstanding
// window, far below this.
func (r *RefSampler) EntrySlotsBudget() int {
	return r.sampler.connectionStateMap.Budget()
}

// TruncatedRecords reports how many records the map's hard slot budget has
// discarded. Non-zero means the trim is not running and the estimate is being
// fed by a truncated send history.
func (r *RefSampler) TruncatedRecords() uint64 {
	return r.sampler.connectionStateMap.TruncatedSlots()
}

// SetWindowLength changes the filter window without touching current samples.
func (r *RefSampler) SetWindowLength(windowRounds uint64) {
	r.maxBandwidth.SetWindowLength(roundTripCount(windowRounds))
	r.sampler.SetMaxAckHeightTrackerWindowLength(roundTripCount(windowRounds))
}
