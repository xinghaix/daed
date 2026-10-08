/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2023, daeuniverse Organization <team@v2raya.org>
 */

package node

import (
	"time"

	"github.com/daeuniverse/dae-wing/common"
	"github.com/graph-gophers/graphql-go"
)

// LatencyResolver resolves NodeLatency. LatencyMs/Alive/Message mirror the
// HTTP probe for clients that predate the per-method results.
type LatencyResolver struct {
	NodeID     uint
	LatencyMsV *int32
	AliveVal   bool
	TestedAtV  time.Time
	MessageV   *string
	PingV      *ProbeResolver
	HttpV      *ProbeResolver
}

func (r *LatencyResolver) ID() graphql.ID {
	return common.EncodeCursor(r.NodeID)
}

func (r *LatencyResolver) LatencyMs() *int32 {
	return r.LatencyMsV
}

func (r *LatencyResolver) Alive() bool {
	return r.AliveVal
}

func (r *LatencyResolver) TestedAt() graphql.Time {
	return graphql.Time{Time: r.TestedAtV}
}

func (r *LatencyResolver) Message() *string {
	return r.MessageV
}

func (r *LatencyResolver) Testing() bool {
	return (r.PingV != nil && r.PingV.PendingV) || (r.HttpV != nil && r.HttpV.PendingV)
}

func (r *LatencyResolver) Ping() *ProbeResolver {
	return r.PingV
}

func (r *LatencyResolver) Http() *ProbeResolver {
	return r.HttpV
}

// ProbeResolver resolves LatencyProbe: the result of one probe method.
type ProbeResolver struct {
	OkV        bool
	LatencyMsV *int32
	MessageV   *string
	TestedAtV  time.Time
	PendingV   bool
	SupportedV bool
}

func (r *ProbeResolver) Ok() bool {
	return r.OkV
}

func (r *ProbeResolver) LatencyMs() *int32 {
	return r.LatencyMsV
}

func (r *ProbeResolver) Message() *string {
	return r.MessageV
}

func (r *ProbeResolver) TestedAt() *graphql.Time {
	if r.TestedAtV.IsZero() {
		return nil
	}
	return &graphql.Time{Time: r.TestedAtV}
}

func (r *ProbeResolver) Pending() bool {
	return r.PendingV
}

func (r *ProbeResolver) Supported() bool {
	return r.SupportedV
}

func probeResolverFromOutcome(o probeOutcome) *ProbeResolver {
	r := &ProbeResolver{OkV: o.Ok, TestedAtV: o.TestedAt, SupportedV: !o.Unsupported}
	if o.Ok {
		ms := latencyMillis(o.Latency)
		r.LatencyMsV = &ms
	}
	if o.Message != "" {
		msg := o.Message
		r.MessageV = &msg
	}
	return r
}

// latencyMillis rounds to whole milliseconds but never reports 0 for a
// successful probe.
func latencyMillis(d time.Duration) int32 {
	ms := int32((d + 500*time.Microsecond) / time.Millisecond)
	if ms < 1 {
		ms = 1
	}
	return ms
}

func cloneProbeResolver(r *ProbeResolver) *ProbeResolver {
	if r == nil {
		return nil
	}
	clone := *r
	if r.LatencyMsV != nil {
		v := *r.LatencyMsV
		clone.LatencyMsV = &v
	}
	if r.MessageV != nil {
		v := *r.MessageV
		clone.MessageV = &v
	}
	return &clone
}

// syncLegacyFields derives latencyMs/alive/message/testedAt from the HTTP
// result (or PING when HTTP has not reported yet).
func (r *LatencyResolver) syncLegacyFields() {
	src := r.HttpV
	if src == nil || src.PendingV && src.TestedAtV.IsZero() {
		if r.PingV != nil && !r.PingV.PendingV {
			src = r.PingV
		}
	}
	if src == nil || src.PendingV {
		return
	}
	r.AliveVal = src.OkV
	r.LatencyMsV = nil
	if src.LatencyMsV != nil {
		v := *src.LatencyMsV
		r.LatencyMsV = &v
	}
	r.MessageV = nil
	if src.MessageV != nil {
		v := *src.MessageV
		r.MessageV = &v
	}
	if !src.TestedAtV.IsZero() {
		r.TestedAtV = src.TestedAtV
	}
}
