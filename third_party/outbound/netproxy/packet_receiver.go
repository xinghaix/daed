/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package netproxy

// RegisterMappedPacketReceiver registers a receiver on an underlying
// transport and maps each packet before handing it to the outer connection.
// The mapping function owns the input packet for the duration of the call.
// Returning false drops the input packet; returning true returns a mapped
// packet. A mapped packet may be the input packet after in-place decoding.
func RegisterMappedPacketReceiver(
	receiver PacketReceiver,
	handler PacketReceiveHandler,
	mapPacket func(*ReceivedPacket) (*ReceivedPacket, bool),
) (func(), bool) {
	if receiver == nil || handler == nil || mapPacket == nil {
		return nil, false
	}
	return receiver.RegisterPacketReceiver(func(packet *ReceivedPacket) bool {
		if packet == nil {
			return true
		}
		mapped, ok := mapPacket(packet)
		if !ok || mapped == nil {
			packet.Release()
			return true
		}
		if mapped != packet {
			packet.Release()
		}
		if handler(mapped) {
			return true
		}
		mapped.Release()
		return true
	})
}
