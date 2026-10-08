/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2023, daeuniverse Organization <team@v2raya.org>
 */

package node

func Schema() (string, error) {
	return `
type Node {
	id: ID!
	link: String!
	name: String!
	address: String!
	protocol: String!
	tag: String
	subscriptionID: ID
}
type NodesConnection {
	totalCount: Int!
	edges: [Node!]!
	pageInfo: PageInfo! 
}
type NodeLatency {
	id: ID!
	# latencyMs, alive, testedAt and message mirror the http probe.
	latencyMs: Int
	alive: Boolean!
	testedAt: Time!
	message: String
	# testing is true while a probe of this node is running.
	testing: Boolean!
	# handshake is a direct (not proxied) handshake with the node's server:
	# TLS for TLS nodes, QUIC for hysteria2/tuic/juicity, a TCP connect for
	# plain-TCP and Reality nodes. probe.method says which one ran.
	handshake: LatencyProbe
	# http is a request to the selected config's tcp_check_url through the node.
	http: LatencyProbe
}

type LatencyProbe {
	# method is TLS, TCP or QUIC for the handshake probe and HTTP for http.
	# Empty while a never-measured probe is pending.
	method: String!
	ok: Boolean!
	latencyMs: Int
	# message explains a failure, e.g. "HTTP 404", "timeout". On success it
	# may carry a warning, e.g. a handshake answered by a local transparent proxy.
	message: String
	testedAt: Time
	# pending is true while this method is being measured; the other fields
	# then hold the previous result.
	pending: Boolean!
	# supported is false when the method does not apply, e.g. the handshake of an obfuscated QUIC node.
	supported: Boolean!
}
`, nil
}
