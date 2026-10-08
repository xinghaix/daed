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
	# ping is a direct TCP connect to the node's server (not proxied).
	ping: LatencyProbe
	# http is a request to the selected config's tcp_check_url through the node.
	http: LatencyProbe
}

type LatencyProbe {
	ok: Boolean!
	latencyMs: Int
	# message explains a failure, e.g. "HTTP 404", "timeout".
	message: String
	testedAt: Time
	# pending is true while this method is being measured; the other fields
	# then hold the previous result.
	pending: Boolean!
	# supported is false when the method does not apply, e.g. PING for UDP-only protocols.
	supported: Boolean!
}
`, nil
}
