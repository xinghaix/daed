package netproxy

// WriteDeadlineBehavior optionally describes a nonstandard SetWriteDeadline:
// an independent expiry timer closes the session or association, even when no
// write is blocked. TUIC and Hysteria2 UDP associations use this behavior.
// Callers must not arm such a timer merely to probe for a stalled write.
//
// Ordinary deadlines limit pending and future writes until changed or cleared;
// they do not close an idle association just because time passed. This does not
// imply that a timed-out write is recoverable: for example, a TLS write timeout
// can make subsequent writes fail permanently.
//
// This property is independent of TransportLifecycle. Adapters that delegate
// SetWriteDeadline must also forward the underlying behavior declaration.
// Implementations with ordinary deadlines can omit this interface.
type WriteDeadlineBehavior interface {
	// WriteDeadlineClosesSession reports whether SetWriteDeadline arms an
	// independent timer that closes the session or association on expiry.
	WriteDeadlineClosesSession() bool
}

// WriteDeadlineClosesSession checks the optional WriteDeadlineBehavior contract.
// It returns false for nil or undeclared connections; it does not promise that
// the connection remains usable after an actual write timeout.
func WriteDeadlineClosesSession(conn any) bool {
	behavior, ok := conn.(WriteDeadlineBehavior)
	return ok && behavior.WriteDeadlineClosesSession()
}
