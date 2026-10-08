package netproxy

const maxDialerUnwrapDepth = 32

type TransportCacheNamespaceProvider interface {
	TransportCacheNamespace() string
}

type DialerUnwrapper interface {
	UnwrapDialer() Dialer
}

func TransportCacheNamespace(d Dialer) string {
	for depth := 0; depth < maxDialerUnwrapDepth && d != nil; depth++ {
		if provider, ok := d.(TransportCacheNamespaceProvider); ok {
			if namespace := provider.TransportCacheNamespace(); namespace != "" {
				return namespace
			}
		}
		unwrapper, ok := d.(DialerUnwrapper)
		if !ok {
			return ""
		}
		d = unwrapper.UnwrapDialer()
	}
	return ""
}
