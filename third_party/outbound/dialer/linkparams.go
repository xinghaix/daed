package dialer

import (
	"net/url"
	"strconv"
)

// The link parsers historically accepted several spellings of the same TLS
// option because different client ecosystems emitted different parameter
// names. These helpers centralize that acceptance so new parsers stop
// copy-pasting cascades that drift.

// AllowInsecureFromQuery reports whether any known spelling of the
// allow-insecure flag is set to a truthy value.
func AllowInsecureFromQuery(query url.Values) bool {
	for _, key := range []string{"allowInsecure", "allow_insecure", "allowinsecure", "skipVerify"} {
		if value := query.Get(key); value != "" {
			if allowInsecure, _ := strconv.ParseBool(value); allowInsecure {
				return true
			}
		}
	}
	return false
}

// SNIFromQuery returns the SNI override carried by the "peer" then "sni"
// query parameters, falling back to fallback (conventionally the link
// hostname).
func SNIFromQuery(query url.Values, fallback string) string {
	if sni := query.Get("peer"); sni != "" {
		return sni
	}
	if sni := query.Get("sni"); sni != "" {
		return sni
	}
	return fallback
}

// CwndFromQuery parses the "cwnd" query parameter. Negative and malformed
// values are treated as unset so a malformed link degrades to the default
// congestion controller instead of panicking downstream.
func CwndFromQuery(u *url.URL) int {
	cwnd, err := strconv.Atoi(u.Query().Get("cwnd"))
	if err != nil || cwnd < 0 {
		return 0
	}
	return cwnd
}
