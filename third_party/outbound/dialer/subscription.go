package dialer

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/daeuniverse/outbound/common"
)

var ErrInvalidSubscription = errors.New("invalid subscription")

// ParseSubscription extracts share links from a plaintext or Base64-encoded
// subscription body. Fetching the body is intentionally left to the caller.
func ParseSubscription(content string) ([]string, error) {
	if links, ok := subscriptionLinks(content); ok {
		return links, nil
	}

	encoded := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, content)

	decoders := []func(string) (string, error){
		common.Base64StdDecode,
		common.Base64UrlDecode,
	}
	for _, decode := range decoders {
		decoded, err := decode(encoded)
		if err != nil {
			continue
		}
		if links, ok := subscriptionLinks(decoded); ok {
			return links, nil
		}
	}

	return nil, fmt.Errorf("%w: expected share-link lines or their Base64 encoding", ErrInvalidSubscription)
}

func subscriptionLinks(content string) ([]string, bool) {
	content = strings.TrimPrefix(content, "\ufeff")
	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	links := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !isShareLink(line) {
			return nil, false
		}
		links = append(links, line)
	}
	return links, len(links) > 0
}

func isShareLink(link string) bool {
	_, linklike := common.GetTagFromLinkLikePlaintext(link)
	for _, chained := range strings.Split(linklike, "->") {
		chained = strings.TrimSpace(chained)
		colon := strings.IndexByte(chained, ':')
		if colon <= 0 || !strings.HasPrefix(chained[colon:], "://") {
			return false
		}
		if _, err := linkScheme(chained); err != nil {
			return false
		}
	}
	return true
}
