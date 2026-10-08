package hysteria2

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

func decodeECHConfigList(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("empty ECH config list")
	}

	var validationErr error
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, encoding := range encodings {
		configList, err := encoding.DecodeString(value)
		if err != nil {
			continue
		}
		if err := validateECHConfigList(configList); err != nil {
			if validationErr == nil {
				validationErr = err
			}
			continue
		}
		return configList, nil
	}
	if validationErr != nil {
		return nil, validationErr
	}
	return nil, errors.New("ECH config list is not valid base64")
}

func validateECHConfigList(configList []byte) error {
	if len(configList) < 2 {
		return errors.New("malformed ECH config list: truncated length prefix")
	}
	bodyLen := int(binary.BigEndian.Uint16(configList[:2]))
	if bodyLen != len(configList)-2 {
		return errors.New("malformed ECH config list: invalid list length")
	}

	body := configList[2:]
	if len(body) == 0 {
		return errors.New("ECH config list contains no configs")
	}
	for len(body) > 0 {
		if len(body) < 4 {
			return errors.New("malformed ECH config list: truncated config header")
		}
		configLen := int(binary.BigEndian.Uint16(body[2:4]))
		entryLen := 4 + configLen
		if entryLen > len(body) {
			return fmt.Errorf("malformed ECH config list: config length %d exceeds remaining data", configLen)
		}
		body = body[entryLen:]
	}
	return nil
}
