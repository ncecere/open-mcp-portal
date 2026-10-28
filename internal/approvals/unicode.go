package approvals

import "unicode/utf8"

// losslessJSONStrings rejects input that encoding/json would silently repair.
// Otherwise distinct lone UTF-16 surrogates or invalid UTF-8 bytes can bind to
// the same replacement rune while another upstream parser sees different data.
// JSON syntax is still validated by the canonical argument decoder.
func losslessJSONStrings(raw []byte) bool {
	if !utf8.Valid(raw) {
		return false
	}
	quoted := false
	for i := 0; i < len(raw); i++ {
		if !quoted {
			if raw[i] == '"' {
				quoted = true
			}
			continue
		}
		if raw[i] == '"' {
			quoted = false
			continue
		}
		if raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return false
		}
		code, ok := unicodeHex4(raw[i+1 : i+5])
		if !ok {
			return false
		}
		i += 4
		switch {
		case code >= 0xd800 && code <= 0xdbff:
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return false
			}
			low, ok := unicodeHex4(raw[i+3 : i+7])
			if !ok || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		case code >= 0xdc00 && code <= 0xdfff:
			return false
		}
	}
	return !quoted
}

func unicodeHex4(raw []byte) (uint16, bool) {
	var value uint16
	for _, b := range raw {
		value <<= 4
		switch {
		case b >= '0' && b <= '9':
			value |= uint16(b - '0')
		case b >= 'a' && b <= 'f':
			value |= uint16(b - 'a' + 10)
		case b >= 'A' && b <= 'F':
			value |= uint16(b - 'A' + 10)
		default:
			return 0, false
		}
	}
	return value, true
}
