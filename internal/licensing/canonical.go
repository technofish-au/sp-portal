// Canonical JSON serialisation for the signed licence document.
//
// The signed bytes of a licence document are the canonical form of its
// "licence" member: a strict subset of RFC 8785 (JCS) covering the value
// types the licence payload uses — strings, non-negative integers below
// 2^53, booleans, null, arrays and objects. Object members are sorted by
// key; keys must be ASCII (all licence fields are snake_case), which makes
// JCS's UTF-16 sort order identical to byte order. Strings are escaped
// exactly as JCS prescribes.
//
// appliances re-canonicalise the parsed "licence" member and compare the
// signature over the resulting bytes — see docs/fakeportal.md.
package licensing

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
)

// CanonicalJSON returns the JCS-subset canonical encoding of v. v must be
// a decoded JSON value (map[string]any, []any, string, float64, bool, nil)
// or a json.Marshaler-friendly struct. Numbers must be integers below 2^53
// in magnitude; floating-point values are rejected so the encoding stays
// unambiguous across implementations.
func CanonicalJSON(v any) ([]byte, error) {
	decoded, err := toDecoded(v)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := encodeCanonical(&buf, decoded); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// toDecoded normalises v into decoded-JSON form. Raw JSON passes through
// decoding; other values go through a marshal/unmarshal round trip.
func toDecoded(v any) (any, error) {
	switch t := v.(type) {
	case json.RawMessage:
		var out any
		if err := json.Unmarshal(t, &out); err != nil {
			return nil, fmt.Errorf("licensing: canonical json: %w", err)
		}
		return out, nil
	case map[string]any, []any, string, float64, bool, nil:
		return t, nil
	default:
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("licensing: canonical json: %w", err)
		}
		var out any
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, fmt.Errorf("licensing: canonical json: %w", err)
		}
		return out, nil
	}
}

func encodeCanonical(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		encodeJCSString(buf, t)
	case float64:
		if math.Trunc(t) != t || math.Abs(t) >= 1<<53 {
			return fmt.Errorf("licensing: canonical json: non-integer or out-of-range number %v", t)
		}
		buf.WriteString(strconv.FormatInt(int64(t), 10))
	case []any:
		buf.WriteByte('[')
		for i, item := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encodeCanonical(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			for _, r := range k {
				if r > 127 {
					return fmt.Errorf("licensing: canonical json: non-ASCII object key %q", k)
				}
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			encodeJCSString(buf, k)
			buf.WriteByte(':')
			if err := encodeCanonical(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("licensing: canonical json: unsupported type %T", v)
	}
	return nil
}

// jcsEscapes are the short escapes JCS uses; other C0 controls become
// \u00XX with lower-case hex.
var jcsEscapes = [256]byte{
	'"':  '"',
	'\\': '\\',
	'\b': 'b',
	'\f': 'f',
	'\n': 'n',
	'\r': 'r',
	'\t': 't',
}

// encodeJCSString writes s as a JCS-escaped JSON string: the mandatory
// escapes for '"', '\' and C0 controls, no others (encoding/json also
// escapes '<', '>' and '&', which JCS forbids — hence this hand-rolled
// encoder).
func encodeJCSString(buf *bytes.Buffer, s string) {
	const hexdigits = "0123456789abcdef"
	buf.WriteByte('"')
	for _, r := range s {
		if r < 0x20 || r == '"' || r == '\\' {
			if short := jcsEscapes[r]; short != 0 {
				buf.WriteByte('\\')
				buf.WriteByte(short)
			} else {
				buf.WriteString("\\u00")
				buf.WriteByte(hexdigits[byte(r)>>4])
				buf.WriteByte(hexdigits[byte(r)&0xf])
			}
			continue
		}
		buf.WriteRune(r)
	}
	buf.WriteByte('"')
}
