package mcptasks

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"
)

const (
	InputKeyPrefix         = "ompin_"
	inputKeyBytes          = 16
	inputKeyLength         = len(InputKeyPrefix) + 22
	MaxOutstandingInputs   = 8
	MaxLifetimeInputs      = 128
	MaxInputRequestsBytes  = 16 << 10
	MaxInputResponsesBytes = 64 << 10
	maxServerInputKeyBytes = 256
)

// InputRecord maps a stable portal key to a server's private input key. Server
// keys never reach a client; portal keys never reach the server. Attempted is
// one-way: once a response is committed for transport it is never restored,
// even if the send/ack is lost, so a stale poll cannot replay the answer.
type InputRecord struct {
	Key       string `json:"key"`
	ServerKey string `json:"serverKey"`
	Digest    string `json:"digest"`
	Attempted bool   `json:"attempted"`
}

func validInputKey(k string) bool {
	if len(k) != inputKeyLength || !strings.HasPrefix(k, InputKeyPrefix) {
		return false
	}
	enc := k[len(InputKeyPrefix):]
	raw, err := base64.RawURLEncoding.Strict().DecodeString(enc)
	return err == nil && len(raw) == inputKeyBytes && base64.RawURLEncoding.EncodeToString(raw) == enc
}

func validServerInputKey(k string) bool {
	return k != "" && len(k) <= maxServerInputKeyBytes && utf8.ValidString(k)
}

func validLedger(ledger []InputRecord) bool {
	if len(ledger) > MaxLifetimeInputs {
		return false
	}
	keys, servers := map[string]bool{}, map[string]bool{}
	for _, r := range ledger {
		if !validInputKey(r.Key) || !validServerInputKey(r.ServerKey) || !validDigest(r.Digest) || keys[r.Key] || servers[r.ServerKey] {
			return false
		}
		keys[r.Key], servers[r.ServerKey] = true, true
	}
	return true
}

func newInputKey(random io.Reader) (string, error) {
	var raw [inputKeyBytes]byte
	if _, err := io.ReadFull(random, raw[:]); err != nil {
		return "", ErrUnavailable
	}
	return InputKeyPrefix + base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

type member struct {
	key   string
	value json.RawMessage
}

// objectMembers decodes a bounded JSON object in wire order, rejecting
// duplicate keys (which could make two components disagree on a value).
func objectMembers(raw json.RawMessage, limit, maxMembers int) ([]member, bool) {
	if len(raw) > limit || !utf8.Valid(raw) {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, false
	}
	var out []member
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		key, ok := tok.(string)
		if err != nil || !ok || seen[key] || len(out) >= maxMembers {
			return nil, false
		}
		var value json.RawMessage
		if dec.Decode(&value) != nil {
			return nil, false
		}
		seen[key] = true
		out = append(out, member{key, value})
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	return out, true
}

func encodeMembers(members []member) json.RawMessage {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, m := range members {
		if i > 0 {
			buf.WriteByte(',')
		}
		k, _ := json.Marshal(m.key)
		buf.Write(k)
		buf.WriteByte(':')
		buf.Write(m.value)
	}
	buf.WriteByte('}')
	return buf.Bytes()
}

func requestDigest(value json.RawMessage) (string, bool) {
	trimmed := bytes.TrimSpace(value)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return "", false
	}
	var compact bytes.Buffer
	if json.Compact(&compact, trimmed) != nil {
		return "", false
	}
	sum := sha256.Sum256(compact.Bytes())
	return hex.EncodeToString(sum[:]), true
}

// MapInputRequests rewrites a server's validated inputRequests object to stable
// portal keys. A server reusing one key for a different request, exceeding the
// outstanding/lifetime bounds or sending duplicates fails closed. Already
// attempted keys are not offered again. The caller still validates and rebuilds
// each request (form/URL elicitation, trust level) before showing it.
func MapInputRequests(ledger []InputRecord, raw json.RawMessage, random io.Reader) ([]InputRecord, json.RawMessage, error) {
	members, ok := objectMembers(raw, MaxInputRequestsBytes, MaxOutstandingInputs)
	if !ok || !validLedger(ledger) {
		return nil, nil, ErrUnavailable
	}
	next := append([]InputRecord(nil), ledger...)
	out := make([]member, 0, len(members))
	for _, m := range members {
		if !validServerInputKey(m.key) {
			return nil, nil, ErrUnavailable
		}
		digest, ok := requestDigest(m.value)
		if !ok {
			return nil, nil, ErrUnavailable
		}
		found := -1
		for i := range next {
			if next[i].ServerKey == m.key {
				found = i
				break
			}
		}
		if found >= 0 {
			if next[found].Digest != digest {
				return nil, nil, ErrUnavailable // key reused for a different request
			}
			if !next[found].Attempted {
				out = append(out, member{next[found].Key, m.value})
			}
			continue
		}
		if len(next) >= MaxLifetimeInputs {
			return nil, nil, ErrUnavailable
		}
		key, err := newInputKey(random)
		if err != nil {
			return nil, nil, err
		}
		next = append(next, InputRecord{Key: key, ServerKey: m.key, Digest: digest})
		out = append(out, member{key, m.value})
	}
	return next, encodeMembers(out), nil
}

// SelectInputResponses maps a client's inputResponses to server keys and marks
// each selected key attempted BEFORE the caller's single transport. Unknown,
// malformed-key or already attempted entries are ignored, as the extension
// allows. count==0 means nothing may be forwarded.
func SelectInputResponses(ledger []InputRecord, raw json.RawMessage) ([]InputRecord, json.RawMessage, int, error) {
	members, ok := objectMembers(raw, MaxInputResponsesBytes, MaxLifetimeInputs)
	if !ok || !validLedger(ledger) {
		return nil, nil, 0, ErrUnavailable
	}
	next := append([]InputRecord(nil), ledger...)
	out := make([]member, 0, len(members))
	for _, m := range members {
		for i := range next {
			if next[i].Key == m.key && !next[i].Attempted {
				next[i].Attempted = true
				out = append(out, member{next[i].ServerKey, m.value})
				break
			}
		}
	}
	return next, encodeMembers(out), len(out), nil
}

// randomReader is the production entropy source for input keys.
var randomReader io.Reader = rand.Reader

// worstCaseLedger is the largest encodable ledger: Reserve seals it as a probe
// so a task can never become unsealable after the upstream has created work.
func worstCaseLedger() []InputRecord {
	out := make([]InputRecord, MaxLifetimeInputs)
	for i := range out {
		raw := make([]byte, inputKeyBytes)
		raw[0], raw[1] = byte(i), byte(i>>8)
		server := []byte(strings.Repeat("\x00", maxServerInputKeyBytes-2))
		server = append(server, byte('a'+i%26), byte('a'+i/26))
		out[i] = InputRecord{Key: InputKeyPrefix + base64.RawURLEncoding.EncodeToString(raw), ServerKey: string(server), Digest: strings.Repeat("a", 64), Attempted: true}
	}
	return out
}
