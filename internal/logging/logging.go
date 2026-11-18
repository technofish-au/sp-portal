// Package logging builds the portal's JSON slog logger and provides a
// slog.Handler that redacts secret values ("secrets never appear in logs").
// Mirrors sp-platform's internal/logging.
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"slices"
	"strings"
)

// Redacted replaces the value of every attribute whose key looks secret.
const Redacted = "[REDACTED]"

// maxDepth bounds recursion into nested groups and maps.
const maxDepth = 16

// sensitiveExact lists normalised keys (lower case, '-' → '_') that are
// always redacted.
var sensitiveExact = map[string]struct{}{
	"key":            {},
	"password":       {},
	"passwd":         {},
	"secret":         {},
	"token":          {},
	"authorization":  {},
	"cookie":         {},
	"set_cookie":     {},
	"private_key":    {},
	"api_key":        {},
	"licence_key":    {},
	"stripe_secret":  {},
	"webhook_secret": {},
}

// sensitiveSubstrings redact any key containing one of these fragments,
// e.g. db_password, client_secret, access_token, proxy_authorization.
var sensitiveSubstrings = []string{
	"password", "passphrase", "secret", "token", "authorization", "cookie",
}

// IsSensitiveKey reports whether values logged under key must be redacted.
// Matching is case-insensitive; '-' and '_' are equivalent. Besides the
// exact names it matches keys that contain
// password/passphrase/secret/token/authorization/cookie or end in "_key".
func IsSensitiveKey(key string) bool {
	k := strings.ReplaceAll(strings.ToLower(key), "-", "_")
	if _, ok := sensitiveExact[k]; ok {
		return true
	}
	if strings.HasSuffix(k, "_key") {
		return true
	}
	for _, s := range sensitiveSubstrings {
		if strings.Contains(k, s) {
			return true
		}
	}
	return false
}

// RedactingHandler wraps another slog.Handler and replaces the values of
// sensitive attributes (see IsSensitiveKey) with Redacted. It descends into
// groups, values implementing slog.LogValuer (resolved first) and maps with
// string keys (e.g. http.Header).
type RedactingHandler struct {
	inner slog.Handler
}

var _ slog.Handler = (*RedactingHandler)(nil)

// NewRedactingHandler returns a handler that redacts secrets before passing
// records to inner.
func NewRedactingHandler(inner slog.Handler) *RedactingHandler {
	return &RedactingHandler{inner: inner}
}

// Enabled implements slog.Handler.
func (h *RedactingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// Handle implements slog.Handler.
func (h *RedactingHandler) Handle(ctx context.Context, r slog.Record) error {
	nr := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r.Attrs(func(a slog.Attr) bool {
		nr.AddAttrs(redactAttr(a, 0))
		return true
	})
	return h.inner.Handle(ctx, nr)
}

// WithAttrs implements slog.Handler.
func (h *RedactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		out[i] = redactAttr(a, 0)
	}
	return &RedactingHandler{inner: h.inner.WithAttrs(out)}
}

// WithGroup implements slog.Handler.
func (h *RedactingHandler) WithGroup(name string) slog.Handler {
	return &RedactingHandler{inner: h.inner.WithGroup(name)}
}

func redactAttr(a slog.Attr, depth int) slog.Attr {
	if a.Key != "" && IsSensitiveKey(a.Key) {
		return slog.String(a.Key, Redacted)
	}
	v := a.Value.Resolve()
	if depth >= maxDepth {
		return slog.Attr{Key: a.Key, Value: v}
	}
	switch v.Kind() {
	case slog.KindGroup:
		group := v.Group()
		out := make([]slog.Attr, len(group))
		for i, ga := range group {
			out[i] = redactAttr(ga, depth+1)
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(out...)}
	case slog.KindAny:
		if g, ok := mapToGroup(v.Any()); ok {
			return redactAttr(slog.Attr{Key: a.Key, Value: g}, depth)
		}
	}
	return slog.Attr{Key: a.Key, Value: v}
}

// mapToGroup converts a non-nil map with string keys into a group value
// (sorted by key) so that its entries can be redacted.
func mapToGroup(x any) (slog.Value, bool) {
	rv := reflect.ValueOf(x)
	if rv.Kind() != reflect.Map || rv.Type().Key().Kind() != reflect.String || rv.IsNil() {
		return slog.Value{}, false
	}
	keys := make([]string, 0, rv.Len())
	for _, k := range rv.MapKeys() {
		keys = append(keys, k.String())
	}
	slices.Sort(keys)
	attrs := make([]slog.Attr, 0, len(keys))
	for _, k := range keys {
		val := rv.MapIndex(reflect.ValueOf(k).Convert(rv.Type().Key()))
		attrs = append(attrs, slog.Any(k, val.Interface()))
	}
	return slog.GroupValue(attrs...), true
}

// ParseLevel parses debug|info|warn|error (case-insensitive). The empty
// string means info.
func ParseLevel(s string) (slog.Level, error) {
	if strings.TrimSpace(s) == "" {
		return slog.LevelInfo, nil
	}
	var l slog.Level
	if err := l.UnmarshalText([]byte(strings.TrimSpace(s))); err != nil {
		return slog.LevelInfo, fmt.Errorf("invalid log level %q: %w", s, err)
	}
	return l, nil
}

// New returns a JSON logger writing to w at the given level, with secret
// redaction applied to every record.
func New(w io.Writer, level slog.Leveler) *slog.Logger {
	return slog.New(NewRedactingHandler(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})))
}
