// Package instauth authenticates appliance (instance) requests with the
// SP-Ed25519 scheme (docs/fakeportal.md):
//
//	Authorization: SP-Ed25519 instance="<instances.id>",
//	               key="<base64 ed25519 pubkey>", ts="<unix seconds>",
//	               nonce="<hex>", sig="<base64 signature>"
//
// The signature covers the canonical request string
//
//	SP-ED25519-V1\n<METHOD>\n<path>\n<ts>\n<nonce>\n<sha256-hex(body)>\n
//
// verified against the key bound to the instance at activation. Requests
// are rejected when the timestamp is outside ±MaxSkew, when the signature
// digest has been seen before (replay cache), or when the presented key
// differs from the bound key. A per-instance token bucket rate-limits
// authenticated requests.
package instauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/technofish-au/sp-portal/internal/db/dbq"
)

// Scheme is the Authorization scheme name.
const Scheme = "SP-Ed25519"

// Defaults.
const (
	DefaultMaxSkew         = 10 * time.Minute
	DefaultRateLimitPerMin = 60
	defaultMaxBody         = 1 << 20
	replayCacheCapacity    = 100_000
	nonceMaxLen            = 128
)

// Options tunes the authenticator; zero values take the defaults.
type Options struct {
	MaxSkew         time.Duration // timestamp acceptance window, ±
	RateLimitPerMin int           // sustained requests/min per instance
	ReplayTTL       time.Duration // defaults to MaxSkew*2
	// MaxBody bounds the request bytes the middleware buffers to verify
	// the body hash (default 1MiB). Raise it only where a large signed
	// body is legitimate (support-bundle uploads) — the whole body is
	// held in memory for the signature check.
	MaxBody int64
	Now     func() time.Time
}

// Auth is the instance-authentication middleware plus its DB lookups.
type Auth struct {
	q       *dbq.Queries
	store   *Store
	maxSkew time.Duration
	maxBody int64
	replay  *replayCache
	limiter *rateLimiter
	now     func() time.Time
}

// New returns the authenticator over db.
func New(db *sql.DB, opts Options) *Auth {
	if opts.MaxSkew <= 0 {
		opts.MaxSkew = DefaultMaxSkew
	}
	if opts.RateLimitPerMin <= 0 {
		opts.RateLimitPerMin = DefaultRateLimitPerMin
	}
	if opts.ReplayTTL <= 0 {
		opts.ReplayTTL = 2 * opts.MaxSkew
	}
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}
	if opts.MaxBody <= 0 {
		opts.MaxBody = defaultMaxBody
	}
	return &Auth{
		q:       dbq.New(db),
		store:   NewStore(db),
		maxSkew: opts.MaxSkew,
		maxBody: opts.MaxBody,
		replay:  newReplayCache(opts.ReplayTTL, replayCacheCapacity),
		limiter: newRateLimiter(opts.RateLimitPerMin, opts.Now),
		now:     opts.Now,
	}
}

// KeyStore exposes the binding records activation writes.
func (a *Auth) KeyStore() *Store { return a.store }

// credentials is the parsed Authorization header.
type credentials struct {
	instanceID string
	pub        ed25519.PublicKey
	ts         int64
	nonce      string
	sig        []byte
}

// ctxKey identifies the authed instance in the request context.
type ctxKey struct{}

// InstanceFrom returns the authenticated instance carried by ctx.
func InstanceFrom(ctx context.Context) (dbq.Instance, bool) {
	inst, ok := ctx.Value(ctxKey{}).(dbq.Instance)
	return inst, ok
}

// Middleware requires a valid SP-Ed25519 credential and places the
// authenticated dbq.Instance in the request context.
func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := a.authenticate(w, r); err != nil {
			return // authenticate wrote the error response
		}
		next.ServeHTTP(w, r)
	})
}

func (a *Auth) authenticate(w http.ResponseWriter, r *http.Request) error {
	cred, err := parseAuthorization(r.Header.Get("Authorization"))
	if err != nil {
		return authError(w, http.StatusUnauthorized, "bad_auth_header", err.Error())
	}
	if !a.limiter.Allow(cred.instanceID) {
		w.Header().Set("Retry-After", "60")
		return authError(w, http.StatusTooManyRequests, "rate_limited", "too many authenticated requests")
	}
	// Freshness first: a stale timestamp is rejected before any DB work.
	now := a.now()
	if skew := now.Unix() - cred.ts; skew > int64(a.maxSkew.Seconds()) || skew < -int64(a.maxSkew.Seconds()) {
		return authError(w, http.StatusUnauthorized, "stale_timestamp",
			fmt.Sprintf("timestamp outside ±%s window", a.maxSkew))
	}
	inst, err := a.q.GetInstance(r.Context(), cred.instanceID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return authError(w, http.StatusUnauthorized, "unknown_instance", "no such instance")
		}
		return authError(w, http.StatusInternalServerError, "internal", "instance lookup failed")
	}
	bound, found, err := a.store.BoundKey(r.Context(), inst.ID)
	if err != nil {
		return authError(w, http.StatusInternalServerError, "internal", "key lookup failed")
	}
	if !found {
		return authError(w, http.StatusUnauthorized, "no_key_bound", "instance has no bound key")
	}
	if subtle.ConstantTimeCompare(bound, cred.pub) != 1 {
		return authError(w, http.StatusUnauthorized, "wrong_key", "presented key does not match the bound key")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, a.maxBody+1))
	if err != nil {
		return authError(w, http.StatusBadRequest, "bad_body", "request body unreadable")
	}
	if int64(len(body)) > a.maxBody {
		return authError(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body too large")
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	msg := StringToSign(r.Method, requestPath(r), cred.ts, cred.nonce, body)
	if !ed25519.Verify(bound, msg, cred.sig) {
		return authError(w, http.StatusUnauthorized, "bad_signature", "signature verification failed")
	}
	if a.replay.checkAndMark(sha256.Sum256(append([]byte(inst.ID), cred.sig...)), now) {
		return authError(w, http.StatusUnauthorized, "replay", "signature already presented")
	}
	*r = *r.WithContext(context.WithValue(r.Context(), ctxKey{}, inst))
	return nil
}

// requestPath is the signed path: the request-target up to '?', i.e. the
// path exactly as the client sent it (no query string).
func requestPath(r *http.Request) string {
	if i := strings.IndexByte(r.RequestURI, '?'); i >= 0 {
		return r.RequestURI[:i]
	}
	return r.RequestURI
}

// StringToSign builds the canonical request string the signature covers —
// exported so clients, tests and docs/fakeportal.md share the definition.
func StringToSign(method, path string, ts int64, nonce string, body []byte) []byte {
	sum := sha256.Sum256(body)
	return []byte(fmt.Sprintf("SP-ED25519-V1\n%s\n%s\n%d\n%s\n%x\n",
		strings.ToUpper(method), path, ts, nonce, sum))
}

// Authorization builds a well-formed header value for cred — the client's
// half of the contract, exported for tests and fakeportal harnesses.
func Authorization(instanceID string, pub ed25519.PublicKey, ts int64, nonce string, sig []byte) string {
	return fmt.Sprintf("%s instance=%q, key=%q, ts=%q, nonce=%q, sig=%q",
		Scheme, instanceID,
		base64.StdEncoding.EncodeToString(pub),
		strconv.FormatInt(ts, 10), nonce,
		base64.StdEncoding.EncodeToString(sig))
}

// SignRequest produces the Authorization value for a request: convenience
// for clients/tests implementing the scheme.
func SignRequest(priv ed25519.PrivateKey, instanceID, method, path string, ts int64, nonce string, body []byte) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("instauth: private key is %d bytes", len(priv))
	}
	sig := ed25519.Sign(priv, StringToSign(method, path, ts, nonce, body))
	return Authorization(instanceID, priv.Public().(ed25519.PublicKey), ts, nonce, sig), nil
}

// parseAuthorization splits "SP-Ed25519 k=\"v\", ..." into credentials.
func parseAuthorization(header string) (credentials, error) {
	var cred credentials
	scheme, params, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, Scheme) {
		return cred, fmt.Errorf("missing Authorization: %s credentials", Scheme)
	}
	for _, field := range strings.Split(params, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(field), "=")
		if !ok {
			return cred, fmt.Errorf("malformed credential field %q", field)
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
			if unq, err := strconv.Unquote(v); err == nil {
				v = unq
			}
		}
		switch strings.TrimSpace(k) {
		case "instance":
			cred.instanceID = v
		case "key":
			raw, err := base64.StdEncoding.DecodeString(v)
			if err != nil || len(raw) != ed25519.PublicKeySize {
				return cred, fmt.Errorf("key is not a base64 Ed25519 public key")
			}
			cred.pub = raw
		case "ts":
			ts, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return cred, fmt.Errorf("ts is not unix seconds")
			}
			cred.ts = ts
		case "nonce":
			if v == "" || len(v) > nonceMaxLen {
				return cred, fmt.Errorf("nonce missing or too long")
			}
			cred.nonce = v
		case "sig":
			raw, err := base64.StdEncoding.DecodeString(v)
			if err != nil || len(raw) != ed25519.SignatureSize {
				return cred, fmt.Errorf("sig is not a base64 Ed25519 signature")
			}
			cred.sig = raw
		default:
			return cred, fmt.Errorf("unknown credential field %q", k)
		}
	}
	if cred.instanceID == "" || cred.pub == nil || cred.ts == 0 || cred.nonce == "" || cred.sig == nil {
		return cred, fmt.Errorf("incomplete credentials: need instance, key, ts, nonce, sig")
	}
	return cred, nil
}

// authError writes the JSON error envelope and returns a sentinel.
func authError(w http.ResponseWriter, status int, code, message string) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   code,
		"message": message,
	})
	return errors.New(code)
}
