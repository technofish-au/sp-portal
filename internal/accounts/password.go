package accounts

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters (OWASP password-storage guidance; memory in KiB).
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32
	argonSaltLen = 16
)

// ErrBadPHC means the stored string is not a parseable Argon2id PHC hash.
var ErrBadPHC = errors.New("malformed argon2id PHC string")

// HashPassword returns the Argon2id PHC string ($argon2id$v=19$m=…$salt$hash)
// for pw.
func HashPassword(pw string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("argon2: salt: %w", err)
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// VerifyPassword reports whether pw matches the stored PHC string. A
// malformed hash or empty hash reports false rather than an error — the
// caller treats both as "no credential".
func VerifyPassword(pw, phc string) bool {
	params, salt, key, err := parsePHC(phc)
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, params.time, params.memory, params.threads, uint32(len(key)))
	return subtle.ConstantTimeCompare(got, key) == 1
}

type argonParams struct {
	time    uint32
	memory  uint32
	threads uint8
}

// parsePHC decodes "$argon2id$v=19$m=…,t=…,p=…$salt$key".
func parsePHC(phc string) (argonParams, []byte, []byte, error) {
	var p argonParams
	parts := strings.Split(phc, "$")
	// parts: ["", "argon2id", "v=19", "m=…,t=…,p=…", salt, key]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return p, nil, nil, ErrBadPHC
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return p, nil, nil, ErrBadPHC
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memory, &p.time, &p.threads); err != nil {
		return p, nil, nil, ErrBadPHC
	}
	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return p, nil, nil, ErrBadPHC
	}
	key, err := b64.DecodeString(parts[5])
	if err != nil {
		return p, nil, nil, ErrBadPHC
	}
	return p, salt, key, nil
}
