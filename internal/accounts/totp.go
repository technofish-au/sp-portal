package accounts

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec -- RFC 6238 mandates HMAC-SHA1
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP parameters (RFC 6238): 30-second step, 6 digits, ±1 step window.
const (
	totpStep    = 30
	totpDigits  = 6
	totpWindow  = 1
	totpKeyLen  = 20 // 160-bit shared secret
	totpModulus = 1_000_000
)

var totpB32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a new random shared secret, base32-encoded without
// padding (the form otpauth URIs and authenticator apps expect).
func NewTOTPSecret() (string, error) {
	raw := make([]byte, totpKeyLen)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("totp: rand: %w", err)
	}
	return totpB32.EncodeToString(raw), nil
}

// TOTPCode returns the 6-digit code for secret at instant t.
func TOTPCode(secret string, t time.Time) (string, error) {
	key, err := totpB32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", fmt.Errorf("totp: decode secret: %w", err)
	}
	var ctr [8]byte
	binary.BigEndian.PutUint64(ctr[:], uint64(t.Unix())/totpStep)
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(ctr[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[off])&0x7f)<<24 | uint32(sum[off+1])<<16 |
		uint32(sum[off+2])<<8 | uint32(sum[off+3])
	return fmt.Sprintf("%0*d", totpDigits, code%totpModulus), nil
}

// VerifyTOTP reports whether code matches secret within ±totpWindow steps
// of t. Comparison is constant-time per candidate step.
func VerifyTOTP(secret, code string, t time.Time) bool {
	if len(code) != totpDigits {
		return false
	}
	for w := -totpWindow; w <= totpWindow; w++ {
		want, err := TOTPCode(secret, t.Add(time.Duration(w)*totpStep*time.Second))
		if err != nil {
			return false
		}
		if subtle.ConstantTimeCompare([]byte(code), []byte(want)) == 1 {
			return true
		}
	}
	return false
}

// TOTPProvisioningURI returns the otpauth:// URI authenticator apps scan.
func TOTPProvisioningURI(issuer, account, secret string) string {
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", fmt.Sprintf("%d", totpDigits))
	v.Set("period", fmt.Sprintf("%d", totpStep))
	return "otpauth://totp/" + url.PathEscape(issuer+":"+account) + "?" + v.Encode()
}
