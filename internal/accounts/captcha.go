package accounts

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ALTCHA is self-hosted proof-of-work bot protection (https://altcha.org):
// the server issues {salt, challenge=SHA-256(salt+number), signature=HMAC}
// and the widget searches the number. Verification is pure local crypto —
// no outbound calls — so it works offline and in tests.
//
// Captcha verification is disabled entirely when the service has no
// ALTCHA secret (dev bypass: sign-up posts no payload and passes).

// ChallengeTTL bounds how long an issued challenge stays valid; the expiry
// travels inside the salt as an "?expires=<unix>" parameter (ALTCHA salts
// are opaque strings, extra parameters are part of the hashed input).
const ChallengeTTL = 5 * time.Minute

// Challenge is the ALTCHA challenge served to the widget.
type Challenge struct {
	Algorithm string `json:"algorithm"`
	Challenge string `json:"challenge"`
	MaxNumber int    `json:"maxnumber"`
	Salt      string `json:"salt"`
	Signature string `json:"signature"`
}

// newChallenge issues a fresh ALTCHA challenge: a random salt carrying an
// expires parameter, the proof-of-work puzzle SHA-256(salt+number) and the
// HMAC signature over the puzzle.
func (s *Service) newChallenge() (Challenge, error) {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return Challenge{}, fmt.Errorf("altcha: rand: %w", err)
	}
	number := randUint32() % uint32(s.altchaMax)
	salt := fmt.Sprintf("%s?expires=%d", hex.EncodeToString(buf), s.now().Add(ChallengeTTL).Unix())
	sum := sha256.Sum256(append([]byte(salt), []byte(strconv.FormatUint(uint64(number), 10))...))
	mac := hmac.New(sha256.New, s.altchaSecret)
	_, _ = mac.Write([]byte(hex.EncodeToString(sum[:])))
	return Challenge{
		Algorithm: "SHA-256",
		Challenge: hex.EncodeToString(sum[:]),
		MaxNumber: s.altchaMax,
		Salt:      salt,
		Signature: hex.EncodeToString(mac.Sum(nil)),
	}, nil
}

func randUint32() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint32(time.Now().UnixNano())
	}
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// captchaPayload is the base64 JSON the ALTCHA widget submits.
type captchaPayload struct {
	Algorithm string `json:"algorithm"`
	Challenge string `json:"challenge"`
	Number    int    `json:"number"`
	Salt      string `json:"salt"`
	Signature string `json:"signature"`
	Took      int64  `json:"took"`
}

var errCaptcha = errors.New("captcha verification failed")

// verifyCaptcha checks a submitted ALTCHA payload: the signature must be
// the HMAC of the challenge, the challenge must be SHA-256(salt+number)
// and the salt's expires parameter must still be in the future.
func (s *Service) verifyCaptcha(payload string) error {
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		if raw, err = base64.RawURLEncoding.DecodeString(payload); err != nil {
			return errCaptcha
		}
	}
	var p captchaPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return errCaptcha
	}
	// Signature over the challenge hex string.
	mac := hmac.New(sha256.New, s.altchaSecret)
	_, _ = mac.Write([]byte(p.Challenge))
	if subtle.ConstantTimeCompare([]byte(p.Signature), []byte(hex.EncodeToString(mac.Sum(nil)))) != 1 {
		return errCaptcha
	}
	// Replay the proof of work.
	sum := sha256.Sum256(append([]byte(p.Salt), []byte(strconv.Itoa(p.Number))...))
	if subtle.ConstantTimeCompare([]byte(p.Challenge), []byte(hex.EncodeToString(sum[:]))) != 1 {
		return errCaptcha
	}
	// Expiry embedded in the salt parameters.
	if i := strings.Index(p.Salt, "?expires="); i >= 0 {
		exp, err := strconv.ParseInt(p.Salt[i+len("?expires="):], 10, 64)
		if err != nil || exp <= s.now().Unix() {
			return errCaptcha
		}
	}
	return nil
}
