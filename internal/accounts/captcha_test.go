package accounts

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"testing"
	"time"
)

// solveChallenge does the widget's proof of work: find the number whose
// SHA-256(salt+number) equals the challenge.
func solveChallenge(t *testing.T, c Challenge) captchaPayload {
	t.Helper()
	for n := 0; n <= c.MaxNumber; n++ {
		sum := sha256.Sum256(append([]byte(c.Salt), []byte(strconv.Itoa(n))...))
		if hex.EncodeToString(sum[:]) == c.Challenge {
			return captchaPayload{
				Algorithm: c.Algorithm, Challenge: c.Challenge,
				Number: n, Salt: c.Salt, Signature: c.Signature,
			}
		}
	}
	t.Fatal("no solution found")
	return captchaPayload{}
}

func encodePayload(t *testing.T, p captchaPayload) string {
	t.Helper()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func testService(t *testing.T, secret []byte, max int, now time.Time) *Service {
	t.Helper()
	return &Service{
		altchaSecret: secret,
		altchaMax:    max,
		secret:       []byte("svc-secret"),
		now:          func() time.Time { return now },
	}
}

func TestAltchaRoundTrip(t *testing.T) {
	svc := testService(t, []byte("altcha-key"), 10_000, time.Now().UTC())
	ch, err := svc.newChallenge()
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}
	p := solveChallenge(t, ch)
	if err := svc.verifyCaptcha(encodePayload(t, p)); err != nil {
		t.Fatalf("valid payload rejected: %v", err)
	}
}

func TestAltchaTamperedRejected(t *testing.T) {
	svc := testService(t, []byte("altcha-key"), 10_000, time.Now().UTC())
	ch, _ := svc.newChallenge()
	p := solveChallenge(t, ch)
	// A wrong number breaks the proof of work.
	p.Number++
	if p.Number > ch.MaxNumber {
		p.Number = 0
	}
	if err := svc.verifyCaptcha(encodePayload(t, p)); err == nil {
		t.Fatal("tampered number accepted")
	}
	// A forged signature is rejected.
	p = solveChallenge(t, ch)
	p.Signature = "deadbeef"
	if err := svc.verifyCaptcha(encodePayload(t, p)); err == nil {
		t.Fatal("forged signature accepted")
	}
	// Garbage payload is rejected.
	if err := svc.verifyCaptcha("not-base64!!"); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestAltchaExpiredRejected(t *testing.T) {
	now := time.Now().UTC()
	svc := testService(t, []byte("altcha-key"), 10_000, now.Add(-ChallengeTTL-time.Minute))
	ch, _ := svc.newChallenge() // issued "in the past", already expired
	p := solveChallenge(t, ch)
	svc.now = func() time.Time { return now }
	if err := svc.verifyCaptcha(encodePayload(t, p)); err == nil {
		t.Fatal("expired challenge accepted")
	}
}
