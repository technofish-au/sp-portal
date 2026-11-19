package accounts

import (
	"strings"
	"testing"
	"time"
)

func TestHashAndVerifyPassword(t *testing.T) {
	phc, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if !strings.HasPrefix(phc, "$argon2id$v=19$") {
		t.Fatalf("not a PHC argon2id string: %q", phc)
	}
	if !VerifyPassword("correct horse battery staple", phc) {
		t.Fatal("correct password rejected")
	}
	if VerifyPassword("wrong", phc) {
		t.Fatal("wrong password accepted")
	}
	if VerifyPassword("anything", "not-a-phc") || VerifyPassword("anything", "") {
		t.Fatal("malformed/empty hash accepted")
	}
}

func TestSealRoundTrip(t *testing.T) {
	key := []byte("test-auth-secret-key-32-bytes-pad!!!")
	sealed, err := Seal(key, []byte("JBSWY3DPEHPK3PXP"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	plain, err := Open(key, sealed)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if string(plain) != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("roundtrip mismatch: %q", plain)
	}
	if _, err := Open([]byte("wrong-key"), sealed); err == nil {
		t.Fatal("opened with wrong key")
	}
	if _, err := Open(key, sealed[:len(sealed)-4]); err == nil {
		t.Fatal("opened truncated ciphertext")
	}
}

func TestTOTP(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatalf("secret: %v", err)
	}
	now := time.Unix(1_700_000_000, 0)
	code, err := TOTPCode(secret, now)
	if err != nil {
		t.Fatalf("code: %v", err)
	}
	if len(code) != totpDigits {
		t.Fatalf("code length %d", len(code))
	}
	if !VerifyTOTP(secret, code, now) {
		t.Fatal("own code rejected")
	}
	// ±1 step window passes, ±2 fails.
	prev, _ := TOTPCode(secret, now.Add(-totpStep*time.Second))
	if !VerifyTOTP(secret, prev, now) {
		t.Fatal("previous-step code rejected inside window")
	}
	old, _ := TOTPCode(secret, now.Add(-3*totpStep*time.Second))
	if old != code && VerifyTOTP(secret, old, now) {
		t.Fatal("stale code accepted")
	}
	if VerifyTOTP(secret, "000000", now) && code != "000000" && prev != "000000" {
		t.Fatal("bad code accepted")
	}
	uri := TOTPProvisioningURI("ServerPerch", "a@b.c", secret)
	if !strings.HasPrefix(uri, "otpauth://totp/") || !strings.Contains(uri, "secret="+secret) {
		t.Fatalf("bad uri: %q", uri)
	}
}
