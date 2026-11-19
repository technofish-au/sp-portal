package accounts

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
)

// errSealed is returned when a sealed blob cannot be decrypted (wrong key
// or corrupted ciphertext).
var errSealed = errors.New("sealed value failed to open")

// sealKey derives the AES-256 key for TOTP-secret sealing from the auth
// secret: a distinct domain ("totp-seal") so the same master secret can
// also sign sessions without key reuse.
func sealKey(secret []byte) []byte {
	sum := sha256.Sum256(append([]byte("totp-seal\x00"), secret...))
	return sum[:]
}

// Seal encrypts plaintext with AES-256-GCM under a key derived from the
// auth secret; the output is nonce || ciphertext.
func Seal(secret, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(sealKey(secret))
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	out := make([]byte, 0, gcm.NonceSize()+len(plaintext)+gcm.Overhead())
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("seal: nonce: %w", err)
	}
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, plaintext, nil)
	return out, nil
}

// Open decrypts a value produced by Seal.
func Open(secret, sealed []byte) ([]byte, error) {
	block, err := aes.NewCipher(sealKey(secret))
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	if len(sealed) < gcm.NonceSize()+gcm.Overhead() {
		return nil, errSealed
	}
	plain, err := gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], nil)
	if err != nil {
		return nil, errSealed
	}
	return plain, nil
}
