package session

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"
)

// signingMaxSkew bounds how far signed_at may drift from the agent's
// clock before the message is rejected as stale (covers replay).
const signingMaxSkew = 5 * time.Minute

// errMissingSignature distinguishes "no signature attached" from a bad
// one; HandleExec uses it to decide whether the require-signature gate
// applies.
var errMissingSignature = errors.New("missing signature")

// LoadSigningKey reads an Ed25519 public key from a PEM file. The file
// must encode a SubjectPublicKeyInfo (the output of `openssl pkey -pubout`).
// An empty path returns (nil, nil) so call sites can pass through the
// flag value without an extra branch.
func LoadSigningKey(path string) (ed25519.PublicKey, error) {
	if path == "" {
		return nil, nil
	}
	// #nosec G304 -- operator-supplied --signing-pubkey-file path.
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read signing pubkey: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse pubkey: %w", err)
	}
	ed, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected Ed25519 public key, got %T", pub)
	}
	return ed, nil
}

// verifySig checks an Ed25519 signature against signingInput. signedAt
// is the message's claimed timestamp (RFC3339) — it must be within
// signingMaxSkew of `now` or the message is treated as stale.
func verifySig(pub ed25519.PublicKey, signingInput []byte, sigB64, signedAt string, now time.Time) error {
	if pub == nil {
		return nil // no key configured -> verification disabled
	}
	if sigB64 == "" || signedAt == "" {
		return errMissingSignature
	}

	ts, err := time.Parse(time.RFC3339, signedAt)
	if err != nil {
		return fmt.Errorf("parse signed_at: %w", err)
	}
	if d := now.Sub(ts); d > signingMaxSkew || d < -signingMaxSkew {
		return fmt.Errorf("signed_at outside ±%s of agent clock", signingMaxSkew)
	}

	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(pub, signingInput, sig) {
		return errors.New("signature mismatch")
	}
	return nil
}
