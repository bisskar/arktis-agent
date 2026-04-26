package session

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bisskar/arktis-agent/internal/protocol"
)

func writePubKeyPEM(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIX: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "pub.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{
		Type: "PUBLIC KEY", Bytes: der,
	}), 0o600); err != nil {
		t.Fatalf("write pem: %v", err)
	}
	return path
}

func TestLoadSigningKey(t *testing.T) {
	t.Parallel()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	path := writePubKeyPEM(t, pub)

	got, err := LoadSigningKey(path)
	if err != nil {
		t.Fatalf("LoadSigningKey: %v", err)
	}
	if !pub.Equal(got) {
		t.Errorf("loaded key does not match generated key")
	}
}

func TestLoadSigningKeyEmptyPath(t *testing.T) {
	t.Parallel()
	got, err := LoadSigningKey("")
	if err != nil || got != nil {
		t.Errorf("empty path should return (nil, nil); got (%v, %v)", got, err)
	}
}

func TestVerifySigOK(t *testing.T) {
	t.Parallel()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	msg := &protocol.ExecMessage{
		RequestID:    "abc",
		Command:      "id",
		ExecutorName: "bash",
		SignedAt:     now.Format(time.RFC3339),
	}
	sig := ed25519.Sign(priv, protocol.SigInputExec(msg))
	msg.Signature = base64.StdEncoding.EncodeToString(sig)

	if err := verifySig(pub, protocol.SigInputExec(msg), msg.Signature, msg.SignedAt, now); err != nil {
		t.Errorf("verifySig: %v", err)
	}
}

func TestVerifySigMissingTreatedAsSentinel(t *testing.T) {
	t.Parallel()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	err := verifySig(pub, []byte("x"), "", "", time.Now())
	if !errors.Is(err, errMissingSignature) {
		t.Errorf("missing signature should return errMissingSignature; got %v", err)
	}
}

func TestVerifySigBadSignatureRejected(t *testing.T) {
	t.Parallel()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	garbage := base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	err := verifySig(pub, []byte("payload"), garbage, now.Format(time.RFC3339), now)
	if err == nil || errors.Is(err, errMissingSignature) {
		t.Errorf("expected signature mismatch; got %v", err)
	}
}

func TestVerifySigStaleRejected(t *testing.T) {
	t.Parallel()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	tooOld := now.Add(-2 * signingMaxSkew).Format(time.RFC3339)
	msg := &protocol.ExecMessage{RequestID: "abc", Command: "id", ExecutorName: "bash", SignedAt: tooOld}
	sig := ed25519.Sign(priv, protocol.SigInputExec(msg))

	err := verifySig(pub, protocol.SigInputExec(msg), base64.StdEncoding.EncodeToString(sig), tooOld, now)
	if err == nil {
		t.Errorf("expected stale signature to be rejected")
	}
}
