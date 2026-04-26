package connection

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"testing"
	"time"
)

// makeSelfSignedCert returns an ECDSA self-signed cert for "127.0.0.1".
func makeSelfSignedCert(t *testing.T) *x509.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

func TestSPKIHashStable(t *testing.T) {
	t.Parallel()
	cert := makeSelfSignedCert(t)
	got1 := spkiHash(cert)
	got2 := spkiHash(cert)
	if got1 != got2 {
		t.Errorf("SPKI hash not stable: %s vs %s", got1, got2)
	}
	expected := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	if got1 != hex.EncodeToString(expected[:]) {
		t.Errorf("SPKI hash does not match SHA-256 of SubjectPublicKeyInfo")
	}
}

func TestSPKIHashDiffersAcrossKeys(t *testing.T) {
	t.Parallel()
	a := makeSelfSignedCert(t)
	b := makeSelfSignedCert(t)
	if spkiHash(a) == spkiHash(b) {
		t.Errorf("two distinct keys produced the same SPKI hash")
	}
}
