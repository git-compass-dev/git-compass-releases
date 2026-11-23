package registry

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Key text formats. The private key is the 32-byte ed25519 seed; it only ever
// lives in the CI secret GC_SIGNING_KEY (and on the machine that made it).
const (
	pubPrefix  = "gcpk1:"
	privPrefix = "gcsk1:"
	// Domain separation: a signature over a registry document can never be
	// replayed as a signature over anything else.
	sigContext = "git-compass-registry-v1\n"
)

// PublicKey is a trusted signing key.
type PublicKey struct {
	ID  string
	Key ed25519.PublicKey
}

// KeyID is the first 8 bytes of sha256(public key), hex.
func KeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:8])
}

// ParsePublicKey reads "gcpk1:<base64 32 bytes>".
func ParsePublicKey(s string) (PublicKey, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, pubPrefix) {
		return PublicKey{}, errors.New("public key: want gcpk1:<base64>")
	}
	b, err := base64.StdEncoding.DecodeString(s[len(pubPrefix):])
	if err != nil || len(b) != ed25519.PublicKeySize {
		return PublicKey{}, errors.New("public key: bad base64 or length")
	}
	return PublicKey{ID: KeyID(b), Key: ed25519.PublicKey(b)}, nil
}

// FormatPublicKey is the inverse of ParsePublicKey.
func FormatPublicKey(pub ed25519.PublicKey) string {
	return pubPrefix + base64.StdEncoding.EncodeToString(pub)
}

// ParsePrivateKey reads "gcsk1:<base64 32-byte seed>".
func ParsePrivateKey(s string) (ed25519.PrivateKey, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, privPrefix) {
		return nil, errors.New("private key: want gcsk1:<base64 seed>")
	}
	b, err := base64.StdEncoding.DecodeString(s[len(privPrefix):])
	if err != nil || len(b) != ed25519.SeedSize {
		return nil, errors.New("private key: bad base64 or length")
	}
	return ed25519.NewKeyFromSeed(b), nil
}

// FormatPrivateKey is the inverse of ParsePrivateKey.
func FormatPrivateKey(k ed25519.PrivateKey) string {
	return privPrefix + base64.StdEncoding.EncodeToString(k.Seed())
}

// GenerateKey makes a new signing key pair (gcpack keygen).
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// Signature is one signature in an envelope.
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// envelope is a signed document on disk:
//
//	{"signed": <payload JSON, exact bytes signed>, "signatures": [...]}
//
// The payload stays readable (indented JSON). Readers verify the exact raw
// bytes of "signed", so no canonical form is needed.
type envelope struct {
	Signed     json.RawMessage `json:"signed"`
	Signatures []Signature     `json:"signatures"`
}

// SignDocument marshals payload (indented) and signs it with every key.
func SignDocument(payload any, keys ...ed25519.PrivateKey) ([]byte, error) {
	if len(keys) == 0 {
		return nil, errors.New("sign: no key")
	}
	body, err := json.MarshalIndent(payload, "  ", "  ")
	if err != nil {
		return nil, err
	}
	sigs := make([]Signature, 0, len(keys))
	for _, k := range keys {
		sig := ed25519.Sign(k, append([]byte(sigContext), body...))
		sigs = append(sigs, Signature{
			KeyID: KeyID(k.Public().(ed25519.PublicKey)),
			Sig:   base64.StdEncoding.EncodeToString(sig),
		})
	}
	sb, err := json.MarshalIndent(sigs, "  ", "  ")
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteString("{\n  \"signed\": ")
	buf.Write(body)
	buf.WriteString(",\n  \"signatures\": ")
	buf.Write(sb)
	buf.WriteString("\n}\n")
	return buf.Bytes(), nil
}

// ErrBadSignature: no trusted key signed the document.
var ErrBadSignature = errors.New("registry: no valid signature from a trusted key")

// OpenDocument verifies data against the trusted keys and decodes the
// payload into out. Unknown payload fields are ignored so newer documents
// stay readable by older cores (the signature already covers them). Signatures from unknown keys
// are ignored; one valid trusted signature is enough.
func OpenDocument(data []byte, trusted []PublicKey, out any) error {
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	if len(env.Signed) == 0 {
		return errors.New("registry: document has no signed payload")
	}
	msg := append([]byte(sigContext), env.Signed...)
	ok := false
	for _, s := range env.Signatures {
		for _, k := range trusted {
			if s.KeyID != k.ID {
				continue
			}
			sig, err := base64.StdEncoding.DecodeString(s.Sig)
			if err == nil && ed25519.Verify(k.Key, msg, sig) {
				ok = true
			}
		}
	}
	if !ok {
		return ErrBadSignature
	}
	if err := json.Unmarshal(env.Signed, out); err != nil {
		return fmt.Errorf("registry: payload: %w", err)
	}
	return nil
}
