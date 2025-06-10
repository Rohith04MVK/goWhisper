package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf" // For KDF
	"golang.org/x/crypto/sha3"
)

var curve = ecdh.X25519()

type KeyPair struct {
	PrivateKey *ecdh.PrivateKey
	PublicKey  *ecdh.PublicKey
}

func GenerateECDHKeyPair() (*KeyPair, error) {
	privKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDH private key: %w", err)
	}
	pubKey := privKey.PublicKey()
	return &KeyPair{PrivateKey: privKey, PublicKey: pubKey}, nil
}

func ECDHSharedSecret(privKey *ecdh.PrivateKey, peerPubKeyBytes []byte) ([]byte, error) {
	peerPubKey, err := curve.NewPublicKey(peerPubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid peer public key bytes: %w", err)
	}

	sharedBytes, err := privKey.ECDH(peerPubKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH computation failed: %w", err)
	}

	// Use HKDF to derive a key of a specific length (e.g., 32 bytes for AES-256)
	// Salt can be empty or a fixed value if not exchanging it.
	// Info can be context-specific string, e.g., "gowhisper-aes-gcm-key"
	hkdf := hkdf.New(sha3.New256, sharedBytes, nil, []byte("gowhisper-aes-gcm-key"))
	derivedKey := make([]byte, 32) // 32 bytes for AES-256
	if _, err := io.ReadFull(hkdf, derivedKey); err != nil {
		return nil, fmt.Errorf("HKDF key derivation failed: %w", err)
	}

	return derivedKey, nil
}

func EncryptAES_GCM(plaintext []byte, key []byte) (ciphertext []byte, nonce []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("AES cipher creation failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("AES GCM creation failed: %w", err)
	}

	nonce = make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("nonce generation failed: %w", err)
	}

	ciphertext = gcm.Seal(nil, nonce, plaintext, nil) // Prepend nonce to ciphertext for easier handling
	return ciphertext, nonce, nil
}

func DecryptAES_GCM(ciphertext []byte, nonce []byte, key []byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("AES cipher creation failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("AES GCM creation failed: %w", err)
	}

	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("incorrect nonce length")
	}

	plaintext, err = gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("AES GCM decryption failed: %w", err)
	}
	return plaintext, nil
}

// CurveForECDH returns the ECDH curve being used (X25519).
func CurveForECDH() ecdh.Curve {
	return curve // curve is the unexported ecdh.X25519() variable
}
