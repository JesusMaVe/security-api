package main

import (
	"fmt"

	"github.com/fernet/fernet-go"
)

// cryptoService encrypts/decrypts data stored in the database using a single
// fixed Fernet key (AES-CBC + HMAC). Ported from the reference cia-api
// implementation, stripped of key rotation: this key (DATABASE_ENCRYPTION_KEY)
// must never rotate, or previously stored records become undecryptable.
type cryptoService struct {
	key *fernet.Key
}

func newCryptoService(encodedKey string) (*cryptoService, error) {
	key, err := fernet.DecodeKey(encodedKey)
	if err != nil {
		return nil, fmt.Errorf("invalid DATABASE_ENCRYPTION_KEY: %w", err)
	}
	return &cryptoService{key: key}, nil
}

func (c *cryptoService) Encrypt(plaintext string) (string, error) {
	tok, err := fernet.EncryptAndSign([]byte(plaintext), c.key)
	if err != nil {
		return "", fmt.Errorf("encryption failed")
	}
	return string(tok), nil
}

func (c *cryptoService) Decrypt(ciphertext string) (string, error) {
	msg := fernet.VerifyAndDecrypt([]byte(ciphertext), 0, []*fernet.Key{c.key})
	if msg == nil {
		return "", fmt.Errorf("invalid or expired ciphertext")
	}
	return string(msg), nil
}
