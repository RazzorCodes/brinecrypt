package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// GetKEK reads the key encryption key from BRINECRYPT_KEK (hex-encoded 32 bytes).
func GetKEK() ([]byte, error) {
	hexKey := os.Getenv("BRINECRYPT_KEK")
	if hexKey == "" {
		return nil, fmt.Errorf("BRINECRYPT_KEK not set")
	}
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("invalid BRINECRYPT_KEK: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("BRINECRYPT_KEK must be 32 bytes (64 hex chars), got %d", len(key))
	}
	return key, nil
}

func GenerateDEK() ([]byte, error) {
	key := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	return key, err
}

func EncryptDEK(dek, kek []byte) (string, error) {
	return sealGCM(dek, kek)
}

func DecryptDEK(encryptedDEK string, kek []byte) ([]byte, error) {
	return openGCM(encryptedDEK, kek)
}

func EncryptValue(plaintext string, dek []byte) (string, error) {
	return sealGCM([]byte(plaintext), dek)
}

func DecryptValue(ciphertext string, dek []byte) (string, error) {
	b, err := openGCM(ciphertext, dek)
	return string(b), err
}

// sealGCM encrypts plaintext with AES-256-GCM and returns base64(nonce + ciphertext).
func sealGCM(plaintext, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// openGCM decrypts base64(nonce + ciphertext) with AES-256-GCM.
func openGCM(encoded string, key []byte) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(data) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
