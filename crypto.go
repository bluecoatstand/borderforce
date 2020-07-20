package borderforce

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
)

func encryptString(secretKey []byte, plainText string, encoding string) (string, error) {
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	iv := make([]byte, aesgcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}

	cipherText := aesgcm.Seal(iv, iv, []byte(plainText), nil)

	if encoding == "base64" {
		return base64.RawURLEncoding.EncodeToString(cipherText), nil
	}

	return hex.EncodeToString(cipherText), nil
}

func decryptString(secretKey []byte, cipherText string, encoding string) (string, error) {
	var err error

	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	var data []byte

	if encoding == "base64" {
		data, err = base64.RawURLEncoding.DecodeString(cipherText)
	} else {
		data, err = hex.DecodeString(cipherText)
	}
	if err != nil {
		return "", err
	}

	if len(data) < aesgcm.NonceSize() {
		return "", errors.New("Malformed encrypted data")
	}

	plain, err := aesgcm.Open(nil, data[:aesgcm.NonceSize()], data[aesgcm.NonceSize():], nil)
	if err != nil {
		return "", err
	}

	return string(plain), nil
}
