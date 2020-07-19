package borderforce

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
)

func encryptString(secretKey []byte, plainText string) (string, error) {
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

	return hex.EncodeToString(cipherText), nil
}

func decryptString(secretKey []byte, cipherText string) (string, error) {
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	data, err := hex.DecodeString(cipherText)
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
