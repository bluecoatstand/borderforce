package borderforce

import (
	"encoding/hex"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	secretKey, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")

	plainText := "Hello world"

	cipherText, err := encryptString(secretKey, plainText)
	if err != nil {
		t.Error(err)
		t.Fail()
	}

	plainText2, err := decryptString(secretKey, cipherText)
	if err != nil {
		t.Error(err)
		t.Fail()
	}

	if plainText2 != plainText {
		t.Errorf("Expected %q, got %q", plainText, plainText2)
		t.Fail()
	}
	t.Log(plainText2)
}
