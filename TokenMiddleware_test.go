package borderforce

import (
	"encoding/hex"
	"testing"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

func TestCreateAndVerify(t *testing.T) {
	jwtKey := "0000000000000000000000000000000000000000000000000000000000000000"
	secretKey, _ := hex.DecodeString(jwtKey)
	encoding := "base64"

	token, err := CreateToken(jwtKey, secretKey, encoding, true, time.Minute*15, jwt.MapClaims{
		"account_id": "42",
	})

	if err != nil {
		t.Error(err)
		t.Fail()
	}

	t.Log(token)

	claims, err := VerifyToken(jwtKey, secretKey, encoding, token)
	if err != nil {
		t.Error(err)
		t.Fail()
	}

	t.Logf("%v", claims)

}
