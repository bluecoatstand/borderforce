package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/bluecoatstand/borderforce"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

func main() {
	jwtKey := "0000000000000000000000000000000000000000000000000000000000000000"
	secretKey, _ := hex.DecodeString(jwtKey)
	encoding := "base64"

	key := borderforce.ContextKey("account_id")

	token, _ := borderforce.CreateToken(jwtKey, secretKey, encoding, true, time.Minute*15, jwt.MapClaims{
		"account_id": "42",
	})
	fmt.Printf("Try:\n\ncurl -H \"Authorization: Bearer %s\" localhost:8000\n", token)

	router := mux.NewRouter().StrictSlash(true)

	bfFunc := borderforce.Middleware(&borderforce.Config{
		IDKey:                "account_id",
		IsActive:             func(string) bool { return true },
		JWTKey:               jwtKey,
		SecretKey:            secretKey,
		Encoding:             encoding,
		RejectOnTokenFailure: true,
	})

	router.HandleFunc("/", bfFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf("Hello world - %s\n", r.Context().Value(key))))
	})).Methods(http.MethodGet)

	srv := &http.Server{
		Handler: router,
		Addr:    "127.0.0.1:8000",
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Fatal(srv.ListenAndServe())
}
