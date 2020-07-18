package main

import (
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
	key := borderforce.ContextKey("account_id")

	token, _ := borderforce.CreateToken(jwtKey, jwt.MapClaims{
		"account_id": "42",
		"exp":        time.Now().AddDate(0, 0, 365).Unix(),
	})
	log.Printf("TOKEN: %s\n", token)

	router := mux.NewRouter().StrictSlash(true)

	bfFunc := borderforce.Middleware(&borderforce.Config{
		IDKey:                "account_id",
		IsActive:             func(string) bool { return true },
		JWTKey:               jwtKey,
		RejectOnTokenFailure: true,
	})

	router.HandleFunc("/", bfFunc(func(w http.ResponseWriter, r *http.Request) {
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
