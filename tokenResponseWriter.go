package borderforce

import (
	"log"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

// tokenResponseWriter is used to send a new session token in each response
type tokenResponseWriter struct {
	w      http.ResponseWriter
	claims jwt.MapClaims
	jwtKey string
}

// newTokenResponseWriter will return an instance of the tokenResponseWriter
func newTokenResponseWriter(w http.ResponseWriter, jwtKey string, claims jwt.MapClaims) tokenResponseWriter {
	return tokenResponseWriter{
		w:      w,
		claims: claims,
		jwtKey: jwtKey,
	}
}

// Write delegates to the wrapped ResponseWriter
func (r tokenResponseWriter) Write(b []byte) (int, error) {
	return r.w.Write(b) // pass it to the original ResponseWriter
}

// Header delegates to the wrapped ResponseWriter
func (r tokenResponseWriter) Header() http.Header {
	return r.w.Header()
}

// WriteHeader adds a refreshed token to the response and then delegates to the wrapped ResponseWriter
func (r tokenResponseWriter) WriteHeader(statusCode int) {
	session, ok := r.claims["session"]
	if ok {
		isSession, ok := session.(bool)

		if ok && isSession {
			r.claims["exp"] = time.Now().Add(time.Minute * 15).Unix()

			token := jwt.NewWithClaims(jwt.SigningMethodHS256, r.claims)

			signedToken, err := token.SignedString([]byte(r.jwtKey))
			if err != nil {
				log.Printf("Failed to create token: [%v]", err)
				return
			}

			r.w.Header().Set("Authorization", signedToken)
		}
	}
	r.w.WriteHeader(statusCode)
}
