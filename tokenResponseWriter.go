package borderforce

import (
	"fmt"
	"log"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

// tokenResponseWriter is used to send a new session token in each response
type tokenResponseWriter struct {
	w         http.ResponseWriter
	claims    jwt.MapClaims
	jwtKey    string
	secretKey []byte
	duration  time.Duration
	encoding  string
}

// newTokenResponseWriter will return an instance of the tokenResponseWriter
func newTokenResponseWriter(w http.ResponseWriter, jwtKey string, secretKey []byte, duration time.Duration, encoding string, claims jwt.MapClaims) tokenResponseWriter {
	return tokenResponseWriter{
		w:         w,
		claims:    claims,
		jwtKey:    jwtKey,
		secretKey: secretKey,
		duration:  duration,
		encoding:  encoding,
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
	sc := fmt.Sprintf("%d", statusCode)
	switch sc[0] {
	case '2':
		fallthrough
	case '3':
		session, ok := r.claims["session"]
		if ok {
			isSession, ok := session.(bool)

			if ok && isSession {
				token, err := CreateToken(r.jwtKey, r.secretKey, r.encoding, true, r.duration, r.claims)
				if err != nil {
					log.Printf("Failed to create token: [%v]", err)
					return
				}

				r.w.Header().Set("Authorization", token)
			}
		}
	}
	r.w.WriteHeader(statusCode)
}
