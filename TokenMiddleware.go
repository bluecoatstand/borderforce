package borderforce

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/bluecoatstand/ttlmap"
	jwt "github.com/dgrijalva/jwt-go"
)

// ContextKey type
type ContextKey string

var activeTTLMap = ttlmap.NewTTLMap(10 * time.Second)

// Middleware returns a middleware function that can be used to wrap other handlers
func Middleware(config *Config) func(http.HandlerFunc) http.HandlerFunc {
	var contextAccountIDKey = ContextKey(config.IDKey)
	var contextClaimsKey = ContextKey("claims")

	if config.Encoding == "" {
		config.Encoding = "hex"
	}

	if config.Duration == 0 {
		config.Duration = time.Minute * 15
	}

	return func(next http.HandlerFunc) http.HandlerFunc {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if config.JWTKey == "" {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Missing JWTKey in Config"))
				return
			}

			tokenString := r.Header.Get("Authorization")
			if len(tokenString) == 0 {
				if config.RejectOnTokenFailure {
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte("Missing token"))
					return
				}
				// No Authorization header, so allow the request to continue anonymously
				next.ServeHTTP(w, r)
				return
			}

			tokenString = strings.Replace(tokenString, "Bearer ", "", 1)

			claims, err := VerifyToken(config.JWTKey, config.SecretKey, config.Encoding, tokenString)
			if err != nil {
				if config.RejectOnTokenFailure {
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte("Invalid token: " + err.Error()))
					return
				}
				// Invalid token, so allow the request to continue anonymously
				next.ServeHTTP(w, r)
				return
			}

			claimsMap, ok := claims.(jwt.MapClaims)
			if ok {
				accountIDFromToken, found := claimsMap[config.IDKey]
				if found {
					accountID, ok := accountIDFromToken.(string)
					if ok {
						// Check account is active...
						var active bool

						value, found := activeTTLMap.Get(accountID)
						if found {
							active, ok = value.(bool)
							if !ok {
								active = false
							}
						} else {
							active = config.IsActive(accountID)
							activeTTLMap.Set(accountID, active)
						}

						if !active {
							w.WriteHeader(http.StatusUnauthorized)
							w.Write([]byte("Inactive token"))
							return
						}

						ctx := context.WithValue(r.Context(), contextAccountIDKey, accountID)

						if config.PushClaimsToContext {
							m := make(map[string]interface{})

							for k, v := range claimsMap {
								m[k] = v
							}
							ctx = context.WithValue(ctx, contextClaimsKey, m)
						}

						next.ServeHTTP(newTokenResponseWriter(w, config.JWTKey, config.SecretKey, config.Duration, config.Encoding, claimsMap), r.WithContext(ctx))
						return
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// CreateToken creates a JWT token.
func CreateToken(jwtKey string, secretKey []byte, encoding string, session bool, duration time.Duration, claims jwt.MapClaims) (string, error) {
	if jwtKey == "" {
		return "", errors.New("No jwtKey is defined")
	}

	claims["session"] = session
	claims["exp"] = time.Now().Add(duration).Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenStr, err := token.SignedString([]byte(jwtKey))
	if err != nil {
		return "", err
	}

	if len(secretKey) > 0 {
		var err error
		tokenStr, err = encryptString(secretKey, tokenStr, encoding)
		if err != nil {
			return "", err
		}
	}

	return tokenStr, nil
}

// VerifyToken takes a token string and returns the Claims within it.
func VerifyToken(jwtKey string, secretKey []byte, encoding string, tokenStr string) (jwt.Claims, error) {
	if len(secretKey) > 0 {
		var err error
		tokenStr, err = decryptString(secretKey, tokenStr, encoding)
		if err != nil {
			return nil, errors.New("Invalid token")
		}
	}

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtKey), nil
	})

	if err != nil {
		return nil, err
	}

	return token.Claims, nil
}
