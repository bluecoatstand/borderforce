package borderforce

import "time"

// Config is used to pass in configuration for BorderForce
type Config struct {
	IsActive             func(string) bool
	JWTKey               string
	SecretKey            []byte
	IDKey                string
	RejectOnTokenFailure bool
	Encoding             string
	Duration             time.Duration
}
