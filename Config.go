package borderforce

// Config is used to pass in configuration for BorderForce
type Config struct {
	IsActive             func(string) bool
	JWTKey               string
	IDKey                string
	RejectOnTokenFailure bool
}