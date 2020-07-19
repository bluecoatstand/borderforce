module server

go 1.14

replace github.com/bluecoatstand/borderforce => ../

require (
	github.com/bluecoatstand/borderforce v0.0.2
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/gorilla/mux v1.7.4
)
