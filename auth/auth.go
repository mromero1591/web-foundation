// Package auth provides authentication and authorization support.
package auth

import (
	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/pkg/errors"
)

// These are the expected values for Claims.Roles.
const (
	RoleAdmin = "ADMIN"
	RoleUser  = "USER"
)

// ctxKey represents the type of value for the context key.
type ctxKey int

// Key is used to store/retrieve a Claims value from a context.Context.
const Key ctxKey = 1

// Claims represents the authorization claims transmitted via a JWT.
type Claims struct {
	jwt.StandardClaims
	Name     string   `json:"name"`
	UserName string   `json:"username"`
	Roles    []string `json:"roles"`
}

// Authorized returns true if the claims has at least one of the provided roles.
func (c Claims) Authorized(roles ...string) bool {
	for _, has := range c.Roles {
		for _, want := range roles {
			if has == want {
				return true
			}
		}
	}
	return false
}

// Auth is used to authenticate clients. It can generate a token for a
// set of user claims and recreate the claims by parsing the token.
type Auth struct {
	signingKey string
	method     jwt.SigningMethod
	keyFunc    func(t *jwt.Token) (interface{}, error)
	parser     jwt.Parser
}

// New creates an Auth to support authentication/authorization.
func New(signingKey string, alg string) (*Auth, error) {
	method := jwt.GetSigningMethod(alg)
	if method == nil {
		return nil, errors.Errorf("configuring algorithm")
	}

	keyFunc := func(t *jwt.Token) (interface{}, error) {
		return []byte(signingKey), nil
	}

	// Create the token parser to use. The algorithm used to sign the JWT must be
	// validated to avoid a critical vulnerability:
	// https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
	parser := jwt.Parser{
		ValidMethods: []string{alg},
	}

	a := Auth{
		signingKey: signingKey,
		method:     method,
		keyFunc:    keyFunc,
		parser:     parser,
	}

	return &a, nil
}

// GenerateToken generates a signed JWT token string representing the user Claims.
func (a *Auth) GenerateToken(claims Claims) (string, error) {
	token := jwt.NewWithClaims(a.method, claims)
	str, err := token.SignedString([]byte(a.signingKey))
	if err != nil {
		return "", errors.Wrap(err, "signing token")
	}

	return str, nil
}

// ValidateToken recreates the Claims that were used to generate a token. It
// verifies that the token was signed using our key.
func (a *Auth) ValidateToken(tokenStr string) (Claims, error) {
	var claims Claims
	token, err := a.parser.ParseWithClaims(tokenStr, &claims, a.keyFunc)
	if err != nil {
		return Claims{}, errors.Wrap(err, "parsing token")
	}

	if !token.Valid {
		return Claims{}, errors.New("invalid token")
	}

	return claims, nil
}
