package firebase

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
)

const (
	firebaseAudience = "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit"
)

var (
	reservedNames = []string{
		"acr",
		"amr",
		"at_hash",
		"aud",
		"auth_time",
		"azp",
		"cnf",
		"c_hash",
		"exp",
		"firebase",
		"iat",
		"iss",
		"jti",
		"nbf",
		"nonce",
		"sub",
	}
)

func init() {
	sort.Strings(reservedNames)
}

// createSignedCustomAuthTokenForUser creates a custom auth token for a given user.
func createSignedCustomAuthTokenForUser(uid string, developerClaims *Claims, issuer string, privateKey *rsa.PrivateKey) (string, error) {
	if uid == "" {
		return "", errors.New("Uid must be provided.")
	}
	if issuer == "" {
		return "", errors.New("Must provide an issuer.")
	}
	if len(uid) > 128 {
		return "", errors.New("Uid must be shorter than 128 characters")
	}

	method := crypto.SigningMethodRS256
	claims := jws.Claims{}
	claims.Set("uid", uid)
	claims.SetIssuer(issuer)
	claims.SetSubject(issuer)
	claims.SetAudience(firebaseAudience)
	now := clock.Now()
	claims.SetIssuedAt(now)
	claims.SetExpiration(now.Add(time.Hour))

	if developerClaims != nil {
		for claim := range *developerClaims {
			if isReserved(claim) {
				return "", fmt.Errorf("developer_claims cannot contain a reserved key: %s", claim)
			}
		}
		claims.Set("claims", developerClaims)
	}

	jwt := jws.NewJWT(claims, method)
	bytes, err := jwt.Serialize(privateKey)
	if err != nil {
		return "", err
	}

	return string(bytes), nil
}

// isReserved determines whether a given name is a reserved name via binary search.
func isReserved(name string) bool {
	if len(reservedNames) > 0 {
		l, r := 0, len(reservedNames)-1
		for l <= r {
			m := l + (r-l)/2
			curr := reservedNames[m]
			if curr == name {
				return true
			} else if curr > name {
				r = m - 1
			} else /* if curr < name */ {
				l = m + 1
			}
		}
	}
	return false
}
