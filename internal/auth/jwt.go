package auth

import (
	"crypto/rsa"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTIssuer struct {
	priv *rsa.PrivateKey
	pub  *rsa.PublicKey
	ttl  time.Duration
}

func NewJWTIssuer(priv *rsa.PrivateKey, pub *rsa.PublicKey, ttl time.Duration) *JWTIssuer {
	return &JWTIssuer{priv: priv, pub: pub, ttl: ttl}
}

type accessClaims struct {
	jwt.RegisteredClaims
}

func (j *JWTIssuer) IssueAccessToken(steamID string) (string, error) {
	now := time.Now()
	claims := accessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   steamID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(j.ttl)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(j.priv)
}

// VerifyAccessToken возвращает SteamID из валидного токена, либо ошибку,
// если подпись неверна, алгоритм не совпадает, или срок истёк.
func (j *JWTIssuer) VerifyAccessToken(tokenString string) (string, error) {
	token, err := jwt.ParseWithClaims(tokenString, &accessClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("неожиданный алгоритм подписи")
		}
		return j.pub, nil
	})
	if err != nil {
		return "", err
	}

	claims, ok := token.Claims.(*accessClaims)
	if !ok || !token.Valid {
		return "", errors.New("невалидный токен")
	}
	return claims.Subject, nil
}
