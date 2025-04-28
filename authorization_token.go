package kurojwt

import (
	"github.com/golang-jwt/jwt/v5"
	"time"
)

type AuthorizationToken struct {
	Id                    string    `json:"id"`
	AccessToken           string    `json:"access_token"`
	AccessTokenExpiresIn  time.Time `json:"access_token_expires_in"`
	RefreshToken          string    `json:"refresh_token"`
	RefreshTokenExpiresIn time.Time `json:"refresh_token_expires_in"`
	Domain                string    `json:"domain"`
	jwt.Claims
}
