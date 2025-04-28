package kurojwt

import (
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

func (j *defaultJWT) ExtendRefreshToken(refreshToken string) (*AuthorizationToken, error) {
	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(j.config.Secret), nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("invalid or expired refresh token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("failed to parse token")
	}

	u, ok := claims["sub"].(string)
	if !ok {
		return nil, errors.New("failed to parse token")
	}

	//id, err := strconv.Atoi(u)
	//if err != nil {
	//	return nil, err
	//}

	extentDateTime, extentTime := j.generateExpireTime(time.Minute * time.Duration(j.config.Expire))
	newRefreshDateTime, newRefreshTime := j.generateExpireTime(time.Minute * time.Duration(j.config.RefreshExpire))

	accessToken, vErr := j.generateTokenClaim(u, extentTime)
	if vErr != nil {
		return nil, vErr
	}

	newRefreshToken, vErr := j.generateTokenClaim(u, newRefreshTime)
	if vErr != nil {
		return nil, vErr
	}

	return &AuthorizationToken{
		AccessToken:           accessToken,
		AccessTokenExpiresIn:  extentDateTime,
		RefreshToken:          newRefreshToken,
		RefreshTokenExpiresIn: newRefreshDateTime,
		Domain:                j.config.Domain,
	}, nil
}
