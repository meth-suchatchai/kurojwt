package kurojwt

import "time"

func (j *defaultJWT) GenerateAccessToken(id string) (*AuthorizationToken, error) {
	accessTokenExpireDate, accessTokenExpire := j.generateExpireTime(time.Minute * time.Duration(j.config.Expire))
	refreshTokenExpireDate, refreshTokenExpire := j.generateExpireTime(time.Minute * time.Duration(j.config.RefreshExpire))

	accessToken, err := j.generateTokenClaim(id, accessTokenExpire)
	if err != nil {
		return nil, err
	}
	refreshToken, err := j.generateTokenClaim(id, refreshTokenExpire)
	if err != nil {
		return nil, err
	}

	return &AuthorizationToken{
		AccessToken:           accessToken,
		AccessTokenExpiresIn:  accessTokenExpireDate,
		RefreshToken:          refreshToken,
		RefreshTokenExpiresIn: refreshTokenExpireDate,
		Domain:                j.config.Domain,
	}, nil
}
