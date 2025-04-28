package kurojwt

import (
	"github.com/golang-jwt/jwt/v5"
	"log"
	"time"
)

type KuroJsonWebToken interface {
	ParseToken(accessToken string) (interface{}, error)
	GenerateAccessToken(id string) (*AuthorizationToken, error)
	ExtendRefreshToken(refreshToken string) (*AuthorizationToken, error)
}

type Config struct {
	Secret        string `mapstructure:"SECRET"`
	Issuer        string `mapstructure:"ISSUER"`
	Domain        string `mapstructure:"DOMAIN"`
	Expire        int64  `mapstructure:"EXPIRATION_TIME"`
	RefreshExpire int64  `mapstructure:"REFRESH_EXPIRATION_TIME"`
}

type defaultJWT struct {
	config   *Config
	timezone *time.Location
}

func NewJWT(config *Config) KuroJsonWebToken {
	if config == nil {
		log.Fatal("config is empty")
	}
	timezone, err := time.LoadLocation("Asia/Bangkok")
	if err != nil {
		log.Fatal("failed to load timezone location.")
	}
	return &defaultJWT{config: config, timezone: timezone}
}

func (j *defaultJWT) generateExpireTime(duration time.Duration) (time.Time, int64) {
	dateTime := time.Now().In(j.timezone).Add(time.Minute * duration)
	return dateTime, dateTime.Unix()
}

func (j *defaultJWT) generateTokenClaim(id string, exp int64) (string, error) {
	initJWT := jwt.New(jwt.SigningMethodHS256)
	claimsJWT := initJWT.Claims.(jwt.MapClaims)
	claimsJWT["iss"] = j.config.Issuer
	claimsJWT["sub"] = id
	claimsJWT["exp"] = exp
	claimsJWT["iat"] = time.Now().In(j.timezone).Unix()
	verifiedToken, err := initJWT.SignedString([]byte(j.config.Secret))

	if err != nil {
		return "", err
	}

	return verifiedToken, err
}
