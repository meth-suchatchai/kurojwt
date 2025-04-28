package kurojwt

import (
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"log"
)

func (j *defaultJWT) ParseToken(accessToken string) (interface{}, error) {
	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(j.config.Secret), nil
	})

	if err != nil {
		return nil, err
	}

	log.Println(token.Claims)

	if claims, ok := token.Claims.(jwt.Claims); ok && token.Valid {
		// Access your data (claims)
		fmt.Printf("claims: %v", claims)
		return claims, nil
	} else {
		return nil, errors.New(fmt.Sprintf("invalid token %v %v", ok, token.Valid))
	}
}
