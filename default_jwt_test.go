package kurojwt

import "testing"

var config = Config{
	Secret:        "secret",
	Issuer:        "test",
	Domain:        "test.com",
	Expire:        3600,
	RefreshExpire: 64000,
}

func TestNewJWT(t *testing.T) {
	j := NewJWT(&config)
	auth, err := j.GenerateAccessToken("")
	if err != nil {
		t.Error(err)
	}

	t.Log(auth)

	data, err := j.ParseToken(auth.AccessToken)
	if err != nil {
		t.Error(err)
	}
	t.Log(data)
}
