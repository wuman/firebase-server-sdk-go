package firebase

import "github.com/SermoDigital/jose/jwt"

// Token is a parsed read-only ID Token struct.  It can be used to get the uid
// and other attributes of the user provided in the token.
type Token struct {
	delegate jwt.JWT
}

func (t *Token) Uid() (string, bool) {
	return t.delegate.Claims().Subject()
}

func (t *Token) Issuer() (string, bool) {
	return t.delegate.Claims().Issuer()
}

func (t *Token) Name() (string, bool) {
	name, ok := t.delegate.Claims().Get("name").(string)
	return name, ok
}

func (t *Token) Picture() (string, bool) {
	picture, ok := t.delegate.Claims().Get("picture").(string)
	return picture, ok
}

func (t *Token) Email() (string, bool) {
	email, ok := t.delegate.Claims().Get("email").(string)
	return email, ok
}

func (t *Token) IsEmailVerified() (bool, bool) {
	emailVerified, ok := t.delegate.Claims().Get("email_verified").(bool)
	return emailVerified, ok
}

func (t *Token) Claims() Claims {
	return Claims(t.delegate.Claims())
}
