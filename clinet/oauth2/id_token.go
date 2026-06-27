package oauth2

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var ErrInvalidIDToken = errors.New("oauth2: invalid id_token")

type IDTokenClaims struct {
	Issuer    string          `json:"iss"`
	Subject   string          `json:"sub"`
	Audience  json.RawMessage `json:"aud"`
	ExpiresAt int64           `json:"exp"`
	NotBefore int64           `json:"nbf"`
	IssuedAt  int64           `json:"iat"`
	JWTID     string          `json:"jti"`
	UserID    string          `json:"user_id"`
	Email     string          `json:"email"`
	Username  string          `json:"username"`
	Role      string          `json:"role"`
	TokenType string          `json:"token_type"`
	ClientID  string          `json:"client_id"`
	Scope     string          `json:"scope"`
	Nonce     string          `json:"nonce"`
	AuthTime  int64           `json:"auth_time"`
	AMR       []string        `json:"amr"`
	ATHash    string          `json:"at_hash"`
	AZP       string          `json:"azp"`
}

type idTokenHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

func (c *Client) ValidateIDToken(idToken string) (*IDTokenClaims, error) {
	return ValidateIDToken(idToken, c.config.ClientID, c.config.ClientSecret, c.config.Issuer)
}

func (c *Client) ValidateIDTokenWithAccessToken(idToken, accessToken string) (*IDTokenClaims, error) {
	return ValidateIDTokenWithAccessToken(idToken, c.config.ClientID, c.config.ClientSecret, c.config.Issuer, accessToken)
}

func ValidateIDToken(idToken, clientID, clientSecret, issuer string) (*IDTokenClaims, error) {
	return validateIDToken(idToken, clientID, clientSecret, issuer, "", false)
}

func ValidateIDTokenWithAccessToken(idToken, clientID, clientSecret, issuer, accessToken string) (*IDTokenClaims, error) {
	return validateIDToken(idToken, clientID, clientSecret, issuer, accessToken, true)
}

func validateIDToken(idToken, clientID, clientSecret, issuer, accessToken string, checkATHash bool) (*IDTokenClaims, error) {
	if idToken == "" || clientID == "" || clientSecret == "" || issuer == "" {
		return nil, ErrInvalidIDToken
	}

	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidIDToken
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrInvalidIDToken
	}
	var header idTokenHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, ErrInvalidIDToken
	}
	if header.Algorithm != "HS256" {
		return nil, ErrInvalidIDToken
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidIDToken
	}
	var claims IDTokenClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, ErrInvalidIDToken
	}

	mac := hmac.New(sha256.New, []byte(clientSecret))
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	expected := mac.Sum(nil)
	actual, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrInvalidIDToken
	}
	if !hmac.Equal(actual, expected) {
		return nil, ErrInvalidIDToken
	}

	now := time.Now().Unix()
	if claims.Issuer != issuer || claims.TokenType != "id_token" || claims.ClientID != clientID {
		return nil, ErrInvalidIDToken
	}
	if claims.Subject == "" || claims.ExpiresAt <= now {
		return nil, ErrInvalidIDToken
	}
	if claims.NotBefore > 0 && claims.NotBefore > now {
		return nil, ErrInvalidIDToken
	}
	if !idTokenAudienceContains(claims.Audience, clientID) {
		return nil, ErrInvalidIDToken
	}
	if claims.AZP != "" && claims.AZP != clientID {
		return nil, ErrInvalidIDToken
	}
	if checkATHash && claims.ATHash != "" && (accessToken == "" || claims.ATHash != accessTokenHash(accessToken)) {
		return nil, ErrInvalidIDToken
	}

	return &claims, nil
}

func accessTokenHash(accessToken string) string {
	if accessToken == "" {
		return ""
	}
	digest := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(digest[:len(digest)/2])
}

func idTokenAudienceContains(raw json.RawMessage, clientID string) bool {
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return single == clientID
	}

	var values []string
	if err := json.Unmarshal(raw, &values); err == nil {
		for _, value := range values {
			if value == clientID {
				return true
			}
		}
	}
	return false
}

func (c *Client) validateTokenIDToken(token *Token) error {
	if token == nil || token.IDToken == "" {
		return nil
	}
	if c.config.ClientSecret == "" || c.config.Issuer == "" {
		return nil
	}
	if _, err := c.ValidateIDTokenWithAccessToken(token.IDToken, token.AccessToken); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidIDToken, err)
	}
	return nil
}
