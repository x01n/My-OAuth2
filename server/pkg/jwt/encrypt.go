package jwt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"strings"

	"golang.org/x/crypto/hkdf"
)

/* 加密令牌前缀：客户端可见但无法在无密钥时解密载荷 */
const encryptedTokenPrefix = "o2e1."

var (
	ErrCiphertextTooShort = errors.New("encrypted token ciphertext too short")
	ErrDecryptFailed      = errors.New("failed to decrypt token")
)

/*
 * deriveEncryptionKey 从 JWT 签名密钥派生 AES-256 加密密钥（与 HMAC 密钥分离）
 */
func deriveEncryptionKey(secret string) []byte {
	reader := hkdf.New(sha256.New, []byte(secret), nil, []byte("my-oauth2-jwt-aes-gcm-v1"))
	key := make([]byte, 32)
	_, _ = io.ReadFull(reader, key)
	return key
}

/* IsEncryptedToken 是否为服务端加密的令牌格式 */
func IsEncryptedToken(token string) bool {
	return strings.HasPrefix(token, encryptedTokenPrefix)
}

/*
 * encryptSignedJWT 对已签名的 JWT 字符串做 AES-256-GCM 加密
 * 第三方/前端仅能看到 o2e1.* 密文，无法 Base64 解码 claims
 */
func encryptSignedJWT(encKey []byte, signed string) (string, error) {
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(signed), nil)
	blob := append(nonce, ciphertext...)
	return encryptedTokenPrefix + base64.RawURLEncoding.EncodeToString(blob), nil
}

/* decryptTokenIfNeeded 解密 o2e1.* 令牌，返回内部 JWT 供校验 */
func decryptTokenIfNeeded(encKey []byte, token string) (string, error) {
	if !IsEncryptedToken(token) {
		return token, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, encryptedTokenPrefix))
	if err != nil {
		return "", ErrDecryptFailed
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(raw) < nonceSize {
		return "", ErrCiphertextTooShort
	}
	nonce, ciphertext := raw[:nonceSize], raw[nonceSize:]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", ErrDecryptFailed
	}
	return string(plain), nil
}
