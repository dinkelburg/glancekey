package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// The saved login password is sealed: encrypted to each iPhone's password key, a key-agreement key in the iPhone's
// Secure Enclave that only works after Face ID, so the agent's files are useless without the iPhone. To unlock,
// hello sends the seal's one-time key and a fresh session key; the iPhone works out the key that opens the password
// and sends it back encrypted to the session key, signed with the command (signedMessageV2). The agent opens the
// password, types it and forgets it. Core/Sources/AppCore/PasswordSeal.swift is the Swift side; the vectors in
// seal_test.go and the Swift tests keep them in step.
//
// Until every paired iPhone has a sealed copy (an iPhone on an older app version has no password key), the plain
// password stays in the keyring as before, and the agent seals it for each iPhone as soon as it can.

// SealedPassword is the password sealed to one iPhone, as agent.json keeps it.
type SealedPassword struct {
	// Key is the X9.63 public half of the one-time key it was sealed with.
	Key []byte `json:"key"`
	// Box is the AES-256-GCM nonce ‖ ciphertext ‖ tag.
	Box []byte `json:"box"`
}

// SealedPasswordChallenge is what hello sends the iPhone so it can open its sealed password.
type SealedPasswordChallenge struct {
	SealKey    string `json:"sealKey"`
	SessionKey string `json:"sessionKey"`
}

// WrappedKey is the key that opens a sealed password, encrypted by the iPhone to the challenge's session key.
type WrappedKey struct {
	// Key is the base64 X9.63 public half of the iPhone's one-time key.
	Key string `json:"key"`
	// Box is base64 AES-GCM nonce ‖ ciphertext ‖ tag.
	Box string `json:"box"`
}

func sealInfo(machineID, deviceID string) []byte {
	return []byte(fmt.Sprintf("faceunlock-seal/v1\n%s\n%s", machineID, deviceID))
}

func wrapInfo(machineID, deviceID, nonce string) []byte {
	return []byte(fmt.Sprintf("faceunlock-wrap/v1\n%s\n%s\n%s", machineID, deviceID, nonce))
}

// sealPassword encrypts password to an iPhone's password key (X9.63).
func sealPassword(password string, passwordKey []byte, machineID, deviceID string) (SealedPassword, error) {
	ephemeral, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return SealedPassword{}, err
	}
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return SealedPassword{}, err
	}
	return sealPasswordWith(password, passwordKey, machineID, deviceID, ephemeral, nonce)
}

func sealPasswordWith(password string, passwordKey []byte, machineID, deviceID string, ephemeral *ecdh.PrivateKey, nonce []byte) (SealedPassword, error) {
	phone, err := ecdh.P256().NewPublicKey(passwordKey)
	if err != nil {
		return SealedPassword{}, err
	}
	shared, err := ephemeral.ECDH(phone)
	if err != nil {
		return SealedPassword{}, err
	}
	sealKey := ephemeral.PublicKey().Bytes()
	box, err := gcmSeal(hkdfSHA256(shared, sealKey, sealInfo(machineID, deviceID)), nonce, []byte(password))
	if err != nil {
		return SealedPassword{}, err
	}
	return SealedPassword{Key: sealKey, Box: box}, nil
}

var errCantOpen = errors.New("the password can't be opened with this key")

// openPassword opens sealed with the key the iPhone wrapped to session for the challenge nonce.
func openPassword(sealed SealedPassword, wrapped WrappedKey, session *ecdh.PrivateKey, machineID, deviceID, nonce string) (string, error) {
	ephemeralKey, err1 := base64.StdEncoding.DecodeString(wrapped.Key)
	box, err2 := base64.StdEncoding.DecodeString(wrapped.Box)
	if err1 != nil || err2 != nil || session == nil {
		return "", errCantOpen
	}
	ephemeral, err := ecdh.P256().NewPublicKey(ephemeralKey)
	if err != nil {
		return "", errCantOpen
	}
	shared, err := session.ECDH(ephemeral)
	if err != nil {
		return "", errCantOpen
	}
	key, err := gcmOpen(hkdfSHA256(shared, ephemeralKey, wrapInfo(machineID, deviceID, nonce)), box)
	if err != nil || len(key) != 32 {
		return "", errCantOpen
	}
	password, err := gcmOpen(key, sealed.Box)
	if err != nil {
		return "", errCantOpen
	}
	return string(password), nil
}

// hkdfSHA256 is HKDF (RFC 5869) with SHA-256 for one 32-byte key, as CryptoKit's hkdfDerivedSymmetricKey makes it.
func hkdfSHA256(secret, salt, info []byte) []byte {
	extract := hmac.New(sha256.New, salt)
	extract.Write(secret)
	expand := hmac.New(sha256.New, extract.Sum(nil))
	expand.Write(info)
	expand.Write([]byte{1})
	return expand.Sum(nil)
}

// gcmSeal returns nonce ‖ ciphertext ‖ tag, CryptoKit's combined form.
func gcmSeal(key, nonce, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(append([]byte(nil), nonce...), nonce, plaintext, nil), nil
}

func gcmOpen(key, combined []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(combined) < gcm.NonceSize()+gcm.Overhead() {
		return nil, errCantOpen
	}
	return gcm.Open(nil, combined[:gcm.NonceSize()], combined[gcm.NonceSize():], nil)
}
