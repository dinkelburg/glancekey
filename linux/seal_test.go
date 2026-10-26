package main

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// Made by CryptoKit (Core/Tests/AppCoreTests, SealVectors) from keys whose raw bytes are all 0x11 (the iPhone's
// password key), 0x22 (seal), 0x33 (session), 0x44 (wrap) and 0x77 (signing), with AES-GCM nonces of 0x55 (seal)
// and 0x66 (wrap); machine-1, phone-1, nonce-1.
const (
	sealVectorPassword    = "correct horse battery staple"
	sealVectorPasswordKey = "BAIX5hfwtkQ5KCePlpmeaaI6TywVK99tbN9m5bgCgtTtGUp968uXcS0t2jyoWqh2Wlb0X8dYWZZS8ol8ZTBuV5Q="
	sealVectorSessionKey  = "BFGnWAgziY6hsYPL1zUKQJkHjG7xweGOlwzXaDA18l59ARBSJxKwtafP8IFoVIaYSpTmgx7axG5zYPqdg0p6gaE="
	sealVectorSealKey     = "BNZak5d8qj0bCBhS/1ennkZfFmBXcwS66tUF3TpIWJzzUBheiVNy32Ih6joTdVfkc/3bZ1XwW9UHw8Uz/OnJEoU="
	sealVectorSealedBox   = "VVVVVVVVVVVVVVVVDSFIX1bYxnvb+2RCqQpeh2FPuhlUCy/2ZlGbPV4EVJre1BD/9OD7UWgVDmg="
	sealVectorWrappedKey  = "BFs2iQ2svXyalrt0oe4os9LXW3LgmiDvJc+Ob9ip8DUNDhS+2NRoKjTYNTi9/1uW6JpmZuwNtXRdAvoSEAct91o="
	sealVectorWrappedBox  = "ZmZmZmZmZmZmZmZmBqoiN6viHPwBy8Tb6PhiiOq+F9l6JCoi/Tlia5A9u9srfDhbzMgc59lM5WGgn6La"
	sealVectorSigningKey  = "BORQVOtbGr2XZlD385W/UdDY3Rk+AXTnoUocjBJ/vfLbrv4yk7BEXz+Sv44QggLgCUFciZSZYgxxt/bfkCETLJw="
	// Over the v2 signed message for unlock with the session key, password key and wrapped key above.
	sealVectorSignature = "/sz4g7aULdEIQ9+nSBRu0O5vqJYoi27erdL8QLnE3HtEDDY83docWnPwXr+85DXMdNSjsAZLeLFUxq6mGAJjyw=="
	// v2 pairing proof for token-1, deviceName "iPhone", the signing key and the password key.
	sealVectorProof = "4oi3gBnMscPvs7i3pHKT/t4JitYW/oswzpVx8YkWwcI="
)

func fixedKey(t *testing.T, b byte) *ecdh.PrivateKey {
	key, err := ecdh.P256().NewPrivateKey(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func b64(data []byte) string { return base64.StdEncoding.EncodeToString(data) }

func TestSealVectorsMatchCryptoKit(t *testing.T) {
	phone, session := fixedKey(t, 0x11), fixedKey(t, 0x33)
	if b64(phone.PublicKey().Bytes()) != sealVectorPasswordKey || b64(session.PublicKey().Bytes()) != sealVectorSessionKey {
		t.Fatal("public keys differ from CryptoKit's")
	}
	sealed, err := sealPasswordWith(sealVectorPassword, phone.PublicKey().Bytes(), "machine-1", "phone-1", fixedKey(t, 0x22),
		bytes.Repeat([]byte{0x55}, 12))
	if err != nil {
		t.Fatal(err)
	}
	if b64(sealed.Key) != sealVectorSealKey || b64(sealed.Box) != sealVectorSealedBox {
		t.Fatalf("sealed differently from CryptoKit: %s %s", b64(sealed.Key), b64(sealed.Box))
	}

	wrapped := WrappedKey{Key: sealVectorWrappedKey, Box: sealVectorWrappedBox}
	password, err := openPassword(sealed, wrapped, session, "machine-1", "phone-1", "nonce-1")
	if err != nil || password != sealVectorPassword {
		t.Fatalf("couldn't open CryptoKit's wrapped key: %v %q", err, password)
	}
	for _, nonce := range []string{"nonce-2", ""} {
		if _, err := openPassword(sealed, wrapped, session, "machine-1", "phone-1", nonce); err == nil {
			t.Fatalf("opened for challenge %q", nonce)
		}
	}
	if _, err := openPassword(sealed, wrapped, fixedKey(t, 0x34), "machine-1", "phone-1", "nonce-1"); err == nil {
		t.Fatal("opened with another session key")
	}

	signingKey, _ := base64.StdEncoding.DecodeString(sealVectorSigningKey)
	key, err := parsePublicKey(signingKey)
	if err != nil {
		t.Fatal(err)
	}
	message := signedMessageV2("machine-1", "phone-1", actionUnlock, "nonce-1", sealVectorSessionKey, sealVectorPasswordKey, &wrapped)
	if !validSignature(key, message, sealVectorSignature) {
		t.Fatal("CryptoKit v2 signature rejected")
	}
	swapped := signedMessageV2("machine-1", "phone-1", actionUnlock, "nonce-1", sealVectorSealKey, sealVectorPasswordKey, &wrapped)
	if validSignature(key, swapped, sealVectorSignature) {
		t.Fatal("signature accepted with another session key")
	}

	if !validPairingProof(sealVectorProof, "token-1", "machine-1", "phone-1", "iPhone", sealVectorSigningKey, sealVectorPasswordKey) {
		t.Fatal("CryptoKit v2 pairing proof rejected")
	}
	if validPairingProof(sealVectorProof, "token-1", "machine-1", "phone-1", "iPhone", sealVectorSigningKey, sealVectorSealKey) {
		t.Fatal("pairing proof accepted with a swapped password key")
	}
}

// RFC 5869 test case 1; hkdfSHA256 makes the first 32 bytes of its output.
func TestHKDF(t *testing.T) {
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")
	info, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	got := hex.EncodeToString(hkdfSHA256(bytes.Repeat([]byte{0x0b}, 22), salt, info))
	if want := "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"; got != want {
		t.Fatalf("got %s", got)
	}
}
