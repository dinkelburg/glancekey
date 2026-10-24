package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// Produced by CryptoKit; the same vectors are in Core/Tests/FaceUnlockCoreTests, so Swift and Go agree on the wire format.
const (
	vectorPublicKey = "BAgPR2YEAVXtH4FV5lz7GfgmXFGdGeSUbwNl/aQuMfhqUZBYED2VyexlxQ8BJj+derxoiayhgiX9Brpn8PSdlSo="
	vectorSignature = "/ZB+omIwMIBk3ZC8I6bqsnPVnoLG4nVQpBIHfBaibW/1X5xhPvSPrcEjDHbILAeiXRVhgVH5BHcirEgxlQqo2A=="
	vectorProof     = "ozz/3xgOMjJa3B9AFHhgoRBQrwoewVS2qZoU7kAXjYc="
)

func TestCryptoKitSignatureVerifies(t *testing.T) {
	keyData, _ := base64.StdEncoding.DecodeString(vectorPublicKey)
	key, err := parsePublicKey(keyData)
	if err != nil {
		t.Fatal(err)
	}
	message := signedMessage("machine-1", "phone-1", actionUnlock, "nonce-1")
	if !validSignature(key, message, vectorSignature) {
		t.Fatal("CryptoKit signature rejected")
	}
	if validSignature(key, signedMessage("machine-1", "phone-1", actionLock, "nonce-1"), vectorSignature) {
		t.Fatal("signature accepted for a different action")
	}
}

func TestCryptoKitPairingProofMatches(t *testing.T) {
	if !validPairingProof(vectorProof, "token-1", "machine-1", "phone-1", "iPhone", vectorPublicKey) {
		t.Fatal("CryptoKit pairing proof rejected")
	}
	if validPairingProof(vectorProof, "token-2", "machine-1", "phone-1", "iPhone", vectorPublicKey) {
		t.Fatal("proof accepted with the wrong token")
	}
}

func TestInviteURL(t *testing.T) {
	invite := PairingInvite{V: protocolVersion, MachineID: "m", MachineName: "omarchy", Platform: "linux", Relay: defaultRelay, Token: "t"}
	url := invite.URL()
	if !strings.HasPrefix(url, "faceunlock://pair?d=") {
		t.Fatalf("unexpected URL %s", url)
	}
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(url, "faceunlock://pair?d="))
	if err != nil {
		t.Fatal(err)
	}
	var decoded PairingInvite
	if err := json.Unmarshal(data, &decoded); err != nil || decoded != invite {
		t.Fatalf("round trip failed: %v %+v", err, decoded)
	}
}
