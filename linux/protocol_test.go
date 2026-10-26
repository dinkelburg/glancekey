package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// Produced by CryptoKit; the same vectors are in Core/Tests/AppCoreTests, so Swift and Go agree on the wire format.
const (
	vectorPublicKey = "BAgPR2YEAVXtH4FV5lz7GfgmXFGdGeSUbwNl/aQuMfhqUZBYED2VyexlxQ8BJj+derxoiayhgiX9Brpn8PSdlSo="
	vectorSignature = "/ZB+omIwMIBk3ZC8I6bqsnPVnoLG4nVQpBIHfBaibW/1X5xhPvSPrcEjDHbILAeiXRVhgVH5BHcirEgxlQqo2A=="
	vectorProof     = "ozz/3xgOMjJa3B9AFHhgoRBQrwoewVS2qZoU7kAXjYc="
	// Approval of "sudo pacman -Syu" (id approval-1, nonce nonce-1, detail "ruben on pts/1") on machine-1 by phone-1.
	vectorApprovalPublicKey = "BL6yw1jEZ48le5S3AmGdVzJQ+uE8yMhKPjoXpbbVZpQlIhZju4aFpgIFFKdm9YxAc985PsCyKqRQMovVORAeHKc="
	vectorApprovalSignature = "lT/6MJw2iN0NA/g4fMugjVeO+Zl5qPDtLLHXaupF0TDxWl1J9l8mbrnhha2zC3W8lW/C+Ism+Px5hp/w6PqG1Q=="
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

func TestCryptoKitApprovalSignatureVerifies(t *testing.T) {
	keyData, _ := base64.StdEncoding.DecodeString(vectorApprovalPublicKey)
	device := PairedDevice{ID: "phone-1", PublicKey: keyData}
	approval := Approval{ID: "approval-1", Title: "sudo pacman -Syu", Detail: "ruben on pts/1", Nonce: "nonce-1", ExpiresIn: 30}
	if !device.validSignature(approvalMessage("machine-1", "phone-1", approval), vectorApprovalSignature) {
		t.Fatal("CryptoKit approval signature rejected")
	}
	approval.Title = "sudo rm -rf /"
	if device.validSignature(approvalMessage("machine-1", "phone-1", approval), vectorApprovalSignature) {
		t.Fatal("signature accepted for a different command")
	}
}

func TestValidPushToken(t *testing.T) {
	token := strings.Repeat("0123456789abcdef", 4)
	for value, want := range map[string]bool{
		token:                   true,
		strings.ToUpper(token):  true,
		"abcdef":                false,
		token + "/../x":         false,
		strings.Repeat("ａ", 64): false,
	} {
		if validPushToken(value) != want {
			t.Errorf("validPushToken(%q) != %v", value, want)
		}
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
	if !strings.HasPrefix(url, urlScheme+"://pair?d=") {
		t.Fatalf("unexpected URL %s", url)
	}
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(url, urlScheme+"://pair?d="))
	if err != nil {
		t.Fatal(err)
	}
	var decoded PairingInvite
	if err := json.Unmarshal(data, &decoded); err != nil || decoded != invite {
		t.Fatalf("round trip failed: %v %+v", err, decoded)
	}
}
