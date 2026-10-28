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
	if !validPairingProof(vectorProof, "token-1", "machine-1", "phone-1", "iPhone", vectorPublicKey, "") {
		t.Fatal("CryptoKit pairing proof rejected")
	}
	if validPairingProof(vectorProof, "token-2", "machine-1", "phone-1", "iPhone", vectorPublicKey, "") {
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

// The same JSON is in the Swift tests (ProtocolTests.sealedPasswordJSON), so both sides use the same field names.
const (
	jsonInvite  = `{"v":2,"machineId":"m","machineName":"n","platform":"linux","relay":"https://r","token":"t","wantsPasswordKey":true}`
	jsonHello   = `{"machineId":"m","machineName":"n","nonce":"x","wantsPasswordKey":true,"sealedPassword":{"sealKey":"S","sessionKey":"T"}}`
	jsonPair    = `{"deviceId":"d","deviceName":"iPhone","passwordKey":"P","proof":"p","publicKey":"k"}`
	jsonCommand = `{"action":"unlock","deviceId":"d","nonce":"x","passwordKey":"P","signature":"s","wrappedKey":{"box":"B","key":"K"}}`
)

func TestSealedPasswordJSONMatchesSwift(t *testing.T) {
	invite, _ := json.Marshal(PairingInvite{V: 2, MachineID: "m", MachineName: "n", Platform: "linux", Relay: "https://r", Token: "t", WantsPasswordKey: true})
	hello, _ := json.Marshal(HelloResponse{MachineID: "m", MachineName: "n", Nonce: "x", WantsPasswordKey: true,
		SealedPassword: &SealedPasswordChallenge{SealKey: "S", SessionKey: "T"}})
	if string(invite) != jsonInvite || string(hello) != jsonHello {
		t.Fatalf("agent writes\n%s\n%s", invite, hello)
	}
	var pair PairRequest
	var command CommandRequest
	if json.Unmarshal([]byte(jsonPair), &pair) != nil || pair.PasswordKey != "P" {
		t.Fatalf("pair request: %+v", pair)
	}
	if json.Unmarshal([]byte(jsonCommand), &command) != nil || command.PasswordKey != "P" || command.WrappedKey == nil ||
		*command.WrappedKey != (WrappedKey{Key: "K", Box: "B"}) {
		t.Fatalf("command: %+v", command)
	}
}

// The same JSON is in the Swift tests (ProtocolTests.cardJSON).
const jsonCard = `{"card":{"approvals":[{"detail":"ruben on pts/1","expiresIn":60,"id":"a1","title":"sudo true"}],"cards":["` +
	"abababababababababababababababababababababababababababababababab" + `"],"locked":true}}`

func TestCardJSONMatchesSwift(t *testing.T) {
	card := strings.Repeat("ab", 32)
	locked := true
	data, _ := json.Marshal(RelayCard{Card: Card{Cards: []string{card}, Locked: &locked,
		Approvals: []CardWaiting{{ID: "a1", Title: "sudo true", Detail: "ruben on pts/1", ExpiresIn: 60}}}})
	if string(data) != jsonCard {
		t.Fatalf("agent writes\n%s", data)
	}
	empty, _ := json.Marshal(RelayCard{Card: Card{Cards: []string{card}, Approvals: []CardWaiting{}}})
	if string(empty) != `{"card":{"approvals":[],"cards":["`+card+`"]}}` {
		t.Fatalf("agent writes\n%s", empty)
	}
	var hello HelloRequest
	if json.Unmarshal([]byte(`{"cardId":"`+card+`","deviceId":"d"}`), &hello) != nil || hello.CardID == nil || *hello.CardID != card {
		t.Fatalf("hello: %+v", hello)
	}
}

func TestValidCardID(t *testing.T) {
	// SHA-256 of "secret", as CardId.of(secret:) makes it in Swift.
	id := "2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b"
	if !validCardID(id) || validCardID(strings.ToUpper(id)) || validCardID(id[1:]) || validCardID(id[1:]+"/") {
		t.Fatal("validCardID")
	}
}

// The same bytes are pinned in the Swift tests (ProtocolTests.waitMessage).
func TestWaitMessageMatchesSwift(t *testing.T) {
	if string(waitMessage("m", "d", "n", 300)) != "faceunlock-wait/v1\nm\nd\nn\n300" {
		t.Fatal("wait message")
	}
	var request CommandRequest
	if json.Unmarshal([]byte(`{"action":"setWait","deviceId":"d","nonce":"n","signature":"s","wait":300}`), &request) != nil ||
		request.Action != actionSetWait || request.Wait != 300 {
		t.Fatalf("%+v", request)
	}
}

// Core's PairedDevice.keyFingerprint and RelayNotification pin the same values.
func TestKeyFingerprintMatchesSwift(t *testing.T) {
	if got := keyFingerprint([]byte("test")); got != "9F86-D081-884C" {
		t.Fatalf("got %q", got)
	}
}

func TestNotifyJSONMatchesSwift(t *testing.T) {
	data, _ := json.Marshal(RelayNotification{Notify: Notify{MachineName: "Mac", PushTokens: []string{"t"}, ExpiresIn: 900}})
	if string(data) != `{"notify":{"machineName":"Mac","pushTokens":["t"],"expiresIn":900}}` {
		t.Fatalf("got %s", data)
	}
}
