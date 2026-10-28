package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Wire protocol, mirroring Core/Sources/AppCore/Protocol.swift. The "faceunlock…/v1" prefixes of signed messages
// and the pairing proof are fixed protocol constants from the app's first name, not the app's name (brand.go):
// changing them would break every pairing and the vectors shared with the Swift tests.

const (
	protocolVersion = 2
	nonceLifetime   = 60 * time.Second
	pairingLifetime = 5 * time.Minute
)

type Action string

const (
	actionUnlock Action = "unlock"
	actionLock   Action = "lock"
	actionStatus Action = "status"
	// actionApprove and actionDeny answer an Approval. Approving is signed with approvalMessage; denying isn't
	// signed, since it only makes the computer ask for its password instead.
	actionApprove Action = "approve"
	actionDeny    Action = "deny"
	// actionSetWait sets how long approvals wait for the iPhone (CommandRequest.Wait), signed with waitMessage.
	actionSetWait Action = "setWait"
)

// PairingInvite is what the pairing QR code holds.
type PairingInvite struct {
	V           int    `json:"v"`
	MachineID   string `json:"machineId"`
	MachineName string `json:"machineName"`
	Platform    string `json:"platform"`
	Relay       string `json:"relay"`
	Token       string `json:"token"`
	// WantsPasswordKey asks the iPhone for a password key, so the agent can seal the password to it (seal.go).
	WantsPasswordKey bool `json:"wantsPasswordKey,omitempty"`
}

// URL opens straight in the iPhone app when scanned with the Camera app.
func (i PairingInvite) URL() string {
	data, _ := json.Marshal(i)
	return urlScheme + "://pair?d=" + base64.RawURLEncoding.EncodeToString(data)
}

type PairRequest struct {
	DeviceID   string `json:"deviceId"`
	DeviceName string `json:"deviceName"`
	PublicKey  string `json:"publicKey"`
	Proof      string `json:"proof"`
	// PasswordKey is the iPhone's password key (seal.go), base64 X9.63, when the invite asked for one.
	PasswordKey string `json:"passwordKey,omitempty"`
}

type PairResponse struct {
	MachineID   string `json:"machineId"`
	MachineName string `json:"machineName"`
}

type HelloRequest struct {
	DeviceID string `json:"deviceId"`
	// PushToken is the iPhone's push token (see validPushToken): nil leaves the saved one, "" removes it.
	PushToken *string `json:"pushToken,omitempty"`
	// CardID is the iPhone's lock screen card on the relay (see RelayCard): nil leaves the saved one, "" removes it.
	CardID *string `json:"cardId,omitempty"`
}

type HelloResponse struct {
	MachineID   string     `json:"machineId"`
	MachineName string     `json:"machineName"`
	Nonce       string     `json:"nonce"`
	Locked      *bool      `json:"locked,omitempty"`
	Approvals   []Approval `json:"approvals,omitempty"`
	// WantsPasswordKey asks the iPhone to register a password key with its next signed command.
	WantsPasswordKey bool `json:"wantsPasswordKey,omitempty"`
	// SealedPassword lets the iPhone open the password sealed to it, when unlocking.
	SealedPassword *SealedPasswordChallenge `json:"sealedPassword,omitempty"`
	// ApprovalWait is how long approvals wait for the iPhone, in seconds (wait.go).
	ApprovalWait int `json:"approvalWait,omitempty"`
}

// Approval is a password prompt (sudo, a polkit dialog) waiting for the iPhone. The root-owned checker
// (checker.go) creates it and checks the signature itself.
type Approval struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Detail    string `json:"detail"`
	Nonce     string `json:"nonce"`
	ExpiresIn int    `json:"expiresIn"`
}

type CommandRequest struct {
	DeviceID   string `json:"deviceId"`
	Action     Action `json:"action"`
	Nonce      string `json:"nonce"`
	Signature  string `json:"signature"`
	ApprovalID string `json:"approvalId,omitempty"`
	// PasswordKey registers the iPhone's password key (base64 X9.63) when hello asked for one.
	PasswordKey string `json:"passwordKey,omitempty"`
	// WrappedKey opens the sealed password when hello sent a challenge.
	WrappedKey *WrappedKey `json:"wrappedKey,omitempty"`
	// Wait is the approval wait that actionSetWait sets, in seconds.
	Wait int `json:"wait,omitempty"`
}

// carriesPasswordKeys says whether the command is signed with signedMessageV2.
func (r CommandRequest) carriesPasswordKeys() bool {
	return r.PasswordKey != "" || r.WrappedKey != nil
}

type CommandResponse struct {
	OK      bool   `json:"ok"`
	Locked  bool   `json:"locked"`
	Message string `json:"message"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

// RelayRequest is a phone request as the relay hands it over the WebSocket; Body is the JSON text.
type RelayRequest struct {
	ID   string `json:"id"`
	Path string `json:"path"`
	Body string `json:"body"`
}

type RelayResponse struct {
	ID     string `json:"id"`
	Status int    `json:"status"`
	Body   string `json:"body"`
}

// RelayNotification is what the agent sends the relay over its WebSocket when it's waiting for an approval. The
// relay turns it into "<machineName> is waiting for you" and pushes that to the iPhones through Apple's push service.
type RelayNotification struct {
	Notify Notify `json:"notify"`
}

type Notify struct {
	MachineName string   `json:"machineName"`
	PushTokens  []string `json:"pushTokens"`
	// ExpiresIn: seconds until the request stops waiting, so Apple can still deliver to an iPhone that was offline.
	ExpiresIn int `json:"expiresIn,omitempty"`
}

// RelayCard is what the agent sends the relay over its WebSocket for the iPhones' lock screen cards, whenever it
// changes: whether the screen is locked and what's waiting for approval. The relay keeps the latest one for each
// card, combines the computers on it and pushes the card to the iPhone through Apple's push service (a Live
// Activity). Fields are in alphabetical order, as the Swift tests pin them.
type RelayCard struct {
	Card Card `json:"card"`
}

type Card struct {
	Approvals []CardWaiting `json:"approvals"`
	// Cards are the cards of the paired iPhones that have one (validCardID).
	Cards []string `json:"cards"`
	// Locked is nil if the agent couldn't tell.
	Locked *bool `json:"locked,omitempty"`
}

// CardWaiting is an Approval without its challenge, which the iPhone gets from the agent itself when it answers.
type CardWaiting struct {
	Detail    string `json:"detail"`
	ExpiresIn int    `json:"expiresIn"`
	ID        string `json:"id"`
	Title     string `json:"title"`
}

// sameAs reports whether two cards are the same apart from the seconds left on each request.
func (c Card) sameAs(other Card) bool {
	if len(c.Approvals) != len(other.Approvals) || len(c.Cards) != len(other.Cards) ||
		(c.Locked == nil) != (other.Locked == nil) || c.Locked != nil && *c.Locked != *other.Locked {
		return false
	}
	for i, waiting := range c.Approvals {
		waiting.ExpiresIn = other.Approvals[i].ExpiresIn
		if waiting != other.Approvals[i] {
			return false
		}
	}
	for i, card := range c.Cards {
		if card != other.Cards[i] {
			return false
		}
	}
	return true
}

// signedMessage is what the iPhone signs for a command.
func signedMessage(machineID, deviceID string, action Action, nonce string) []byte {
	return []byte(fmt.Sprintf("faceunlock/v1\n%s\n%s\n%s\n%s", machineID, deviceID, action, nonce))
}

// signedMessageV2 is what the iPhone signs instead when the command carries a password key or a wrapped key. It
// covers the challenge's session key, so a session key swapped in on the way makes the signature fail. None of the
// fields can contain a line break (base64), so they can't shift.
func signedMessageV2(machineID, deviceID string, action Action, nonce, sessionKey, passwordKey string, wrapped *WrappedKey) []byte {
	wrappedKey, wrappedBox := "", ""
	if wrapped != nil {
		wrappedKey, wrappedBox = wrapped.Key, wrapped.Box
	}
	return []byte(strings.Join([]string{"faceunlock/v2", machineID, deviceID, string(action), nonce, sessionKey, passwordKey,
		wrappedKey, wrappedBox}, "\n"))
}

// waitMessage is what the iPhone signs to set the approval wait, so nothing in between can change the value.
func waitMessage(machineID, deviceID, nonce string, wait int) []byte {
	return []byte(fmt.Sprintf("faceunlock-wait/v1\n%s\n%s\n%s\n%d", machineID, deviceID, nonce, wait))
}

// approvalMessage is what the iPhone signs to approve. It includes what the iPhone showed, so a swapped title
// or detail makes the signature fail; the checker never puts line breaks in them, so fields can't shift.
func approvalMessage(machineID, deviceID string, approval Approval) []byte {
	return []byte(fmt.Sprintf("faceunlock-approve/v1\n%s\n%s\n%s\n%s\n%s\n%s",
		machineID, deviceID, approval.ID, approval.Nonce, approval.Title, approval.Detail))
}

// Notifications go through Apple's push service (APNs): the iPhone app gets a push token from Apple and gives it
// to the agent in hello, and the relay sends the notification for it. It only says which computer is waiting; the
// details travel over the relay when the app asks.

// validPushToken allows only hex, as APNs tokens are (32 bytes today; Apple says they may grow), so a token can't
// smuggle anything else in.
func validPushToken(token string) bool {
	if len(token) < 64 || len(token) > 200 {
		return false
	}
	for _, c := range token {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// validCardID allows a lock screen card's id on the relay: the SHA-256 (lowercase hex) of a secret only the iPhone
// knows, which it needs to tell the relay where to push the card. The agent only gets the id.
func validCardID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// pairingProof is an HMAC keyed with the QR code's token, so the token itself never crosses the network. With a
// password key it covers that too (v2), so nobody can swap in their own.
func pairingProof(token, machineID, deviceID, deviceName, publicKey, passwordKey string) []byte {
	mac := hmac.New(sha256.New, []byte(token))
	if passwordKey == "" {
		fmt.Fprintf(mac, "faceunlock-pair/v1\n%s\n%s\n%s\n%s", machineID, deviceID, deviceName, publicKey)
	} else {
		fmt.Fprintf(mac, "faceunlock-pair/v2\n%s\n%s\n%s\n%s\n%s", machineID, deviceID, deviceName, publicKey, passwordKey)
	}
	return mac.Sum(nil)
}

func validPairingProof(proof, token, machineID, deviceID, deviceName, publicKey, passwordKey string) bool {
	given, err := base64.StdEncoding.DecodeString(proof)
	return err == nil && hmac.Equal(given, pairingProof(token, machineID, deviceID, deviceName, publicKey, passwordKey))
}

// parsePublicKey reads an uncompressed X9.63 P-256 key, as CryptoKit's x963Representation writes it.
func parsePublicKey(data []byte) (*ecdsa.PublicKey, error) {
	x, y := elliptic.Unmarshal(elliptic.P256(), data)
	if x == nil {
		return nil, errors.New("invalid P-256 public key")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

// validSignature checks a raw r‖s ECDSA P-256 SHA-256 signature, as CryptoKit's rawRepresentation writes it.
func validSignature(key *ecdsa.PublicKey, message []byte, signature string) bool {
	raw, err := base64.StdEncoding.DecodeString(signature)
	if err != nil || len(raw) != 64 {
		return false
	}
	digest := sha256.Sum256(message)
	return ecdsa.Verify(key, digest[:], new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:]))
}

func randomToken(byteCount int) string {
	bytes := make([]byte, byteCount)
	if _, err := rand.Read(bytes); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes)
}

func randomUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%X-%X-%X-%X-%X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
