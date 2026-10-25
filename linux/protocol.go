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
)

// PairingInvite is what the pairing QR code holds.
type PairingInvite struct {
	V           int    `json:"v"`
	MachineID   string `json:"machineId"`
	MachineName string `json:"machineName"`
	Platform    string `json:"platform"`
	Relay       string `json:"relay"`
	Token       string `json:"token"`
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
}

type PairResponse struct {
	MachineID   string `json:"machineId"`
	MachineName string `json:"machineName"`
}

type HelloRequest struct {
	DeviceID string `json:"deviceId"`
	// NotifyTopic is the iPhone's ntfy topic: nil leaves the saved one, "" removes it.
	NotifyTopic *string `json:"notifyTopic,omitempty"`
}

type HelloResponse struct {
	MachineID   string     `json:"machineId"`
	MachineName string     `json:"machineName"`
	Nonce       string     `json:"nonce"`
	Locked      *bool      `json:"locked,omitempty"`
	Approvals   []Approval `json:"approvals,omitempty"`
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

// signedMessage is what the iPhone signs for a command.
func signedMessage(machineID, deviceID string, action Action, nonce string) []byte {
	return []byte(fmt.Sprintf("faceunlock/v1\n%s\n%s\n%s\n%s", machineID, deviceID, action, nonce))
}

// approvalMessage is what the iPhone signs to approve. It includes what the iPhone showed, so a swapped title
// or detail makes the signature fail; the checker never puts line breaks in them, so fields can't shift.
func approvalMessage(machineID, deviceID string, approval Approval) []byte {
	return []byte(fmt.Sprintf("faceunlock-approve/v1\n%s\n%s\n%s\n%s\n%s\n%s",
		machineID, deviceID, approval.ID, approval.Nonce, approval.Title, approval.Detail))
}

// Notifications go through ntfy (https://ntfy.sh): the iPhone app picks a random topic, and its free ntfy app
// shows what's posted there. Only the computer's name goes to ntfy; the details travel over the relay.
const (
	ntfyServer    = "https://ntfy.sh"
	notifyOpenURL = urlScheme + "://approve"
)

// validTopic allows only letters, digits, - and _, so a topic can't point the computer anywhere but ntfy.
func validTopic(topic string) bool {
	if len(topic) < 16 || len(topic) > 64 {
		return false
	}
	for _, c := range topic {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// pairingProof is an HMAC keyed with the QR code's token, so the token itself never crosses the network.
func pairingProof(token, machineID, deviceID, deviceName, publicKey string) []byte {
	mac := hmac.New(sha256.New, []byte(token))
	fmt.Fprintf(mac, "faceunlock-pair/v1\n%s\n%s\n%s\n%s", machineID, deviceID, deviceName, publicKey)
	return mac.Sum(nil)
}

func validPairingProof(proof, token, machineID, deviceID, deviceName, publicKey string) bool {
	given, err := base64.StdEncoding.DecodeString(proof)
	return err == nil && hmac.Equal(given, pairingProof(token, machineID, deviceID, deviceName, publicKey))
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
