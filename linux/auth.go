package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// keyFingerprint is a short, readable form of an iPhone's public key: the first 6 bytes of its SHA-256, like
// "9F86-D081-884C". The iPhone app shows the same for its key, so a key paired behind your back stands out even when
// every iPhone is called "iPhone". Core's PairedDevice.keyFingerprint does the same.
func keyFingerprint(publicKey []byte) string {
	sum := sha256.Sum256(publicKey)
	digits := strings.ToUpper(hex.EncodeToString(sum[:6]))
	return digits[0:4] + "-" + digits[4:8] + "-" + digits[8:12]
}

type PairedDevice struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	PublicKey  []byte     `json:"publicKey"`
	PairedAt   time.Time  `json:"pairedAt"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
	// PushToken is where to notify the iPhone when an approval is waiting (see validPushToken).
	PushToken string `json:"pushToken,omitempty"`
	// CardID is the iPhone's lock screen card on the relay (see RelayCard).
	CardID string `json:"cardId,omitempty"`
	// PasswordKey is the iPhone's password key (X9.63), which the password is sealed to (seal.go). Empty for an
	// iPhone on an older app version.
	PasswordKey []byte `json:"passwordKey,omitempty"`
	// OpenedSealed: this iPhone has opened its sealed copy, so its password key works. Until every iPhone has,
	// the keyring keeps a plain copy.
	OpenedSealed bool `json:"openedSealed,omitempty"`
}

// validSignature checks the iPhone's signature over message with its paired key.
func (d PairedDevice) validSignature(message []byte, signature string) bool {
	key, err := parsePublicKey(d.PublicKey)
	return err == nil && validSignature(key, message, signature)
}

// authError messages match AuthError in the Swift core; the iPhone shows them as is.
type authError string

func (e authError) Error() string { return string(e) }

const (
	errNoPairing       authError = "Pairing isn't active. Start pairing on your computer first."
	errPairingExpired  authError = "That pairing code expired. Start pairing again on your computer."
	errBadPairingToken authError = "That pairing code isn't valid. Scan the code your computer is showing now."
	errBadDeviceInfo   authError = "The iPhone sent invalid device details."
	errBadPublicKey    authError = "The iPhone sent an invalid key."
	errUnknownDevice   authError = "This iPhone isn't paired with that computer anymore. Pair it again."
	errUnknownNonce    authError = "The request was out of date. Try again."
	errExpiredNonce    authError = "The request took too long. Try again."
	errBadSignature    authError = "The computer rejected this iPhone's signature."
	errApprovalGone    authError = "That request isn't waiting anymore."
)

const maxOutstandingNonces = 64

type challenge struct {
	deviceID string
	expires  time.Time
	// session is the one-time key the iPhone wraps the sealed password's key to (seal.go), if hello sent one.
	session *ecdh.PrivateKey
}

// Authenticator holds the pairing window and single-use challenges. Safe for concurrent use.
type Authenticator struct {
	machineID string
	now       func() time.Time

	mu             sync.Mutex
	pairingToken   string
	pairingExpires time.Time
	nonces         map[string]challenge
}

func newAuthenticator(machineID string, now func() time.Time) *Authenticator {
	return &Authenticator{machineID: machineID, now: now, nonces: map[string]challenge{}}
}

func (a *Authenticator) StartPairing() (token string, expires time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pairingToken = randomToken(16)
	a.pairingExpires = a.now().Add(pairingLifetime)
	return a.pairingToken, a.pairingExpires
}

func (a *Authenticator) CancelPairing() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pairingToken = ""
}

func (a *Authenticator) PairingActive() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.pairingToken != "" && a.now().Before(a.pairingExpires)
}

func (a *Authenticator) CompletePairing(req PairRequest) (PairedDevice, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pairingToken == "" {
		return PairedDevice{}, errNoPairing
	}
	if !a.now().Before(a.pairingExpires) {
		a.pairingToken = ""
		return PairedDevice{}, errPairingExpired
	}
	if !validPairingProof(req.Proof, a.pairingToken, a.machineID, req.DeviceID, req.DeviceName, req.PublicKey, req.PasswordKey) {
		return PairedDevice{}, errBadPairingToken
	}
	if n := len(req.DeviceID); n < 1 || n > 100 {
		return PairedDevice{}, errBadDeviceInfo
	}
	if n := utf8.RuneCountInString(req.DeviceName); n < 1 || n > 100 {
		return PairedDevice{}, errBadDeviceInfo
	}
	keyData, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil {
		return PairedDevice{}, errBadPublicKey
	}
	if _, err := parsePublicKey(keyData); err != nil {
		return PairedDevice{}, errBadPublicKey
	}
	var passwordKey []byte
	if req.PasswordKey != "" {
		if passwordKey, err = parsePasswordKey(req.PasswordKey); err != nil {
			return PairedDevice{}, errBadPublicKey
		}
	}
	a.pairingToken = ""
	return PairedDevice{ID: req.DeviceID, Name: req.DeviceName, PublicKey: keyData, PairedAt: a.now(), PasswordKey: passwordKey}, nil
}

// parsePasswordKey checks a base64 X9.63 P-256 key-agreement key.
func parsePasswordKey(encoded string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	if _, err := ecdh.P256().NewPublicKey(data); err != nil {
		return nil, err
	}
	return data, nil
}

func (a *Authenticator) IssueNonce(deviceID string) string {
	return a.issueNonce(deviceID, nil)
}

// IssueNonceWithSession also makes the one-time session key for a sealed password and returns its public half (X9.63).
func (a *Authenticator) IssueNonceWithSession(deviceID string) (nonce string, sessionKey []byte, err error) {
	session, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, err
	}
	return a.issueNonce(deviceID, session), session.PublicKey().Bytes(), nil
}

func (a *Authenticator) issueNonce(deviceID string, session *ecdh.PrivateKey) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	oldest, oldestExpiry := "", time.Time{}
	for nonce, c := range a.nonces {
		if !now.Before(c.expires) {
			delete(a.nonces, nonce)
		} else if oldest == "" || c.expires.Before(oldestExpiry) {
			oldest, oldestExpiry = nonce, c.expires
		}
	}
	if len(a.nonces) >= maxOutstandingNonces {
		delete(a.nonces, oldest)
	}
	nonce := randomToken(32)
	a.nonces[nonce] = challenge{deviceID: deviceID, expires: now.Add(nonceLifetime), session: session}
	return nonce
}

// Verify checks a signed command and returns the device that sent it, with the challenge's session key if it had one.
// Each nonce works once.
func (a *Authenticator) Verify(req CommandRequest, devices []PairedDevice) (PairedDevice, *ecdh.PrivateKey, error) {
	var device *PairedDevice
	for i := range devices {
		if devices[i].ID == req.DeviceID {
			device = &devices[i]
		}
	}
	if device == nil {
		return PairedDevice{}, nil, errUnknownDevice
	}

	a.mu.Lock()
	c, found := a.nonces[req.Nonce]
	delete(a.nonces, req.Nonce)
	now := a.now()
	a.mu.Unlock()

	if !found || c.deviceID != device.ID {
		return PairedDevice{}, nil, errUnknownNonce
	}
	if !now.Before(c.expires) {
		return PairedDevice{}, nil, errExpiredNonce
	}
	message := signedMessage(a.machineID, device.ID, req.Action, req.Nonce)
	if req.Action == actionSetWait {
		message = waitMessage(a.machineID, device.ID, req.Nonce, req.Wait)
	} else if req.carriesPasswordKeys() {
		sessionKey := ""
		if c.session != nil {
			sessionKey = base64.StdEncoding.EncodeToString(c.session.PublicKey().Bytes())
		}
		message = signedMessageV2(a.machineID, device.ID, req.Action, req.Nonce, sessionKey, req.PasswordKey, req.WrappedKey)
	}
	if !device.validSignature(message, req.Signature) {
		return PairedDevice{}, nil, errBadSignature
	}
	return *device, c.session, nil
}
