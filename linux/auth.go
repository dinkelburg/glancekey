package main

import (
	"encoding/base64"
	"sync"
	"time"
	"unicode/utf8"
)

type PairedDevice struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	PublicKey  []byte     `json:"publicKey"`
	PairedAt   time.Time  `json:"pairedAt"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
	// PushToken is where to notify the iPhone when an approval is waiting (see validPushToken).
	PushToken string `json:"pushToken,omitempty"`
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
	if !validPairingProof(req.Proof, a.pairingToken, a.machineID, req.DeviceID, req.DeviceName, req.PublicKey) {
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
	a.pairingToken = ""
	return PairedDevice{ID: req.DeviceID, Name: req.DeviceName, PublicKey: keyData, PairedAt: a.now()}, nil
}

func (a *Authenticator) IssueNonce(deviceID string) string {
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
	a.nonces[nonce] = challenge{deviceID: deviceID, expires: now.Add(nonceLifetime)}
	return nonce
}

// Verify checks a signed command and returns the device that sent it. Each nonce works once.
func (a *Authenticator) Verify(req CommandRequest, devices []PairedDevice) (PairedDevice, error) {
	var device *PairedDevice
	for i := range devices {
		if devices[i].ID == req.DeviceID {
			device = &devices[i]
		}
	}
	if device == nil {
		return PairedDevice{}, errUnknownDevice
	}

	a.mu.Lock()
	c, found := a.nonces[req.Nonce]
	delete(a.nonces, req.Nonce)
	now := a.now()
	a.mu.Unlock()

	if !found || c.deviceID != device.ID {
		return PairedDevice{}, errUnknownNonce
	}
	if !now.Before(c.expires) {
		return PairedDevice{}, errExpiredNonce
	}
	if !device.validSignature(signedMessage(a.machineID, device.ID, req.Action, req.Nonce), req.Signature) {
		return PairedDevice{}, errBadSignature
	}
	return *device, nil
}
