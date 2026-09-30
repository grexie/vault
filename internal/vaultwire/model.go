package vaultwire

import "time"

// Request is immutable and signed by the paired requesting device. A browser
// verifies that signature against its locally encrypted pinned device list.
type Request struct {
	ID           string    `json:"id"`
	DeviceID     string    `json:"deviceId"`
	AgentID      string    `json:"agentId"`
	Session      string    `json:"session"`
	Reason       string    `json:"reason"`
	Kind         string    `json:"kind"` // create, ssh, age, ethereum, bitcoin, lookup
	Identity     string    `json:"identity"`
	IdentityType string    `json:"identityType"`
	Network      string    `json:"network,omitempty"`
	Payload      []byte    `json:"payload,omitempty"`
	Duration     int64     `json:"duration"`
	CreatedAt    time.Time `json:"createdAt"`
	ExpiresAt    time.Time `json:"expiresAt"`
	Managed      bool      `json:"managed,omitempty"`
}

// Receiver is signed by the pinned agent, so a relay cannot substitute an
// ephemeral recipient key and receive decrypted key material itself.
type Receiver struct {
	RequestID   string    `json:"requestId"`
	RequestHash string    `json:"requestHash"`
	PublicKey   []byte    `json:"publicKey"`
	ExpiresAt   time.Time `json:"expiresAt"`
}
type Approval struct {
	RequestID       string    `json:"requestId"`
	RequestHash     string    `json:"requestHash"`
	ReceiverHash    string    `json:"receiverHash"`
	IdentityID      string    `json:"identityId"`
	IdentityType    string    `json:"identityType"`
	PublicKey       string    `json:"publicKey"`
	Secret          []byte    `json:"secret"`
	ExpiresAt       time.Time `json:"expiresAt"`
	RequesterPublic []byte    `json:"requesterPublic,omitempty"`
}

// Authorization is public approval metadata. The owner signs the exact routing
// keys and receiver so callers can authenticate a remote agent through a relay.
type Authorization struct {
	RequestID    string    `json:"requestId"`
	RequestHash  string    `json:"requestHash"`
	ReceiverHash string    `json:"receiverHash"`
	AgentPublic  []byte    `json:"agentPublic"`
	PublicKey    string    `json:"publicKey"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

type RPC struct {
	RequestID   string    `json:"requestId"`
	Nonce       string    `json:"nonce"`
	Method      string    `json:"method"`
	Data        []byte    `json:"data,omitempty"`
	ReplyPublic []byte    `json:"replyPublic"`
	ExpiresAt   time.Time `json:"expiresAt"`
}
type RPCResult struct {
	Nonce       string `json:"nonce"`
	RequestHash string `json:"requestHash"`
	Data        []byte `json:"data,omitempty"`
	Error       string `json:"error,omitempty"`
}
type Pairing struct {
	DeviceID       string `json:"deviceId"`
	OwnerID        string `json:"ownerId"`
	OwnerPublic    []byte `json:"ownerPublic"`
	OwnerBoxPublic []byte `json:"ownerBoxPublic"`
	MAC            []byte `json:"mac"`
}
type Response struct {
	RequestID   string    `json:"requestId"`
	RequestHash string    `json:"requestHash"`
	Result      []byte    `json:"result,omitempty"`
	Error       string    `json:"error,omitempty"`
	ExpiresAt   time.Time `json:"expiresAt"`
}
type DeviceDescriptor struct {
	Role      string `json:"role"`
	ID        string `json:"id"`
	Name      string `json:"name"`
	PublicKey []byte `json:"publicKey"`
	BoxPublic []byte `json:"boxPublic"`
}

type HTTPProof struct {
	DeviceID string    `json:"deviceId"`
	Method   string    `json:"method"`
	Path     string    `json:"path"`
	BodyHash string    `json:"bodyHash"`
	Nonce    string    `json:"nonce"`
	At       time.Time `json:"at"`
}
type Enrollment struct {
	Device      DeviceDescriptor `json:"device"`
	PairingHash string           `json:"pairingHash"`
}
type RequestState struct {
	ID               string    `json:"id"`
	OwnerID          string    `json:"ownerId"`
	DeviceID         string    `json:"deviceId"`
	AgentID          string    `json:"agentId"`
	Session          string    `json:"session"`
	Reason           string    `json:"reason"`
	Status           string    `json:"status"`
	Signed           Signed    `json:"signed"`
	Receiver         *Signed   `json:"receiver,omitempty"`
	Box              *Envelope `json:"box,omitempty"`
	Response         *Signed   `json:"response,omitempty"`
	Authorization    *Signed   `json:"authorization,omitempty"`
	ExpiresAt        time.Time `json:"expiresAt"`
	ApprovalDeadline time.Time `json:"approvalDeadline"`
}
type Invocation struct {
	Provider    string   `json:"provider"`
	ProfileHash string   `json:"profileHash"`
	Command     string   `json:"command"`
	Arguments   []string `json:"arguments"`
	Mode        string   `json:"mode"` // command releases credentials; api retains them
}
