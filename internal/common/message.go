package common

import "time"

const (
	// Client to Server
	MsgTypeRegisterUser    = "register_user"    // Client sends username, password, pubkey for new account
	MsgTypeLoginUser       = "login_user"       // Client sends username, password to login
	MsgTypeRequestPubKey   = "request_pub_key"  // Client A requests pubkey of Client B
	MsgTypeEncryptedDM     = "encrypted_dm"     // Client sends an E2E encrypted DM
	MsgTypeClientInitiate  = "client_initiate"  // Client signals it's ready after login
	MsgTypeRequestUserList = "request_user_list" // Client requests list of online users

	// Server to Client
	MsgTypeRegistrationSuccess = "registration_success"
	MsgTypeRegistrationFailed  = "registration_failed"
	MsgTypeLoginSuccess        = "login_success" // Includes user's own pubkey, maybe active users
	MsgTypeLoginFailed         = "login_failed"
	MsgTypePublicKeyResponse   = "public_key_response" // Server sends requested pubkey
	MsgTypeUserListResponse    = "user_list_response" // Server sends list of online users
	MsgTypeServerInfo          = "server_info"
	MsgTypeError               = "error"
	MsgTypeUserStatusUpdate  = "user_status_update" // For online/offline notifications (future)
)

// BaseMessage is embedded in more specific messages
type BaseMessage struct {
	Type      string    `json:"type"`
	Timestamp time.Time `json:"timestamp"`
}

// For client -> server
type ClientAuthMessage struct {
	BaseMessage
	Username      string `json:"username"`
	Password      string `json:"password,omitempty"` // Only for register/login
	ECDHPublicKey []byte `json:"ecdh_public_key,omitempty"` // For registration
}

type RequestPubKeyMessage struct {
	BaseMessage
	TargetUser string `json:"target_user"` // User whose pubkey is requested
}

type EncryptedDirectMessage struct {
	BaseMessage
	Sender    string `json:"sender"`
	Recipient string `json:"recipient"`
	Ciphertext []byte `json:"ciphertext"`
	Nonce     []byte `json:"nonce"`
}

// For server -> client
type AuthResponseMessage struct {
	BaseMessage
	Username      string   `json:"username,omitempty"`
	ECDHPublicKey []byte   `json:"ecdh_public_key,omitempty"` // User's own pubkey on login success
	Message       string   `json:"message,omitempty"`
	OnlineUsers   []string `json:"online_users,omitempty"` // Send on login
}

type PublicKeyResponseMessage struct {
	BaseMessage
	TargetUser    string `json:"target_user"`
	ECDHPublicKey []byte `json:"ecdh_public_key,omitempty"`
	Found         bool   `json:"found"`
}

type UserListResponseMessage struct {
	BaseMessage
	Usernames []string `json:"usernames"`
}

type ServerInfoMessage struct {
	BaseMessage
	Content string `json:"content"`
}

type ErrorMessage struct {
	BaseMessage
	Content string `json:"content"`
}

// Generic message for parsing type first
type GenericMessage struct {
	Type string `json:"type"`
}