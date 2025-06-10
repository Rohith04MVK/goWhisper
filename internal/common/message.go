package common

import "time"

const (
	MsgTypeRegister      = "register"       // Client sends username to register with server
	MsgTypeChat          = "chat"           // A direct message or group message
	MsgTypeServerInfo    = "server_info"    // Info from server (e.g., connection success)
	MsgTypeUserStatus    = "user_status"    // User online/offline (future)
	MsgTypeError         = "error"          // Error message from server
	MsgTypeDirectMessage = "direct_message" // Client indicates it's a DM
)

type Message struct {
	Type      string    `json:"type"`
	Sender    string    `json:"sender,omitempty"`    // Username of the sender
	Recipient string    `json:"recipient,omitempty"` // Username of the recipient (for DMs)
	Content   string    `json:"content"`
	Timestamp time.Time `json:"timestamp"`
}
