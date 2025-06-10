package server

import (
	"encoding/json"
	"log"
	"sync"
	"time"

	"database/sql"

	"gowhisper/internal/common"
	"gowhisper/internal/db"

	"github.com/gorilla/websocket"
)

type Client struct {
	username string
	conn     *websocket.Conn
	hub      *Hub
	send     chan []byte
	isAuthed bool
}

type Hub struct {
	clients     map[*Client]bool
	register    chan *Client
	unregister  chan *Client
	incomingMsg chan clientMessage // For processing messages from clients

	userClients map[string]*Client // username -> client mapping for online users
	mu          sync.RWMutex       // Protects userClients and clients map
}

type clientMessage struct {
	client *Client
	data   []byte
}

func NewHub() *Hub {
	return &Hub{
		incomingMsg: make(chan clientMessage),
		register:    make(chan *Client),
		unregister:  make(chan *Client),
		clients:     make(map[*Client]bool),
		userClients: make(map[string]*Client),
	}
}

func (h *Hub) getOnlineUsernames() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	usernames := make([]string, 0, len(h.userClients))
	for username := range h.userClients {
		usernames = append(usernames, username)
	}
	return usernames
}

func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()
			log.Printf("Client connected, awaiting authentication.")

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				if client.username != "" && client.isAuthed {
					delete(h.userClients, client.username)
					log.Printf("User %s unregistered and disconnected.", client.username)
					// TODO: Broadcast user offline status
				} else {
					log.Printf("Unauthenticated client disconnected.")
				}
				close(client.send)
			}
			h.mu.Unlock()

		case cm := <-h.incomingMsg:
			h.handleClientMessage(cm.client, cm.data)
		}
	}
}

func (h *Hub) handleClientMessage(client *Client, data []byte) {
	var genericMsg common.GenericMessage
	if err := json.Unmarshal(data, &genericMsg); err != nil {
		log.Printf("Error unmarshalling generic message: %v", err)
		client.sendError("Invalid message format")
		return
	}

	// Authenticated routes
	if client.isAuthed {
		switch genericMsg.Type {
		case common.MsgTypeEncryptedDM:
			var edm common.EncryptedDirectMessage
			if err := json.Unmarshal(data, &edm); err != nil {
				client.sendError("Invalid encrypted DM format")
				return
			}
			edm.Sender = client.username // Ensure sender is correct
			h.routeEncryptedDM(&edm)
		case common.MsgTypeRequestPubKey:
			var reqPKey common.RequestPubKeyMessage
			if err := json.Unmarshal(data, &reqPKey); err != nil {
				client.sendError("Invalid public key request format")
				return
			}
			h.handleRequestPubKey(client, reqPKey.TargetUser)
		case common.MsgTypeRequestUserList:
			onlineUsers := h.getOnlineUsernames()
			resp := common.UserListResponseMessage{
				BaseMessage: common.BaseMessage{Type: common.MsgTypeUserListResponse, Timestamp: time.Now()},
				Usernames:   onlineUsers,
			}
			respBytes, _ := json.Marshal(resp)
			client.send <- respBytes

		default:
			log.Printf("Received unhandled message type %s from authenticated user %s", genericMsg.Type, client.username)
			client.sendError("Unknown command after authentication.")
		}
		return
	}

	// Unauthenticated routes (login/register)
	switch genericMsg.Type {
	case common.MsgTypeRegisterUser:
		var regMsg common.ClientAuthMessage
		if err := json.Unmarshal(data, &regMsg); err != nil {
			client.sendError("Invalid registration message format")
			return
		}
		h.handleUserRegistration(client, &regMsg)
	case common.MsgTypeLoginUser:
		var loginMsg common.ClientAuthMessage
		if err := json.Unmarshal(data, &loginMsg); err != nil {
			client.sendError("Invalid login message format")
			return
		}
		h.handleUserLogin(client, &loginMsg)
	default:
		log.Printf("Received message type %s from unauthenticated client.", genericMsg.Type)
		client.sendError("Authentication required.")
		// Consider closing connection after a few bad attempts
	}
}

func (h *Hub) handleUserRegistration(client *Client, msg *common.ClientAuthMessage) {
	if msg.Username == "" || msg.Password == "" || len(msg.ECDHPublicKey) == 0 {
		client.sendAuthResponse(common.MsgTypeRegistrationFailed, msg.Username, nil, "Username, password, and public key are required.")
		return
	}
	// Check if user already exists
	// db.GetUserPublicKey now returns (nil, sql.ErrNoRows) if not found,
	// (key, nil) if found, or (nil, otherError) for other DB issues.
	_, err := db.GetUserPublicKey(msg.Username)

	if err == nil { // User found (GetUserPublicKey returned (key, nil))
		client.sendAuthResponse(common.MsgTypeRegistrationFailed, msg.Username, nil, "Username already exists.")
		return
	} else if err == sql.ErrNoRows { // User not found, proceed with registration
		// This is the expected case for a new user. Registration can proceed.
	} else { // Another DB error occurred (err != nil AND err != sql.ErrNoRows)
		log.Printf("DB error checking user %s: %v", msg.Username, err)
		client.sendAuthResponse(common.MsgTypeRegistrationFailed, msg.Username, nil, "Server error during registration.")
		return
	}

	// If we reach here, err was sql.ErrNoRows, so register the user
	regErr := db.RegisterUser(msg.Username, msg.Password, msg.ECDHPublicKey)
	if regErr != nil {
		log.Printf("Error registering user %s: %v", msg.Username, regErr)
		client.sendAuthResponse(common.MsgTypeRegistrationFailed, msg.Username, nil, "Failed to register user.")
		return
	}
	client.sendAuthResponse(common.MsgTypeRegistrationSuccess, msg.Username, msg.ECDHPublicKey, "Registration successful. Please login.")
	log.Printf("User %s registered.", msg.Username)
}

func (h *Hub) handleUserLogin(client *Client, msg *common.ClientAuthMessage) {
	user, err := db.AuthenticateUser(msg.Username, msg.Password)
	if err != nil {
		log.Printf("Error authenticating user %s: %v", msg.Username, err)
		client.sendAuthResponse(common.MsgTypeLoginFailed, msg.Username, nil, "Server error during login.")
		return
	}
	if user == nil {
		client.sendAuthResponse(common.MsgTypeLoginFailed, msg.Username, nil, "Invalid username or password.")
		return
	}

	h.mu.Lock()
	if _, exists := h.userClients[user.Username]; exists {
		h.mu.Unlock()
		client.sendAuthResponse(common.MsgTypeLoginFailed, user.Username, nil, "User already logged in elsewhere.")
		// Optionally disconnect the old client
		return
	}
	client.username = user.Username
	client.isAuthed = true
	h.userClients[user.Username] = client
	h.mu.Unlock()

	onlineUsers := h.getOnlineUsernames()
	client.sendAuthResponse(common.MsgTypeLoginSuccess, user.Username, user.ECDHPublicKey, "Login successful.", onlineUsers...)
	log.Printf("User %s logged in.", user.Username)
	// TODO: Broadcast user online status to other clients
}

func (h *Hub) handleRequestPubKey(client *Client, targetUsername string) {
	pubKeyBytes, err := db.GetUserPublicKey(targetUsername)
	if err != nil || pubKeyBytes == nil {
		log.Printf("Public key not found for %s (requested by %s): %v", targetUsername, client.username, err)
		resp := common.PublicKeyResponseMessage{
			BaseMessage: common.BaseMessage{Type: common.MsgTypePublicKeyResponse, Timestamp: time.Now()},
			TargetUser:  targetUsername,
			Found:       false,
		}
		respBytes, _ := json.Marshal(resp)
		client.send <- respBytes
		return
	}

	resp := common.PublicKeyResponseMessage{
		BaseMessage:   common.BaseMessage{Type: common.MsgTypePublicKeyResponse, Timestamp: time.Now()},
		TargetUser:    targetUsername,
		ECDHPublicKey: pubKeyBytes,
		Found:         true,
	}
	respBytes, _ := json.Marshal(resp)
	client.send <- respBytes
}

func (h *Hub) routeEncryptedDM(edm *common.EncryptedDirectMessage) {
	h.mu.RLock()
	recipientClient, ok := h.userClients[edm.Recipient]
	h.mu.RUnlock()

	if ok {
		msgBytes, err := json.Marshal(edm)
		if err != nil {
			log.Printf("Error marshalling encrypted DM: %v", err)
			// Potentially send error back to sender
			return
		}
		select {
		case recipientClient.send <- msgBytes:
		default:
			log.Printf("Recipient %s's send channel full.", recipientClient.username)
			// TODO: Handle offline messaging or error to sender
		}
	} else {
		log.Printf("Recipient %s for DM not found or offline.", edm.Recipient)
		// TODO: Send 'user offline' message to sender
		senderClient, sOk := h.userClients[edm.Sender]
		if sOk {
			senderClient.sendError("User " + edm.Recipient + " is not online.")
		}
	}
}

// Helper for client to send auth responses
func (c *Client) sendAuthResponse(msgType, username string, pubKey []byte, message string, onlineUsers ...string) {
	resp := common.AuthResponseMessage{
		BaseMessage:   common.BaseMessage{Type: msgType, Timestamp: time.Now()},
		Username:      username,
		ECDHPublicKey: pubKey,
		Message:       message,
		OnlineUsers:   onlineUsers,
	}
	respBytes, _ := json.Marshal(resp)
	c.send <- respBytes
}

// Helper for client to send generic errors
func (c *Client) sendError(errMsg string) {
	errResp := common.ErrorMessage{
		BaseMessage: common.BaseMessage{Type: common.MsgTypeError, Timestamp: time.Now()},
		Content:     errMsg,
	}
	errBytes, _ := json.Marshal(errResp)
	select {
	case c.send <- errBytes:
	default:
		log.Printf("Client %s send channel full when trying to send error.", c.username)
	}
}

// readPump and writePump for individual clients (similar to before but simpler)
func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()
	for {
		_, messageBytes, err := c.conn.ReadMessage()
		if err != nil {
			// Handle close errors
			break
		}
		c.hub.incomingMsg <- clientMessage{client: c, data: messageBytes}
	}
}

func (c *Client) writePump() {
	defer func() {
		c.conn.Close()
	}()
	for {
		select {
		case message, ok := <-c.send:
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				return
			}
		}
	}
}
