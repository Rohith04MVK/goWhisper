package server

import (
	"encoding/json"
	"log"
	"sync"
	"time"

	"gowhisper/internal/common"

	"github.com/gorilla/websocket"
)

// Client represents a connected user.
type Client struct {
	username string
	conn     *websocket.Conn
	hub      *Hub
	send     chan []byte // Buffered channel of outbound messages
}

// Hub maintains the set of active clients and broadcasts messages.
type Hub struct {
	clients    map[*Client]bool     // Connected clients
	register   chan *Client         // Register requests from clients
	unregister chan *Client         // Unregister requests from clients
	broadcast  chan []byte          // Inbound messages from the clients (to be broadcast or routed)
	directMsg  chan *common.Message // Inbound direct messages

	// For mapping usernames to clients for DMs
	userClients map[string]*Client
	mu          sync.Mutex // Protects userClients
}

func NewHub() *Hub {
	return &Hub{
		broadcast:   make(chan []byte),
		directMsg:   make(chan *common.Message),
		register:    make(chan *Client),
		unregister:  make(chan *Client),
		clients:     make(map[*Client]bool),
		userClients: make(map[string]*Client),
	}
}

func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			if client.username != "" {
				h.userClients[client.username] = client
				log.Printf("User %s registered", client.username)
			}
			h.mu.Unlock()

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				if client.username != "" {
					delete(h.userClients, client.username)
					log.Printf("User %s unregistered", client.username)
				}
				close(client.send)
			}
			h.mu.Unlock()

		case msg := <-h.directMsg:
			h.mu.Lock()
			recipientClient, ok := h.userClients[msg.Recipient]
			h.mu.Unlock()

			if ok {
				msgBytes, err := json.Marshal(msg)
				if err != nil {
					log.Printf("Error marshalling direct message: %v", err)
					continue
				}
				select {
				case recipientClient.send <- msgBytes:
				default: // If recipient's send channel is full
					log.Printf("Recipient %s's send channel full, closing connection.", recipientClient.username)
					close(recipientClient.send)
					delete(h.clients, recipientClient)
					h.mu.Lock()
					delete(h.userClients, recipientClient.username)
					h.mu.Unlock()
				}
			} else {
				log.Printf("Recipient %s not found for DM", msg.Recipient)
				// TODO: Send an error back to the sender
			}
		// Example broadcast (not used much with DMs, but good to have)
		case message := <-h.broadcast:
			h.mu.Lock()
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					close(client.send)
					delete(h.clients, client)
					if client.username != "" {
						delete(h.userClients, client.username)
					}
				}
			}
			h.mu.Unlock()
		}
	}
}

// readPump pumps messages from the WebSocket connection to the hub.
func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()
	// Configure connection limits, timeouts etc.
	for {
		_, messageBytes, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("Client %s error: %v", c.username, err)
			}
			break
		}

		var msg common.Message
		if err := json.Unmarshal(messageBytes, &msg); err != nil {
			log.Printf("Error unmarshalling message from %s: %v", c.username, err)
			// Send error back to client?
			continue
		}
		msg.Timestamp = time.Now()

		// First message should be registration
		if c.username == "" && msg.Type == common.MsgTypeRegister && msg.Sender != "" {
			c.username = msg.Sender // Assign username to this client connection
			c.hub.mu.Lock()
			// Check if username is already taken (basic check)
			if _, exists := c.hub.userClients[c.username]; exists {
				log.Printf("Username %s already taken.", c.username)
				// TODO: Send error to client and close connection
				c.username = "" // Reset username
				c.hub.mu.Unlock()
				c.conn.WriteJSON(common.Message{Type: common.MsgTypeError, Content: "Username already taken."})
				return // Close connection
			}
			c.hub.userClients[c.username] = c
			c.hub.mu.Unlock()
			log.Printf("Client identified as: %s", c.username)
			// Send confirmation to client
			c.send <- []byte(`{"type":"` + common.MsgTypeServerInfo + `","content":"Registered successfully."}`)
			continue
		} else if c.username == "" {
			log.Printf("Client tried to send message before registering.")
			c.conn.WriteJSON(common.Message{Type: common.MsgTypeError, Content: "Please register first."})
			return // Close connection
		}

		// Subsequent messages
		msg.Sender = c.username // Ensure sender is correctly set

		if msg.Type == common.MsgTypeDirectMessage && msg.Recipient != "" {
			c.hub.directMsg <- &msg
		} else {
			// For now, other types could be broadcast or handled differently
			// c.hub.broadcast <- messageBytes
			log.Printf("Received unhandled message type %s from %s", msg.Type, c.username)
		}
	}
}

// writePump pumps messages from the hub to the WebSocket connection.
func (c *Client) writePump() {
	defer func() {
		c.conn.Close()
	}()
	for {
		select {
		case message, ok := <-c.send:
			if !ok {
				// The hub closed the channel.
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				return
			}
		}
	}
}
