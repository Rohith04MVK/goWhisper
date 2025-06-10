package client

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"gowhisper/internal/common"
	"gowhisper/internal/crypto"

	"github.com/chzyer/readline"
	"github.com/gorilla/websocket"
)

const keyDir = ".gowhisper_keys" // Directory to store keys

type Client struct {
	addr         string
	conn         *websocket.Conn
	send         chan []byte
	done         chan struct{}
	currentState UserInputState

	// User specific
	username    string
	ecdhKeyPair *crypto.KeyPair // Store the actual keypair object

	// E2EE session state
	activeSessions      map[string][]byte // recipientUsername -> sharedSecret
	activeSessionsMutex sync.RWMutex
	pendingPubKeys      map[string]chan []byte // recipientUsername -> channel to receive their pubkey
	pendingPubKeysMutex sync.Mutex
	pendingDMs          map[string][]common.EncryptedDirectMessage // senderUsername -> list of DMs waiting for key
	pendingDMsMutex     sync.Mutex                                 // Mutex for pendingDMs
}

func New(addr string) *Client {
	return &Client{
		addr:           addr,
		send:           make(chan []byte),
		done:           make(chan struct{}),
		currentState:   StateUnauthenticated,
		activeSessions: make(map[string][]byte),
		pendingPubKeys: make(map[string]chan []byte),
		pendingDMs:     make(map[string][]common.EncryptedDirectMessage), // Initialize pendingDMs
	}
}

func (c *Client) loadOrGenerateKeys(username string) error {
	// Simplistic key storage in a file named after the user.
	// NOT SECURE FOR PRODUCTION. Should use OS keychain or encrypted storage.
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("could not get user home dir: %w", err)
	}
	userKeyDir := filepath.Join(home, keyDir)
	if err := os.MkdirAll(userKeyDir, 0700); err != nil {
		return fmt.Errorf("could not create key directory: %w", err)
	}

	privKeyPath := filepath.Join(userKeyDir, username+".priv")
	pubKeyPath := filepath.Join(userKeyDir, username+".pub")

	if _, err := os.Stat(privKeyPath); err == nil {
		// Keys exist, load them
		privBytes, err := os.ReadFile(privKeyPath)
		if err != nil {
			return fmt.Errorf("failed to read private key: %w", err)
		}
		pubBytes, err := os.ReadFile(pubKeyPath)
		if err != nil {
			return fmt.Errorf("failed to read public key: %w", err)
		}

		// Assuming crypto.curve is accessible or you pass it
		privKey, err := crypto.CurveForECDH().NewPrivateKey(privBytes) // crypto.curve should be ecdh.X25519()
		if err != nil {
			return fmt.Errorf("failed to parse private key: %w", err)
		}
		pubKey, err := crypto.CurveForECDH().NewPublicKey(pubBytes)
		if err != nil {
			return fmt.Errorf("failed to parse public key: %w", err)
		}
		c.ecdhKeyPair = &crypto.KeyPair{PrivateKey: privKey, PublicKey: pubKey}
		PrintSystem(fmt.Sprintf("🔑 Loaded existing keys for %s.", username))
		return nil
	}

	// Keys don't exist, generate them
	kp, err := crypto.GenerateECDHKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate ECDH keys: %w", err)
	}
	c.ecdhKeyPair = kp

	if err := os.WriteFile(privKeyPath, kp.PrivateKey.Bytes(), 0600); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}
	if err := os.WriteFile(pubKeyPath, kp.PublicKey.Bytes(), 0600); err != nil {
		return fmt.Errorf("failed to save public key: %w", err)
	}
	PrintSystem(fmt.Sprintf("🔑 Generated and saved new keys for %s.", username))
	return nil
}

func (c *Client) getSharedSecret(recipientUsername string) ([]byte, error) {
	c.activeSessionsMutex.RLock()
	secret, ok := c.activeSessions[recipientUsername]
	c.activeSessionsMutex.RUnlock()
	if ok {
		return secret, nil
	}

	// No existing session, need to request public key and derive secret
	PrintSystem(fmt.Sprintf("🔐 Requesting public key for %s...", recipientUsername))
	reqMsg := common.RequestPubKeyMessage{
		BaseMessage: common.BaseMessage{Type: common.MsgTypeRequestPubKey, Timestamp: time.Now()},
		TargetUser:  recipientUsername,
	}
	reqBytes, _ := json.Marshal(reqMsg)
	c.send <- reqBytes

	// Wait for the public key response
	c.pendingPubKeysMutex.Lock()
	respChan, exists := c.pendingPubKeys[recipientUsername]
	if !exists {
		respChan = make(chan []byte, 1) // Buffered channel
		c.pendingPubKeys[recipientUsername] = respChan
	}
	c.pendingPubKeysMutex.Unlock()

	select {
	case peerPubKeyBytes := <-respChan:
		if peerPubKeyBytes == nil { // Indicates key not found or error
			return nil, fmt.Errorf("public key for %s not received or not found", recipientUsername)
		}
		sharedSecret, err := crypto.ECDHSharedSecret(c.ecdhKeyPair.PrivateKey, peerPubKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to derive shared secret with %s: %w", recipientUsername, err)
		}
		c.activeSessionsMutex.Lock()
		c.activeSessions[recipientUsername] = sharedSecret
		c.activeSessionsMutex.Unlock()
		PrintSystem(fmt.Sprintf("🔐 Secure session established with %s.", recipientUsername))

		// Process any DMs that were pending for this user
		c.processPendingDMsForUser(recipientUsername, sharedSecret)

		return sharedSecret, nil
	case <-time.After(10 * time.Second): // Timeout
		c.pendingPubKeysMutex.Lock()
		delete(c.pendingPubKeys, recipientUsername) // Clean up
		c.pendingPubKeysMutex.Unlock()
		return nil, fmt.Errorf("timeout waiting for %s's public key", recipientUsername)
	}
}

func (c *Client) connect() error {
	u := url.URL{Scheme: "ws", Host: c.addr, Path: "/ws"}
	PrintConnectingMessage()

	var err error
	c.conn, _, err = websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		return fmt.Errorf("dial error: %w", err)
	}
	PrintSystem("🔗 Connected to server. Please /register or /login.")
	return nil
}

func (c *Client) Run() {
	if err := InitReadline(); err != nil {
		log.Fatalf("Failed to initialize readline: %v", err)
	}
	defer CloseReadline()

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

	if err := c.connect(); err != nil {
		PrintError(fmt.Sprintf("Failed to connect: %v", err))
		return
	}
	defer c.conn.Close()
	defer PrintSessionEnded()

	go c.readPump()
	go c.writePump()

	PrintHelp() // Show help on start

	for {
		// rl.SetPrompt(fmt.Sprintf("(%s) > ", c.username)) // Dynamic prompt (optional)
		userInput, err := GetUserInput()
		if err != nil {
			if err == readline.ErrInterrupt && userInput == "" { // Ctrl+C on empty line
				userInput = cmdExit
			} else if err != nil && err != io.EOF && err != readline.ErrInterrupt {
				PrintError(fmt.Sprintf("Input error: %v", err))
				continue
			}
		}

		msgToSend, msgType, shouldExit := ParseUserInput(userInput, c.currentState, c.username)

		if shouldExit {
			close(c.done)
			// Best effort close message
			_ = c.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			time.Sleep(200 * time.Millisecond)
			return
		}

		if msgToSend != nil {
			var finalMsgBytes []byte
			var marshalErr error

			switch msgType {
			case common.MsgTypeRegisterUser:
				authMsg := msgToSend.(common.ClientAuthMessage)
				// Generate keys before sending registration
				if err := c.loadOrGenerateKeys(authMsg.Username); err != nil {
					PrintError(fmt.Sprintf("Key generation/loading error: %v", err))
					continue
				}
				authMsg.ECDHPublicKey = c.ecdhKeyPair.PublicKey.Bytes()
				authMsg.Timestamp = time.Now()
				finalMsgBytes, marshalErr = json.Marshal(authMsg)

			case common.MsgTypeLoginUser:
				authMsg := msgToSend.(common.ClientAuthMessage)
				// Load keys for login attempt. If they don't exist, user needs to register.
				if err := c.loadOrGenerateKeys(authMsg.Username); err != nil {
					// This might happen if user tries to login with a new username without registering
					// Or if key files are corrupted/deleted.
					PrintError(fmt.Sprintf("Error accessing keys for %s: %v. Please /register if new.", authMsg.Username, err))
					continue
				}
				authMsg.Timestamp = time.Now()
				finalMsgBytes, marshalErr = json.Marshal(authMsg)

			case common.MsgTypeEncryptedDM:
				dmData := msgToSend.(map[string]string) // From ParseUserInput
				recipient := dmData["recipient"]
				content := dmData["content"]

				sharedSecret, err := c.getSharedSecret(recipient)
				if err != nil {
					PrintError(fmt.Sprintf("Could not establish secure session with %s: %v", recipient, err))
					continue
				}
				ciphertext, nonce, err := crypto.EncryptAES_GCM([]byte(content), sharedSecret)
				if err != nil {
					PrintError(fmt.Sprintf("Encryption error: %v", err))
					continue
				}
				edm := common.EncryptedDirectMessage{
					BaseMessage: common.BaseMessage{Type: common.MsgTypeEncryptedDM, Timestamp: time.Now()},
					Sender:      c.username,
					Recipient:   recipient,
					Ciphertext:  ciphertext,
					Nonce:       nonce,
				}
				finalMsgBytes, marshalErr = json.Marshal(edm)
				if marshalErr == nil {
					PrintOutgoingDM(recipient, content) // Show plaintext of what was sent
				}

			case common.MsgTypeRequestUserList:
				listReq := msgToSend.(common.BaseMessage)
				listReq.Timestamp = time.Now()
				finalMsgBytes, marshalErr = json.Marshal(listReq)

			default:
				PrintError("Unhandled message type to send.")
				continue
			}

			if marshalErr != nil {
				PrintError(fmt.Sprintf("Error preparing message: %v", marshalErr))
				continue
			}
			c.send <- finalMsgBytes
		}
	}
}

func (c *Client) readPump() {
	defer func() {
		close(c.done)
	}()
	for {
		_, messageBytes, err := c.conn.ReadMessage()
		if err != nil {
			// Handle various close errors
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure, websocket.CloseNormalClosure) {
				PrintError("Server connection lost: " + err.Error())
			} else if err.Error() == "websocket: close 1000 (normal)" {
				// Normal close
			} else {
				PrintError("Read error: " + err.Error())
			}
			return
		}

		var genericMsg common.GenericMessage
		if err := json.Unmarshal(messageBytes, &genericMsg); err != nil {
			PrintError("Error parsing generic message from server: " + err.Error())
			continue
		}

		switch genericMsg.Type {
		case common.MsgTypeRegistrationSuccess:
			var resp common.AuthResponseMessage
			json.Unmarshal(messageBytes, &resp)
			PrintSystem(resp.Message)
		case common.MsgTypeRegistrationFailed:
			var resp common.AuthResponseMessage
			json.Unmarshal(messageBytes, &resp)
			PrintError(resp.Message)
		case common.MsgTypeLoginSuccess:
			var resp common.AuthResponseMessage
			json.Unmarshal(messageBytes, &resp)
			c.username = resp.Username
			c.currentState = StateAuthenticated
			// Store own public key if needed, though it's already in c.ecdhKeyPair
			PrintSystem(resp.Message)
			if len(resp.OnlineUsers) > 0 {
				PrintSystem(fmt.Sprintf("Currently online: %s", strings.Join(resp.OnlineUsers, ", ")))
			}
			PrintSystem(fmt.Sprintf("🔑 Logged in as %s. You are now E2E encrypted!", c.username))
		case common.MsgTypeLoginFailed:
			var resp common.AuthResponseMessage
			json.Unmarshal(messageBytes, &resp)
			PrintError(resp.Message)
			c.currentState = StateUnauthenticated // Revert state if login fails
			c.username = ""
		case common.MsgTypeEncryptedDM:
			var edm common.EncryptedDirectMessage
			if err := json.Unmarshal(messageBytes, &edm); err != nil {
				PrintError("Error parsing encrypted DM: " + err.Error())
				continue
			}

			sender := edm.Sender
			c.activeSessionsMutex.RLock()
			sharedSecret, secretExists := c.activeSessions[sender]
			c.activeSessionsMutex.RUnlock()

			if secretExists {
				plaintext, err := crypto.DecryptAES_GCM(edm.Ciphertext, edm.Nonce, sharedSecret)
				if err != nil {
					PrintError(fmt.Sprintf("Decryption error from %s: %v", edm.Sender, err))
					continue
				}
				PrintIncomingDM(edm.Sender, string(plaintext))
			} else {
				// Secret not available, queue the DM and request key if not already pending
				c.queueDMAndRequestKeyIfNeeded(edm)
			}
		case common.MsgTypePublicKeyResponse:
			var resp common.PublicKeyResponseMessage
			if err := json.Unmarshal(messageBytes, &resp); err != nil {
				PrintError("Error parsing public key response: " + err.Error())
				continue
			}
			c.pendingPubKeysMutex.Lock()
			respChan, exists := c.pendingPubKeys[resp.TargetUser]
			if exists {
				if resp.Found {
					respChan <- resp.ECDHPublicKey
				} else {
					respChan <- nil // Signal not found
					PrintError(fmt.Sprintf("Server could not find public key for %s.", resp.TargetUser))
				}
				delete(c.pendingPubKeys, resp.TargetUser) // Clean up
			}
			c.pendingPubKeysMutex.Unlock()
		case common.MsgTypeUserListResponse:
			var resp common.UserListResponseMessage
			json.Unmarshal(messageBytes, &resp)
			if len(resp.Usernames) == 0 {
				PrintSystem("No other users currently online.")
			} else {
				PrintSystem(fmt.Sprintf("Online users: %s", strings.Join(resp.Usernames, ", ")))
			}
		case common.MsgTypeServerInfo:
			var info common.ServerInfoMessage
			json.Unmarshal(messageBytes, &info)
			PrintServerInfo(info.Content)
		case common.MsgTypeError:
			var errMsg common.ErrorMessage
			json.Unmarshal(messageBytes, &errMsg)
			PrintError(errMsg.Content)
		default:
			PrintServerInfo("Received unknown message type from server: " + genericMsg.Type)
		}
	}
}

func (c *Client) writePump() {
	ticker := time.NewTicker(45 * time.Second) // Keepalive ping
	defer func() {
		ticker.Stop()
		// c.conn.Close() // readPump or main loop will handle
	}()
	for {
		select {
		case message, ok := <-c.send:
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				PrintError("Write error: " + err.Error())
				return
			}
		case <-ticker.C: // Send ping
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				PrintError("Ping error: " + err.Error())
				return
			}
		case <-c.done:
			return
		}
	}
}

func (c *Client) queueDMAndRequestKeyIfNeeded(edm common.EncryptedDirectMessage) {
	senderUsername := edm.Sender // We need sender's key to decrypt

	c.pendingDMsMutex.Lock()
	c.pendingDMs[senderUsername] = append(c.pendingDMs[senderUsername], edm)
	c.pendingDMsMutex.Unlock()

	// Check if a request for this key is already out or if we need to make one.
	c.pendingPubKeysMutex.Lock()
	_, requestAlreadyPending := c.pendingPubKeys[senderUsername]
	if !requestAlreadyPending {
		// No request pending, so we must initiate one.
		// Create the channel that readPump will use to deliver the key.
		keyDeliveryChan := make(chan []byte, 1)
		c.pendingPubKeys[senderUsername] = keyDeliveryChan
		c.pendingPubKeysMutex.Unlock() // Unlock before network I/O or goroutine spawn

		// Send the actual request message to the server
		reqMsg := common.RequestPubKeyMessage{
			BaseMessage: common.BaseMessage{Type: common.MsgTypeRequestPubKey, Timestamp: time.Now()},
			TargetUser:  senderUsername,
		}
		reqBytes, _ := json.Marshal(reqMsg)
		c.send <- reqBytes // Goes to writePump, non-blocking for readPump's loop

		PrintSystem(fmt.Sprintf("🔐 Requesting public key for %s to decrypt incoming message(s)...", senderUsername))

		// Launch a new goroutine to wait for the key and process DMs for this sender.
		go c.handleKeyArrivalAndDecrypt(senderUsername, keyDeliveryChan)
	} else {
		// Request is already pending. The existing waiter will handle these DMs.
		c.pendingPubKeysMutex.Unlock()
	}
}

func (c *Client) handleKeyArrivalAndDecrypt(username string, keyChan <-chan []byte) {
	// This function is run in a new goroutine. It waits for a key or timeout.
	// The keyChan is the same channel that readPump's MsgTypePublicKeyResponse handler will send to.
	select {
	case peerPubKeyBytes := <-keyChan: // Key delivered by readPump
		// readPump would have already deleted 'username' from c.pendingPubKeys after sending to keyChan.
		if peerPubKeyBytes == nil { // Indicates key not found or error by server
			PrintError(fmt.Sprintf("Public key for %s not found by server. Cannot decrypt messages.", username))
			c.clearPendingDMsForUser(username, "public key not found")
			return
		}

		sharedSecret, err := crypto.ECDHSharedSecret(c.ecdhKeyPair.PrivateKey, peerPubKeyBytes)
		if err != nil {
			PrintError(fmt.Sprintf("Failed to derive shared secret with %s: %v. Cannot decrypt messages.", username, err))
			c.clearPendingDMsForUser(username, "failed to derive shared secret")
			return
		}

		c.activeSessionsMutex.Lock()
		c.activeSessions[username] = sharedSecret
		c.activeSessionsMutex.Unlock()
		PrintSystem(fmt.Sprintf("🔐 Secure session for incoming messages from %s established.", username))

		c.processPendingDMsForUser(username, sharedSecret)

	case <-time.After(15 * time.Second): // Timeout for this specific key request (e.g. 15s)
		PrintError(fmt.Sprintf("Timeout waiting for %s's public key to decrypt messages.", username))

		c.pendingPubKeysMutex.Lock()
		// Clean up our responsibility if readPump hasn't processed it.
		if currentChan, ok := c.pendingPubKeys[username]; ok && currentChan == keyChan {
			delete(c.pendingPubKeys, username)
		}
		c.pendingPubKeysMutex.Unlock()
		c.clearPendingDMsForUser(username, "timeout waiting for public key")
	}
}

// processPendingDMsForUser decrypts and prints DMs queued for a user once their shared secret is known.
func (c *Client) processPendingDMsForUser(username string, sharedSecret []byte) {
	c.pendingDMsMutex.Lock()
	queuedMessages, exists := c.pendingDMs[username]
	if !exists || len(queuedMessages) == 0 {
		c.pendingDMsMutex.Unlock()
		return
	}
	delete(c.pendingDMs, username) // Clear processed DMs from queue
	c.pendingDMsMutex.Unlock()

	PrintSystem(fmt.Sprintf("Processing %d queued message(s) from %s...", len(queuedMessages), username))
	for _, edm := range queuedMessages {
		plaintext, err := crypto.DecryptAES_GCM(edm.Ciphertext, edm.Nonce, sharedSecret)
		if err != nil {
			PrintError(fmt.Sprintf("Decryption error for queued message from %s: %v", edm.Sender, err))
			continue
		}
		PrintIncomingDM(edm.Sender, string(plaintext))
	}
}

// clearPendingDMsForUser removes queued DMs if key acquisition fails.
func (c *Client) clearPendingDMsForUser(username string, reason string) {
	c.pendingDMsMutex.Lock()
	queuedMessages, exists := c.pendingDMs[username]
	if exists {
		delete(c.pendingDMs, username)
	}
	c.pendingDMsMutex.Unlock()

	if len(queuedMessages) > 0 {
		PrintError(fmt.Sprintf("Could not decrypt %d message(s) from %s: %s.", len(queuedMessages), username, reason))
	}
}
