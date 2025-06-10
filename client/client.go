package client

import (
	"bufio"
	"encoding/json"
	"log"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"gowhisper/internal/common"

	"github.com/gorilla/websocket"
)

type Client struct {
	addr     string
	username string
	conn     *websocket.Conn
	send     chan []byte   // Channel for messages to send to server
	done     chan struct{} // Channel to signal client shutdown
}

func New(addr, username string) *Client {
	return &Client{
		addr:     addr,
		username: username,
		send:     make(chan []byte),
		done:     make(chan struct{}),
	}
}

func (c *Client) Connect() error {
	u := url.URL{Scheme: "ws", Host: c.addr, Path: "/ws"}
	PrintConnectingMessages() // This prints "Connecting...", "Loading keys...", etc.

	var err error
	c.conn, _, err = websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		return err
	}

	// Register with server
	regMsg := common.Message{
		Type:   common.MsgTypeRegister,
		Sender: c.username,
	}
	regMsgBytes, _ := json.Marshal(regMsg)
	err = c.conn.WriteMessage(websocket.TextMessage, regMsgBytes)
	if err != nil {
		c.conn.Close()
		return err
	}

	return nil
}

func (c *Client) Run() {
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

	if err := c.Connect(); err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer c.conn.Close()
	defer PrintSessionEnded()

	go c.readPump()
	go c.writePump()

	// Initial prompt
	PrintPrompt()

	// Main loop for user input or interrupt
	stdInReader := bufio.NewReader(os.Stdin)
	for {
		select {
		case <-c.done: // If readPump or writePump exits
			return
		case <-interrupt:
			log.Println("Interrupt received, closing connection...")
			// Attempt to send a close message.
			err := c.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			if err != nil {
				log.Println("write close:", err)
			}
			// Wait a bit for the close message to be sent before closing done
			select {
			case <-time.After(time.Second):
			case <-c.done: // If already closed by read/write pump
			}
			return
		default:
			// Non-blocking read attempt for user input or check done channel
			// This part is a bit tricky to make responsive without blocking select.
			// A simpler approach for CLI is just a blocking read here.
			// For this example, let's use a blocking read from stdin
			// but we need to ensure select still works.
			// A better way would be to have user input on its own goroutine.

			// For simplicity in this initial version, let's make user input handling blocking
			// and rely on the interrupt for clean exit.
			// A more robust CLI would use a library or more complex select with timeout.
			input, err := stdInReader.ReadString('\n')
			if err != nil {
				log.Printf("Error reading input: %v. Exiting.", err)
				close(c.done) // Signal other goroutines to stop
				return
			}
			input = strings.TrimSpace(input)
			msgToSend, shouldExit := ParseUserInput(input, c.username)

			if shouldExit {
				close(c.done)
				// Send close message to server (best effort)
				c.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
				time.Sleep(200 * time.Millisecond) // Give it a moment
				return
			}

			if msgToSend != nil {
				// Simulate sending by printing what would be sent
				// PrintOutgoingDM(msgToSend.Recipient, msgToSend.Content) // Already handled by UI if needed

				msgBytes, err := json.Marshal(msgToSend)
				if err != nil {
					PrintError("Error preparing message: " + err.Error())
					continue
				}
				c.send <- msgBytes // Send to writePump
			}
		}
	}
}

func (c *Client) readPump() {
	defer func() {
		close(c.done) // Signal main loop and writePump to exit
	}()
	for {
		_, messageBytes, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure, websocket.CloseNormalClosure) {
				PrintError("Server connection lost: " + err.Error())
			} else if err.Error() == "websocket: close 1000 (normal)" {
				// Normal close from server or self-initiated
			} else {
				PrintError("Read error: " + err.Error())
			}
			return
		}

		var msg common.Message
		if err := json.Unmarshal(messageBytes, &msg); err != nil {
			PrintError("Error parsing message from server: " + err.Error())
			continue
		}

		switch msg.Type {
		case common.MsgTypeDirectMessage:
			// For E2EE, decryption would happen here
			PrintIncomingDM(msg.Sender, msg.Content)
		case common.MsgTypeServerInfo:
			PrintServerInfo(msg.Content)
		case common.MsgTypeError:
			PrintError(msg.Content)
		default:
			PrintServerInfo("Received unknown message type: " + msg.Type)
		}
	}
}

func (c *Client) writePump() {
	defer func() {
		// No need to close(c.done) here as readPump handles it on connection close
		// c.conn.Close() // readPump or main loop will handle closing connection
	}()
	for {
		select {
		case message, ok := <-c.send:
			if !ok {
				// Channel closed, means we are shutting down
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			err := c.conn.WriteMessage(websocket.TextMessage, message)
			if err != nil {
				PrintError("Write error: " + err.Error())
				return // Stop pump if write fails
			}
			// Echo what was sent for user feedback (optional if ParseUserInput handles it)
			// For DMs, ParseUserInput gives feedback, so this might be redundant or for other message types
			var sentMsg common.Message
			if json.Unmarshal(message, &sentMsg) == nil && sentMsg.Type == common.MsgTypeDirectMessage {
				PrintOutgoingDM(sentMsg.Recipient, sentMsg.Content)
			}

		case <-c.done: // If readPump signals done (e.g. connection closed)
			return
		}
	}
}
