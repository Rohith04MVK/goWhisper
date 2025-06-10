package client

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"gowhisper/internal/common"
)

const (
	prompt           = "> "
	connectingMsg    = "🔗 Connecting to whispernet..."
	keysLoadingMsg   = "🔑 Loading keys..."
	secureChannelMsg = "🔐 Establishing secure channel..."
	connectedMsg     = "🦊 Connected to whispernet"
	helpMsg          = "Type @username <message> to send a direct message.\nType /list to see users (TODO).\nType /exit to quit."
	sessionEndedMsg  = "🦊 Session ended. whispers forgotten."
	defaultUsername  = "anon"
	dmPrefix         = "@"
	cmdExit          = "/exit"
	cmdHelp          = "/help"
	colorReset       = "\033[0m"
	colorRed         = "\033[31m"
	colorGreen       = "\033[32m"
	colorYellow      = "\033[33m"
	colorBlue        = "\033[34m"
	colorPurple      = "\033[35m"
	colorCyan        = "\033[36m"
)

func GetUsername() string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("👤 Enter your username (default: anon): ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)
	if username == "" {
		return defaultUsername
	}
	return username
}

func PrintConnectingMessages() {
	fmt.Println(connectingMsg)
	// Simulate work
	time.Sleep(500 * time.Millisecond)
	fmt.Println(keysLoadingMsg + " OK") // Placeholder
	time.Sleep(500 * time.Millisecond)
	fmt.Println(secureChannelMsg + " done") // Placeholder
	time.Sleep(200 * time.Millisecond)
	fmt.Println(connectedMsg)
	fmt.Println(helpMsg)
}

func PrintPrompt() {
	fmt.Print(prompt)
}

func PrintOutgoingDM(recipient, message string) {
	// Clears the current line where user was typing, then prints
	fmt.Printf("\r%s(you to %s): %s%s\n", colorBlue, recipient, message, colorReset)
	PrintPrompt()
}

func PrintIncomingDM(sender, message string) {
	// Clears the current line if user is typing, then prints
	fmt.Printf("\r%s(%s): %s%s\n", colorGreen, sender, message, colorReset)
	PrintPrompt()
}

func PrintServerInfo(message string) {
	fmt.Printf("\r%s[SERVER]: %s%s\n", colorYellow, message, colorReset)
	PrintPrompt()
}

func PrintError(message string) {
	fmt.Printf("\r%s[ERROR]: %s%s\n", colorRed, message, colorReset)
	PrintPrompt()
}

func PrintSessionEnded() {
	fmt.Println(sessionEndedMsg)
}

// ParseUserInput takes raw input and determines if it's a command or DM
func ParseUserInput(input, currentUser string) (*common.Message, bool) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, false // No action for empty input
	}

	if strings.ToLower(input) == cmdExit {
		return nil, true // Signal to exit
	}
	if strings.ToLower(input) == cmdHelp {
		fmt.Println(helpMsg)
		PrintPrompt()
		return nil, false
	}

	if strings.HasPrefix(input, dmPrefix) {
		parts := strings.Fields(input)
		if len(parts) < 2 {
			PrintError("Invalid DM format. Use @username <message>")
			return nil, false
		}
		recipient := strings.TrimPrefix(parts[0], dmPrefix)
		if recipient == currentUser {
			PrintError("You can't send a message to yourself using @ notation here.")
			return nil, false
		}
		messageContent := strings.Join(parts[1:], " ")
		return &common.Message{
			Type:      common.MsgTypeDirectMessage,
			Sender:    currentUser, // Will be set by client before sending
			Recipient: recipient,
			Content:   messageContent,
			Timestamp: time.Now(),
		}, false
	}

	// Default: treat as a general message (though DMs are primary focus)
	// Or print error: "Unknown command or not a DM. Type /help."
	PrintError("Unknown command. Type @username <message> or /help.")
	return nil, false
}
