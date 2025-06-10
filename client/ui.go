package client

import (
	"fmt"
	"io"
	"log"
	"strings"

	"gowhisper/internal/common"

	"github.com/chzyer/readline" // Import readline
)

const (
	prompt          = "> "
	connectingMsg   = "🔗 Connecting to whispernet..."
	sessionEndedMsg = "🦊 Session ended. whispers forgotten."
	cmdExit         = "/exit"
	cmdHelp         = "/help"
	cmdRegister     = "/register"
	cmdLogin        = "/login"
	cmdList         = "/list"
	dmPrefix        = "@"
	colorReset      = "\033[0m"
	colorRed        = "\033[31m"
	colorGreen      = "\033[32m"
	colorYellow     = "\033[33m"
	colorBlue       = "\033[34m"
	colorCyan       = "\033[36m"
	colorPurple     = "\033[35m"
)

var rl *readline.Instance // Global readline instance

func InitReadline() error {
	var err error
	rl, err = readline.NewEx(&readline.Config{
		Prompt:          prompt,
		HistoryFile:     "/tmp/gowhisper_history.txt",
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
	})
	if err != nil {
		return err
	}
	log.SetOutput(rl.Stderr()) // Log readline errors to its stderr
	return nil
}

func CloseReadline() {
	if rl != nil {
		rl.Close()
	}
}

func PrintConnectingMessage() {
	fmt.Println(connectingMsg)
}

func PrintHelp() {
	helpText := fmt.Sprintf(`
%sGoWhisper Commands:%s
  %s/register <username> <password>%s - Create a new account.
  %s/login <username> <password>%s    - Log into an existing account.
  %s@<username> <message>%s           - Send a secure direct message.
  %s/list%s                           - List online users.
  %s/help%s                           - Show this help message.
  %s/exit%s                           - Exit GoWhisper.
`, colorCyan, colorReset, colorGreen, colorReset, colorGreen, colorReset, colorGreen, colorReset, colorGreen, colorReset, colorGreen, colorReset, colorGreen, colorReset)
	fmt.Fprint(rl.Stdout(), helpText)
}

func PrintMessage(prefix, sender, message, prefixColor, senderColor, msgColor string) {
	// This is tricky with readline as it redraws the prompt.
	// We need to clear the current line, print the message, then redraw.
	// For simplicity, we'll just print above the prompt.
	// rl.Stdout() is the correct writer to use with readline.
	fullMsg := fmt.Sprintf("\r%s[%s]%s %s%s:%s %s%s%s\n",
		prefixColor, prefix, colorReset,
		senderColor, sender, colorReset,
		msgColor, message, colorReset,
	)
	fmt.Fprint(rl.Stdout(), fullMsg)
	rl.Refresh() // Redraw the prompt
}

func PrintOutgoingDM(recipient, message string) {
	PrintMessage("YOU", recipient, message, colorBlue, colorBlue, colorReset)
}

func PrintIncomingDM(sender, message string) {
	PrintMessage("DM", sender, message, colorGreen, colorGreen, colorReset)
}

func PrintServerInfo(message string) {
	PrintMessage("SRV", "INFO", message, colorYellow, colorYellow, colorReset)
}

func PrintError(message string) {
	PrintMessage("ERR", "ERROR", message, colorRed, colorRed, colorReset)
}

func PrintSystem(message string) {
	fmt.Fprintf(rl.Stdout(), "\r%s%s%s\n", colorCyan, message, colorReset)
	rl.Refresh()
}

func PrintSessionEnded() {
	fmt.Fprintln(rl.Stdout(), sessionEndedMsg)
}

// GetUserInput uses readline
func GetUserInput() (string, error) {
	line, err := rl.Readline()
	if err == readline.ErrInterrupt { // User pressed Ctrl+C
		// If line is empty, it means they just wanted to interrupt/exit
		if len(line) == 0 {
			return cmdExit, nil
		}
		// If line is not empty, they might have been typing, so return the line
		return line, nil
	} else if err == io.EOF { // User pressed Ctrl+D
		return cmdExit, nil
	}
	return strings.TrimSpace(line), err
}

// UserInputState determines the context for ParseUserInput
type UserInputState int

const (
	StateUnauthenticated UserInputState = iota
	StateAuthenticated
)

// ParseUserInput processes input based on authentication state
func ParseUserInput(input string, currentState UserInputState, currentUser string) (interface{}, string, bool) {
	// interface{} is the message struct, string is the command type, bool is shouldExit
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, "", false
	}

	parts := strings.Fields(input)
	command := strings.ToLower(parts[0])

	if command == cmdExit {
		return nil, cmdExit, true
	}
	if command == cmdHelp {
		PrintHelp()
		return nil, cmdHelp, false
	}

	if currentState == StateUnauthenticated {
		switch command {
		case cmdRegister:
			if len(parts) < 3 {
				PrintError("Usage: /register <username> <password>")
				return nil, "", false
			}
			return common.ClientAuthMessage{
				BaseMessage: common.BaseMessage{Type: common.MsgTypeRegisterUser},
				Username:    parts[1],
				Password:    strings.Join(parts[2:], " "), // Password can have spaces
			}, common.MsgTypeRegisterUser, false
		case cmdLogin:
			if len(parts) < 3 {
				PrintError("Usage: /login <username> <password>")
				return nil, "", false
			}
			return common.ClientAuthMessage{
				BaseMessage: common.BaseMessage{Type: common.MsgTypeLoginUser},
				Username:    parts[1],
				Password:    strings.Join(parts[2:], " "),
			}, common.MsgTypeLoginUser, false
		default:
			PrintError("You are not logged in. Use /register or /login. Type /help for commands.")
			return nil, "", false
		}
	}

	// Authenticated state commands
	if currentState == StateAuthenticated {
		if strings.HasPrefix(command, dmPrefix) {
			if len(parts) < 2 {
				PrintError("Usage: @username <message>")
				return nil, "", false
			}
			recipient := strings.TrimPrefix(parts[0], dmPrefix)
			if recipient == currentUser {
				PrintError("You can't send a message to yourself using @ notation here.")
				return nil, "", false
			}
			messageContent := strings.Join(parts[1:], " ")
			// This will be an EncryptedDirectMessage, but encryption happens in client.go
			return map[string]string{
				"recipient": recipient,
				"content":   messageContent,
			}, common.MsgTypeEncryptedDM, false // Special map for client to handle encryption
		}
		switch command {
		case cmdList:
			return common.BaseMessage{Type: common.MsgTypeRequestUserList}, common.MsgTypeRequestUserList, false
		default:
			PrintError("Unknown command. Type @username <message> or /help.")
			return nil, "", false
		}
	}
	return nil, "", false // Should not reach here
}
