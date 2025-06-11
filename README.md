# goWhisper

**Encrypted chat. Minimal interface. Maximum paranoia.**

goWhisper is a terminal-based chat application that uses post-quantum encryption to secure messages even against future quantum threats. This project is designed to explore secure messaging using post-quantum encryption and to experiment with Go’s capabilities for building a clean, minimalist, and secure CLI application.

The encryption is powered by `goKyber`, a custom PQE library (still in development). This is not a production-ready tool but a **learning project** aimed at building foundational knowledge around secure communication tools.

---

## Why This Exists

- To learn how to implement post-quantum encryption in a real-world scenario
- To design a simple, secure, and ephemeral chat system in Go
- To experiment with command-line interfaces for security applications
- To avoid the unnecessary complexity of web-based tools

---

## Features

- **Post-Quantum Encryption**  
  Uses Kyber-based key exchange (via `goKyber` — WIP)

- **Ephemeral Messaging**  
  Sessions end and messages vanish. There’s nothing to store or leak.

- **Simple CLI Interface**  
  A no-nonsense chat experience. You, your messages, and encryption.

---

## Project Status

This is a work in progress. The core functionality works, but the `goKyber` encryption library is still under development. If you’re looking for a finished product, this is not it. But if you’re looking to learn or experiment, this is a good place to start.

---

## Installation

Clone the repository and build the project.

```bash
git clone https://github.com/yourusername/goWhisper
cd goWhisper
go build
```

You’ll have a `gowhisper` binary ready to run.

### Running the Server
To run the server (handling multiple client connections), execute:
```bash
go run main.go -server
# OR
./gowhisper -server
```
The server will listen for incoming client connections.

### Running the Client
To run the client and connect to the server:
```bash
go run main.go connect
# OR
./gowhisper connect
```
The client will prompt for login or registration details.

### Client Interaction
Upon running the client, you'll see:
```bash
🔗 Connecting to whispernet...
🔗 Connected to server. Please /register or /login.

GoWhisper Commands:
  /register <username> <password> - Create a new account.
  /login <username> <password>    - Log into an existing account.
  @<username> <message>           - Send a secure direct message.
  /list                           - List online users.
  /help                           - Show this help message.
  /exit                           - Exit GoWhisper.
```

### Example Session
```bash
$ gowhisper connect

🔗 Connecting to whispernet...
🔗 Connected to server. Please /register or /login.

> /register alice mysecurepassword
🔐 Account created for alice

> /login alice mysecurepassword
🔐 Successfully logged in as alice

> @bob Hello, Bob!
(you): Secure message to Bob sent

> /exit
🦊 Session closed. Messages wiped.
```

### Available Commands

| Command            | Description                                |
|--------------------|--------------------------------------------|
| `/register`        | Register a new user account                |
| `/login`           | Log into an existing account               |
| `@<username>`      | Send a direct encrypted message to a user  |
| `/list`            | List all online users                      |
| `/help`            | Display available commands                 |
| `/exit`            | End the current session                    |

---

## Crypto Design

- **Key Exchange**: Kyber512 (via `goKyber`)
- **Message Encryption**: AES-GCM or ChaCha20
- **Forward Secrecy**: Achieved through ephemeral keys
- **Persistence**: No logs or history saved

Everything is encrypted end-to-end with no central server storing messages or metadata.

---

## Roadmap

- [ ] Finalize and fully integrate `goKyber`
- [ ] TUI frontend (Bubble Tea or similar)
- [ ] Secure file transfer capability
- [ ] Peer discovery or relay for NAT-punching
- [ ] Group chat support

---

## License

MIT. Feel free to use, modify, and learn.

---

## Final Thoughts

goWhisper is not a complete, polished product - but it’s a start. It’s a tool to experiment with post-quantum encryption and secure communications in a minimalist CLI setting. If you’re interested in cryptography, Go, or just want to try building your own encrypted chat system, this project has plenty of learning potential.

This is a whisper, not a broadcast.
