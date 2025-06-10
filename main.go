package main

import (
	"flag"
	"fmt"
	"gowhisper/client"
	"gowhisper/server"
	"os"
)

func main() {
	isServer := flag.Bool("server", false, "Run as server")
	serverAddr := flag.String("addr", "localhost:8080", "Server address (for client to connect or server to listen on)")
	flag.Parse()

	if *isServer {
		fmt.Println("Starting GoWhisper server...")
		server.StartServer(*serverAddr)
	} else {
		// Client mode
		if flag.NArg() == 0 || flag.Arg(0) != "connect" { // Expect "connect" command
			fmt.Println("Usage: gowhisper connect [-addr <ip:port>]")
			fmt.Println("Or:    gowhisper -server [-addr <ip:port>]")
			os.Exit(1)
		}
		// Username is now handled via /register or /login commands within the client UI
		appClient := client.New(*serverAddr)
		appClient.Run()
	}
}
