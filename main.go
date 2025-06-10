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
		args := flag.Args()
		if len(args) > 0 && args[0] == "connect" {
			username := client.GetUsername()
			appClient := client.New(*serverAddr, username)
			appClient.Run()
		} else {
			fmt.Println("Usage: gowhisper connect")
			fmt.Println("Or:    gowhisper -server [-addr <ip:port>]")
			os.Exit(1)
		}
	}
}
