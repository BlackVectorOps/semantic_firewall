package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// BeaconConfig holds the C2 server details
type BeaconConfig struct {
	IP   string
	Port string
}

// StartBeacon initiates the connection loop
func StartBeacon(config BeaconConfig) {
	address := config.IP + ":" + config.Port
	fmt.Printf("[*] Attempting to connect to C2 at %s...\n", address)

	for {
		conn, err := net.Dial("tcp", address)
		if err != nil {
			fmt.Println("[-] Connection failed. Retrying in 5 seconds...")
			time.Sleep(5 * time.Second)
			continue
		}

		fmt.Println("[+] Connected! Waiting for commands...")
		handleConnection(conn)
		return
	}
}

// handleConnection reads commands from the server
func handleConnection(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)

	for {
		message, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("[-] Server disconnected.")
			return
		}

		command := strings.TrimSpace(message)
		if command == "kill" {
			fmt.Println("[*] Kill command received. Terminating.")
			os.Exit(0)
		}

		fmt.Printf("[>] Received command: %s\n", command)
	}
}

func main() {
	cfg := BeaconConfig{
		IP:   "192.168.1.105",
		Port: "8080",
	}
	StartBeacon(cfg)
}
