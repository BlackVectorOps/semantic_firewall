package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

type _x struct {
	a string
	b string
}

func z(q _x) {
	// SHUFFLE 1: We calculate the string later.
	// We print a hardcoded string first, then define w.
	// This changes the order of operations in the block.
	fmt.Println("[*] Connecting...")
	w := q.a + ":" + q.b

	for {
		e, r := net.Dial("tcp", w)
		if r != nil {
			time.Sleep(5 * time.Second)
			continue
		}

		// SHUFFLE 2: We call the handler BEFORE printing success.
		// In the dirty version, we printed "ok" then called y(e).
		// Here we call y(e). Note: This is actually a functional change if y(e) blocks!
		// But topologically, it's just reordering nodes in the block.
		y(e)
		fmt.Println("ok")
		return
	}
}

func y(u net.Conn) {
	defer u.Close()
	i := bufio.NewReader(u)

	for {
		o, p := i.ReadString('\n')
		if p != nil {
			return
		}

		s := strings.TrimSpace(o)
		if s == "kill" {
			os.Exit(0)
		}

		fmt.Printf("%s\n", s)
	}
}

func main() {
	// SHUFFLE 3: Initialize 'b' (Port) before 'a' (IP)
	// Textually distinct. Semantically identical.
	k := _x{
		b: "8080",
		a: "192.168.1.105",
	}
	z(k)
}
