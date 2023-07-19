package proxy

import (
	"fmt"
	"io"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/fly-hiring/platform-challenge/pkg/neterr"
)

func HandleConn(client net.Conn, port string, targets []string) {
	fmt.Printf("[%s] handling connection\n", port)

	// server will hold the actual upstream connection
	// the target string is just for logging
	var server net.Conn
	var target string

	// make a copy of the slice to filter
	// TODO: probably a better way to do this
	candidates := make([]string, len(targets))
	copy(candidates, targets)

	// while our list of targets is not empty
	for len(candidates) > 0 {
		// pick a random target
		idx := rand.Intn(len(candidates))
		candidate := candidates[idx]

		// remove the candidate target from the list
		candidates = append(candidates[:idx], candidates[idx+1:]...)

		// try to connect to the target
		conn, err := net.DialTimeout("tcp", candidate, time.Second*2)
		if err != nil {
			fmt.Printf("[%s] failed connecting to target %s: %v\n", port, candidate, err)
			continue // try another randomly selected target
		}

		// successfully connected to the target
		server = conn
		target = candidate
		break
	}

	// this means we tried all targets in the list randomly and failed to reach any
	if server == nil {
		fmt.Printf("[%s] failed connecting to any targets\n", port)
		client.Close()
		return
	}

	// splice the client/server together with io.Copy
	splice(port, target, client, server)
}

func splice(port string, target string, client, server net.Conn) {
	fmt.Printf("[%s] splicing client/target %s\n", port, target)

	clientClosed := make(chan struct{})
	serverClosed := make(chan struct{})

	go func() {
		defer close(clientClosed)
		_, err := io.Copy(server, client)
		if err != nil {
			fmt.Printf("[%s] server write error for target %s: %v\n", port, target, err)
		}
	}()

	go func() {
		defer close(serverClosed)
		_, err := io.Copy(client, server)
		if err != nil {
			// TODO: if client closes first, server doesn't know and this causes a failed write to the client.
			// log a nicer error than the verbose failure from underlying net.Conn.
			if strings.Contains(err.Error(), neterr.ErrConnClosed) {
				fmt.Printf("[%s] client closed connection for target %s\n", port, target)
				return
			}
			fmt.Printf("[%s] client write error for target %s: %v\n", port, target, err)
		}
	}()

	var closer net.Conn

	select {
	case <-serverClosed:
		fmt.Printf("[%s] server connection closed gracefully: %s\n", port, target)
		closer = client
	case <-clientClosed:
		fmt.Printf("[%s] client connection closed gracefully: %s\n", port, target)
		closer = server
	}

	// Close whoever is still open (should we do this?)
	closer.Close()
}
