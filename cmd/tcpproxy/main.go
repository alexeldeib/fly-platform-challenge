package main

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fly-hiring/platform-challenge/pkg/config"
	"github.com/fly-hiring/platform-challenge/pkg/neterr"
	"github.com/fly-hiring/platform-challenge/pkg/proxy"
)

func main() {
	rand.Seed(time.Now().UnixNano())
	ctx := newCancelableContext()

	cfgStore := config.NewConfigStore("./config.json")

	// watch for changes to the config
	ch, err := cfgStore.StartWatcher()
	if err != nil {
		log.Fatalln(err)
	}
	defer cfgStore.Close()

	cfg, err := cfgStore.Read()
	if err != nil {
		log.Fatalln(err)
	}

	prx := &tcpproxy{}
	prx.reload(&cfg)

	go func() {
		for cfg := range ch {
			fmt.Println("got config change:", cfg)
			prx.reload(&cfg)
			fmt.Println("done reloading")
		}
	}()

	<-ctx.Done()
}

// newCancelableContext returns a context that gets canceled by a SIGINT
func newCancelableContext() context.Context {
	doneCh := make(chan os.Signal, 1)
	signal.Notify(doneCh, os.Interrupt)

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	go func() {
		<-doneCh
		log.Println("signal recieved")
		cancel()
	}()

	return ctx
}

type tcpproxy struct {
	listeners []*listener
	wg        sync.WaitGroup
}

func (p *tcpproxy) reload(cfg *config.Config) {
	// close all listeners
	// drain all connections
	p.close()
	p.listeners = nil
	p.wg = sync.WaitGroup{}

	// enumerate apps x ports and create listeners for all combinations
	for _, app := range cfg.Apps {
		fmt.Printf("[%s] setting up app\n", app.Name)
		for _, port := range app.Ports {
			fmt.Printf("[%s]:[%d] setting up listener\n", app.Name, port)
			portStr := strconv.Itoa(port)

			ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
			if err != nil {
				log.Fatalln(err)
			}

			// track the listener so we can gracefully terminate all its
			// connections before reloading.
			closeListener := &listener{Listener: ln}
			p.listeners = append(p.listeners, closeListener)

			// start listening for connections
			go closeListener.listen(portStr, app.Targets)
		}
	}
}

func (p *tcpproxy) close() {
	p.wg.Add(len(p.listeners))
	for i := range p.listeners {
		ln := p.listeners[i]
		go func() {
			ln.close()
			p.wg.Done()
		}()
	}
	p.wg.Wait()
}

type listener struct {
	net.Listener
	wg sync.WaitGroup
}

func (ln *listener) listen(port string, targets []string) {
	for {
		fmt.Printf("[%s] accepting new connection\n", port)

		client, err := ln.Accept()
		if err != nil {
			if strings.Contains(err.Error(), neterr.ErrConnClosed) {
				return // better way to handle this? we already closed elsewhere
			}
			fmt.Printf("[%s] failed accepting connection: %v\n", port, err)
			continue
		}

		// increment the number of currently active connections
		ln.wg.Add(1)
		go func() {
			// handle connection, block
			proxy.HandleConn(client, port, targets)
			ln.wg.Done() // decrement the number of currently active connections
		}()
	}
}

func (ln *listener) close() {
	ln.Listener.Close()
	ln.wg.Wait()
}
