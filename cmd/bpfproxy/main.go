//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ../../bpf/sk_lookup.c
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/fly-hiring/platform-challenge/pkg/config"
	"github.com/fly-hiring/platform-challenge/pkg/neterr"
	"github.com/fly-hiring/platform-challenge/pkg/proxy"
)

func main() {
	var portFlag = flag.Int("p", 8000, "port for tcpproxy to listen on")
	flag.Parse()

	rand.Seed(time.Now().UnixNano())

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

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

	prx := newBpfProxy(*portFlag, objs.bpfPrograms.RedirPort, objs.bpfMaps.SockMap, objs.bpfMaps.PortMap)

	fmt.Println("starting with initial config")
	if err := prx.start(&cfg); err != nil {
		log.Fatalf("failed to start proxy: %v", err)
	}
	fmt.Println("started up proxy")

	go func() {
		for cfg := range ch {
			fmt.Println("got config change:", cfg)
			prx.reload(&cfg)
			fmt.Println("done reloading")
		}
	}()

	fmt.Println("serving...")
	ctx := newCancelableContext()
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

type bpfproxy struct {
	port           int
	skProg         *ebpf.Program
	sockMap        *ebpf.Map
	portMap        *ebpf.Map
	portsToTargets map[int][]string
}

func newBpfProxy(port int, prog *ebpf.Program, sockMap, portMap *ebpf.Map) *bpfproxy {
	return &bpfproxy{
		port:           port,
		skProg:         prog,
		sockMap:        sockMap,
		portMap:        portMap,
		portsToTargets: make(map[int][]string),
	}
}

func (p *bpfproxy) start(cfg *config.Config) error {
	// read netns fd
	netns, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return err
	}
	defer netns.Close()

	// attach sk_lookup program to netns
	_, err = link.AttachNetNs(int(netns.Fd()), p.skProg)
	if err != nil {
		return fmt.Errorf("failed to attach sk_lookup program to netns: %w", err)
	}

	// listen on one port for tcp connections
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", p.port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", p.port, err)
	}

	// start accepting tcp connections
	// no ports pointing to us yet
	go p.listen(ln)

	// net.Listener doesn't expose Fd() but TCPListener does
	tcpLn := (ln).(*net.TCPListener)

	// get the raw fd
	file, err := tcpLn.File()
	if err != nil {
		return fmt.Errorf("failed to get file descriptor from tcp listener: %w", err)
	}

	// put the fd into the bpf map for bpf_assign_sk
	if err := p.sockMap.Put(uint32(0), uint64(file.Fd())); err != nil {
		return fmt.Errorf("failed to write socket fd to bpf map: %w", err)
	}

	// load the config, also tells sk_lookup prog which ports to point to us
	p.reload(cfg)

	return nil
}

func (p *bpfproxy) reload(cfg *config.Config) {
	newTargets := make(map[int]bool)

	// enumerate apps x ports and route ports to targets
	for _, app := range cfg.Apps {
		for _, port := range app.Ports {
			fmt.Printf("[%s] setting up port %d\n", app.Name, port)
			newTargets[port] = true
			p.portsToTargets[port] = app.Targets
			if err := p.portMap.Put(uint16(port), uint8(0)); err != nil {
				log.Fatalf("failed to write port config to bpf map: %v", err)
			}
		}
	}

	for port := range p.portsToTargets {
		if !newTargets[port] {
			fmt.Printf("removing stale port %d from bpf map\n", port)
			delete(p.portsToTargets, port)
			if err := p.portMap.Delete(uint16(port)); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				log.Fatalf("failed to remove stale port from bpf map: %v", err)
			}
		}
	}
}

func (p *bpfproxy) listen(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if strings.Contains(err.Error(), neterr.ErrConnClosed) {
				return // better way to handle this? we already closed elsewhere
			}
			fmt.Printf("failed accepting connection: %v\n", err)
			continue
		}

		go func() {
			// handle connection, block
			p.handleConn(conn)
		}()
	}
}

func (p *bpfproxy) handleConn(client net.Conn) {
	fmt.Printf("handling connection to local %s from remote %s\n", client.LocalAddr().String(), client.RemoteAddr().String())

	localAddr := client.LocalAddr().String()
	port := strings.Split(localAddr, ":")[1]
	portNum, err := strconv.Atoi(port)
	if err != nil {
		fmt.Printf("failed to parse port: %v\n", err)
		return
	}

	targets := p.portsToTargets[portNum]

	// handle connection, block
	proxy.HandleConn(client, port, targets)
}
