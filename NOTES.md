# Notes

Hello, proxy!

## How to use it

There are two versions of the proxy: "simple" and "bpf-steered".

To build everything in a docker container with all dependencies installed:
```bash
$ make build-in-container
$ ls -al bin/
total 7744
drwxrwxr-x 2 azureuser azureuser    4096 Apr 24 04:58 .
drwxrwxr-x 8 azureuser azureuser    4096 Apr 24 04:42 ..
-rwxrwxr-x 1 azureuser azureuser 4608340 Apr 24 04:58 bpfproxy
-rwxrwxr-x 1 azureuser azureuser 3305813 Apr 24 04:58 tcpproxy
```

### Simple Proxy

Run the "simple" proxy with one listener per port:

```bash
$ go run cmd/tcpproxy/main.go
```

Try it with nc, hot reload and connection draining should work.
```bash
# from another terminal
$ echo "hello" | nc -4 localhost 6300
# don't ctrl-c!
```

While you have that open, edit config.json. The proxy will close all active
listeners and wait for their connections to terminate before starting new
listeners. When you ctrl-c the `nc` process, the proxy will immediately reload
the new config.

### BPF Steered Proxy

Run the "bpf-steered" proxy with a single listener:

```bash
$ make bpfproxy
$ sudo ./bin/bpfproxy [-p 8000]
# edit config.json to add a port
# try nc with the new port, it should work
# now remove it, hot reload should work.
# no connection draining since we reuse one listener
```

Only regenerate the bpf code:
```bash
# will `go get github.com/cilium/ebpf/cmd/bpf2go` 
$ make generate
```

## What I did

The core of both versions of the proxy is the same -- we have a client tcp
connection, we need to find an available backend, and then we splice the
connections together by io.Copy'ing from client to server and vice versa.

The logic for retrying backends is fairly naive. Each time a connection comes
in, we copy the list of potential targets, randomly popping one and trying to
connect until we succeed or run out of targets.

My simple proxy reads a config file and starts a listener per port per app. Each
listener loops accepting new connections and handling them in a new goroutine.
For each new connection, it increments a counter for the given listener. When
the connection terminates, we decrement the counter. This lets us drain
connections easily. When the simple proxy receives a config reload, it closes all
open listeners and waits for all listeners' connections to drain. Then it loads
the new config, starting new listeners per app per port.

The bpf steered proxy is (ironically) simpler. It only has one listener, with a
port configured by flag. It has one bpf program and two maps. The proxy loads
the program and both maps into the kernel on startup, initially empty. The proxy
creates the listener and writes the file descriptor for the listener into the
first map. This completes the startup configuration. Then the proxy loads the
initial configuration for apps, writing each port into the second bpf map as a
key with no value. Whenever the config file changes, the proxy loads the new
configuration by writing new ports into the map and deleting ports which were
previously written but no longer present in the new config.

When a connection comes in, the sk_lookup program checks for the target port in
the map. If it's not present, we immediately return with SK_PASS -- this packet
is not relevant to us. Otherwise if it's there, we need to lookup the listener's
file descriptor. We wrote that into the other bpf map during the proxy startup.
Then we call bpf_sk_assign on the socket, which steers the connection to our
proxy. The proxy parses the port from the connection and finds an available
backend for the requested app. Failure at any point in the bpf program results
in SK_PASS without bpf_sk_assign (perhaps a questionable default instead of
SK_DROP). The go code unloads the bpf program and maps when it terminates thanks
to Cilium's ebpf package.

### Handling Load + Improvements

Neither proxy has a limit on active connections, so the number of goroutines
could easily grow without bound. The TCP connection handling also doesn't handle
any sort of timeouts so it would be easy for a malicious client to keep
connections open indefinitely if the backends cooperate. A nice addition would
be adding a worker pool to handle new connections to limit concurrency and
resource usage.

The backend retry logic could also use a few subtantial improvements. We
randomly try all targets one by one. This could get quite tedious if we have a
long list, so it might we worth limiting retries to a constant number. We could
also implement healthchecking for the backend targets and try to connect only to
backends we already believe to be healthy.

The simple proxy in particular has a few weak points -- config reloads are "big
bang" style, tearing everything down and setting it back up. Although it has
some connection draining, this is still wasteful if all the frontend
ports/listeners remain the same and only the backend targets changed. We could
avoid tearing down listeners and only check which ones we need to start or stop.

There's no config validation or validation against port conflicts between
different apps. In the real world, Fly might be able to use app hostnames to
disambiguate ports and routing. Here however, there's no way to tell which app
should receive a connection if two apps have the same frontend port. Adding
validation for this sort of error case would be good. Similarly, the bpf version
fails terminally if it can't write bpf into the bpf maps for hot reloads.

The other big improvements I'd make would probably be tests + CI :)
