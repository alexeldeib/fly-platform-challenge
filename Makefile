CLANG ?= clang-14
STRIP ?= llvm-strip-14
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)
DOCKER_TAG := flydev
DOCKER_CMD := docker run -it --rm -v $(PWD):/work -w /work $(DOCKER_TAG)

.PHONY: fmt generate tcpproxy bpfproxy build-in-container

all: generate bpfproxy tcpproxy

generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate:
# wasteful to repeat -__-
	go get github.com/cilium/ebpf/cmd/bpf2go 
	go generate ./cmd/bpfproxy/...
	
bpfproxy: fmt vet generate
	go build -buildvcs=false -o bin/bpfproxy ./cmd/bpfproxy/.

tcpproxy: fmt vet
	go build -buildvcs=false -o bin/tcpproxy ./cmd/tcpproxy/main.go

fmt: 
	gofmt -w -s ./cmd ./pkg

vet:
	go vet -buildvcs=false ./cmd/... ./pkg/...

container: 
	docker build . -t $(DOCKER_TAG)

build-in-container: container
	$(DOCKER_CMD) make
# docker build messes up generated file permissions.
	sudo chown -R $$(whoami):$$(whoami) ./cmd/bpfproxy/bpf_bpf*
