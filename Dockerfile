FROM ubuntu:20.04

# install dependencies and tools
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive && \
  apt-get install --no-install-recommends -y \
  ca-certificates\
  curl \
  gnupg2 \
  git \
  libelf-dev \
  make \
  netcat \
  openssh-server \
  openssl \
  && rm -rf /var/lib/apt/lists/*

# install kernel headers, libbpf, and bpftool
# on Ubuntu 21.01 this can be replaced with: libbpf-dev linux-tools-5.13.0-30-generic linux-cloud-tools-5.13.0-30-generic
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive && \
  apt-get install --no-install-recommends -y \
  autoconf bison cmake dkms flex gawk gcc python3 rsync \
  libiberty-dev libncurses-dev libpci-dev libssl-dev libudev-dev \
  && curl https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.13.tar.gz | tar -xz \
  && make -C /linux-5.13 headers_install INSTALL_HDR_PATH=/usr \
  && make -C /linux-5.13/tools/lib/bpf install INSTALL_HDR_PATH=/usr \
  && make -C /linux-5.13/tools/bpf/bpftool install \
  && apt-get remove -y \
  autoconf bison cmake dkms flex gawk python3 rsync \
  libiberty-dev libncurses-dev libpci-dev libssl-dev libudev-dev \
  && apt autoremove -y \
  && rm -rf /var/lib/apt/lists/* \
  && rm -rf /linux-5.13

RUN apt update && \
  apt install -yq gcc wget lsb-release software-properties-common && \
  curl -LO https://apt.llvm.org/llvm.sh && \
  chmod +x llvm.sh && \
  ./llvm.sh 14 && \
  apt update && \
  apt install -yq llvm-14

# install go
ENV GOPATH="/go"
ENV PATH="/usr/local/go/bin:$GOPATH/bin:$PATH" 

RUN curl -L https://go.dev/dl/go1.18.linux-amd64.tar.gz | tar -xz -C /usr/local;
RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"
