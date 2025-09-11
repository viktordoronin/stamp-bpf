# syntax=docker/dockerfile:1
FROM golang:1.24.5-alpine AS builder

RUN apk add --no-cache \
    make \
    clang \
    llvm \
    libc-dev \
    linux-headers \
    linux-tools \
    elfutils-dev \
    libbpf-dev

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN make binaries

FROM debian:latest

RUN apt-get update && apt-get install -y \
    iproute2 \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/cmd/bin/reflector /usr/local/bin/reflector
COPY --from=builder /app/cmd/bin/sender /usr/local/bin/sender

ENTRYPOINT tail -F /dev/null
