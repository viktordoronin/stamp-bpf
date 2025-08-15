//go:generate go run github.com/cilium/ebpf/cmd/bpf2go reflector reflector.bpf.c

package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/viktordoronin/stamp-bpf/internal/userspace/cli"
	"github.com/viktordoronin/stamp-bpf/internal/userspace/loader"
)

func main(){
	// TODO: start/stop mode w/ program pins

	// parse and validate args, get a struct with the stuff we will need
	// reflector and sender use the same struct, so for reflector many of args fields will be zero - be careful
	args:=cli.ParseReflectorArgs()
	
	// Load the compiled eBPF ELF and load it into the kernel.
	bpf:=loader.LoadReflector(args)
	defer bpf.Close()
	
	// hang up
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper
}
