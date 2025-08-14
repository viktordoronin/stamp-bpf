//go:generate go run github.com/cilium/ebpf/cmd/bpf2go reflector reflector.bpf.c

package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/viktordoronin/stamp-bpf/internal/bpf/reflector"
	"github.com/viktordoronin/stamp-bpf/internal/userspace/cli"
	"github.com/viktordoronin/stamp-bpf/internal/userspace/loader"
	"github.com/viktordoronin/stamp-bpf/internal/userspace/privileges"
)

func main(){

	// TODO: bring all the features on par with sender
	// TODO: start/stop mode w/ program pins
	
	args:=cli.ParseReflectorArgs()
	
	// check privileges before we do anything else
	if err:=privileges.Check(862); err!=nil{
		log.Fatalf("Error checking privileges: %s",err)
	}

	iface, err := net.InterfaceByName(args.Dev)
	if err!=nil{
		log.Fatalf("Could not get interface: %v",err)
	}
	
	// Load the compiled eBPF ELF and load it into the kernel.
	var objs reflector.ReflectorObjects
	var l_in, l_out link.Link
	loader.LoadReflector(&objs,&l_in,&l_out,iface)
	defer objs.Close()
	defer l_out.Close()
	defer l_in.Close()

	// hang up
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper
}
