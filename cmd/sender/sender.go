//go:generate go run github.com/cilium/ebpf/cmd/bpf2go sender sender.bpf.c

package main

import (
	"log"
	"net"
	"time"

	//	"time"

	"sync"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/viktordoronin/stamp-bpf/internals/bpf/sender"
	"github.com/viktordoronin/stamp-bpf/internals/userspace/loader"
	"github.com/viktordoronin/stamp-bpf/internals/userspace/outputrdr"
	"github.com/viktordoronin/stamp-bpf/internals/userspace/pktsender"
	"github.com/viktordoronin/stamp-bpf/internals/userspace/privileges"
)

func main(){
	// TODO: CLI interface, config map passed from userspace
	//opts: source/dest IP, source/dest port, (down the line) stateless/stateful, (way down the line) reflector/sender

	// check privileges before we do anything else
	if err:=privileges.Check(862); err!=nil{
		log.Fatalf("Error checking privileges: %s",err)
	}

	// TODO: remove this when I move away from hardcoded interfaces
	// TODO: look into parsing /proc/net/route and seeing if we can infer the interface from the dest IP
	iface, err := net.InterfaceByName("docker0")
	if err!=nil{
		log.Fatalf("Could not get interface: %v",err)
	}
	
	// Load the compiled eBPF ELF and load it into the kernel
	// A bit messy but this way we get to properly handle the FDs without having a shitton of code here
	var objs sender.SenderObjects
	var l_in, l_out link.Link	
	loader.LoadSender(&objs,&l_in,&l_out,iface)
	defer objs.Close()
	defer l_out.Close()
	defer l_in.Close()
	
	// send packets
	// FYI ping default delay is 1 sec
	go pktsender.StartSession(4, time.Second,iface)
	
	//parse timestamps and print out the metrics
	rd, err := ringbuf.NewReader(objs.Output)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()
	go outputrdr.ReadOutput(rd)
	
	// this hangs up the program without destroying your CPU
	// TODO: errgroups
	var wg sync.WaitGroup
	wg.Add(1)
	wg.Wait()
}
