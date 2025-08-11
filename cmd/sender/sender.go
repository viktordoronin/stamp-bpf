//go:generate go run github.com/cilium/ebpf/cmd/bpf2go sender sender.bpf.c

package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/viktordoronin/stamp-bpf/internal/bpf/sender"
	"github.com/viktordoronin/stamp-bpf/internal/userspace/loader"
	"github.com/viktordoronin/stamp-bpf/internal/userspace/output"
	"github.com/viktordoronin/stamp-bpf/internal/userspace/pktsender"
	"github.com/viktordoronin/stamp-bpf/internal/userspace/privileges"
)

func main(){
	// TODO: CLI interface, config map passed from userspace
	//opts: source/dest IP, source/dest port, (down the line) stateless/stateful, (way down the line) reflector/sender

	// TODO: move from hardcoded literals to hardcoded vars(opts typedef?) in preparation for CLI implementation
	var interval time.Duration = time.Second
	var count uint32 = 0
	var interf string = "docker0"
	// var dest_ip, src_port, dest_port string
	
	
	// check privileges before we do anything else
	if err:=privileges.Check(862); err!=nil{
		log.Fatalf("Error checking privileges: %s",err)
	}

	// TODO: look into parsing /proc/net/route and see if we can infer the interface from the dest IP
	iface, err := net.InterfaceByName(interf)
	if err!=nil{
		log.Fatalf("Could not get interface: %v",err)
	}
	
	// Load the compiled eBPF ELF and load it into the kernel
	// A bit ugly but this way we get to properly handle the FDs without having a shitton of code here
	var objs sender.SenderObjects
	var l_in, l_out link.Link	
	loader.LoadSender(&objs,&l_in,&l_out,iface)
	defer objs.Close()
	defer l_out.Close()
	defer l_in.Close()
	
	// send packets
	// FYI ping default delay is 1 sec
	go pktsender.StartSession(count, interval,iface)
	
	//parse timestamps and print out the metrics
	rd, err := ringbuf.NewReader(objs.Output)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	go output.ReadAndParse(rd,interval)
	go output.UpdateAndPrint()
	
	// this hangs up the program without destroying your CPU
	// TODO: errgroups
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper
}
