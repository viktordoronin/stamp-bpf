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
	"github.com/viktordoronin/stamp-bpf/internal/userspace/cli"
	"github.com/viktordoronin/stamp-bpf/internal/userspace/loader"
	"github.com/viktordoronin/stamp-bpf/internal/userspace/output"
	"github.com/viktordoronin/stamp-bpf/internal/userspace/pktsender"
	"github.com/viktordoronin/stamp-bpf/internal/userspace/privileges"
)

// this will probably need to be in a separate package
var opts struct {
	interval time.Duration
	count uint32
	interf string
}

func main(){
	// TODO: arg checking and error handling
	// should probably return some sort of struct with processed opts
	cli.ParseSenderArgs()
	
	// check privileges before we do anything else
	if err:=privileges.Check(cli.SenderArgs.Src); err!=nil{
		log.Fatalf("Error checking privileges: %s",err)
	}

	// TODO: look into parsing /proc/net/route and see if we can infer the interface from the dest IP
	iface, err := net.InterfaceByName(cli.SenderArgs.Dev)
	if err!=nil{
		log.Fatalf("Could not get interface %s: %v",cli.SenderArgs.Dev,err)
	}
	
	// Load the compiled eBPF ELF and load it into the kernel
	// A bit ugly but this way we get to properly handle the FDs without having a shitton of code here
	// TODO: the FDs could be package variables
	var objs sender.SenderObjects
	var l_in, l_out link.Link
	loader.LoadSender(&objs,&l_in,&l_out,iface)
	defer objs.Close()
	defer l_out.Close()
	defer l_in.Close()
	
	//parse timestamps and print out the metrics
	rd, err := ringbuf.NewReader(objs.Output)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	// TODO: put them into one package, likely start the goroutines from there
	// we call these funcs from here so that we can fold it into a single errorgroup
	go pktsender.StartSession(cli.SenderArgs.Count, time.Duration(cli.SenderArgs.Interval)*time.Millisecond, iface, cli.SenderArgs.IP)
	go output.ReadAndParse(rd,time.Duration(cli.SenderArgs.Interval)*time.Millisecond)
	go output.UpdateAndPrint()
	
	// this hangs up the program without destroying your CPU
	// TODO: errgroups
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper
}
