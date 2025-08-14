//go:generate go run github.com/cilium/ebpf/cmd/bpf2go sender sender.bpf.c

package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/viktordoronin/stamp-bpf/internal/userspace/cli"
	"github.com/viktordoronin/stamp-bpf/internal/userspace/loader"
	"github.com/viktordoronin/stamp-bpf/internal/userspace/privileges"
	"github.com/viktordoronin/stamp-bpf/internal/userspace/stamp"
)

func main(){
	// TODO: arg checking and error handling
	// should probably return some sort of struct with processed opts
	args:=cli.ParseSenderArgs()

	// TODO: this too can be probably done inside the CLI package
	// check privileges before we do anything else
	if err:=privileges.Check(args.Src); err!=nil{
		log.Fatalf("Error checking privileges: %s",err)
	}

	// TODO: this should be checked by cli
	// TODO: look into parsing /proc/net/route and see if we can infer the interface from the dest IP
	iface, err := net.InterfaceByName(args.Dev)
	if err!=nil{
		log.Fatalf("Could not get interface %s: %v",args.Dev,err)
	}
	
	// Load the compiled eBPF ELF and load it into the kernel
	fd:=loader.LoadSender(iface)
	defer fd.Close()
	
	//parse timestamps and print out the metrics
	// TODO: fold this into stamp pkg
	rd, err := ringbuf.NewReader(fd.Objs.Output)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	// TODO: put them into one package, likely start the goroutines from there
	// TODO: stamp.Args
	// we call these funcs from here so that we can fold it into a single errorgroup
	go stamp.StartSession(args.Count, time.Duration(args.Interval)*time.Millisecond, iface, args.IP)
	go stamp.ReadAndParse(rd,time.Duration(args.Interval)*time.Millisecond)
	go stamp.UpdateAndPrint()
	
	// this hangs up the program without destroying your CPU
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper
}
