//go:generate go run github.com/cilium/ebpf/cmd/bpf2go sender sender.bpf.c

package main

import (
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main(){
	fmt.Print("Hello world\n")
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil { 
		log.Fatal("Removing memlock:", err)
	}
	
	// Load the compiled eBPF ELF and load it into the kernel.
	var objs senderObjects
	var opts = ebpf.CollectionOptions{Programs:ebpf.ProgramOptions{LogLevel:1}}
	if err := loadSenderObjects(&objs, &opts); err != nil {
		//this bit prints out the full log on error
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			log.Fatalf("%+v\n", verr)
		}
	} else {
		fmt.Print("verifier logs:\n")
		fmt.Print(objs.SenderOut.VerifierLog)
	}
	defer objs.Close()

	var iface *net.Interface
	var err error
	
	if iface, err = net.InterfaceByName("lo"); err!=nil{
		log.Fatalf("Could not get interface: %v",err)
	}
	
	tcxopts:=link.TCXOptions{
		Interface: iface.Index,
		Program: objs.SenderOut,
		Attach: ebpf.AttachTCXEgress,
	}

	l_out,err:=link.AttachTCX(tcxopts)
	if err!=nil{
		log.Fatalf("Error attaching the egress program: %v",err)
	}
	defer l_out.Close()

}
