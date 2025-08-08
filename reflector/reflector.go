//go:generate go run github.com/cilium/ebpf/cmd/bpf2go reflector reflector.bpf.c

package main

import (
	"errors"
	"log"
	"net"
	"os/user"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"sync"
)

// TODO: REFACTOR
func main(){	
	//check if we have root
	if usr,_:=user.Current();usr.Uid!="0" {
		log.Fatalf("Forgot sudo, dumbass")
	}
	
	// Load the compiled eBPF ELF and load it into the kernel.
	var objs reflectorObjects
	var opts = ebpf.CollectionOptions{Programs:ebpf.ProgramOptions{LogLevel:1}}
	if err := loadReflectorObjects(&objs, &opts); err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			log.Fatalf("Verifier error: %+v\n", verr) 
		}
		log.Fatalf("Error loading programs: %v",err)
		} else {
		log.Print("All programs successfully loaded and verified")
		log.Print(objs.ReflectorIn.VerifierLog)
		log.Print(objs.ReflectorOut.VerifierLog)
	}
	defer objs.Close()

	iface, err := net.InterfaceByName("eth0")
	if err!=nil{
		log.Fatalf("Could not get interface: %v",err)
	}
	
	tcxopts:=link.TCXOptions{
		Interface: iface.Index,
		Program: objs.ReflectorOut,
		Attach: ebpf.AttachTCXEgress,
	}
	l_out,err:=link.AttachTCX(tcxopts)
	if err!=nil{
		log.Fatalf("Error attaching the egress program: %v",err)
	}
	defer l_out.Close()

	tcxopts=link.TCXOptions{
		Interface: iface.Index,
		Program: objs.ReflectorIn,
		Attach: ebpf.AttachTCXIngress,
	}
	l_in,err:=link.AttachTCX(tcxopts)
	if err!=nil{
		log.Fatalf("Error attaching the egress program: %v",err)
	}
	defer l_in.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	wg.Wait()
}
