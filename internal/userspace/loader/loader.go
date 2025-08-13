package loader

import (
	"errors"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/viktordoronin/stamp-bpf/internal/bpf/reflector"
	"github.com/viktordoronin/stamp-bpf/internal/bpf/sender"
)

// TODO: make it into an interface with 2 different FD structs for sender and reflector, both with Close()

var FDs struct {
	SObjs sender.SenderObjects
	RObjs reflector.ReflectorObjects
	L_in,L_out link.Link
}

func CloseFDs(){
	FDs.SObjs.Close()
	FDs.RObjs.Close()
	FDs.L_in.Close()
	FDs.L_out.Close()
}

// TODO: error handling
func LoadSender(iface *net.Interface){
	// Load TCX programs
	var opts = ebpf.CollectionOptions{Programs:ebpf.ProgramOptions{LogLevel:1}}
	err := sender.LoadSenderObjects(&FDs.SObjs, &opts)
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			log.Fatalf("Verifier error: %+v\n", verr) 
		}
		log.Fatalf("Error loading programs: %v",err)
		} else {
		log.Print("All programs successfully loaded and verified")
		log.Print(FDs.SObjs.SenderOut.VerifierLog)
		log.Print(FDs.SObjs.SenderIn.VerifierLog)
	}
	
	// Attach TCX programs
	tcxopts:=link.TCXOptions{
		Interface: iface.Index,
		Program: FDs.SObjs.SenderOut,
		Attach: ebpf.AttachTCXEgress,
	}
	FDs.L_out,err=link.AttachTCX(tcxopts)
	if err!=nil{
		log.Fatalf("Error attaching the egress program: %v",err)
	}	
	tcxopts=link.TCXOptions{
		Interface: iface.Index,
		Program: FDs.SObjs.SenderIn,
		Attach: ebpf.AttachTCXIngress,
	}
	FDs.L_in,err=link.AttachTCX(tcxopts)
	if err!=nil{
		log.Fatalf("Error attaching the egress program: %v",err)
	}
}

func LoadReflector(objs *reflector.ReflectorObjects,l_out, l_in *link.Link, iface *net.Interface){
	var opts = ebpf.CollectionOptions{Programs:ebpf.ProgramOptions{LogLevel:1}}
	err := reflector.LoadReflectorObjects(objs, &opts)
	if err != nil {
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
		tcxopts:=link.TCXOptions{
		Interface: iface.Index,
		Program: objs.ReflectorOut,
		Attach: ebpf.AttachTCXEgress,
	}
	*l_out,err=link.AttachTCX(tcxopts)
	if err!=nil{
		log.Fatalf("Error attaching the egress program: %v",err)
	}
		tcxopts=link.TCXOptions{
		Interface: iface.Index,
		Program: objs.ReflectorIn,
		Attach: ebpf.AttachTCXIngress,
	}
	*l_in,err=link.AttachTCX(tcxopts)
	if err!=nil{
		log.Fatalf("Error attaching the egress program: %v",err)
	}
}
