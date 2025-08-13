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

type FD interface {
	Close() error
}

type senderFD struct {
	Objs sender.SenderObjects
	L_in,L_out link.Link
}

func (s senderFD) Close() {
	s.Objs.Close()
	s.L_in.Close()
	s.L_out.Close()
}

type reflectorFD struct {
	Objs reflector.ReflectorObjects
	L_in,L_out link.Link
}

func (s reflectorFD) Close() {
	s.Objs.Close()
	s.L_in.Close()
	s.L_out.Close()
}

// TODO: error handling
func LoadSender(iface *net.Interface) senderFD{
	// Load TCX programs
	var Objs sender.SenderObjects
	var opts = ebpf.CollectionOptions{Programs:ebpf.ProgramOptions{LogLevel:1}}
	err := sender.LoadSenderObjects(&Objs, &opts)
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			log.Fatalf("Verifier error: %+v\n", verr) 
		}
		log.Fatalf("Error loading programs: %v",err)
		} else {
		log.Print("All programs successfully loaded and verified")
		log.Print(Objs.SenderOut.VerifierLog)
		log.Print(Objs.SenderIn.VerifierLog)
	}
	
	// Attach TCX programs
	tcxopts:=link.TCXOptions{
		Interface: iface.Index,
		Program: Objs.SenderOut,
		Attach: ebpf.AttachTCXEgress,
	}
	L_out,err:=link.AttachTCX(tcxopts)
	if err!=nil{
		log.Fatalf("Error attaching the egress program: %v",err)
	}	
	tcxopts=link.TCXOptions{
		Interface: iface.Index,
		Program: Objs.SenderIn,
		Attach: ebpf.AttachTCXIngress,
	}
	L_in,err:=link.AttachTCX(tcxopts)
	if err!=nil{
		log.Fatalf("Error attaching the egress program: %v",err)
	}
	return senderFD{Objs:Objs,L_in:L_in,L_out:L_out}
}

func LoadReflector(Objs *reflector.ReflectorObjects,L_out, L_in *link.Link, iface *net.Interface){
	var opts = ebpf.CollectionOptions{Programs:ebpf.ProgramOptions{LogLevel:1}}
	err := reflector.LoadReflectorObjects(Objs, &opts)
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			log.Fatalf("Verifier error: %+v\n", verr) 
		}
		log.Fatalf("Error loading programs: %v",err)
		} else {
		log.Print("All programs successfully loaded and verified")
		log.Print(Objs.ReflectorIn.VerifierLog)
		log.Print(Objs.ReflectorOut.VerifierLog)
	}
		tcxopts:=link.TCXOptions{
		Interface: iface.Index,
		Program: Objs.ReflectorOut,
		Attach: ebpf.AttachTCXEgress,
	}
	*L_out,err=link.AttachTCX(tcxopts)
	if err!=nil{
		log.Fatalf("Error attaching the egress program: %v",err)
	}
		tcxopts=link.TCXOptions{
		Interface: iface.Index,
		Program: Objs.ReflectorIn,
		Attach: ebpf.AttachTCXIngress,
	}
	*L_in,err=link.AttachTCX(tcxopts)
	if err!=nil{
		log.Fatalf("Error attaching the egress program: %v",err)
	}
}
