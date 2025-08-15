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

type fd interface {
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

func LoadSender(iface *net.Interface) senderFD{
	// Load TCX programs
	var objs sender.SenderObjects
	var opts = ebpf.CollectionOptions{Programs:ebpf.ProgramOptions{LogLevel:1}}
	err := sender.LoadSenderObjects(&objs, &opts)
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			log.Fatalf("Verifier error: %+v\n", verr) 
		}
		log.Fatalf("Error loading programs: %v",err)
		} else {
		log.Print("All programs successfully loaded and verified")
		log.Print(objs.SenderOut.VerifierLog)
		log.Print(objs.SenderIn.VerifierLog)
	}
	
	// Attach TCX programs
	tcxopts:=link.TCXOptions{
		Interface: iface.Index,
		Program: objs.SenderOut,
		Attach: ebpf.AttachTCXEgress,
	}
	l_out,err:=link.AttachTCX(tcxopts)
	if err!=nil{
		log.Fatalf("Error attaching the egress program: %v",err)
	}	
	tcxopts=link.TCXOptions{
		Interface: iface.Index,
		Program: objs.SenderIn,
		Attach: ebpf.AttachTCXIngress,
	}
	l_in,err:=link.AttachTCX(tcxopts)
	if err!=nil{
		log.Fatalf("Error attaching the ingress program: %v",err)
	}
	return senderFD{Objs:objs,L_in:l_in,L_out:l_out}
}

func LoadReflector(iface *net.Interface) reflectorFD{
	var objs reflector.ReflectorObjects
	var opts = ebpf.CollectionOptions{Programs:ebpf.ProgramOptions{LogLevel:1}}
	err := reflector.LoadReflectorObjects(&objs, &opts)
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
	l_out,err:=link.AttachTCX(tcxopts)
	if err!=nil{
		log.Fatalf("Error attaching the egress program: %v",err)
	}
		tcxopts=link.TCXOptions{
		Interface: iface.Index,
		Program: objs.ReflectorIn,
		Attach: ebpf.AttachTCXIngress,
	}
	l_in,err:=link.AttachTCX(tcxopts)
	if err!=nil{
		log.Fatalf("Error attaching the ingress program: %v",err)
	}
	return reflectorFD{Objs:objs,L_in:l_in,L_out:l_out}
}
