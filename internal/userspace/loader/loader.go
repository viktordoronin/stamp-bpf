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

// TODO: (struct loaderFDs, struct loaderArgs) before this gets out of hand
// TODO: error handling
func LoadSender(objs *sender.SenderObjects, l_out, l_in *link.Link, iface *net.Interface){
	// Load TCX programs
	var opts = ebpf.CollectionOptions{Programs:ebpf.ProgramOptions{LogLevel:1}}
	err := sender.LoadSenderObjects(objs, &opts)
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
	*l_out,err=link.AttachTCX(tcxopts)
	if err!=nil{
		log.Fatalf("Error attaching the egress program: %v",err)
	}	
	tcxopts=link.TCXOptions{
		Interface: iface.Index,
		Program: objs.SenderIn,
		Attach: ebpf.AttachTCXIngress,
	}
	*l_in,err=link.AttachTCX(tcxopts)
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
