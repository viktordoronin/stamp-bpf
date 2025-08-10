//go:generate go run github.com/cilium/ebpf/cmd/bpf2go sender sender.bpf.c

package main

import (
	"errors"
	"log"
	"net"
	"time"

	//	"time"

	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/viktordoronin/stamp-bpf/internals/bpf/sender"
	"github.com/viktordoronin/stamp-bpf/internals/userspace/outputrdr"
	"github.com/viktordoronin/stamp-bpf/internals/userspace/pktsender"
	"github.com/viktordoronin/stamp-bpf/internals/userspace/privileges"
)

func main(){
	// TODO: refactor this shit, it's a mess
	// TODO: CLI interface, config map passed from userspace
	//opts: source/dest IP, source/dest port, (down the line) stateless/stateful, (way down the line) reflector/sender

	//check privileges
	if err:=privileges.Check(); err!=nil{
		log.Fatalf("Error checking privileges: %s",err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs sender.SenderObjects
	var l_in, l_out link.Link
	var opts = ebpf.CollectionOptions{Programs:ebpf.ProgramOptions{LogLevel:1}}
	if err := sender.LoadSenderObjects(&objs, &opts); err != nil {
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
	defer objs.Close()

	// Attach TCX programs
	iface, err := net.InterfaceByName("docker0")
	if err!=nil{
		log.Fatalf("Could not get interface: %v",err)
	}
	tcxopts:=link.TCXOptions{
		Interface: iface.Index,
		Program: objs.SenderOut,
		Attach: ebpf.AttachTCXEgress,
	}
	l_out,err=link.AttachTCX(tcxopts)
	if err!=nil{
		log.Fatalf("Error attaching the egress program: %v",err)
	}
	defer l_out.Close()
	tcxopts=link.TCXOptions{
		Interface: iface.Index,
		Program: objs.SenderIn,
		Attach: ebpf.AttachTCXIngress,
	}
	l_in,err=link.AttachTCX(tcxopts)
	if err!=nil{
		log.Fatalf("Error attaching the egress program: %v",err)
	}
	defer l_in.Close()
	
	// send packets
	// FYI ping default delay is 1 sec
	go pktsender.StartSession(50, time.Second)

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
