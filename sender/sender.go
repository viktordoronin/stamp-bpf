//go:generate go run github.com/cilium/ebpf/cmd/bpf2go sender sender.bpf.c

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"time"

	//	"time"

	// "sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/viktordoronin/stamp-bpf/internals/bpf/sender"
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
	l_out,err:=link.AttachTCX(tcxopts)
	if err!=nil{
		log.Fatalf("Error attaching the egress program: %v",err)
	}
	defer l_out.Close()
	tcxopts=link.TCXOptions{
		Interface: iface.Index,
		Program: objs.SenderIn,
		Attach: ebpf.AttachTCXIngress,
	}
	l_in,err:=link.AttachTCX(tcxopts)
	if err!=nil{
		log.Fatalf("Error attaching the egress program: %v",err)
	}
	defer l_in.Close()

	//send packets
	go pktsender.StartSession(3, time.Second)

	//READ OUTPUT
	// TODO: refactor into a goroutinable package
	rd, err := ringbuf.NewReader(objs.Output)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	var timestamp sender.SenderPacketTs
	var record ringbuf.Record
	// TODO: this needs to loop only until we've read <num> packets; implement after packet loss
	for {
		record, err=rd.Read()
		//this fires when we read a record
		if err==nil{
			//read a record
			if err:=binary.Read(bytes.NewBuffer(record.RawSample),binary.LittleEndian, &timestamp); err!=nil {
				log.Fatalf("Parsing ringbuf record: %v",err)
			}
			//calculate metrics and print them out
			// TODO: min max avg jitter
			// TODO: packet loss(RTO customizable, default 1 sec); emit a warning prompting to customize RTO on high enough loss
			// ideas: goroutines, time.Timer, time.Ticker, time.AfterFunc() (favouring this rn)
			var roundtrip float64 = (float64) ( timestamp.Ts[3]-timestamp.Ts[0]) * 1e-6
			var outbound float64 = (float64) ( timestamp.Ts[1]-timestamp.Ts[0]) * 1e-6
			var inbound float64 = (float64) ( timestamp.Ts[3]-timestamp.Ts[2]) * 1e-6
			log.Printf("Sequence number: %d",timestamp.Seq)
			log.Printf("Latencies:\nNear-end: %.3f ms\nFar-end: %.3f ms\nRoundtrip: %.3f ms",outbound,inbound,roundtrip)
		}
	}
	
	// log.Printf("Sequence number: %d\nt1: %d\nt2: %d\nt3: %d\nt4: %d",timestamp.Seq, timestamp.Ts[0], timestamp.Ts[1], timestamp.Ts[2], timestamp.Ts[3])

	
	// this hangs up the program without destroying your CPU
	// var wg sync.WaitGroup
	// wg.Add(1)
	// wg.Wait()
}
