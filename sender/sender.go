//go:generate go run github.com/cilium/ebpf/cmd/bpf2go sender sender.bpf.c

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net"

	//	"time"

	//"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/viktordoronin/stamp-bpf/internals/userspace/privileges"
)

type senderpacket struct{
	Seq uint32
	Ts_s uint32
	Ts_f uint32
	MBZ [32]byte
}

func main(){
	// TODO: refactor this shit, it's a mess
	// TODO: CLI interface, config map passed from userspace
	//opts: source/dest IP, source/dest port, (down the line) stateless/stateful, (way down the line) reflector/sender

	//check privileges
	if err:=privileges.Check(); err!=nil{
		log.Fatalf("Error checking privileges: %s",err)
	}
	
	// Load the compiled eBPF ELF and load it into the kernel.
	var objs senderObjects
	var opts = ebpf.CollectionOptions{Programs:ebpf.ProgramOptions{LogLevel:1}}
	if err := loadSenderObjects(&objs, &opts); err != nil {
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
	
	//PACKET EMISSION
	localaddr:=net.UDPAddr{
		IP:net.ParseIP("172.17.0.1"),
		Port: 862,
	}
	remoteaddr:=net.UDPAddr{
		IP:net.ParseIP("172.17.0.2"),
		Port: 862,
	}
	conn, err:=net.DialUDP("udp",&localaddr,&remoteaddr)
	if err!=nil{
		log.Fatalf("Error connecting: ",err)
	}

	go func(){
		net.ListenUDP("udp",&localaddr)
		for{}
	}()
	
	mypacket:=senderpacket{
		Seq: 0x12,
		Ts_s: 0,
		Ts_f: 0,
	}	
	var buff = make([]byte,44)
	_,err=binary.Encode(buff,binary.BigEndian,mypacket)
	if err!=nil{
		log.Fatalf("Encode error:",err)
	}	
	conn.Write(buff)
	log.Print("(presumably) sent a packet...")

	rd, err := ringbuf.NewReader(objs.Output)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	// TODO: goroutines and continuously sending-parsing packets
	//will probably require to listen on the same socket
	
	//this goroutine polls the ringbuf every half a second 
	// var tsc = make(chan senderPacketTs)
	// go func(rd *ringbuf.Reader, tsc chan senderPacketTs){
	// 	var ts senderPacketTs
	// 	for {
	// 		record,err:=rd.Read()
	// 		if err!=nil{
	// 			log.Fatalf("Reading from ringbuf reader: %v",err)
	// 		}
	// 		if err:=binary.Read(bytes.NewBuffer(record.RawSample),binary.BigEndian, &ts); err!=nil {
	// 			log.Fatalf("Parsing ringbuf record: %v",err)
	// 			continue
	// 		}
	// 		tsc <- ts
	// 	}
	// }(rd,tsc)

	
	//I assume this blocks until received
	// timestamp = <- tsc

	var timestamp senderPacketTs
	var record ringbuf.Record
	for {
		record, err=rd.Read()
		if err==nil{
			break
		}
	}
	if err:=binary.Read(bytes.NewBuffer(record.RawSample),binary.LittleEndian, &timestamp); err!=nil {
		  log.Fatalf("Parsing ringbuf record: %v",err)
		}

	// TODO: min max avg jitter
	// TODO: packet loss(RTO customizable, default 1 sec); emit a warning prompting to customize RTO on high enough loss
	// ideas: goroutines, time.Timer, time.Ticker, time.AfterFunc() (favouring this rn)
	log.Printf("Sequence number: %d\nt1: %d\nt2: %d\nt3: %d\nt4: %d",timestamp.Seq, timestamp.Ts[0], timestamp.Ts[1], timestamp.Ts[2], timestamp.Ts[3])
	var roundtrip float64 = (float64) ( timestamp.Ts[3]-timestamp.Ts[0]) * 1e-6
	var outbound float64 = (float64) ( timestamp.Ts[1]-timestamp.Ts[0]) * 1e-6
	var inbound float64 = (float64) ( timestamp.Ts[3]-timestamp.Ts[2]) * 1e-6
	log.Printf("Latencies:\nNear-end: %.3f ms\nFar-end: %.3f ms\nRoundtrip: %.3f ms",outbound,inbound,roundtrip)
	
	// this hangs up the program without destroying your CPU
	// var wg sync.WaitGroup
	// wg.Add(1)
	// wg.Wait()
}
