//go:generate go run github.com/cilium/ebpf/cmd/bpf2go sender sender.bpf.c

package main

import (
	"encoding/binary"
	"errors"
	"log"
	"net"
	"os/user"
	
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"sync"
)

type senderpacket struct{
	Seq uint32
	Ts_s uint32
	Ts_f uint32
	MBZ [32]byte
}

func main(){
	//check if we have root
	if usr,_:=user.Current();usr.Uid!="0" {
		log.Fatalf("Forgot sudo, dumbass")
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
		Seq: 0x69,
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

	var wg sync.WaitGroup
	wg.Add(1)
}
