package pktsender

import (
	"encoding/binary"
	"log"
	"net"
	"time"
)

type senderpacket struct{
	Seq uint32
	Ts_s uint32
	Ts_f uint32
	MBZ [32]byte
}

// TODO: implement errors
// TODO: goroutine error handling
func dialReflector() *net.UDPConn {
	// TODO: remove this when I move away from hardcoded interfaces
	iface, err := net.InterfaceByName("docker0")
	if err!=nil{
		log.Fatalf("Could not get interface: %v",err)
	}
	addrs,_:=iface.Addrs()	
	localaddr:=net.UDPAddr{
		IP:net.ParseIP(addrs[0].String()),
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
	return conn
}

// TODO: revisit on the weekend to see if this can be improved
func StartSession(packet_count uint32, interval time.Duration) {
	//setup
	conn:=dialReflector()
	var seq uint32 = 1
	ticker:=time.NewTicker(interval)

	for packet_count >= seq {
		var buff = make([]byte,44)
		_,err:=binary.Encode(buff,binary.BigEndian,senderpacket{Seq: seq})
		if err!=nil{
			log.Fatalf("Encode error:",err)
		}	
		conn.Write(buff)
		log.Print("Sent a packet")
		seq++
		<- ticker.C
	}
}
