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
func dialReflector(iface *net.Interface) *net.UDPConn {
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

func StartSession(packet_count uint32, interval time.Duration, iface *net.Interface) {
	//setup
	conn:=dialReflector(iface)
	var seq uint32 = 1
	ticker:=time.NewTicker(interval)
	for packet_count >= seq || packet_count==0 {
		var buff = make([]byte,44)
		_,err:=binary.Encode(buff,binary.BigEndian,senderpacket{Seq: seq})
		if err!=nil{
			log.Fatalf("Encode error:",err)
		}	
		conn.Write(buff)
		seq++
		<- ticker.C
	}
}
