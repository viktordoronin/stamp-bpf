package stamp

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

type senderpacket struct{
	Seq uint32
	Ts_s uint32
	Ts_f uint32
	MBZ [32]byte
}

func dialReflector(laddr, addr net.IP, s_port, d_port int) (*net.UDPConn, error) {
	localaddr:=net.UDPAddr{IP:laddr,	Port: s_port}
	var remoteaddr net.UDPAddr
	remoteaddr=net.UDPAddr{IP: addr, Port: d_port}
	conn, err:=net.DialUDP("udp",&localaddr,&remoteaddr)
	if err!=nil{
		return nil, fmt.Errorf("Error connecting: %w",err)
	}
	return conn, nil
}

func send(ctx context.Context, args Args) error {
	//setup
	conn, err:=dialReflector(args.Localaddr, args.IP, args.S_port, args.D_port)
	if err!=nil{
		return fmt.Errorf("Error dialing reflector: %w",err)
	}
	var seq uint32 = 1
	var buff = make([]byte,44)
	ticker:=time.NewTicker(args.Interval)
	//send packets
	for args.Count >= seq || args.Count==0 {
		select {
		case <- ctx.Done(): return nil
		default:
		}
		_,err:=binary.Encode(buff,binary.BigEndian,senderpacket{Seq: seq})
		if err!=nil{
			return fmt.Errorf("Encode error: %w",err)
		}	
		conn.Write(buff)
		queuePacket(seq,args.Timeout)
		seq++
		<- ticker.C
	}
	return nil
}
