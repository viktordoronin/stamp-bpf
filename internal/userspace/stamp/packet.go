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

func dialReflector(iface *net.Interface, addr net.IP, s_port, d_port int) (*net.UDPConn, error) {
	addrs,err:=iface.Addrs()
	if err!=nil {
		return nil, fmt.Errorf("Error fetching local address of interface %s: %w",iface.Name,err)
	}
	localaddr:=net.UDPAddr{IP:net.ParseIP(addrs[0].String()),	Port: s_port}
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
	conn, err:=dialReflector(args.Dev, args.IP, args.S_port, args.D_port)
	if err!=nil{
		return fmt.Errorf("Error dialing reflector: %w",err)
	}
	var seq uint32 = 1
	ticker:=time.NewTicker(args.Interval)
	//send packets
	for args.Count >= seq || args.Count==0 {
		select {
		case <- ctx.Done(): return nil
		default:
		}
		var buff = make([]byte,44)
		_,err:=binary.Encode(buff,binary.BigEndian,senderpacket{Seq: seq})
		if err!=nil{
			return fmt.Errorf("Encode error: %w",err)
		}	
		conn.Write(buff)
		seq++
		<- ticker.C
	}
	return nil
}
