package cli

import (
	"fmt"
	"net"
	"time"

	"github.com/alexflint/go-arg"
	"github.com/viktordoronin/stamp-bpf/internal/userspace/stamp"
)

type senderArgs struct {
	Dev string `arg:"positional,required"`
	IP string `arg:"positional,required"`
	Src uint16 `arg:"-s" default:"862"`
	Dest uint16 `arg:"-d" default:"862"`
	Count uint32 `arg:"-c,--" default:"0"`
	Interval float64 `arg:"-i,--" default:"1"`
}

func ParseSenderArgs() stamp.Args {
	var args senderArgs
	var res stamp.Args
	parser:=arg.MustParse(&args)
	
	// check privileges before we do anything else
	if err:=CheckPrivileges(int(args.Src)); err!=nil{
		parser.Fail(fmt.Sprint(err))
	}

	// grab interface
	// TODO: look into parsing /proc/net/route and see if we can infer the interface from the dest IP
	if iface, err := net.InterfaceByName(args.Dev); err!=nil {
		parser.Fail(fmt.Sprintf("Could not get interface %s: %v",args.Dev,err))
	} else { res.Dev=iface }
	
	// grab local IP
	addrs,err:=res.Dev.Addrs()
	res.Localaddr,_,err=net.ParseCIDR(addrs[0].String())
	if res.Localaddr==nil || err != nil {
		parser.Fail(fmt.Sprintf("Failed to fetch local IP: %v", err))
	}

	// parse IP
	if parsedIP:=net.ParseIP(args.IP); parsedIP==nil {
		parser.Fail(fmt.Sprintf("Can't parse IP: %s",args.IP))
	} else { res.IP=parsedIP }

	// cool hack - by making port numbers uint16, we limit them to 0-65536 without any explicit checks
	res.S_port=int(args.Src)
	res.D_port=int(args.Dest)

	if args.Interval<=0 {
		parser.Fail(fmt.Sprintf("Interval has to be positive"))
	} else { res.Interval=time.Millisecond*time.Duration(args.Interval*1000) }
	
	res.Count=args.Count
	
	return res
}

type reflectorArgs struct {
	Dev string `arg:"positional,required"`
	Src uint16 `arg:"-s" default:"862"`
}

func ParseReflectorArgs() stamp.Args {
	var args reflectorArgs
	var res stamp.Args
	parser:=arg.MustParse(&args)
	
	// check privileges before we do anything else
	if err:=CheckPrivileges(int(args.Src)); err!=nil{
		parser.Fail(fmt.Sprint(err))
	}	
	
	// grab interface
	if iface, err := net.InterfaceByName(args.Dev);err!=nil{
		parser.Fail(fmt.Sprintf("Could not get interface %s: %v",args.Dev,err))
	} else {res.Dev=iface}

	// grab local IP
	addrs,err:=res.Dev.Addrs()
	res.Localaddr,_,err=net.ParseCIDR(addrs[0].String())
	if res.Localaddr==nil || err != nil {
		parser.Fail(fmt.Sprintf("Failed to fetch local IP: %v", err))
	}

	res.S_port=int(args.Src)

	return res	
}
