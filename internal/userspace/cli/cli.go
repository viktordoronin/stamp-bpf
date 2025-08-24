package cli

import (
	"fmt"
	"net"
	"time"

	"github.com/alexflint/go-arg"
	"github.com/viktordoronin/stamp-bpf/internal/userspace/stamp"
)

func (senderArgs) Description() string {
	return "\nSTAMP Session-Sender\n"
}

func (senderArgs) Epilogue() string {
	return "head over to https://github.com/viktordoronin/stamp-bpf for more info and updates\n"
}

type senderArgs struct {
	Device   string   `arg:"positional,required" help:"network device to attach BPF programs to, e.g. eth0"`
	IP       string   `arg:"positional,required" help:"Session-Reflector's IP to send packets to"`
	Src      uint16   `arg:"-s" default:"862" help:"source port"`
	Dest     uint16   `arg:"-d" default:"862" help:"destination port"`
	Count    uint32   `arg:"-c,--" default:"0" help:"number of packets to send; infinite by default"`
	Interval float64  `arg:"-i,--" default:"1" help:"interval between packets sent, in seconds; takes sub-1 arguments"`
	Debug    bool     `help:"get BPF verifier output log and other debug info"`
	Timeout  uint32   `arg:"-w,--" default:"1" help:"timeout before a packet is considered lost, in seconds"`
	Hist     []uint32 `help:"print out a histogram, args: number of bins, value floor, value ceiling"`
	Histpath string   `default:"./hist" help:"output path for the histogram"`
	Sync     bool     `arg:"--enforce-sync" help:"abort if no clock syncing detected"`
	PTP      bool     `arg:"--enforce-ptp" help:"abort if no PTP syncing detected (assumes systemd, possibly unstable)"`
}

func ParseSenderArgs() stamp.Args {
	var args senderArgs
	var res stamp.Args
	res.Output = true
	parser := arg.MustParse(&args)

	// check privileges before we do anything else
	if err := CheckPrivileges(int(args.Src)); err != nil {
		parser.Fail(fmt.Sprint(err))
	}

	// grab interface
	if iface, err := net.InterfaceByName(args.Device); err != nil {
		parser.Fail(fmt.Sprintf("Could not get interface %s: %v", args.Device, err))
	} else {
		res.Dev = iface
	}

	// grab local IP
	addrs, err := res.Dev.Addrs()
	res.Localaddr, _, err = net.ParseCIDR(addrs[0].String())
	if res.Localaddr == nil || err != nil {
		parser.Fail(fmt.Sprintf("Failed to fetch local IP: %v", err))
	}

	// parse IP
	if parsedIP := net.ParseIP(args.IP); parsedIP == nil {
		parser.Fail(fmt.Sprintf("Can't parse IP: %s", args.IP))
	} else {
		res.IP = parsedIP
	}

	// cool hack - by making port numbers uint16, we limit them to 0-65536 without any explicit checks
	res.S_port = int(args.Src)
	res.D_port = int(args.Dest)

	if args.Interval <= 0 {
		parser.Fail(fmt.Sprintf("Interval has to be positive"))
	} else {
		res.Interval = time.Millisecond * time.Duration(args.Interval*1000)
	}

	if args.Timeout <= 0 {
		parser.Fail(fmt.Sprintf("Timeout has to be positive"))
	} else {
		res.Timeout = time.Second * time.Duration(args.Timeout)
	}

	res.Count = args.Count
	res.Debug = args.Debug
	res.Sync = args.Sync
	res.PTP = args.PTP

	if len(args.Hist) == 3 {
		res.Hist = true
		if args.Hist[0] < 3 {
			parser.Fail(fmt.Sprintf("the amount of bins has to be at least 3"))
		}
		res.HistB = args.Hist[0]
		res.HistF = args.Hist[1]
		res.HistC = args.Hist[2]
		res.HistPath = args.Histpath
	} else if len(args.Hist) != 0 {
		parser.Fail(fmt.Sprintf("--hist takes three args: bins, floor, ceiling"))
	} else {
		res.Hist = false
	}

	return res
}

func (reflectorArgs) Description() string {
	return "\nSTAMP Session-Reflector\n"
}

func (reflectorArgs) Epilogue() string {
	return "head over to https://github.com/viktordoronin/stamp-bpf for more info and updates\n"
}

type reflectorArgs struct {
	Device   string   `arg:"positional,required" help:"network device to attach BPF programs to, e.g. eth0"`
	Port     uint16   `arg:"-p" default:"862" help:"port to listen on"`
	Debug    bool     `help:"get BPF verifier output log and other debug info"`
	Output   bool     `help:"print output - CAN'T PROPERLY HANDLE SIMULTANEOUS SESSIONS, HIST ARGS WITHOUT THIS FLAG WILL BE IGNORED"`
	Hist     []uint32 `help:"print out a histogram, args: number of bins, value floor, value ceiling"`
	Histpath string   `default:"./hist" help:"output path for the histogram"`
	Sync     bool     `arg:"--enforce-sync" help:"abort if no clock syncing detected"`
	PTP      bool     `arg:"--enforce-ptp" help:"abort if no PTP syncing detected (assumes systemd, possibly unstable)"`
}

func ParseReflectorArgs() stamp.Args {
	var args reflectorArgs
	var res stamp.Args
	parser := arg.MustParse(&args)

	// check privileges before we do anything else
	if err := CheckPrivileges(int(args.Port)); err != nil {
		parser.Fail(fmt.Sprint(err))
	}

	// grab interface
	if iface, err := net.InterfaceByName(args.Device); err != nil {
		parser.Fail(fmt.Sprintf("Could not get interface %s: %v", args.Device, err))
	} else {
		res.Dev = iface
	}

	// grab local IP
	addrs, err := res.Dev.Addrs()
	res.Localaddr, _, err = net.ParseCIDR(addrs[0].String())
	if res.Localaddr == nil || err != nil {
		parser.Fail(fmt.Sprintf("Failed to fetch local IP: %v", err))
	}

	res.S_port = int(args.Port)
	res.Debug = args.Debug
	res.Output = args.Output
	res.Sync = args.Sync
	res.PTP = args.PTP

	if len(args.Hist) == 3 && args.Output == true {
		res.Hist = true
		if args.Hist[0] < 3 {
			parser.Fail(fmt.Sprintf("the amount of bins has to be at least 3"))
		}
		res.HistB = args.Hist[0]
		res.HistF = args.Hist[1]
		res.HistC = args.Hist[2]
		res.HistPath = args.Histpath
	} else if len(args.Hist) != 0 {
		parser.Fail(fmt.Sprintf("--hist takes three args: bins, floor, ceiling\nmaybe you forgot --output?"))
	} else {
		res.Hist = false
	}

	return res
}
