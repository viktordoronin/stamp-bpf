//go:generate go run github.com/cilium/ebpf/cmd/bpf2go sender sender.bpf.c

package main

import (
	"github.com/viktordoronin/stamp-bpf/internal/userspace/cli"
	"github.com/viktordoronin/stamp-bpf/internal/userspace/loader"
	"github.com/viktordoronin/stamp-bpf/internal/userspace/stamp"
)

func main() {
	//parse and validate args, get a struct with the stuff we will need
	args := cli.ParseSenderArgs()

	// Load the compiled eBPF ELF and load it into the kernel
	bpf := loader.LoadSender(args)
	args.OutputMap = bpf.Objs.Output
	defer bpf.Close()

	// start the STAMP session, all gofuncs are managed in this func
	stamp.StartSession(args)
}
