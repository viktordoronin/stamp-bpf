//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -go-package reflector -output-dir reflector -target amd64 -verbose Reflector reflector.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -go-package sender -output-dir sender -target amd64 -verbose Sender sender.bpf.c

package stamp
