package stamp

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sync/errgroup"
)

type Args struct {
	Dev                 *net.Interface
	Localaddr           net.IP
	IP                  net.IP
	S_port, D_port      int
	Interval            time.Duration
	Count               uint32
	OutputMap           *ebpf.Map
	Debug               bool
	Timeout             time.Duration
	Hist                bool
	HistB, HistF, HistC uint32
	HistPath            string
	Output              bool
	Sync, PTP           bool
}

func StartSession(args Args) {
	var cnt string
	if args.Count == 0 {
		cnt = "infinite"
	} else {
		cnt = fmt.Sprintf("%d", args.Count)
	}
	fmt.Printf("Stateless unauthenticated STAMP session between %s:%d and %s:%d\n%s packets sent at %.3fs interval with %.fs timeout\n\n", args.Localaddr.String(), args.S_port, args.IP.String(), args.D_port, cnt, args.Interval.Seconds(), args.Timeout.Seconds())
	eg, ctx := errgroup.WithContext(context.Background())
	eg.Go(func() error { return send(ctx, args) })
	eg.Go(func() error { return output(ctx, args) })
	if err := eg.Wait(); err != nil {
		log.Fatalf("Error while running the STAMP session: %v", err)
	}
}

func RefSession(args Args) {
	if args.Output == true {
		fmt.Println("Printing out session metrics as they arrive")
		eg, ctx := errgroup.WithContext(context.Background())
		eg.Go(func() error { return reflectorOutput(ctx, args) })
		if err := eg.Wait(); err != nil {
			log.Fatalf("Error while running the STAMP session: %v", err)
		}
	}
}
