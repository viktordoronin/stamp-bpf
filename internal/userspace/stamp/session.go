package stamp

import (
	"context"
	"log"
	"net"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sync/errgroup"
)

type Args struct{
	Dev *net.Interface
	Localaddr net.IP
	IP net.IP
	S_port, D_port int
	Interval time.Duration
	Count uint32
	OutputMap *ebpf.Map
}

func StartSession(args Args){
	eg,ctx:=errgroup.WithContext(context.Background())
	eg.Go(func () error { return send(ctx, args)})
	eg.Go(func () error { return output(ctx, args.OutputMap, args.Interval)})
	if err:=eg.Wait(); err!=nil{
		log.Fatalf("Error while running the STAMP session: %v",err)
	} 
}
