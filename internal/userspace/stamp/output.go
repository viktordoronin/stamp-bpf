package stamp

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/viktordoronin/stamp-bpf/internal/bpf/sender"
)

func output(ctx context.Context, output *ebpf.Map, interval time.Duration, count uint32) error {
	rd, err := ringbuf.NewReader(output)
	if err != nil {
		return fmt.Errorf("opening ringbuf reader: %w", err)
	}
	defer rd.Close()
	var met metricsCollection = newMetricsCollection()
	var record ringbuf.Record
	//this ticks twice as fast to account for the fact that this can start earlier than the actual packet arrives
	//they won't go out of sync either way but this should feel more responsive for longer intervals
	//shorter intervals will look bad tho, which is why we shouldn't do it this way
	ticker:=time.NewTicker(interval/2)
	var sample sender.SenderSample
	fmt.Printf("\n\n\n\n")
	// FIXME: the loop hangs up when we lose a packet, the total should be updated to make it seem responsive
	for ( pktCount + pktLost ) < count || count==0 {
		select {
		case <- ctx.Done(): return nil
		default:
		}
		record, err=rd.Read()
		if err!=nil{
			return fmt.Errorf("Error reading ringbuf:%w",err)
		}
		// this fires when we read a record
		if err==nil{
			//read a record
			if err=binary.Read(bytes.NewBuffer(record.RawSample),binary.LittleEndian, &sample); err!=nil {
				return fmt.Errorf("Parsing ringbuf record: %w",err)
			}
			if validPacket(sample.Seq) == true {
			//update metrics
				met.UpdatemetricsCollection(newSample(&sample)) }
		}
		//this flushes the previous output
		// print out metrics
		fmt.Print(met.String())
		<-ticker.C
	}
	return nil
}
