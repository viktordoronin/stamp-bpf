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
	//this ticks twice as fast to account for the fact that this can start earlier than the actual packet arrives
	//they won't go out of sync either way but this should feel more responsive for longer intervals
	//shorter intervals will look bad tho, which is why we shouldn't do it this way
	ticker := time.NewTicker(interval / 2)
	var sample sender.SenderSample
	var met metricsCollection = newMetricsCollection(newSample(&sample))
	// we gotta set the initial metrics to zero
	// or else we get garbage output if the first packet gets lost
	// for some reason setting them in their own methods doesn't help but this does
	// and I honestly have zero desire to debug this
	// met.UpdatemetricsCollection(newSample(&sample))
	var record ringbuf.Record
	fmt.Printf("\n\n\n\n")
	for (pktCount+pktLost) < count || count == 0 {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		if rd.AvailableBytes() > 0 {
			record, err = rd.Read()
			//read a record
			if err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &sample); err != nil {
				return fmt.Errorf("Parsing ringbuf record: %w", err)
			}
			if validPacket(sample.Seq) == true {
				//update metrics
				met.UpdatemetricsCollection(newSample(&sample))
			}
		}
		// print out metrics
		fmt.Print(met.String())
		<-ticker.C
	}
	// gotta print it before exit to print the last packet received
	fmt.Print(met.String())
	return nil
}
