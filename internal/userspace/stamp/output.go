package stamp

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/viktordoronin/stamp-bpf/internal/bpf/reflector"
	"github.com/viktordoronin/stamp-bpf/internal/bpf/sender"
)

func output(ctx context.Context, args Args) error {
	rd, err := ringbuf.NewReader(args.OutputMap)
	if err != nil {
		return fmt.Errorf("opening ringbuf reader: %w", err)
	}
	defer rd.Close()
	//this ticks twice as fast to account for the fact that this can start earlier than the actual packet arrives
	//they won't go out of sync either way but this should feel more responsive for longer intervals
	//shorter intervals will look bad tho, which is why we shouldn't do it this way
	ticker := time.NewTicker(args.Interval / 2)
	var sample sender.SenderSample
	var met metricsCollection = newMetricsCollection(newSample(&sample))
	var hist stampHist
	//this prints out the hist to a file, but only if we set --hist
	if args.Hist == true {
		histopts := histArgs{Bins: args.HistB, Floor: args.HistF, Ceil: args.HistC}
		hist = newHistogram(histopts)
	}
	var record ringbuf.Record
	fmt.Printf("\n\n\n\n")
	for (pktCount+pktLost) < args.Count || args.Count == 0 {
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
				if args.Hist == true {
					hist.updateHistogram(newSample(&sample).RT)
				}
			}
		}
		// print out metrics
		fmt.Print(met.String())
		<-ticker.C
	}
	// gotta print it before exit to print the last packet received
	fmt.Print(met.String())
	if args.Hist == true {
		os.WriteFile(args.HistPath, []byte(hist.String()), 0644)
	}
	return nil
}

func reflectorOutput(ctx context.Context, args Args) error {
	rd, err := ringbuf.NewReader(args.OutputMap)
	if err != nil {
		return fmt.Errorf("opening ringbuf reader: %w", err)
	}
	defer rd.Close()
	ticker := time.NewTicker(time.Millisecond*100)
	var sample reflector.ReflectorSample
	var met stampMetrics = newMetricsRecord()
	var hist stampHist
	//this prints out the hist to a file, but only if we set --hist
	if args.Hist == true {
		histopts := histArgs{Bins: args.HistB, Floor: args.HistF, Ceil: args.HistC}
		hist = newHistogram(histopts)
	}
	var record ringbuf.Record
	for {
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
			//update metrics
			met.updateMetrics(newRefSample(&sample).sam)
			if args.Hist == true {
				hist.updateHistogram(newRefSample(&sample).sam)
			}
		}
		// print out metrics
		fmt.Printf("%s \r",met.String())
		//we can't make assumptions regarding session length on reflector side
		//so we print a file every time we receive a packet
		if args.Hist == true {
			os.WriteFile(args.HistPath, []byte(hist.String()), 0644)
		}
		<-ticker.C
	}
}
