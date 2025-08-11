package output

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/viktordoronin/stamp-bpf/internal/bpf/sender"
	"github.com/viktordoronin/stamp-bpf/internal/userspace/metrics"
)

// TODO: refactor this shit (lmao)
// rough outline of what I intended to do:
// metrics now has a new struct called Samples
// ReadAndParse() parses timestamps into 3 samples and sends them into channel
// We can implement it as NewSample() that increments PkgCount!
// Printout() calls metrics pkg to calculate metrics and print the whole thing out

func ReadAndParse(rd *ringbuf.Reader, output chan<- metrics.Sample, interval time.Duration){
	//this ticks twice as fast to account for the fact that this can start earlier than the actual packet arrives
	//they won't go out of sync either way but this should feel more responsive for longer intervals
	ticker:=time.NewTicker(interval/2)
	var timestamp sender.SenderPacketTs
	// TODO: this needs to loop only until we've read <num> packets; implement after packet loss
	for{
		record, err:=rd.Read()
		// this fires when we read a record
		// TODO: account for actual read errors aside from pipe empty
		if err==nil{
			//read a record
			if err:=binary.Read(bytes.NewBuffer(record.RawSample),binary.LittleEndian, &timestamp); err!=nil {
				log.Fatalf("Parsing ringbuf record: %v",err)
			}
		}
		output <- metrics.NewSample(&timestamp)
		<-ticker.C
	}
}

func Printout(output <-chan metrics.Sample){
	// TODO: make this look better(metrics collection?)
	var roundTrip = metrics.NewRecord()
	var nearEnd = metrics.NewRecord()
	var farEnd = metrics.NewRecord()
	// this needs to be >= max length of an output line
	empty:=bytes.Repeat([]byte(" "),64)
	// make space for the output
	fmt.Printf("\n\n\n\n")
	for {
		//we gotta do it first because it conveniently hangs up until we receive a sample
		//btw this must be the dumbest syntax ever, why not just sample <- output ?
		sample := <- output
		//this flushes the previous output
		fmt.Printf("\033[F%s\033[F%[1]s\033[F%[1]s\033[F%[1]s\r",empty)
		// calculate latencies and update metrics
		// TODO: move to metrics package
		// TODO: make this work with the new sample format
		roundTrip.CalcMetrics(sampleRT,pktCount)			
		nearEnd.CalcMetrics(sampleNear,pktCount)			
		farEnd.CalcMetrics(sampleFar,pktCount)
		// print out metrics
		fmt.Printf("Packets processed: %d\n",metrics.PktCount) // TODO: packet loss
		fmt.Printf("Roundtrip: min %.3fms max %.3fms avg %.3fms jitter %.2f%%\n",roundTrip.Min,roundTrip.Max,roundTrip.Avg, roundTrip.Jitter)
		fmt.Printf("Near-end: min %.3fms max %.3fms avg %.3fms\n",nearEnd.Min,nearEnd.Max,nearEnd.Avg)
		fmt.Printf("Far-end: min %.3fms max %.3fms avg %.3fms\n",farEnd.Min,farEnd.Max,farEnd.Avg)
	}
}
