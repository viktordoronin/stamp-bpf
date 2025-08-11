package outputrdr

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"math"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/viktordoronin/stamp-bpf/internals/bpf/sender"
)

// TODO: refactor this shit (lmao)

//this needs to be global to calculate average; packets can arrive out of order so we can't rely on packet seq
var pktCount uint32 = 0

type stampMetrics struct {
	min,max,avg,jitter float64
}

func (metrics * stampMetrics) calcMetrics(sample float64){
	metrics.min=math.Min(metrics.min,sample)
	metrics.max=math.Max(metrics.max,sample)
	// math: suppose we got an average of 2 packets so far: avg=(x+y)/2
	// in order to dynamically recalculate average accounting for packet z, we have to reclaim original sum: sum=avg/2
	// add the new packet and get the new average: (sum+z)/3
	// full formula: avg=(oldavg*(pkts-1)+newpkt)/pkts
	metrics.avg=(metrics.avg*(float64(pktCount)-1)+sample)/float64(pktCount)
	// we define jitter as average deviation from the average ping, expressed in percent
	// no I don't know whether it makes sense or is even calculated correctly
	jit:=math.Abs(metrics.avg-sample)
	jit=(jit*(float64(pktCount)-1)+sample)/float64(pktCount)
	metrics.jitter=jit/(metrics.avg/100)
}
	
func ReadOutput(rd *ringbuf.Reader){
	var timestamp sender.SenderPacketTs
	var roundTrip, nearEnd, farEnd stampMetrics
	// this is fucking dumb but still less dumb than Go not having default struct values
	roundTrip.min=math.MaxFloat64
	nearEnd.min=math.MaxFloat64
	farEnd.min=math.MaxFloat64
	// this needs to be >= max length of an output line
	empty:=bytes.Repeat([]byte(" "),64)
	// make space for the output
	fmt.Printf("\n\n\n\n")
	// TODO: this needs to loop only until we've read <num> packets; implement after packet loss
	for {
		record, err:=rd.Read()
		// this fires when we read a record
		// TODO: I should probably read this in a separate goroutine and send the sample through a channel
		// TODO: account for actual read errors aside from pipe empty
		if err==nil{
			//read a record
			if err:=binary.Read(bytes.NewBuffer(record.RawSample),binary.LittleEndian, &timestamp); err!=nil {
				log.Fatalf("Parsing ringbuf record: %v",err)
			}
			pktCount++
			// calculate metrics and print them out
			// TODO: packet loss(RTO customizable, default 1 sec); emit a warning prompting to customize RTO on high enough loss
			// ideas: goroutines, time.Timer, time.Ticker, time.AfterFunc() (favouring this rn)
			//this flushes the previous output
			fmt.Printf("\033[F%s\033[F%[1]s\033[F%[1]s\033[F%[1]s\r",empty)
			// calculate latencies and update metrics
			var sampleRT float64 = (float64) ( timestamp.Ts[3] - timestamp.Ts[0] ) * 1e-6
			roundTrip.calcMetrics(sampleRT)
			var sampleNear float64 = (float64) ( timestamp.Ts[1] - timestamp.Ts[0] ) * 1e-6
			nearEnd.calcMetrics(sampleNear)
			var sampleFar float64 = (float64) ( timestamp.Ts[3] - timestamp.Ts[2] ) * 1e-6
			farEnd.calcMetrics(sampleFar)
			// print out metrics
			fmt.Printf("Packets processed: %d\n",pktCount) // TODO: packet loss
			fmt.Printf("Roundtrip: min %.3fms max %.3fms avg %.3fms jitter %.2f%%\n",roundTrip.min,roundTrip.max,roundTrip.avg, roundTrip.jitter)
			fmt.Printf("Near-end: min %.3fms max %.3fms avg %.3fms\n",nearEnd.min,nearEnd.max,nearEnd.avg)
			fmt.Printf("Far-end: min %.3fms max %.3fms avg %.3fms\n",farEnd.min,farEnd.max,farEnd.avg)
			
		}
	}
}
