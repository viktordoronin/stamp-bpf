package outputrdr

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"


	"github.com/cilium/ebpf/ringbuf"
	"github.com/viktordoronin/stamp-bpf/internal/bpf/sender"
	"github.com/viktordoronin/stamp-bpf/internal/userspace/metrics"
)

// TODO: refactor this shit (lmao)
	
func ReadOutput(rd *ringbuf.Reader){
	//packets can arrive out of order so we can't rely on packet seq
	var pktCount metrics.PktCount 
	var timestamp sender.SenderPacketTs
	var roundTrip = metrics.NewRecord()
	var nearEnd = metrics.NewRecord()
	var farEnd = metrics.NewRecord()
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
			roundTrip.CalcMetrics(sampleRT,pktCount)
			var sampleNear float64 = (float64) ( timestamp.Ts[1] - timestamp.Ts[0] ) * 1e-6
			nearEnd.CalcMetrics(sampleNear,pktCount)
			var sampleFar float64 = (float64) ( timestamp.Ts[3] - timestamp.Ts[2] ) * 1e-6
			farEnd.CalcMetrics(sampleFar,pktCount)
			// print out metrics
			fmt.Printf("Packets processed: %d\n",pktCount) // TODO: packet loss
			fmt.Printf("Roundtrip: min %.3fms max %.3fms avg %.3fms jitter %.2f%%\n",roundTrip.Min,roundTrip.Max,roundTrip.Avg, roundTrip.Jitter)
			fmt.Printf("Near-end: min %.3fms max %.3fms avg %.3fms\n",nearEnd.Min,nearEnd.Max,nearEnd.Avg)
			fmt.Printf("Far-end: min %.3fms max %.3fms avg %.3fms\n",farEnd.Min,farEnd.Max,farEnd.Avg)
			
		}
	}
}
