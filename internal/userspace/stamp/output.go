package stamp

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

var output chan metrics.Sample = make(chan metrics.Sample)

// TODO: output interval shouldn't be tied to packet sending interval: implement bulk sample reading

func ReadAndParse(rd *ringbuf.Reader, interval time.Duration){
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

func UpdateAndPrint(){
	m:=metrics.NewCollection()
	// this needs to be >= max length of an output line
	empty:=bytes.Repeat([]byte(" "),96)
	// make space for the output
	fmt.Printf("\n\n\n\n")
	for {
		//we gotta do it first because it conveniently hangs up until we receive a sample
		//btw this must be the dumbest syntax ever, why not just sample <- output ?
		sample := <- output
		//this flushes the previous output
		fmt.Printf("\033[F%s\033[F%[1]s\033[F%[1]s\033[F%[1]s\r",empty)
		// calculate latencies and update metrics
		m.UpdateCollection(sample)
		// print out metrics
		// TODO: this should be done in metrics package(likely a stringer)
		// TODO: PktCount should be managed by metrics, make it part of collection
		fmt.Printf("Packets processed: %d\n",metrics.PktCount) 
		fmt.Printf("Roundtrip: min %.3fms max %.3fms avg %.3fms last %.3fms jitter %.2f%%\n",m.RT.Min, m.RT.Max, m.RT.Avg, m.RT.Last, m.RT.Jitter)
		fmt.Printf("Near-end: min %.3fms max %.3fms avg %.3fms jitter %.2f%%\n",m.Near.Min, m.Near.Max, m.Near.Avg, m.Near.Jitter)
		fmt.Printf("Far-end: min %.3fms max %.3fms avg %.3fms jitter %.2f%%\n",m.Far.Min, m.Far.Max, m.Far.Avg, m.Far.Jitter)
	}
}
