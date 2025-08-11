package metrics

import (
	"math"

	"github.com/viktordoronin/stamp-bpf/internal/bpf/sender"
)

// TODO: packet loss(RTO customizable, default 1 sec); emit a warning prompting to customize RTO on high enough loss
// ideas: goroutines, time.Timer, time.Ticker, time.AfterFunc() (favouring this rn)

// Packets can arrive out of order so we can't rely on packet's seq
// we do one session per sender run so we don't have to reinitialize it ever
var PktCount uint32=0

// a Sample is a trio of latencies calculated from 4 timestamps
// Samples are used once and discarded
type Sample struct{
	Near, Far, RT float64
}
func NewSample(timestamp *sender.SenderPacketTs) Sample{
	PktCount++
	return Sample{
		Near: (float64) ( timestamp.Ts[1] - timestamp.Ts[0] ) * 1e-6,
		Far: (float64) ( timestamp.Ts[3] - timestamp.Ts[2] ) * 1e-6,
		RT: (float64) ( timestamp.Ts[3] - timestamp.Ts[0] ) * 1e-6,
	}
}

// Metrics are network performance stats derived from latency
type StampMetrics struct {
	Min,Max,Avg,Jitter float64
}
func NewMetricsRecord() StampMetrics{
	//we need to set this to maximum or else it will remain 0 forever
	return StampMetrics{Min: math.MaxFloat64}
}
// we update our Metrics with each new Sample
func (metrics *StampMetrics) UpdateMetrics(sample float64){
	metrics.Min=math.Min(metrics.Min,sample)
	metrics.Max=math.Max(metrics.Max,sample)
	// math: suppose we got an average of 2 packets so far: avg=(x+y)/2
	// in order to dynamically recalculate average accounting for packet z, we have to reclaim original sum: sum=avg*2
	// add the new sample and get the new average: (sum+z)/3
	// full formula: avg=(oldavg*(pkts-1)+newpkt)/pkts
	metrics.Avg=(metrics.Avg*(float64(PktCount)-1)+sample)/float64(PktCount)
	// we define jitter as average deviation from the average ping, expressed in percent
	// no I don't know whether it makes sense or is even calculated correctly
	jit:=math.Abs(metrics.Avg-sample)
	jit=(jit*(float64(PktCount)-1)+sample)/float64(PktCount)
	metrics.Jitter=jit/(metrics.Avg/100)
}

// Collection contains Metrics for each of the three directions(inbound, outbound, roundtrip)
type Collection struct {
	Near, Far, RT StampMetrics
}
func NewCollection() Collection {
	return Collection{Near: NewMetricsRecord(), Far: NewMetricsRecord(), RT: NewMetricsRecord()}
}
//we can feed a sample to a collection and it will update itself
func (col *Collection) UpdateCollection(sample Sample){
	col.RT.UpdateMetrics(sample.RT)
	col.Far.UpdateMetrics(sample.Far)
	col.Near.UpdateMetrics(sample.Near)
}





