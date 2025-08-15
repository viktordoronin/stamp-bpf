package stamp

import (
	"fmt"
	"math"
	"strings"

	"github.com/viktordoronin/stamp-bpf/internal/bpf/sender"
)

// TODO: packet loss(RTO customizable, default 1 sec); emit a warning prompting to customize RTO on high enough loss
// ideas: goroutines, time.Timer, time.Ticker, time.AfterFunc() (favouring this rn)

// Packets can arrive out of order so we can't rely on packet's seq
// we do one session per sender run so we don't have to reinitialize it ever
var pktCount uint32=0

// a Sample is a trio of latencies calculated from 4 timestamps
// Samples are used once and discarded
type sample struct{
	Seq uint32
	Near, Far, RT float64
}
func newSample(s *sender.SenderSample) sample{
	return sample{
		Near: (float64) (s.Near)  * 1e-6,
		Far: (float64) ( s.Far ) * 1e-6,
		RT: (float64) ( s.Rt ) * 1e-6,
		Seq: s.Seq,
	}
}

// Metrics are network performance stats derived from latency
type stampMetrics struct {
	Min,Max,Avg,Jitter,Last float64
	jitterAbs float64
}
func newMetricsRecord() stampMetrics{
	//we need to set this to maximum or else it will remain 0 forever
	return stampMetrics{Min: math.MaxFloat64}
}
// we update our Metrics with each new Sample
func (m *stampMetrics) updateMetrics(sample float64){
	m.Last=sample
	m.Min=math.Min(m.Min,sample)
	m.Max=math.Max(m.Max,sample)
	// math: suppose we got an average of 2 packets so far: avg=(x+y)/2
	// in order to dynamically recalculate average accounting for packet z, we have to reclaim original sum: sum=avg*2
	// add the new sample and get the new average: (sum+z)/3
	// full formula: avg=(oldavg*(pkts-1)+newpkt)/pkts
	m.Avg=(m.Avg*(float64(pktCount)-1)+sample)/float64(pktCount)
	// we define jitter as average deviation from the average ping, expressed in percent
	// no I don't know whether it makes sense or is even calculated correctly
	diff:=math.Abs(m.Avg-sample)	
	m.jitterAbs=(m.jitterAbs*(float64(pktCount)-1)+diff)/float64(pktCount)
	m.Jitter=m.jitterAbs/(m.Avg/100)
}
func (m *stampMetrics) String() string{
	return fmt.Sprintf("min %7.3fms max %7.3fms avg %7.3fms last %7.3fms jitter %6.2f%%",m.Min,m.Max,m.Avg,m.Last,m.Jitter)
}

// MetricsCollection contains Metrics for each of the three directions(inbound, outbound, roundtrip)
type metricsCollection struct {
	Near, Far, RT stampMetrics
}
func newMetricsCollection() metricsCollection {
	return metricsCollection{Near: newMetricsRecord(), Far: newMetricsRecord(), RT: newMetricsRecord()}
}
//we can feed a sample to a collection and it will update itself
func (col *metricsCollection) UpdatemetricsCollection(sample sample){
	pktCount++
	col.RT.updateMetrics(sample.RT)
	col.Far.updateMetrics(sample.Far)
	col.Near.updateMetrics(sample.Near)
}
func (col *metricsCollection) String() string{
	var res strings.Builder
	fmt.Fprintf(&res,"\033[F\033[F\033[F\033[FPackets processed: %d\n",pktCount)
	fmt.Fprintf(&res,"Near-end:  %s\n",col.Near.String())
	fmt.Fprintf(&res,"Far-end:   %s\n",col.Far.String())
	fmt.Fprintf(&res,"Roundtrip: %s\n",col.RT.String())	
	return res.String()
}
