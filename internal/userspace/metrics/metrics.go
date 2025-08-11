package metrics

import "math"

type StampMetrics struct {
	Min,Max,Avg,Jitter float64
}

type PktCount uint32

// if I ever fold all three measurements(near/far/rt) into one object I'll be able to use this
// var pktCount PktCount

func NewRecord() StampMetrics{
	return StampMetrics{Min: math.MaxFloat64}
}

func (metrics *StampMetrics) CalcMetrics(sample float64, pktCount PktCount){
	metrics.Min=math.Min(metrics.Min,sample)
	metrics.Max=math.Max(metrics.Max,sample)
	// math: suppose we got an average of 2 packets so far: avg=(x+y)/2
	// in order to dynamically recalculate average accounting for packet z, we have to reclaim original sum: sum=avg/2
	// add the new packet and get the new average: (sum+z)/3
	// full formula: avg=(oldavg*(pkts-1)+newpkt)/pkts
	metrics.Avg=(metrics.Avg*(float64(pktCount)-1)+sample)/float64(pktCount)
	// we define jitter as average deviation from the average ping, expressed in percent
	// no I don't know whether it makes sense or is even calculated correctly
	jit:=math.Abs(metrics.Avg-sample)
	jit=(jit*(float64(pktCount)-1)+sample)/float64(pktCount)
	metrics.Jitter=jit/(metrics.Avg/100)
}
