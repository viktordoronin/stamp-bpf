//go:build ignore
#include "stamp.bpf.h"

#include <stdint.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_endian.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/if_packet.h>

char __license[] SEC("license")="GPL";

//parsed packet's timestamps
/* struct packet_ts{ */
/*   uint64_t ts[4]; //0-1 are outbound journey, 2-3 are inbound */
/* }__attribute__((packed)); */

struct sample{
  uint32_t seq;
  uint64_t near,far,rt;
}__attribute__((packed));
  
//packet info - for output
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 4096);
  __type(value, struct sample);
} output SEC(".maps");

SEC("tcx/egress")
int sender_out(struct __sk_buff *skb){
  //RETURN VALUE: ALWAYS TCX_PASS

  //for-me check
  if ( ! for_me(skb, FORME_OUTBOUND) ) return TCX_PASS;
  
  // T1
  uint32_t offset=stampoffset(offsetof(struct senderpkt, t1_s));
  //timestamp at the last possible moment
  struct ntp_ts ts;
  timestamp(&ts);
  bpf_skb_store_bytes(skb, offset, &ts, sizeof(ts),0);
  return TCX_PASS;
} 

SEC("tc/ingress")
int sender_in(struct __sk_buff *skb){
  //RETURN VALUE: FOR-ME ? TCX_DROP : TCX_PASS
  
  //timestamp as soon as we get the packet
  uint64_t last_ts = bpf_ktime_get_tai_ns();

  //for-me check
  if (!for_me(skb, FORME_INBOUND)) return TCX_PASS;
  
  // grab the actual packet
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
    
  //Grab three stamps+seq
  struct reflectorpkt *rf = data + sizeof(struct iphdr) + sizeof(struct ethhdr) + sizeof(struct udphdr);
  if(data + sizeof(struct iphdr) + sizeof(struct ethhdr) + sizeof(struct udphdr) + sizeof(struct reflectorpkt) > data_end)
    return TCX_PASS;
  
  /* struct packet_ts timestamps; */
  uint64_t timestamps[4];
  struct sample s;
  struct ntp_ts ntpts;
  //grab seq
  s.seq=bpf_ntohl(rf->seq);
  //grab sender timestamp
  ntpts.ntp_secs=rf->t1_s;
  ntpts.ntp_fracs=rf->t1_f;
  timestamps[0]=untimestamp(&ntpts);
  //grab reflector stamps
  ntpts.ntp_secs=rf->t2_s;
  ntpts.ntp_fracs=rf->t2_f;
  timestamps[1]=untimestamp(&ntpts);
  ntpts.ntp_secs=rf->t3_s;
  ntpts.ntp_fracs=rf->t3_f;
  timestamps[2]=untimestamp(&ntpts);
  //save the last one we saved earlier
  timestamps[3]=last_ts;
  //calculate samples
  s.near=timestamps[1]-timestamps[0];
  s.far=timestamps[3]-timestamps[2];
  s.rt=timestamps[3]-timestamps[0];
  //send it
  bpf_ringbuf_output(&output, &s, sizeof(struct sample), 0);
   
  //We're done with the packet:
  return TCX_DROP; 
}
