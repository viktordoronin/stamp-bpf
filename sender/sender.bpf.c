//go:build ignore

#include "../headers/stamp.h"

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

//histogram - just an array
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, 20);
} hist SEC(".maps");

//parsed packet's timestamps
struct packet_ts{
  uint32_t seq;
  uint64_t ts[4]; //0-1 are outbound journey, 2-3 are inbound
}__attribute__((packed));

//packet info - for output
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 4096);
  __type(value, struct packet_ts);
} output SEC(".maps");

SEC("tcx/egress")
int sender_out(struct __sk_buff *skb){
  //RETURN VALUE: ALWAYS TCX_PASS
  //TODO: Refactor this checking sequence into a separate function
  //is it an IP packet?
  if(skb->protocol!=bpf_htons(ETH_P_IP)) return TCX_PASS;
  //grab the actual packet
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;  
  //IP header
  struct iphdr *iph = data+sizeof(struct ethhdr);
  //these kinds of checks are mandated by the eBPF verifier, without them the program won't get loaded
  if (data + sizeof(struct iphdr) + sizeof(struct ethhdr) > data_end) return TCX_PASS;
  //Is it UDP?
  if (iph->protocol!=IPPROTO_UDP) return TCX_PASS;
  //UDP header
  struct udphdr *udph = data + sizeof(struct iphdr)+sizeof(struct ethhdr);
  if (data + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct ethhdr) > data_end) return TCX_PASS;
  //862 is a well-known TWAMP port
  //we'll need some communication mechanism for custom ports
  if (udph->dest!=bpf_ntohs(862) || udph->source!=bpf_ntohs(862)) return TCX_PASS;
  
  // now we can timestamp it
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

  //is it IP?
  if(skb->protocol!=bpf_htons(ETH_P_IP)){
    return TCX_PASS;
  }
  
  //grab the actual packet
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  
  //IP header
  struct iphdr *iph = data+sizeof(struct ethhdr);
  //these kinds of checks are mandated by the eBPF verifier, without them the program won't get loaded
  if (data + sizeof(struct iphdr) + sizeof(struct ethhdr) > data_end)
    return TCX_PASS;
  //TODO: is it for us? (send the local IP from userspace as part of the config)
  /* if(iph->daddr!=skb->local_ip4) { */
  /*   bpf_printk("Failed for-me IP check"); */
  /*   return TCX_PASS; */
  /* } */
  
  //Is it UDP?
  if (iph->protocol!=IPPROTO_UDP){
    return TCX_PASS;
  }
  
  //UDP header
  struct udphdr *udph = data + sizeof(struct iphdr)+sizeof(struct ethhdr);
  if (data + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct ethhdr) > data_end)
    return TCX_PASS;
  //862 is a well-known TWAMP port
  //we'll need some communication mechanism for custom ports
  if (udph->dest!=bpf_ntohs(862) || udph->source!=bpf_ntohs(862)){
    return TCX_PASS;
  }

  //Grab three stamps+seq
  struct reflectorpkt *rf = data + sizeof(struct iphdr) + sizeof(struct ethhdr) + sizeof(struct udphdr);
  if(data + sizeof(struct iphdr) + sizeof(struct ethhdr) + sizeof(struct udphdr) + sizeof(struct reflectorpkt) > data_end)
    return TCX_PASS;
  
  struct packet_ts timestamps;
  struct ntp_ts ntpts;
  //grab seq
  timestamps.seq=bpf_ntohl(rf->seq);
  //grab sender timestamp
  ntpts.ntp_secs=rf->t1_s;
  ntpts.ntp_fracs=rf->t1_f;
  timestamps.ts[0]=untimestamp(&ntpts);
  //grab reflector stamps
  ntpts.ntp_secs=rf->t2_s;
  ntpts.ntp_fracs=rf->t2_f;
  timestamps.ts[1]=untimestamp(&ntpts);
  ntpts.ntp_secs=rf->t3_s;
  ntpts.ntp_fracs=rf->t3_f;
  timestamps.ts[2]=untimestamp(&ntpts);
  //save the last one we saved earlier
  timestamps.ts[3]=last_ts;
  //send it
  bpf_ringbuf_output(&output, &timestamps, sizeof(struct packet_ts), 0);
  
  //TODO: histogram
  
  //We're done with the packet:
  return TCX_DROP;
}
