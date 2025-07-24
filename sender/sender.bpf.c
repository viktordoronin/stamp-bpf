//go:build ignore

#include "../bpf/stamp.h"

#include <stdint.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
//includes for packet header structs below
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_endian.h>
#include <linux/udp.h>

char __license[] SEC("license")="GPL";

//histogram - just an array
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(value, __u32);
  __uint(max_entries, 20);
} hist SEC(".maps");

//parsed packet's timestamps
struct packet_ts{
  uint32_t seq;
  uint64_t ts[4];
};

//packet info - for output
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 4096);
  __type(value, struct packet_ts);
} output SEC(".maps");

SEC("tcx/egress")
int sender_out(struct __sk_buff *skb){
  //RETURN VALUE: ALWAYS TCX_PASS

  //for-me check
  //is it IP?
  //we have to do this every time we want to consult an *skb field
  //since *skb just points to an actual SKB in the kernel
  __u32 proto;
  bpf_probe_read_kernel(&proto,sizeof(__u32),&skb->protocol);
  if(proto!=ETH_P_IP)
    return TCX_PASS;
  //862 is a well-known TWAMP port
  //we'll need some communication mechanism for custom ports
  __u32 local_port, remote_port;
  bpf_probe_read_kernel(&local_port,sizeof(__u32),&skb->local_port);
  bpf_probe_read_kernel(&remote_port,sizeof(__u32),&skb->remote_port);
  if(local_port!=862 && remote_port!=862)
    return TCX_PASS;
  
  //grab the actual packet
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  
  //IP header
  struct iphdr *iph = data;
  //these kinds of checks are mandated by the eBPF verifier, without them the program won't get loaded
  //sometimes(like here) they can be skipped
  /* if (data + sizeof(struct iphdr) > data_end) */
  /*   return TCX_PASS; */

  //UDP header
  //yes we're doing pointer math
  struct udphdr *udph = data + sizeof(struct iphdr);
  /* if (data + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end) */
  /*   return TCX_PASS; */

  //STAMP packet
  /* struct senderpkt *packet = data + sizeof(struct iphdr) + sizeof(struct udphdr); */
  /* if (data + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct senderpkt) > data_end) */
  /*   return TCX_PASS; */
    
  // now we can timestamp it
  /* uint64_t ts=timestamp(); */
  uint64_t ts=69;
  uint32_t offset=sizeof(struct iphdr)+sizeof(struct udphdr)+offsetof(struct senderpkt, t1);
  bpf_skb_store_bytes(skb, offset, &ts, sizeof(ts),0);

  // we're done
  return TCX_PASS;
}

/* SEC("tc/ingress") */
/* int sender_in(struct __sk_buff *skb){ */
/*   //RETURN VALUE: FOR-ME ? TC_ACT_SHOT : TCX_PASS */
/*   //1. For-me check */
/*   //2. Save the last timestamp */
/*   //3. Grab three stamps+seq, write them into packet_ts struct */
/*   //4. Update the histogram */
/*   //5. We're done with the packet: */
/*   return TCX_DROP; */
/* } */
