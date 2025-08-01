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

SEC("tc/ingress")
int reflector_in(struct __sk_buff *skb){
  //lots of work here - convert senderpkt into reflectorpkt
  //Save the receive timestamp
  struct ntp_ts rec_ts;
  timestamp(&rec_ts);

  //is it IP?
  if(skb->protocol!=bpf_htons(ETH_P_IP)){
    bpf_printk("Failed L3 proto check, got: %d, wanted: %d",skb->protocol, bpf_htons(ETH_P_IP));
    return TCX_PASS;
  }
  bpf_printk("Passed L3 proto check");
  
  //grab the actual packet
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  
  //IP header
  struct iphdr *iph = data+sizeof(struct ethhdr);
  //these kinds of checks are mandated by the eBPF verifier, without them the program won't get loaded
  if (data + sizeof(struct iphdr) + sizeof(struct ethhdr) > data_end)
    return TCX_PASS;
  
  //Is it UDP?
  if (iph->protocol!=IPPROTO_UDP){
    bpf_printk("Failed L4 proto check, got: %d, wanted: %d",iph->protocol, IPPROTO_UDP);
    return TCX_PASS;
  }
  bpf_printk("Passed L4 proto check");
  
  //UDP header
  struct udphdr *udph = data + sizeof(struct iphdr)+sizeof(struct ethhdr);
  if (data + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct ethhdr) > data_end)
    return TCX_PASS;
  //862 is a well-known TWAMP port
  //we'll need some communication mechanism for custom ports
  if (udph->dest!=bpf_ntohs(862) || udph->source!=bpf_ntohs(862)){
    bpf_printk("Failed UDP port check");
    return TCX_PASS;
  }
  bpf_printk("Passed UDP port check");

  //Strip senderpkt.seq and senderpkt.t1
  struct senderpkt *sn = data + sizeof(struct iphdr) + sizeof(struct ethhdr) + sizeof(struct udphdr);
  if(data + sizeof(struct iphdr) + sizeof(struct ethhdr) + sizeof(struct udphdr) + sizeof(struct senderpkt) > data_end)
    return TCX_PASS;
  uint32_t seq=sn->seq;
  struct ntp_ts sn_ts;
  sn_ts.ntp_secs=sn->t1_s;
  sn_ts.ntp_fracs=sn->t1_f;
  
  //Populate receivepkt(they're the same size so it's legal)
  /* struct reflectorpkt *rf = data + sizeof(struct iphdr) + sizeof(struct ethhdr) + sizeof(struct udphdr); */
  if(data + sizeof(struct iphdr) + sizeof(struct ethhdr) + sizeof(struct udphdr) + sizeof(struct reflectorpkt) > data_end)
    return TCX_PASS;
  uint32_t offset; //we'll use this a lot
  //going from top to bottom - seq stays the same
  //set t3 to zero
  struct ntp_ts ts;
  ts.ntp_secs=0;
  ts.ntp_fracs=0;
  offset=sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct udphdr)+offsetof(struct reflectorpkt, t3_s);
  bpf_skb_store_bytes(skb,offset,&ts,sizeof(ts),0);
  //populate t2
  offset=stampoffset(offsetof(struct reflectorpkt, t2_s));
  bpf_skb_store_bytes(skb,offset,&rec_ts,sizeof(rec_ts),0);
  //populate sender seq
  offset=stampoffset(offsetof(struct reflectorpkt, s_seq));
  bpf_skb_store_bytes(skb,offset,&seq,sizeof(uint32_t),0);
  //populate sender ts
  offset=stampoffset(offsetof(struct reflectorpkt, t1_s));
  bpf_skb_store_bytes(skb,offset,&sn_ts,sizeof(struct ntp_ts),0);
  //grab and populate sender TTL
  offset=stampoffset(offsetof(struct reflectorpkt, ttl));
  uint8_t ttl;
  uint32_t ipoffset=sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct udphdr);
  bpf_skb_load_bytes(skb,ipoffset+offsetof(struct iphdr, ttl),&ttl,sizeof(uint8_t));
  bpf_skb_store_bytes(skb,offset,&ttl,sizeof(uint8_t),0);

  //Redirection - I'll test if we can put this check before we change the packet
  //maybe this is all unnecessary and I can do this instead:
  //return bpf_redirect(skb->ifindex,0);
  uint64_t red = bpf_redirect(skb->ifindex,0);
  if (red==TCX_DROP) {
    bpf_printk("Something went wrong at redirection, packet dropped");
    return TCX_DROP;
  }
  
  return TCX_REDIRECT;
} 

SEC("tc/egress")
int reflector_out(struct __sk_buff *skb){
  //light work - stamp a packet and send it on its way

  struct ntp_ts ts;
  timestamp(&ts);
  
  //is it IP?
  if(skb->protocol!=bpf_htons(ETH_P_IP)){
    bpf_printk("Failed L3 proto check, got: %d, wanted: %d",skb->protocol, bpf_htons(ETH_P_IP));
    return TCX_PASS;
  }
  bpf_printk("Passed L3 proto check");
  
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
    bpf_printk("Failed L4 proto check, got: %d, wanted: %d",iph->protocol, IPPROTO_UDP);
    return TCX_PASS;
  }
  bpf_printk("Passed L4 proto check");
  
  //UDP header
  struct udphdr *udph = data + sizeof(struct iphdr)+sizeof(struct ethhdr);
  if (data + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct ethhdr) > data_end)
    return TCX_PASS;
  //862 is a well-known TWAMP port
  //we'll need some communication mechanism for custom ports
  if (udph->dest!=bpf_ntohs(862) || udph->source!=bpf_ntohs(862)){
    bpf_printk("Failed UDP port check");
    return TCX_PASS;
  }
  bpf_printk("Passed UDP port check");

  //populate t3
  struct reflectorpkt *rf = data + sizeof(struct iphdr) + sizeof(struct ethhdr) + sizeof(struct udphdr);
  if(data + sizeof(struct iphdr) + sizeof(struct ethhdr) + sizeof(struct udphdr) + sizeof(struct reflectorpkt) > data_end)
    return TCX_PASS;
  uint32_t offset;
  offset=stampoffset(offsetof(struct reflectorpkt,t3_s));
  bpf_skb_store_bytes(skb, offset, &ts, sizeof(ts),0);
  
  return TCX_PASS;
}
