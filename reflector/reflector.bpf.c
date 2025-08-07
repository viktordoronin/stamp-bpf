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

  //Strip sender packet
  struct senderpkt *sn = data + sizeof(struct iphdr) + sizeof(struct ethhdr) + sizeof(struct udphdr);
  if(data + sizeof(struct iphdr) + sizeof(struct ethhdr) + sizeof(struct udphdr) + sizeof(struct senderpkt) > data_end)
    return TCX_PASS;
  uint32_t seq=sn->seq;
  struct ntp_ts sn_ts;
  sn_ts.ntp_secs=sn->t1_s;
  sn_ts.ntp_fracs=sn->t1_f;
  uint8_t ttl=iph->ttl;
  
  //Populate receivepkt(they're the same size so it's legal)
  if(data + sizeof(struct iphdr) + sizeof(struct ethhdr) + sizeof(struct udphdr) + sizeof(struct reflectorpkt) > data_end)
    return TCX_PASS;
  uint32_t offset; //we'll use this a lot
  //going from top to bottom - seq stays the same
  //populate t2
  offset=stampoffset(offsetof(struct reflectorpkt, t2_s));
  bpf_skb_store_bytes(skb,offset,&rec_ts,sizeof(rec_ts),0);
  //populate sender seq
  offset=stampoffset(offsetof(struct reflectorpkt, s_seq));
  bpf_skb_store_bytes(skb,offset,&seq,sizeof(uint32_t),0);
  //populate sender ts
  offset=stampoffset(offsetof(struct reflectorpkt, t1_s));
  bpf_skb_store_bytes(skb,offset,&sn_ts,sizeof(struct ntp_ts),0);
  //populate sender TTL
  if(data+sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct reflectorpkt) > data_end)
     return TCX_PASS;
  /* offset=sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + offsetof(struct reflectorpkt, ttl); */
  offset=stampoffset(offsetof(struct reflectorpkt, ttl));
  bpf_skb_store_bytes(skb,offset,&ttl,sizeof(ttl),0);

  //REDIRECTION
  //TODO: REFACTOR
  
  //Switch IP
  if(data+sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
    return TCX_PASS;
  uint32_t src_ip;
  uint32_t dest_ip;
  bpf_skb_load_bytes(skb,sizeof(struct ethhdr)+offsetof(struct iphdr, saddr),&src_ip,sizeof(src_ip));
  bpf_skb_load_bytes(skb,sizeof(struct ethhdr)+offsetof(struct iphdr, daddr),&dest_ip,sizeof(dest_ip));
  bpf_skb_store_bytes(skb,sizeof(struct ethhdr)+offsetof(struct iphdr, saddr), &dest_ip, sizeof(dest_ip),0);
  bpf_skb_store_bytes(skb,sizeof(struct ethhdr)+offsetof(struct iphdr, daddr), &src_ip, sizeof(src_ip),0);
  
  //Switch MAC
  if(data+sizeof(struct ethhdr) > data_end)
    return TCX_PASS;
  unsigned char src_mac[6], dest_mac[6];
  bpf_skb_load_bytes(skb,offsetof(struct ethhdr, h_source),src_mac,6);
  bpf_skb_load_bytes(skb,offsetof(struct ethhdr, h_dest),dest_mac,6);
  bpf_skb_store_bytes(skb,offsetof(struct ethhdr, h_source),dest_mac,6,0);
  bpf_skb_store_bytes(skb,offsetof(struct ethhdr, h_dest),src_mac,6,0);

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
  
  //populate t3  
  if(data + sizeof(struct iphdr) + sizeof(struct ethhdr) + sizeof(struct udphdr) + sizeof(struct reflectorpkt) > data_end)
    return TCX_PASS;
  uint32_t offset;
  offset=stampoffset(offsetof(struct reflectorpkt,t3_s));
  //timestamp at the last possible moment
  struct ntp_ts ts;
  timestamp(&ts);
  bpf_skb_store_bytes(skb, offset, &ts, sizeof(ts),0);
  
  return TCX_PASS;
}
