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
#include <time.h>

char __license[] SEC("license")="GPL";

SEC("tc/ingress")
int reflector_in(struct __sk_buff *skb){
  //lots of work here - convert senderpkt into reflectorpkt
  //1. Save the receive timestamp(into a var)
  //2. Strip senderpkt.seq and senderpkt.t1_s
  //3. Populate receivepkt(they're the same size so it's legal)
  return TC_ACT_REDIRECT; // actually bpf_redirect() but we'll get to that later
} 

SEC("tc/egress")
int reflector_out(struct __sk_buff *skb){
  //light work - stamp a packet and send it on its way
  return TC_ACT_OK;
}
