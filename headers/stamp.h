//go:build ignore

#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <stdint.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/udp.h>
#include <linux/ip.h>

struct ntp_ts{
  uint32_t ntp_secs;
  uint32_t ntp_fracs;
};

uint32_t timestamp(struct ntp_ts *arg) {
  uint64_t utns = bpf_ktime_get_tai_ns(); //Unix nanoseconds
  uint64_t ntps = utns / 1000000000 ; //this needs to be 64 bit to avoid over/underflows
  uint64_t ntpf = utns % 1000000000 ;
  ntps += 2208988800 ;
  ntpf = ( ntpf << 32 ) ;
  ntpf /= 1000000000 ;
  arg->ntp_secs=bpf_htonl(ntps); //no casting required
  arg->ntp_fracs=bpf_htonl(ntpf);
  return 0;
}

uint64_t untimestamp(struct ntp_ts *arg){
  uint64_t unix_s = bpf_ntohl(arg->ntp_secs);
  uint64_t unix_ns = bpf_ntohl(arg->ntp_fracs);
  //reverse conversion
  unix_s -= 2208988800 ;
  unix_ns *= 1000000000 ;
  unix_ns = unix_ns >> 32 ;
  //put it back into a full ns amount
  uint64_t res = (uint32_t) unix_s*1000000000;
  res+= (uint32_t) unix_ns;
  return res;
}

//a simple function that adds the headers' sizeofs to a packet field's offsetof
uint32_t stampoffset(uint32_t offset){
  return sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct udphdr)+offset;
}

// we won't use these directly but they're still handy for offsetof()
// 
// session-sender packet(RFC 8762)
struct senderpkt{
  uint32_t seq; //sequence number
  uint32_t t1_s;
  uint32_t t1_f;
  uint16_t err; //error estimate(unused)
  uint8_t mbz[30]; //30 octets of MBZ
}__attribute__((packed));

// session-reflector packet(RFC 8762)
struct reflectorpkt {
  uint32_t seq; //reflector seq
  uint32_t t3_s; //timestamp
  uint32_t t3_f;
  uint16_t err;
  uint16_t mbz;
  uint32_t t2_s; //receive timestamp
  uint32_t t2_f;
  uint32_t s_seq; //sender seq
  uint32_t t1_s; //sender timestamp
  uint32_t t1_f;
  uint16_t s_err;
  uint16_t s_mbz;
  uint8_t ttl; //sender ttl
  uint8_t t_mbz[3]; 
}__attribute__((packed));
