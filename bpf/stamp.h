//go:build ignore

#include <stdint.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
//includes for packet header structs below
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <time.h>

//usage: packet.t1_s=timestamp()
uint64_t timestamp(void) {
  return bpf_ktime_get_tai_ns(); //TODO: NTP conversion
}

// we won't use these directly but they're still handy for offsetof()
// session-sender packet(RFC 8762)
struct senderpkt{
  uint32_t seq; //sequence number
  uint64_t t1;
  uint16_t err; //error estimate(unused)
  uint8_t mbz[30]; //30 octets of MBZ
}__attribute__((packed)); 
// session-reflector packet(RFC 8762)
struct reflectorpkt {
  uint32_t seq; //reflector seq
  uint64_t t3; //timestamp
  uint16_t err;
  uint16_t mbz;
  uint64_t t2; //receive timestamp
  uint32_t s_seq; //sender seq
  uint64_t t1; //sender timestamp
  uint16_t s_err;
  uint16_t s_mbz;
  uint8_t ttl; //sender ttl
  uint8_t t_mbz[3]; 
}__attribute__((packed));
