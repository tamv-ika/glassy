// S3 probe: bounces UDP datagrams sent to port 9 back to the sender with XDP_TX, so a remote
// load generator can measure the XDP fast path end to end. Everything else passes through.
//
// Swapping MACs, IPs and ports leaves both the IPv4 and the UDP checksum valid (one's
// complement sums do not depend on order), so no checksum is recomputed.
//
// THROWAWAY: SP0 spike code.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define REFLECT_PORT 9

SEC("xdp")
int xdp_reflect(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end || eth->h_proto != bpf_htons(ETH_P_IP)) {
    return XDP_PASS;
  }
  struct iphdr *ip = (void *)(eth + 1);
  // IPv4 options are rare enough to ignore in a probe.
  if ((void *)(ip + 1) > data_end || ip->ihl != 5 || ip->protocol != IPPROTO_UDP) {
    return XDP_PASS;
  }
  struct udphdr *udp = (void *)(ip + 1);
  if ((void *)(udp + 1) > data_end || udp->dest != bpf_htons(REFLECT_PORT)) {
    return XDP_PASS;
  }

  unsigned char mac[ETH_ALEN];
  __builtin_memcpy(mac, eth->h_source, ETH_ALEN);
  __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
  __builtin_memcpy(eth->h_dest, mac, ETH_ALEN);

  __be32 addr = ip->saddr;
  ip->saddr = ip->daddr;
  ip->daddr = addr;

  __be16 port = udp->source;
  udp->source = udp->dest;
  udp->dest = port;
  return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";
