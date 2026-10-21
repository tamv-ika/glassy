// S3 probe: the smallest XDP program. Loading it tells whether a driver accepts XDP at all.
//
// THROWAWAY: SP0 spike code.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_pass(struct xdp_md *ctx) {
  return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
