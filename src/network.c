// eBPF program

#ifndef __KERNEL__
#define __KERNEL__
#endif // __KERNEL__

#include <linux/bpf.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>
#include <net/dropreason.h>
#include <uapi/linux/bpf.h>

#ifndef __inline
#define __inline inline __attribute__((always_inline))
#endif

BPF_RINGBUF_OUTPUT(pkt_drops, 8);

struct drop_data {
    // L1, auxiliary
    int ifindex;
    int ingress_ifindex;
    void *location;
    uint64_t tstamp;
    enum skb_drop_reason reason;
    // L2
    unsigned char eth_dst_addr[ETH_ALEN];
    unsigned char eth_src_addr[ETH_ALEN];
    __be16 eth_proto; // big-endian, eth-type
    // L3
    __be16 tot_len;
    __u8 ip_proto;
    __be32 saddr;
    __be32 daddr;
    // L4
    // add tcp (inet) connection state?
    // make it a union?
    // __be16 sport;
    // __be16 dport;
    // __be32 seq;
    // __be32 ack;
    // __u8 icmp_type;
    // __u8 icmp_code;
    // __be16 icmp_echo_id;
    // __be16 icmp_echo_seq;
    // payload?
};

// <linux/skbuff.h>
static __inline bool _skb_mac_header_was_set(const struct sk_buff *skb) {
    return skb->mac_header != (typeof(skb->mac_header))~0U;
}

// <linux/skbuff.h>
static __inline unsigned char *_skb_mac_header(const struct sk_buff *skb) {
    // DEBUG_NET_WARN_ON_ONCE(!skb_mac_header_was_set(skb));
    return skb->head + skb->mac_header;
}

// <linux/skbuff.h>
static __inline u32 _skb_network_header_len(const struct sk_buff *skb) {
    return skb->transport_header - skb->network_header;
}

// <linux/skbuff.h>
static __inline unsigned char *_skb_network_header(const struct sk_buff *skb) {
    return skb->head + skb->network_header;
}

// <linux/skbuff.h>
static __inline bool _skb_transport_header_was_set(const struct sk_buff *skb) {
    return skb->transport_header != (typeof(skb->transport_header))~0U;
}

// <linux/skbuff.h>
static __inline unsigned char *
_skb_transport_header(const struct sk_buff *skb) {
    return skb->head + skb->transport_header;
}

// <linux/if_ether.h>
static __inline struct ethhdr *_eth_hdr(const struct sk_buff *skb) {
    return (struct ethhdr *)_skb_mac_header(skb);
}

// <linux/ip.h>
static __inline struct iphdr *_ip_hdr(const struct sk_buff *skb) {
    return (struct iphdr *)_skb_network_header(skb);
}

// <linux/tcp.h>
static __inline struct tcphdr *_tcp_hdr(const struct sk_buff *skb) {
    return (struct tcphdr *)_skb_transport_header(skb);
}

// <linux/udp.h>
static __inline struct udphdr *_udp_hdr(const struct sk_buff *skb) {
    return (struct udphdr *)_skb_transport_header(skb);
}

// <linux/icmp.h>
static __inline struct icmphdr *_icmp_hdr(const struct sk_buff *skb) {
    return (struct icmphdr *)_skb_transport_header(skb);
}

TRACEPOINT_PROBE(skb, kfree_skb) {
    struct drop_data data = {0};
    struct sk_buff *_skb = args->skbaddr;

    // Add additional filtering logic here (e.g., mac addrs, intfs)
    if (_skb->len == 0 || !_skb->skb_iif || args->protocol != ETH_P_IP) {
        return 0;
    }

    // L1
    data.ifindex = _skb->dev->ifindex;
    data.ingress_ifindex = _skb->skb_iif;
    // auxiliary
    data.location = args->location;
    data.tstamp = bpf_ktime_get_ns();
    data.reason = args->reason;

    // L2
    if (_skb_mac_header_was_set(_skb)) {
        struct ethhdr *eth = _eth_hdr(_skb);
        bpf_probe_read_kernel(data.eth_dst_addr, sizeof(data.eth_dst_addr),
                              eth->h_dest);
        bpf_probe_read_kernel(data.eth_src_addr, sizeof(data.eth_src_addr),
                              eth->h_source);
    }

    data.eth_proto = args->protocol;

    // L3
    if (data.eth_proto == ETH_P_IP && _skb_network_header_len(_skb) > 0) {
        struct iphdr *nh = _ip_hdr(_skb);
        data.tot_len = nh->tot_len;
        data.ip_proto = nh->protocol;
        data.saddr = nh->saddr;
        data.daddr = nh->daddr;
    }

    // TODO
    if (_skb_transport_header_was_set(_skb)) {
        if (data.ip_proto == IPPROTO_TCP) {
            struct tcphdr *th = _tcp_hdr(_skb);
        } else if (data.ip_proto == IPPROTO_UDP) {
            struct udphdr *uh = _udp_hdr(_skb);
        } else if (data.ip_proto == IPPROTO_ICMP) {
            struct icmphdr *ih = _icmp_hdr(_skb);
        } else {
            return 0;
        }
    }

    pkt_drops.ringbuf_output(&data, sizeof(data), 0);
    return 0;
}

// TRACEPOINT_PROBE(skb, consume_skb) {
//     struct sk_buff *_skb = args->skbaddr;
//     bpf_trace_printk("[consume_skb] %x", (uint64_t)_skb);
//     return 0;
// }
