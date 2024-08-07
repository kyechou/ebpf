#pragma once

// <linux/if_ether.h>
#define ETH_ALEN      6       /* Octets in one ethernet addr	 */
#define ETH_TLEN      2       /* Octets in ethernet type field */
#define ETH_HLEN      14      /* Total octets in header.	 */
#define ETH_ZLEN      60      /* Min. octets in frame sans FCS */
#define ETH_DATA_LEN  1500    /* Max. octets in payload	 */
#define ETH_FRAME_LEN 1514    /* Max. octets in frame sans FCS */
#define ETH_FCS_LEN   4       /* Octets in the FCS		 */
#define ETH_MIN_MTU   68      /* Min IPv4 MTU per RFC791	*/
#define ETH_MAX_MTU   0xFFFFU /* 65535, same as IP_MAX_MTU	*/

#define ETH_P_LOOP    0x0060  /* Ethernet Loopback packet	*/
#define ETH_P_IP      0x0800  /* Internet Protocol packet	*/
#define ETH_P_ARP     0x0806  /* Address Resolution packet	*/
#define ETH_P_RARP    0x8035  /* Reverse Addr Res packet	*/
#define ETH_P_8021Q   0x8100  /* 802.1Q VLAN Extended Header  */
#define ETH_P_IPV6    0x86DD  /* IPv6 over bluebook		*/

// <linux/icmp.h>
#define ICMP_ECHOREPLY      0  /* Echo Reply			*/
#define ICMP_DEST_UNREACH   3  /* Destination Unreachable	*/
#define ICMP_SOURCE_QUENCH  4  /* Source Quench		*/
#define ICMP_REDIRECT       5  /* Redirect (change route)	*/
#define ICMP_ECHO           8  /* Echo Request			*/
#define ICMP_TIME_EXCEEDED  11 /* Time Exceeded		*/
#define ICMP_PARAMETERPROB  12 /* Parameter Problem		*/
#define ICMP_TIMESTAMP      13 /* Timestamp Request		*/
#define ICMP_TIMESTAMPREPLY 14 /* Timestamp Reply		*/
#define ICMP_INFO_REQUEST   15 /* Information Request		*/
#define ICMP_INFO_REPLY     16 /* Information Reply		*/
#define ICMP_ADDRESS        17 /* Address Mask Request		*/
#define ICMP_ADDRESSREPLY   18 /* Address Mask Reply		*/
#define NR_ICMP_TYPES       18

#ifndef __VMLINUX_H__
#define DEFINE_DROP_REASON(FN, FNe)                                            \
    FN(NOT_SPECIFIED)                                                          \
    FN(NO_SOCKET)                                                              \
    FN(PKT_TOO_SMALL)                                                          \
    FN(TCP_CSUM)                                                               \
    FN(SOCKET_FILTER)                                                          \
    FN(UDP_CSUM)                                                               \
    FN(NETFILTER_DROP)                                                         \
    FN(OTHERHOST)                                                              \
    FN(IP_CSUM)                                                                \
    FN(IP_INHDR)                                                               \
    FN(IP_RPFILTER)                                                            \
    FN(UNICAST_IN_L2_MULTICAST)                                                \
    FN(XFRM_POLICY)                                                            \
    FN(IP_NOPROTO)                                                             \
    FN(SOCKET_RCVBUFF)                                                         \
    FN(PROTO_MEM)                                                              \
    FN(TCP_MD5NOTFOUND)                                                        \
    FN(TCP_MD5UNEXPECTED)                                                      \
    FN(TCP_MD5FAILURE)                                                         \
    FN(SOCKET_BACKLOG)                                                         \
    FN(TCP_FLAGS)                                                              \
    FN(TCP_ZEROWINDOW)                                                         \
    FN(TCP_OLD_DATA)                                                           \
    FN(TCP_OVERWINDOW)                                                         \
    FN(TCP_OFOMERGE)                                                           \
    FN(TCP_RFC7323_PAWS)                                                       \
    FN(TCP_INVALID_SEQUENCE)                                                   \
    FN(TCP_RESET)                                                              \
    FN(TCP_INVALID_SYN)                                                        \
    FN(TCP_CLOSE)                                                              \
    FN(TCP_FASTOPEN)                                                           \
    FN(TCP_OLD_ACK)                                                            \
    FN(TCP_TOO_OLD_ACK)                                                        \
    FN(TCP_ACK_UNSENT_DATA)                                                    \
    FN(TCP_OFO_QUEUE_PRUNE)                                                    \
    FN(TCP_OFO_DROP)                                                           \
    FN(IP_OUTNOROUTES)                                                         \
    FN(BPF_CGROUP_EGRESS)                                                      \
    FN(IPV6DISABLED)                                                           \
    FN(NEIGH_CREATEFAIL)                                                       \
    FN(NEIGH_FAILED)                                                           \
    FN(NEIGH_QUEUEFULL)                                                        \
    FN(NEIGH_DEAD)                                                             \
    FN(TC_EGRESS)                                                              \
    FN(QDISC_DROP)                                                             \
    FN(CPU_BACKLOG)                                                            \
    FN(XDP)                                                                    \
    FN(TC_INGRESS)                                                             \
    FN(UNHANDLED_PROTO)                                                        \
    FN(SKB_CSUM)                                                               \
    FN(SKB_GSO_SEG)                                                            \
    FN(SKB_UCOPY_FAULT)                                                        \
    FN(DEV_HDR)                                                                \
    FN(DEV_READY)                                                              \
    FN(FULL_RING)                                                              \
    FN(NOMEM)                                                                  \
    FN(HDR_TRUNC)                                                              \
    FN(TAP_FILTER)                                                             \
    FN(TAP_TXFILTER)                                                           \
    FN(ICMP_CSUM)                                                              \
    FN(INVALID_PROTO)                                                          \
    FN(IP_INADDRERRORS)                                                        \
    FN(IP_INNOROUTES)                                                          \
    FN(PKT_TOO_BIG)                                                            \
    FNe(MAX)
/**
 * enum skb_drop_reason - the reasons of skb drops
 *
 * The reason of skb drop, which is used in kfree_skb_reason().
 */
enum skb_drop_reason {
    /**
     * @SKB_NOT_DROPPED_YET: skb is not dropped yet (used for no-drop case)
     */
    SKB_NOT_DROPPED_YET = 0,
    /** @SKB_DROP_REASON_NOT_SPECIFIED: drop reason is not specified */
    SKB_DROP_REASON_NOT_SPECIFIED,
    /** @SKB_DROP_REASON_NO_SOCKET: socket not found */
    SKB_DROP_REASON_NO_SOCKET,
    /** @SKB_DROP_REASON_PKT_TOO_SMALL: packet size is too small */
    SKB_DROP_REASON_PKT_TOO_SMALL,
    /** @SKB_DROP_REASON_TCP_CSUM: TCP checksum error */
    SKB_DROP_REASON_TCP_CSUM,
    /** @SKB_DROP_REASON_SOCKET_FILTER: dropped by socket filter */
    SKB_DROP_REASON_SOCKET_FILTER,
    /** @SKB_DROP_REASON_UDP_CSUM: UDP checksum error */
    SKB_DROP_REASON_UDP_CSUM,
    /** @SKB_DROP_REASON_NETFILTER_DROP: dropped by netfilter */
    SKB_DROP_REASON_NETFILTER_DROP,
    /**
     * @SKB_DROP_REASON_OTHERHOST: packet don't belong to current host
     * (interface is in promisc mode)
     */
    SKB_DROP_REASON_OTHERHOST,
    /** @SKB_DROP_REASON_IP_CSUM: IP checksum error */
    SKB_DROP_REASON_IP_CSUM,
    /**
     * @SKB_DROP_REASON_IP_INHDR: there is something wrong with IP header (see
     * IPSTATS_MIB_INHDRERRORS)
     */
    SKB_DROP_REASON_IP_INHDR,
    /**
     * @SKB_DROP_REASON_IP_RPFILTER: IP rpfilter validate failed. see the
     * document for rp_filter in ip-sysctl.rst for more information
     */
    SKB_DROP_REASON_IP_RPFILTER,
    /**
     * @SKB_DROP_REASON_UNICAST_IN_L2_MULTICAST: destination address of L2 is
     * multicast, but L3 is unicast.
     */
    SKB_DROP_REASON_UNICAST_IN_L2_MULTICAST,
    /** @SKB_DROP_REASON_XFRM_POLICY: xfrm policy check failed */
    SKB_DROP_REASON_XFRM_POLICY,
    /** @SKB_DROP_REASON_IP_NOPROTO: no support for IP protocol */
    SKB_DROP_REASON_IP_NOPROTO,
    /** @SKB_DROP_REASON_SOCKET_RCVBUFF: socket receive buff is full */
    SKB_DROP_REASON_SOCKET_RCVBUFF,
    /**
     * @SKB_DROP_REASON_PROTO_MEM: proto memory limition, such as udp packet
     * drop out of udp_memory_allocated.
     */
    SKB_DROP_REASON_PROTO_MEM,
    /**
     * @SKB_DROP_REASON_TCP_MD5NOTFOUND: no MD5 hash and one expected,
     * corresponding to LINUX_MIB_TCPMD5NOTFOUND
     */
    SKB_DROP_REASON_TCP_MD5NOTFOUND,
    /**
     * @SKB_DROP_REASON_TCP_MD5UNEXPECTED: MD5 hash and we're not expecting
     * one, corresponding to LINUX_MIB_TCPMD5UNEXPECTED
     */
    SKB_DROP_REASON_TCP_MD5UNEXPECTED,
    /**
     * @SKB_DROP_REASON_TCP_MD5FAILURE: MD5 hash and its wrong, corresponding
     * to LINUX_MIB_TCPMD5FAILURE
     */
    SKB_DROP_REASON_TCP_MD5FAILURE,
    /**
     * @SKB_DROP_REASON_SOCKET_BACKLOG: failed to add skb to socket backlog (
     * see LINUX_MIB_TCPBACKLOGDROP)
     */
    SKB_DROP_REASON_SOCKET_BACKLOG,
    /** @SKB_DROP_REASON_TCP_FLAGS: TCP flags invalid */
    SKB_DROP_REASON_TCP_FLAGS,
    /**
     * @SKB_DROP_REASON_TCP_ZEROWINDOW: TCP receive window size is zero,
     * see LINUX_MIB_TCPZEROWINDOWDROP
     */
    SKB_DROP_REASON_TCP_ZEROWINDOW,
    /**
     * @SKB_DROP_REASON_TCP_OLD_DATA: the TCP data reveived is already
     * received before (spurious retrans may happened), see
     * LINUX_MIB_DELAYEDACKLOST
     */
    SKB_DROP_REASON_TCP_OLD_DATA,
    /**
     * @SKB_DROP_REASON_TCP_OVERWINDOW: the TCP data is out of window,
     * the seq of the first byte exceed the right edges of receive
     * window
     */
    SKB_DROP_REASON_TCP_OVERWINDOW,
    /**
     * @SKB_DROP_REASON_TCP_OFOMERGE: the data of skb is already in the ofo
     * queue, corresponding to LINUX_MIB_TCPOFOMERGE
     */
    SKB_DROP_REASON_TCP_OFOMERGE,
    /**
     * @SKB_DROP_REASON_TCP_RFC7323_PAWS: PAWS check, corresponding to
     * LINUX_MIB_PAWSESTABREJECTED
     */
    SKB_DROP_REASON_TCP_RFC7323_PAWS,
    /** @SKB_DROP_REASON_TCP_INVALID_SEQUENCE: Not acceptable SEQ field */
    SKB_DROP_REASON_TCP_INVALID_SEQUENCE,
    /** @SKB_DROP_REASON_TCP_RESET: Invalid RST packet */
    SKB_DROP_REASON_TCP_RESET,
    /**
     * @SKB_DROP_REASON_TCP_INVALID_SYN: Incoming packet has unexpected
     * SYN flag
     */
    SKB_DROP_REASON_TCP_INVALID_SYN,
    /** @SKB_DROP_REASON_TCP_CLOSE: TCP socket in CLOSE state */
    SKB_DROP_REASON_TCP_CLOSE,
    /** @SKB_DROP_REASON_TCP_FASTOPEN: dropped by FASTOPEN request socket */
    SKB_DROP_REASON_TCP_FASTOPEN,
    /** @SKB_DROP_REASON_TCP_OLD_ACK: TCP ACK is old, but in window */
    SKB_DROP_REASON_TCP_OLD_ACK,
    /** @SKB_DROP_REASON_TCP_TOO_OLD_ACK: TCP ACK is too old */
    SKB_DROP_REASON_TCP_TOO_OLD_ACK,
    /**
     * @SKB_DROP_REASON_TCP_ACK_UNSENT_DATA: TCP ACK for data we haven't
     * sent yet
     */
    SKB_DROP_REASON_TCP_ACK_UNSENT_DATA,
    /** @SKB_DROP_REASON_TCP_OFO_QUEUE_PRUNE: pruned from TCP OFO queue */
    SKB_DROP_REASON_TCP_OFO_QUEUE_PRUNE,
    /** @SKB_DROP_REASON_TCP_OFO_DROP: data already in receive queue */
    SKB_DROP_REASON_TCP_OFO_DROP,
    /** @SKB_DROP_REASON_IP_OUTNOROUTES: route lookup failed */
    SKB_DROP_REASON_IP_OUTNOROUTES,
    /**
     * @SKB_DROP_REASON_BPF_CGROUP_EGRESS: dropped by BPF_PROG_TYPE_CGROUP_SKB
     * eBPF program
     */
    SKB_DROP_REASON_BPF_CGROUP_EGRESS,
    /** @SKB_DROP_REASON_IPV6DISABLED: IPv6 is disabled on the device */
    SKB_DROP_REASON_IPV6DISABLED,
    /** @SKB_DROP_REASON_NEIGH_CREATEFAIL: failed to create neigh entry */
    SKB_DROP_REASON_NEIGH_CREATEFAIL,
    /** @SKB_DROP_REASON_NEIGH_FAILED: neigh entry in failed state */
    SKB_DROP_REASON_NEIGH_FAILED,
    /** @SKB_DROP_REASON_NEIGH_QUEUEFULL: arp_queue for neigh entry is full */
    SKB_DROP_REASON_NEIGH_QUEUEFULL,
    /** @SKB_DROP_REASON_NEIGH_DEAD: neigh entry is dead */
    SKB_DROP_REASON_NEIGH_DEAD,
    /** @SKB_DROP_REASON_TC_EGRESS: dropped in TC egress HOOK */
    SKB_DROP_REASON_TC_EGRESS,
    /**
     * @SKB_DROP_REASON_QDISC_DROP: dropped by qdisc when packet outputting (
     * failed to enqueue to current qdisc)
     */
    SKB_DROP_REASON_QDISC_DROP,
    /**
     * @SKB_DROP_REASON_CPU_BACKLOG: failed to enqueue the skb to the per CPU
     * backlog queue. This can be caused by backlog queue full (see
     * netdev_max_backlog in net.rst) or RPS flow limit
     */
    SKB_DROP_REASON_CPU_BACKLOG,
    /** @SKB_DROP_REASON_XDP: dropped by XDP in input path */
    SKB_DROP_REASON_XDP,
    /** @SKB_DROP_REASON_TC_INGRESS: dropped in TC ingress HOOK */
    SKB_DROP_REASON_TC_INGRESS,
    /** @SKB_DROP_REASON_UNHANDLED_PROTO: protocol not implemented or not
     * supported */
    SKB_DROP_REASON_UNHANDLED_PROTO,
    /** @SKB_DROP_REASON_SKB_CSUM: sk_buff checksum computation error */
    SKB_DROP_REASON_SKB_CSUM,
    /** @SKB_DROP_REASON_SKB_GSO_SEG: gso segmentation error */
    SKB_DROP_REASON_SKB_GSO_SEG,
    /**
     * @SKB_DROP_REASON_SKB_UCOPY_FAULT: failed to copy data from user space,
     * e.g., via zerocopy_sg_from_iter() or skb_orphan_frags_rx()
     */
    SKB_DROP_REASON_SKB_UCOPY_FAULT,
    /** @SKB_DROP_REASON_DEV_HDR: device driver specific header/metadata is
     * invalid */
    SKB_DROP_REASON_DEV_HDR,
    /**
     * @SKB_DROP_REASON_DEV_READY: the device is not ready to xmit/recv due to
     * any of its data structure that is not up/ready/initialized,
     * e.g., the IFF_UP is not set, or driver specific tun->tfiles[txq]
     * is not initialized
     */
    SKB_DROP_REASON_DEV_READY,
    /** @SKB_DROP_REASON_FULL_RING: ring buffer is full */
    SKB_DROP_REASON_FULL_RING,
    /** @SKB_DROP_REASON_NOMEM: error due to OOM */
    SKB_DROP_REASON_NOMEM,
    /**
     * @SKB_DROP_REASON_HDR_TRUNC: failed to trunc/extract the header from
     * networking data, e.g., failed to pull the protocol header from
     * frags via pskb_may_pull()
     */
    SKB_DROP_REASON_HDR_TRUNC,
    /**
     * @SKB_DROP_REASON_TAP_FILTER: dropped by (ebpf) filter directly attached
     * to tun/tap, e.g., via TUNSETFILTEREBPF
     */
    SKB_DROP_REASON_TAP_FILTER,
    /**
     * @SKB_DROP_REASON_TAP_TXFILTER: dropped by tx filter implemented at
     * tun/tap, e.g., check_filter()
     */
    SKB_DROP_REASON_TAP_TXFILTER,
    /** @SKB_DROP_REASON_ICMP_CSUM: ICMP checksum error */
    SKB_DROP_REASON_ICMP_CSUM,
    /**
     * @SKB_DROP_REASON_INVALID_PROTO: the packet doesn't follow RFC 2211,
     * such as a broadcasts ICMP_TIMESTAMP
     */
    SKB_DROP_REASON_INVALID_PROTO,
    /**
     * @SKB_DROP_REASON_IP_INADDRERRORS: host unreachable, corresponding to
     * IPSTATS_MIB_INADDRERRORS
     */
    SKB_DROP_REASON_IP_INADDRERRORS,
    /**
     * @SKB_DROP_REASON_IP_INNOROUTES: network unreachable, corresponding to
     * IPSTATS_MIB_INADDRERRORS
     */
    SKB_DROP_REASON_IP_INNOROUTES,
    /**
     * @SKB_DROP_REASON_PKT_TOO_BIG: packet size is too big (maybe exceed the
     * MTU)
     */
    SKB_DROP_REASON_PKT_TOO_BIG,
    /**
     * @SKB_DROP_REASON_MAX: the maximum of drop reason, which shouldn't be
     * used as a real 'reason'
     */
    SKB_DROP_REASON_MAX,
};

typedef unsigned char __u8;
typedef short unsigned int __u16;
typedef unsigned int __u32;
typedef long long unsigned int __u64;
typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef long unsigned int __kernel_ulong_t;
typedef __kernel_ulong_t __kernel_size_t;
typedef __kernel_size_t size_t;
#endif // __VMLINUX_H__

struct drop_data {
    // L1, auxiliary
    int ifindex;
    int ingress_ifindex;
    void *location;
    u64 tstamp;
    enum skb_drop_reason reason;
    // L2
    unsigned char eth_dst_addr[ETH_ALEN];
    unsigned char eth_src_addr[ETH_ALEN];
    u16 eth_proto;
    // L3
    u16 tot_len;
    u8 ip_proto;
    u32 saddr;
    u32 daddr;
    // L4
    union {
        struct {
            u16 sport;
            u16 dport;
            u32 seq;
            u32 ack;
        } transport;
        struct {
            u8 icmp_type;
            u16 icmp_echo_id;
            u16 icmp_echo_seq;
        } icmp;
    };
};
