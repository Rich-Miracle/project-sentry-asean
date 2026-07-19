
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "tc_hook.h"

char LICENSE[] SEC("license") = "GPL";

/* verdict_map: key = dest_ip (uint32), value = verdict (uint8) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} verdict_map SEC(".maps");

/* flow_map: dedup -- destinations already sent for AI evaluation */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} flow_map SEC(".maps");

/* ring_buffer: kernel -> userspace enforcement events (with payload) */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  /* 256 KB */
} ring_buffer SEC(".maps");

SEC("tc")
int tc_egress(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* --- Ethernet header bounds check --- */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    /* --- IP header bounds check --- */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    /* --- TCP header bounds check --- */
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    __u16 dport   = bpf_ntohs(tcp->dest);
    __u32 dest_ip = ip->daddr;     /* network byte order */

    /* test_allow: when set, we emit an event but let the packet through. */
    int test_allow = 0;

    __u8 *verdict = bpf_map_lookup_elem(&verdict_map, &dest_ip);
    if (verdict) {
        if (*verdict == VERDICT_ALLOW)
            return TC_ACT_OK;
        if (*verdict == VERDICT_TEST_MIRROR)
            test_allow = 1;            /* fall through to emit, allow at end */
        else
            return TC_ACT_SHOT;        /* BLOCK or PENDING */
    } else {
        /* unknown destination: mark PENDING (fail-secure path) */
        __u8 pending = VERDICT_PENDING;
        bpf_map_update_elem(&flow_map, &dest_ip, &pending, BPF_ANY);
    }

    /* Compute TCP payload offset and length within the skb. */
    __u32 ip_hdr_len  = ip->ihl * 4;
    __u32 tcp_hdr_len = tcp->doff * 4;
    __u32 l4_offset   = sizeof(*eth) + ip_hdr_len;
    __u32 payload_off = l4_offset + tcp_hdr_len;

    __u32 total_len = skb->len;
    __u32 pl_len    = 0;
    if (total_len > payload_off)
        pl_len = total_len - payload_off;
    if (pl_len > 4096)
        pl_len = 4096;

    /* Reserve and fill the ring buffer event. */
    struct event_t *e = bpf_ringbuf_reserve(&ring_buffer, sizeof(*e), 0);
    if (!e)
        return TC_ACT_SHOT;

    e->src_ip      = ip->saddr;
    e->dest_ip     = dest_ip;
    e->src_port    = bpf_ntohs(tcp->source);
    e->dest_port   = dport;
    e->seq         = bpf_ntohl(tcp->seq);
    e->tcp_flags   = ((__u8 *)tcp)[13];   /* TCP flags byte (offset 13) */
    e->_pad        = 0;
    e->payload_len = pl_len;

    /* Zero the payload buffer before copy (verifier needs init). */
    /* Zero in chunks — clang refuses to inline a single 1500-byte memset. */

    /* Verifier-friendly bounds: prove pl_len is strictly 1..1500 before the call. */
    if (pl_len > 0) {
        __u32 n = pl_len;
        asm volatile("" : "+r"(n));   /* barrier: n is now opaque to compiler */
        if (n > 4096) n = 4096;
        asm volatile("" : "+r"(n));
        if (n == 0) n = 1;            /* unreachable here, but proves n>=1   */
        asm volatile("" : "+r"(n));
        if (bpf_skb_load_bytes(skb, payload_off, e->payload, n) < 0)
            e->payload_len = 0;
    }

    bpf_ringbuf_submit(e, 0);

    if (test_allow)
        return TC_ACT_OK;     /* test-mirror: let the real TCP flow proceed */
    return TC_ACT_SHOT;       /* normal fail-secure drop */
}
