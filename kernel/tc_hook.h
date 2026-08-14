#ifndef __TC_HOOK_H
#define __TC_HOOK_H

#define VERDICT_ALLOW   0
#define VERDICT_BLOCK   1
#define VERDICT_PENDING 2
#define VERDICT_TEST_MIRROR 3   /* test-only: mirror payload AND allow through */

/* 5-tuple key for per-flow content clearance (flow_verdict_map).
   Layout MUST match controller/ebpf_loader.go FlowKey struct exactly.
   All fields network byte order to match how the kernel reads packet headers.
   __attribute__((packed)) — no padding, so C and Go agree on the bytes. */
struct flow_key {
    __u32 src_ip;    /* network order */
    __u32 dst_ip;    /* network order */
    __u16 src_port;  /* network order */
    __u16 dst_port;  /* network order */
    __u8  proto;     /* IPPROTO_TCP */
    __u8  _pad[3];   /* explicit pad to 16 bytes, keep Go layout simple */
} __attribute__((packed));

/* Event sent kernel -> userspace via ring buffer.
   Layout MUST match controller/ebpf_loader.go Event struct. */
struct event_t {
    __u32 src_ip;       /* source IPv4 (network order)      */
    __u32 dest_ip;      /* destination IPv4 (network order) */
    __u16 src_port;     /* TCP source port (host order)     */
    __u16 dest_port;    /* TCP dest port (host order)       */
    __u32 seq;          /* TCP sequence number (host order) */
    __u8  tcp_flags;    /* SYN/ACK/FIN/PSH/RST flags        */
    __u8  _pad;
    __u16 payload_len;  /* bytes actually copied below      */
    __u8  payload[4096]; /* up to 1500B of TCP payload        */
};

#endif
