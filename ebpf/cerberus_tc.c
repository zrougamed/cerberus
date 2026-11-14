#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_ARP 0x0806
#define ETH_P_IP  0x0800
#define ETH_P_IPV6 0x86DD

#define PROTO_TCP 6
#define PROTO_UDP 17
#define PROTO_ICMP 1
#define PROTO_ICMPV6 58

#define EVENT_TYPE_ARP 1
#define EVENT_TYPE_TCP 2
#define EVENT_TYPE_UDP 3
#define EVENT_TYPE_ICMP 4
#define EVENT_TYPE_DNS 5
#define EVENT_TYPE_HTTP 6
#define EVENT_TYPE_TLS 7

// DNS port
#define DNS_PORT 53

// HTTP ports
#define HTTP_PORT 80
#define HTTP_ALT_PORT 8080

// HTTPS/TLS port
#define HTTPS_PORT 443
#define HTTPS_ALT_PORT 8443
#define L7_PAYLOAD_SIZE 128

// Verdicts for TCX. A monitor must not end the chain: TC_ACT_OK maps to
// TCX_PASS, which skips every program attached after this one (Cilium,
// shapers, other BPF tools). TC_ACT_UNSPEC is TCX_NEXT: hand the packet on.
#define CERB_PASS TC_ACT_UNSPEC
#define CERB_DROP TC_ACT_SHOT   // TCX_DROP

// Define ICMP header structure directly to avoid including <linux/icmp.h>
struct icmp_hdr {
    __u8  type;
    __u8  code;
    __u16 checksum;
    union {
        struct {
            __u16 id;
            __u16 sequence;
        } echo;
        __u32 gateway;
        struct {
            __u16 unused;
            __u16 mtu;
        } frag;
    } un;
} __attribute__((packed));

struct arp_hdr {
    __u16 ar_hrd;
    __u16 ar_pro;
    __u8  ar_hln;
    __u8  ar_pln;
    __u16 ar_op;
} __attribute__((packed));

struct network_event {
    __u8 event_type;       // 1 byte
    __u8 src_mac[6];       // 6 bytes
    __u8 dst_mac[6];       // 6 bytes
    __u32 src_ip;          // 4 bytes
    __u32 dst_ip;          // 4 bytes
    __u8 is_ipv6;          // 1 byte
    __u8 src_ipv6[16];     // 16 bytes
    __u8 dst_ipv6[16];     // 16 bytes
    __u16 src_port;        // 2 bytes
    __u16 dst_port;        // 2 bytes
    __u8 protocol;         // 1 byte
    __u8 tcp_flags;        // 1 byte
    __u16 arp_op;          // 2 bytes
    __u8 arp_sha[6];       // 6 bytes
    __u8 arp_tha[6];       // 6 bytes
    __u8 icmp_type;        // 1 byte
    __u8 icmp_code;        // 1 byte
    __u32 ifindex;         // 4 bytes
    __u8 l7_payload[L7_PAYLOAD_SIZE];   // 128 bytes
} __attribute__((packed));
// Total: 208 bytes

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Kernel-side counters, read by user space for /metrics. Indexes must match
// internal/kstats. Per-CPU so the hot path needs no atomics.
#define CNT_TOTAL        0  // every packet seen by the classifier
#define CNT_ARP          1
#define CNT_IPV4         2
#define CNT_IPV6         3
#define CNT_OTHER        4  // other ethertypes, or too short to parse
#define CNT_RINGBUF_FULL 5  // events lost because the ring buffer was full
#define CNT_POLICY_DROP  6  // packets dropped by an enforced policy rule
#define CNT_FILTER_LOST  7  // filter log events lost (log ring buffer full)
#define CNT_MAX          8

struct counter {
    __u64 packets;
    __u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, CNT_MAX);
    __type(key, __u32);
    __type(value, struct counter);
} counters SEC(".maps");

static __always_inline void count_len(__u32 idx, __u32 len)
{
    struct counter *c = bpf_map_lookup_elem(&counters, &idx);
    if (c) {
        c->packets++;
        c->bytes += len;
    }
}

static __always_inline void count(__u32 idx, struct __sk_buff *skb)
{
    count_len(idx, skb->len);
}

// ------------------- Policy (active response) -------------------
// Modelled on bpfilter sets: user space fills hash/LPM maps, every rule has
// its own counter, and a global switch decides whether "drop" rules really
// drop (enforce) or only count (monitor / dry run). Layouts must match
// internal/policy.
#define POLICY_ACTION_DROP 1
#define POLICY_ACTION_LOG  2  // count only, never drop

#define POLICY_DIR_SRC 1
#define POLICY_DIR_DST 2

#define MAX_POLICY_RULES 1024

struct policy_val {
    __u32 slot;    // index into policy_counters
    __u8  action;  // POLICY_ACTION_*
    __u8  dir;     // POLICY_DIR_* bitmask (IP rules)
    __u16 pad;
};

struct policy_mac_key {
    __u8  addr[6];
    __u16 pad;
};

struct policy_v4_key {
    __u32 prefixlen;
    __u8  addr[4];
};

struct policy_v6_key {
    __u32 prefixlen;
    __u8  addr[16];
};

// policy_cfg[0] != 0 means enforce; 0 (default) means monitor only.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} policy_cfg SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_POLICY_RULES);
    __type(key, struct policy_mac_key);
    __type(value, struct policy_val);
} policy_mac SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_POLICY_RULES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct policy_v4_key);
    __type(value, struct policy_val);
} policy_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_POLICY_RULES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct policy_v6_key);
    __type(value, struct policy_val);
} policy_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_POLICY_RULES);
    __type(key, __u32);
    __type(value, struct counter);
} policy_counters SEC(".maps");

// Counts the match and reports whether this rule asks for a drop.
static __always_inline int policy_hit(struct __sk_buff *skb, struct policy_val *v)
{
    __u32 slot = v->slot;
    struct counter *c = bpf_map_lookup_elem(&policy_counters, &slot);
    if (c) {
        c->packets++;
        c->bytes += skb->len;
    }
    return v->action == POLICY_ACTION_DROP;
}

static __always_inline int policy_enforcing(void)
{
    __u32 k = 0;
    __u32 *on = bpf_map_lookup_elem(&policy_cfg, &k);
    return on && *on;
}

// Final verdict once all rules matching the packet have been counted.
static __always_inline int policy_should_drop(struct __sk_buff *skb, int want_drop)
{
    if (want_drop && policy_enforcing()) {
        count(CNT_POLICY_DROP, skb);
        return 1;
    }
    return 0;
}

static __always_inline int policy_check_mac(struct __sk_buff *skb, struct ethhdr *eth)
{
    struct policy_mac_key k = {};
    __builtin_memcpy(k.addr, eth->h_source, 6);
    struct policy_val *v = bpf_map_lookup_elem(&policy_mac, &k);
    if (!v)
        return 0;
    return policy_should_drop(skb, policy_hit(skb, v));
}

static __always_inline int policy_check_v4(struct __sk_buff *skb, struct iphdr *iph)
{
    int drop = 0;
    struct policy_v4_key k = { .prefixlen = 32 };
    struct policy_val *v;

    __builtin_memcpy(k.addr, &iph->saddr, 4);
    v = bpf_map_lookup_elem(&policy_v4, &k);
    if (v && (v->dir & POLICY_DIR_SRC))
        drop |= policy_hit(skb, v);

    __builtin_memcpy(k.addr, &iph->daddr, 4);
    v = bpf_map_lookup_elem(&policy_v4, &k);
    if (v && (v->dir & POLICY_DIR_DST))
        drop |= policy_hit(skb, v);

    return policy_should_drop(skb, drop);
}

static __always_inline int policy_check_v6(struct __sk_buff *skb, struct ipv6hdr *ip6h)
{
    int drop = 0;
    struct policy_v6_key k = { .prefixlen = 128 };
    struct policy_val *v;

    __builtin_memcpy(k.addr, &ip6h->saddr, 16);
    v = bpf_map_lookup_elem(&policy_v6, &k);
    if (v && (v->dir & POLICY_DIR_SRC))
        drop |= policy_hit(skb, v);

    __builtin_memcpy(k.addr, &ip6h->daddr, 16);
    v = bpf_map_lookup_elem(&policy_v6, &k);
    if (v && (v->dir & POLICY_DIR_DST))
        drop |= policy_hit(skb, v);

    return policy_should_drop(skb, drop);
}

// ------------------- Filter chain (bpfilter-style rules) -------------------
// An ordered list of rules. Every matcher set on a rule must match. The first
// rule with a terminal verdict decides: ACCEPT (pass, skip the blocklists)
// or DROP. CONTINUE counts/logs and goes on. User space writes the inactive
// half of filter_rules, then flips filter_cfg in one 32-bit store, so a
// packet never sees a half-written chain. Layouts must match internal/policy.
#define MAX_FILTER_RULES 64

#define FV_ACCEPT   1
#define FV_DROP     2
#define FV_CONTINUE 3

#define FM_ICMP_TYPE (1 << 0)
#define FM_ICMP_CODE (1 << 1)
#define FM_SMAC      (1 << 2)
#define FM_NOT_SRC   (1 << 3)
#define FM_NOT_DST   (1 << 4)
#define FM_NOT_SPORT (1 << 5)
#define FM_NOT_DPORT (1 << 6)

// Chain outcome for the classifier.
#define FR_NONE   0  // no terminal match
#define FR_ACCEPT 1  // pass, skip blocklists
#define FR_DROP   2  // drop (enforcing)

struct filter_rule {
    __u32 slot;            // index into filter_counters / filter_log_state
    __u8  verdict;         // FV_*
    __u8  log;             // 1 = publish a log event on match
    __u8  family;          // 0 any, 4 IPv4, 6 IPv6
    __u8  l4proto;         // 0 any, else IP protocol number
    __u32 ifindex;         // 0 any
    __u16 sport_lo, sport_hi;  // sport_hi == 0: any
    __u16 dport_lo, dport_hi;  // dport_hi == 0: any
    __u8  tcp_any;         // match if (flags & tcp_any) != 0; 0 ignores
    __u8  tcp_all;         // match if (flags & tcp_all) == tcp_all; 0 ignores
    __u8  icmp_type;
    __u8  icmp_code;
    __u8  mflags;          // FM_*
    __u8  src_plen;        // 0: any source address
    __u8  dst_plen;        // 0: any destination address
    __u8  pad0;
    __u8  src[16];         // prefix, already masked; IPv4 uses the first 4 bytes
    __u8  dst[16];
    __u8  src_mask[16];    // precomputed by user space from src_plen
    __u8  dst_mask[16];
    __u8  smac[6];
    __u16 pad1;
    __u32 pad2;            // explicit: keeps the u64 below 8-byte aligned
    __u64 log_interval_ns; // minimum gap between two log events; 0 = every match
};

// Parsed once per packet.
struct pkt_info {
    __u32 ifindex;
    __u32 len;
    __u8  family;          // 0 (not IP), 4, 6
    __u8  proto;
    __u8  has_ports;       // TCP or UDP header present
    __u8  tcp_flags;
    __u8  has_icmp;
    __u8  icmp_type;
    __u8  icmp_code;
    __u8  pad;
    __u16 sport, dport;
    __u8  src[16];
    __u8  dst[16];
    __u8  smac[6];
};

struct filter_log_event {
    __u64 ts_ns;           // bpf_ktime_get_ns (monotonic)
    __u32 slot;
    __u32 ifindex;
    __u32 pkt_len;
    __u8  verdict;
    __u8  enforced;        // 1 if a DROP verdict really dropped
    __u8  family;
    __u8  proto;
    __u16 sport, dport;
    __u8  tcp_flags;
    __u8  icmp_type;
    __u8  icmp_code;
    __u8  pad;
    __u8  src[16];
    __u8  dst[16];
    __u8  smac[6];
    __u16 pad1;
};

// filter_cfg[0]: bit 16 selects the active half, low 16 bits are the count.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} filter_cfg SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2 * MAX_FILTER_RULES);
    __type(key, __u32);
    __type(value, struct filter_rule);
} filter_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_FILTER_RULES);
    __type(key, __u32);
    __type(value, struct counter);
} filter_counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_FILTER_RULES);
    __type(key, __u32);
    __type(value, __u64);
} filter_log_state SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} filter_log SEC(".maps");

static __always_inline void parse_pkt(struct __sk_buff *skb, struct ethhdr *eth, struct pkt_info *p)
{
    void *data_end = (void *)(long)skb->data_end;
    void *l4 = 0;

    p->ifindex = skb->ifindex;
    p->len = skb->len;
    __builtin_memcpy(p->smac, eth->h_source, 6);

    __u16 proto = bpf_ntohs(eth->h_proto);
    if (proto == ETH_P_IP) {
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end)
            return;
        __u32 ihl = iph->ihl * 4;
        if (ihl < sizeof(*iph))
            return;
        p->family = 4;
        p->proto = iph->protocol;
        __builtin_memcpy(p->src, &iph->saddr, 4);
        __builtin_memcpy(p->dst, &iph->daddr, 4);
        // Only the first fragment carries the L4 header.
        if (bpf_ntohs(iph->frag_off) & 0x1FFF)
            return;
        l4 = (void *)iph + ihl;
    } else if (proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6h = (void *)(eth + 1);
        if ((void *)(ip6h + 1) > data_end)
            return;
        p->family = 6;
        p->proto = ip6h->nexthdr;   // extension headers are not walked
        __builtin_memcpy(p->src, &ip6h->saddr, 16);
        __builtin_memcpy(p->dst, &ip6h->daddr, 16);
        l4 = (void *)(ip6h + 1);
    } else {
        return;
    }

    if (p->proto == PROTO_TCP) {
        struct tcphdr *th = l4;
        if ((void *)(th + 1) > data_end)
            return;
        p->has_ports = 1;
        p->sport = bpf_ntohs(th->source);
        p->dport = bpf_ntohs(th->dest);
        p->tcp_flags = ((__u8 *)th)[13];
    } else if (p->proto == PROTO_UDP) {
        struct udphdr *uh = l4;
        if ((void *)(uh + 1) > data_end)
            return;
        p->has_ports = 1;
        p->sport = bpf_ntohs(uh->source);
        p->dport = bpf_ntohs(uh->dest);
    } else if (p->proto == PROTO_ICMP || p->proto == PROTO_ICMPV6) {
        __u8 *ih = l4;
        if ((void *)(ih + 2) > data_end)
            return;
        p->has_icmp = 1;
        p->icmp_type = ih[0];
        p->icmp_code = ih[1];
    }
}

// Branch-free masked compare (the mask comes precomputed from user space),
// so the verifier sees one straight-line path instead of 16 branches.
static __always_inline int masked_eq(const __u8 *addr, const __u8 *pfx, const __u8 *mask)
{
    __u8 diff = 0;
#pragma unroll
    for (int i = 0; i < 16; i++)
        diff |= (addr[i] ^ pfx[i]) & mask[i];
    return diff == 0;
}

static __always_inline int port_match(__u16 port, __u16 lo, __u16 hi, int negate)
{
    if (hi == 0)
        return 1;
    int in = port >= lo && port <= hi;
    return negate ? !in : in;
}

static __always_inline int rule_match(struct filter_rule *r, struct pkt_info *p)
{
    if (r->ifindex && r->ifindex != p->ifindex)
        return 0;
    if ((r->mflags & FM_SMAC) && __builtin_memcmp(r->smac, p->smac, 6) != 0)
        return 0;
    if (r->family && r->family != p->family)
        return 0;
    if (r->l4proto && r->l4proto != p->proto)
        return 0;
    if (r->src_plen || r->dst_plen) {
        if (!p->family)
            return 0;
        if (r->src_plen) {
            int m = masked_eq(p->src, r->src, r->src_mask);
            if ((r->mflags & FM_NOT_SRC) ? m : !m)
                return 0;
        }
        if (r->dst_plen) {
            int m = masked_eq(p->dst, r->dst, r->dst_mask);
            if ((r->mflags & FM_NOT_DST) ? m : !m)
                return 0;
        }
    }
    if (r->sport_hi || r->dport_hi) {
        if (!p->has_ports)
            return 0;
        if (!port_match(p->sport, r->sport_lo, r->sport_hi, r->mflags & FM_NOT_SPORT))
            return 0;
        if (!port_match(p->dport, r->dport_lo, r->dport_hi, r->mflags & FM_NOT_DPORT))
            return 0;
    }
    if (r->tcp_any || r->tcp_all) {
        if (p->proto != PROTO_TCP || !p->has_ports)
            return 0;
        if (r->tcp_any && !(p->tcp_flags & r->tcp_any))
            return 0;
        if ((p->tcp_flags & r->tcp_all) != r->tcp_all)
            return 0;
    }
    if (r->mflags & (FM_ICMP_TYPE | FM_ICMP_CODE)) {
        if (!p->has_icmp)
            return 0;
        if ((r->mflags & FM_ICMP_TYPE) && p->icmp_type != r->icmp_type)
            return 0;
        if ((r->mflags & FM_ICMP_CODE) && p->icmp_code != r->icmp_code)
            return 0;
    }
    return 1;
}

static __always_inline void filter_publish(struct filter_rule *r, struct pkt_info *p, __u8 enforced)
{
    __u32 slot = r->slot;
    __u64 now = bpf_ktime_get_ns();
    __u64 *last = bpf_map_lookup_elem(&filter_log_state, &slot);
    if (!last)
        return;
    if (r->log_interval_ns && *last && now - *last < r->log_interval_ns)
        return;
    *last = now;

    struct filter_log_event *e = bpf_ringbuf_reserve(&filter_log, sizeof(*e), 0);
    if (!e) {
        count_len(CNT_FILTER_LOST, p->len);
        return;
    }
    e->ts_ns = now;
    e->slot = slot;
    e->ifindex = p->ifindex;
    e->pkt_len = p->len;
    e->verdict = r->verdict;
    e->enforced = enforced;
    e->family = p->family;
    e->proto = p->proto;
    e->sport = p->sport;
    e->dport = p->dport;
    e->tcp_flags = p->tcp_flags;
    e->icmp_type = p->icmp_type;
    e->icmp_code = p->icmp_code;
    e->pad = 0;
    __builtin_memcpy(e->src, p->src, 16);
    __builtin_memcpy(e->dst, p->dst, 16);
    __builtin_memcpy(e->smac, p->smac, 6);
    e->pad1 = 0;
    bpf_ringbuf_submit(e, 0);
}

// State shared with the bpf_loop callback. The packet info is held by
// value: no pointers cross into the callback.
struct chain_ctx {
    struct pkt_info p;
    __u32 base;
    __u32 n;
    __u32 enforcing;
    __u32 result;   // FR_*
};

// One rule per call; returns 1 to stop the loop. bpf_loop (kernel >= 5.17)
// lets the verifier check this body once instead of 64 unrolled copies.
static long chain_step(__u64 i, void *data)
{
    struct chain_ctx *c = data;
    if (i >= c->n)
        return 1;
    __u32 idx = c->base + (__u32)i;
    struct filter_rule *r = bpf_map_lookup_elem(&filter_rules, &idx);
    if (!r)
        return 1;
    if (!rule_match(r, &c->p))
        return 0;

    __u32 slot = r->slot;
    struct counter *cnt = bpf_map_lookup_elem(&filter_counters, &slot);
    if (cnt) {
        cnt->packets++;
        cnt->bytes += c->p.len;
    }

    __u8 enforced = r->verdict == FV_DROP && c->enforcing;
    if (r->log)
        filter_publish(r, &c->p, enforced);

    if (r->verdict == FV_ACCEPT) {
        c->result = FR_ACCEPT;
        return 1;
    }
    if (r->verdict == FV_DROP) {
        if (enforced) {
            count_len(CNT_POLICY_DROP, c->p.len);
            c->result = FR_DROP;
        }
        return 1; // dry run: decided, but the packet passes
    }
    return 0;     // FV_CONTINUE
}

static __always_inline int filter_chain(struct pkt_info *p)
{
    __u32 k0 = 0;
    __u32 *cfg = bpf_map_lookup_elem(&filter_cfg, &k0);
    if (!cfg)
        return FR_NONE;
    __u32 n = *cfg & 0xFFFF;
    if (n == 0)
        return FR_NONE;

    struct chain_ctx c = {};
    c.p = *p;
    c.n = n;
    c.base = (*cfg & 0x10000) ? MAX_FILTER_RULES : 0;
    c.enforcing = policy_enforcing();
    c.result = FR_NONE;
    bpf_loop(MAX_FILTER_RULES, chain_step, &c, 0);
    return c.result;
}

// Records a lost event and lets the packet through unchanged.
static __always_inline int ringbuf_full(struct __sk_buff *skb)
{
    count(CNT_RINGBUF_FULL, skb);
    return CERB_PASS;
}

// Helper to check if payload looks like HTTP
static __always_inline int is_http_request(__u8 *payload, void *data_end)
{
    if ((void *)(payload + 4) > data_end)
        return 0;
    
    // Check for "GET ", "POST", "HEAD", "PUT ", "DELE" (DELETE)
    if ((payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T' && payload[3] == ' ') ||
        (payload[0] == 'P' && payload[1] == 'O' && payload[2] == 'S' && payload[3] == 'T') ||
        (payload[0] == 'H' && payload[1] == 'E' && payload[2] == 'A' && payload[3] == 'D') ||
        (payload[0] == 'P' && payload[1] == 'U' && payload[2] == 'T' && payload[3] == ' ') ||
        (payload[0] == 'D' && payload[1] == 'E' && payload[2] == 'L' && payload[3] == 'E')) {
        return 1;
    }

    return 0;
}

// Helper to check if payload looks like TLS Client Hello
static __always_inline int is_tls_handshake(__u8 *payload, void *data_end)
{
    if ((void *)(payload + 6) > data_end)
        return 0;
    
    // TLS handshake record: 0x16 (handshake), version (0x03 0x01/0x03), length, handshake type
    if (payload[0] == 0x16 && payload[1] == 0x03) {
        // Check for valid TLS version (SSL 3.0 = 0x0300, TLS 1.0 = 0x0301, TLS 1.2 = 0x0303, TLS 1.3 = 0x0304)
        if (payload[2] >= 0x00 && payload[2] <= 0x04) {
            return 1;
        }
    }

    return 0;
}

// ------------------- ARP -------------------
static __always_inline int handle_arp(struct __sk_buff *skb, struct ethhdr *eth)
{
    void *data_end = (void *)(long)skb->data_end;
    struct arp_hdr *arp = (void *)(eth + 1);
    if ((void *)(arp + 1) > data_end)
        return CERB_PASS;

    if (bpf_ntohs(arp->ar_hrd) != 1 ||
        bpf_ntohs(arp->ar_pro) != ETH_P_IP ||
        arp->ar_hln != 6 || arp->ar_pln != 4)
        return CERB_PASS;

    __u8 *arp_data = (__u8 *)(arp + 1);
    if ((void *)(arp_data + 20) > data_end)
        return CERB_PASS;

    struct network_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return ringbuf_full(skb);

    e->event_type = EVENT_TYPE_ARP;
    __builtin_memcpy(e->src_mac, eth->h_source, 6);
    __builtin_memcpy(e->dst_mac, eth->h_dest, 6);
    __builtin_memcpy(e->arp_sha, arp_data, 6);
    __builtin_memcpy(&e->src_ip, arp_data + 6, 4);
    __builtin_memcpy(e->arp_tha, arp_data + 10, 6);
    __builtin_memcpy(&e->dst_ip, arp_data + 16, 4);
    e->is_ipv6 = 0;
    __builtin_memset(e->src_ipv6, 0, 16);
    __builtin_memset(e->dst_ipv6, 0, 16);
    e->arp_op = bpf_ntohs(arp->ar_op);
    e->protocol = 0;
    e->src_port = 0;
    e->dst_port = 0;
    e->tcp_flags = 0;
    e->icmp_type = 0;
    e->icmp_code = 0;
    e->ifindex = skb->ifindex;
    __builtin_memset(e->l7_payload, 0, sizeof(e->l7_payload));

    bpf_ringbuf_submit(e, 0);
    return CERB_PASS;
}

// ------------------- TCP -------------------
static __always_inline int handle_tcp(struct __sk_buff *skb, struct ethhdr *eth, struct iphdr *iph)
{
    void *data_end = (void *)(long)skb->data_end;
    struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
    if ((void *)(tcph + 1) > data_end) return CERB_PASS;

    __u16 src_port = bpf_ntohs(tcph->source);
    __u16 dst_port = bpf_ntohs(tcph->dest);
    
    struct network_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return ringbuf_full(skb);

    // Default to TCP event type
    e->event_type = EVENT_TYPE_TCP;

    __builtin_memcpy(e->src_mac, eth->h_source, 6);
    __builtin_memcpy(e->dst_mac, eth->h_dest, 6);
    e->src_ip = iph->saddr;
    e->dst_ip = iph->daddr;
    e->is_ipv6 = 0;
    __builtin_memset(e->src_ipv6, 0, 16);
    __builtin_memset(e->dst_ipv6, 0, 16);
    e->src_port = src_port;
    e->dst_port = dst_port;
    e->protocol = PROTO_TCP;
    e->arp_op = 0;
    e->ifindex = skb->ifindex;

    // TCP flags
    __u8 flags = 0;
    if (tcph->syn) flags |= 0x02;
    if (tcph->ack) flags |= 0x10;
    if (tcph->fin) flags |= 0x01;
    if (tcph->rst) flags |= 0x04;
    if (tcph->psh) flags |= 0x08;
    e->tcp_flags = flags;

    e->icmp_type = 0;
    e->icmp_code = 0;
    __builtin_memset(e->arp_sha, 0, 6);
    __builtin_memset(e->arp_tha, 0, 6);

    // Copy first 128 bytes of TCP payload (if present)
    __u8 *payload = (__u8 *)tcph + (tcph->doff * 4);
    __builtin_memset(e->l7_payload, 0, L7_PAYLOAD_SIZE);
    
    if ((void *)payload < data_end) {
        __u64 size = (__u64)data_end - (__u64)payload;
        if (size > 0) {
            if (size > L7_PAYLOAD_SIZE) size = L7_PAYLOAD_SIZE;
            
            #pragma unroll
            for (int i = 0; i < L7_PAYLOAD_SIZE; i++) {
                if (i < size && (void *)(payload + i) < data_end) {
                    e->l7_payload[i] = payload[i];
                } else {
                    break;
                }
            }

            // Detect HTTP on port 80 or 8080 
            if (dst_port == HTTP_PORT || dst_port == HTTP_ALT_PORT || 
                src_port == HTTP_PORT || src_port == HTTP_ALT_PORT) {
                if (is_http_request(payload, data_end)) {
                    e->event_type = EVENT_TYPE_HTTP;
                }
            }
            
            // Detect TLS on port 443 or 8443
            if (dst_port == HTTPS_PORT || dst_port == HTTPS_ALT_PORT ||
                src_port == HTTPS_PORT || src_port == HTTPS_ALT_PORT) {
                if (is_tls_handshake(payload, data_end)) {
                    e->event_type = EVENT_TYPE_TLS;
                }
            }
        }
    }

    bpf_ringbuf_submit(e, 0);
    return CERB_PASS;
}

// ------------------- UDP -------------------
static __always_inline int handle_udp(struct __sk_buff *skb, struct ethhdr *eth, struct iphdr *iph)
{
    void *data_end = (void *)(long)skb->data_end;
    struct udphdr *udph = (void *)iph + (iph->ihl * 4);
    if ((void *)(udph + 1) > data_end) return CERB_PASS;

    __u16 src_port = bpf_ntohs(udph->source);
    __u16 dst_port = bpf_ntohs(udph->dest);
    
    struct network_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return ringbuf_full(skb);

    // Default to UDP event type
    e->event_type = EVENT_TYPE_UDP;
    
    // Check if this is DNS traffic (port 53)
    if (src_port == DNS_PORT || dst_port == DNS_PORT) {
        e->event_type = EVENT_TYPE_DNS;
    }
    
    __builtin_memcpy(e->src_mac, eth->h_source, 6);
    __builtin_memcpy(e->dst_mac, eth->h_dest, 6);
    e->src_ip = iph->saddr;
    e->dst_ip = iph->daddr;
    e->is_ipv6 = 0;
    __builtin_memset(e->src_ipv6, 0, 16);
    __builtin_memset(e->dst_ipv6, 0, 16);
    e->src_port = src_port;
    e->dst_port = dst_port;
    e->protocol = PROTO_UDP;
    e->tcp_flags = 0;
    e->arp_op = 0;
    e->icmp_type = 0;
    e->icmp_code = 0;
    e->ifindex = skb->ifindex;
    __builtin_memset(e->arp_sha, 0, 6);
    __builtin_memset(e->arp_tha, 0, 6);

    // Copy first 128 bytes of UDP payload (DNS, etc.)
    __u8 *payload = (__u8 *)(udph + 1);
    __builtin_memset(e->l7_payload, 0, L7_PAYLOAD_SIZE);
    
    if ((void *)payload < data_end) {
        __u64 size = (__u64)data_end - (__u64)payload;
        if (size > 0) {
            if (size > L7_PAYLOAD_SIZE) size = L7_PAYLOAD_SIZE;
            
            #pragma unroll
            for (int i = 0; i < L7_PAYLOAD_SIZE; i++) {
                if (i < size && (void *)(payload + i) < data_end) {
                    e->l7_payload[i] = payload[i];
                } else {
                    break;
                }
            }
        }
    }

    bpf_ringbuf_submit(e, 0);
    return CERB_PASS;
}

// ------------------- ICMP -------------------
static __always_inline int handle_icmp(struct __sk_buff *skb, struct ethhdr *eth, struct iphdr *iph)
{
    void *data_end = (void *)(long)skb->data_end;
    struct icmp_hdr *icmph = (void *)iph + (iph->ihl * 4);
    if ((void *)(icmph + 1) > data_end) return CERB_PASS;

    struct network_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return ringbuf_full(skb);

    e->event_type = EVENT_TYPE_ICMP;
    __builtin_memcpy(e->src_mac, eth->h_source, 6);
    __builtin_memcpy(e->dst_mac, eth->h_dest, 6);
    e->src_ip = iph->saddr;
    e->dst_ip = iph->daddr;
    e->is_ipv6 = 0;
    __builtin_memset(e->src_ipv6, 0, 16);
    __builtin_memset(e->dst_ipv6, 0, 16);
    e->protocol = PROTO_ICMP;
    e->icmp_type = icmph->type;
    e->icmp_code = icmph->code;
    e->ifindex = skb->ifindex;

    e->tcp_flags = 0;
    e->arp_op = 0;
    e->src_port = 0;
    e->dst_port = 0;
    __builtin_memset(e->arp_sha, 0, 6);
    __builtin_memset(e->arp_tha, 0, 6);
    __builtin_memset(e->l7_payload, 0, L7_PAYLOAD_SIZE);

    bpf_ringbuf_submit(e, 0);
    return CERB_PASS;
}

static __always_inline int handle_tcp6(struct __sk_buff *skb, struct ethhdr *eth, struct ipv6hdr *ip6h)
{
    void *data_end = (void *)(long)skb->data_end;
    struct tcphdr *tcph = (void *)(ip6h + 1);
    if ((void *)(tcph + 1) > data_end) return CERB_PASS;
    __u16 src_port = bpf_ntohs(tcph->source);
    __u16 dst_port = bpf_ntohs(tcph->dest);
    struct network_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return ringbuf_full(skb);
    e->event_type = EVENT_TYPE_TCP;
    __builtin_memcpy(e->src_mac, eth->h_source, 6);
    __builtin_memcpy(e->dst_mac, eth->h_dest, 6);
    e->src_ip = 0;
    e->dst_ip = 0;
    e->is_ipv6 = 1;
    __builtin_memcpy(e->src_ipv6, &ip6h->saddr, 16);
    __builtin_memcpy(e->dst_ipv6, &ip6h->daddr, 16);
    e->src_port = src_port;
    e->dst_port = dst_port;
    e->protocol = PROTO_TCP;
    e->arp_op = 0;
    e->ifindex = skb->ifindex;
    __u8 flags = 0;
    if (tcph->syn) flags |= 0x02;
    if (tcph->ack) flags |= 0x10;
    if (tcph->fin) flags |= 0x01;
    if (tcph->rst) flags |= 0x04;
    if (tcph->psh) flags |= 0x08;
    e->tcp_flags = flags;
    e->icmp_type = 0;
    e->icmp_code = 0;
    __builtin_memset(e->arp_sha, 0, 6);
    __builtin_memset(e->arp_tha, 0, 6);
    __u8 *payload = (__u8 *)tcph + (tcph->doff * 4);
    __builtin_memset(e->l7_payload, 0, L7_PAYLOAD_SIZE);
    if ((void *)payload < data_end) {
        __u64 size = (__u64)data_end - (__u64)payload;
        if (size > 0) {
            if (size > L7_PAYLOAD_SIZE) size = L7_PAYLOAD_SIZE;
            #pragma unroll
            for (int i = 0; i < L7_PAYLOAD_SIZE; i++) {
                if (i < size && (void *)(payload + i) < data_end) e->l7_payload[i] = payload[i];
                else break;
            }
            if (dst_port == HTTP_PORT || dst_port == HTTP_ALT_PORT || src_port == HTTP_PORT || src_port == HTTP_ALT_PORT) {
                if (is_http_request(payload, data_end)) e->event_type = EVENT_TYPE_HTTP;
            }
            if (dst_port == HTTPS_PORT || dst_port == HTTPS_ALT_PORT || src_port == HTTPS_PORT || src_port == HTTPS_ALT_PORT) {
                if (is_tls_handshake(payload, data_end)) e->event_type = EVENT_TYPE_TLS;
            }
        }
    }
    bpf_ringbuf_submit(e, 0);
    return CERB_PASS;
}

static __always_inline int handle_udp6(struct __sk_buff *skb, struct ethhdr *eth, struct ipv6hdr *ip6h)
{
    void *data_end = (void *)(long)skb->data_end;
    struct udphdr *udph = (void *)(ip6h + 1);
    if ((void *)(udph + 1) > data_end) return CERB_PASS;
    __u16 src_port = bpf_ntohs(udph->source);
    __u16 dst_port = bpf_ntohs(udph->dest);
    struct network_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return ringbuf_full(skb);
    e->event_type = EVENT_TYPE_UDP;
    if (src_port == DNS_PORT || dst_port == DNS_PORT) e->event_type = EVENT_TYPE_DNS;
    __builtin_memcpy(e->src_mac, eth->h_source, 6);
    __builtin_memcpy(e->dst_mac, eth->h_dest, 6);
    e->src_ip = 0;
    e->dst_ip = 0;
    e->is_ipv6 = 1;
    __builtin_memcpy(e->src_ipv6, &ip6h->saddr, 16);
    __builtin_memcpy(e->dst_ipv6, &ip6h->daddr, 16);
    e->src_port = src_port;
    e->dst_port = dst_port;
    e->protocol = PROTO_UDP;
    e->tcp_flags = 0;
    e->arp_op = 0;
    e->icmp_type = 0;
    e->icmp_code = 0;
    e->ifindex = skb->ifindex;
    __builtin_memset(e->arp_sha, 0, 6);
    __builtin_memset(e->arp_tha, 0, 6);
    __builtin_memset(e->l7_payload, 0, L7_PAYLOAD_SIZE);
    __u8 *payload = (__u8 *)(udph + 1);
    if ((void *)payload < data_end) {
        __u64 size = (__u64)data_end - (__u64)payload;
        if (size > 0) {
            if (size > 32) size = 32;
            #pragma unroll
            for (int i = 0; i < 32; i++) {
                if (i < size && (void *)(payload + i) < data_end) e->l7_payload[i] = payload[i];
                else break;
            }
        }
    }
    bpf_ringbuf_submit(e, 0);
    return CERB_PASS;
}

static __always_inline int handle_icmp6(struct __sk_buff *skb, struct ethhdr *eth, struct ipv6hdr *ip6h)
{
    void *data_end = (void *)(long)skb->data_end;
    struct icmp_hdr *icmph = (void *)(ip6h + 1);
    if ((void *)(icmph + 1) > data_end) return CERB_PASS;
    struct network_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return ringbuf_full(skb);
    e->event_type = EVENT_TYPE_ICMP;
    __builtin_memcpy(e->src_mac, eth->h_source, 6);
    __builtin_memcpy(e->dst_mac, eth->h_dest, 6);
    e->src_ip = 0;
    e->dst_ip = 0;
    e->is_ipv6 = 1;
    __builtin_memcpy(e->src_ipv6, &ip6h->saddr, 16);
    __builtin_memcpy(e->dst_ipv6, &ip6h->daddr, 16);
    e->protocol = PROTO_ICMPV6;
    e->icmp_type = icmph->type;
    e->icmp_code = icmph->code;
    e->ifindex = skb->ifindex;
    e->tcp_flags = 0;
    e->arp_op = 0;
    e->src_port = 0;
    e->dst_port = 0;
    __builtin_memset(e->arp_sha, 0, 6);
    __builtin_memset(e->arp_tha, 0, 6);
    __builtin_memset(e->l7_payload, 0, L7_PAYLOAD_SIZE);
    bpf_ringbuf_submit(e, 0);
    return CERB_PASS;
}

// ------------------- Classifier -------------------
SEC("classifier")
int xdp_arp_monitor(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;

    count(CNT_TOTAL, skb);
    if ((void *)(eth + 1) > data_end) {
        count(CNT_OTHER, skb);
        return CERB_PASS;
    }

    // Policy: the ordered filter chain first (an ACCEPT match is an
    // exception that also skips the blocklists), then the blocklist sets.
    struct pkt_info pi = {};
    parse_pkt(skb, eth, &pi);
    int chain = filter_chain(&pi);
    if (chain == FR_DROP) return CERB_DROP;
    int skip_sets = chain == FR_ACCEPT;

    // Quarantined devices: drop every frame from the MAC, ARP included.
    if (!skip_sets && policy_check_mac(skb, eth)) return CERB_DROP;

    __u16 proto = bpf_ntohs(eth->h_proto);

    if (proto == ETH_P_ARP) {
        count(CNT_ARP, skb);
        return handle_arp(skb, eth);
    }
    if (proto == ETH_P_IP) {
        count(CNT_IPV4, skb);
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end) return CERB_PASS;
        if (!skip_sets && policy_check_v4(skb, iph)) return CERB_DROP;

        if (iph->protocol == PROTO_TCP) return handle_tcp(skb, eth, iph);
        if (iph->protocol == PROTO_UDP) return handle_udp(skb, eth, iph);
        if (iph->protocol == PROTO_ICMP) return handle_icmp(skb, eth, iph);
    }
    if (proto == ETH_P_IPV6) {
        count(CNT_IPV6, skb);
        struct ipv6hdr *ip6h = (void *)(eth + 1);
        if ((void *)(ip6h + 1) > data_end) return CERB_PASS;
        if (!skip_sets && policy_check_v6(skb, ip6h)) return CERB_DROP;
        if (ip6h->nexthdr == PROTO_TCP) return handle_tcp6(skb, eth, ip6h);
        if (ip6h->nexthdr == PROTO_UDP) return handle_udp6(skb, eth, ip6h);
        if (ip6h->nexthdr == PROTO_ICMPV6) return handle_icmp6(skb, eth, ip6h);
        return CERB_PASS;
    }

    count(CNT_OTHER, skb);
    return CERB_PASS;
}

char _license[] SEC("license") = "GPL";