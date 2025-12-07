#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_ARP 0x0806
#define ETH_P_IP  0x0800

#define PROTO_TCP 6
#define PROTO_UDP 17
#define PROTO_ICMP 1

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
    __u16 src_port;        // 2 bytes
    __u16 dst_port;        // 2 bytes
    __u8 protocol;         // 1 byte
    __u8 tcp_flags;        // 1 byte
    __u16 arp_op;          // 2 bytes
    __u8 arp_sha[6];       // 6 bytes
    __u8 arp_tha[6];       // 6 bytes
    __u8 icmp_type;        // 1 byte
    __u8 icmp_code;        // 1 byte
    __u8 l7_payload[32];   // 32 bytes
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

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
        return TC_ACT_OK;

    if (bpf_ntohs(arp->ar_hrd) != 1 ||
        bpf_ntohs(arp->ar_pro) != ETH_P_IP ||
        arp->ar_hln != 6 || arp->ar_pln != 4)
        return TC_ACT_OK;

    __u8 *arp_data = (__u8 *)(arp + 1);
    if ((void *)(arp_data + 20) > data_end)
        return TC_ACT_OK;

    struct network_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return TC_ACT_OK;

    e->event_type = EVENT_TYPE_ARP;
    __builtin_memcpy(e->src_mac, eth->h_source, 6);
    __builtin_memcpy(e->dst_mac, eth->h_dest, 6);
    __builtin_memcpy(e->arp_sha, arp_data, 6);
    __builtin_memcpy(&e->src_ip, arp_data + 6, 4);
    __builtin_memcpy(e->arp_tha, arp_data + 10, 6);
    __builtin_memcpy(&e->dst_ip, arp_data + 16, 4);
    e->arp_op = bpf_ntohs(arp->ar_op);
    e->protocol = 0;
    e->src_port = 0;
    e->dst_port = 0;
    e->tcp_flags = 0;
    e->icmp_type = 0;
    e->icmp_code = 0;
    __builtin_memset(e->l7_payload, 0, sizeof(e->l7_payload));

    bpf_ringbuf_submit(e, 0);
    return TC_ACT_OK;
}

// ------------------- TCP -------------------
static __always_inline int handle_tcp(struct __sk_buff *skb, struct ethhdr *eth, struct iphdr *iph)
{
    void *data_end = (void *)(long)skb->data_end;
    struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
    if ((void *)(tcph + 1) > data_end) return TC_ACT_OK;

    __u16 src_port = bpf_ntohs(tcph->source);
    __u16 dst_port = bpf_ntohs(tcph->dest);
    
    struct network_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return TC_ACT_OK;

    // Default to TCP event type
    e->event_type = EVENT_TYPE_TCP;
    
    __builtin_memcpy(e->src_mac, eth->h_source, 6);
    __builtin_memcpy(e->dst_mac, eth->h_dest, 6);
    e->src_ip = iph->saddr;
    e->dst_ip = iph->daddr;
    e->src_port = src_port;
    e->dst_port = dst_port;
    e->protocol = PROTO_TCP;
    e->arp_op = 0;

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

    // Copy first 32 bytes of TCP payload (if present)
    __u8 *payload = (__u8 *)tcph + (tcph->doff * 4);
    __builtin_memset(e->l7_payload, 0, 32);
    
    if ((void *)payload < data_end) {
        __u64 size = (__u64)data_end - (__u64)payload;
        if (size > 0) {
            if (size > 32) size = 32;
            
            #pragma unroll
            for (int i = 0; i < 32; i++) {
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
    return TC_ACT_OK;
}

// ------------------- UDP -------------------
static __always_inline int handle_udp(struct __sk_buff *skb, struct ethhdr *eth, struct iphdr *iph)
{
    void *data_end = (void *)(long)skb->data_end;
    struct udphdr *udph = (void *)iph + (iph->ihl * 4);
    if ((void *)(udph + 1) > data_end) return TC_ACT_OK;

    __u16 src_port = bpf_ntohs(udph->source);
    __u16 dst_port = bpf_ntohs(udph->dest);
    
    struct network_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return TC_ACT_OK;

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
    e->src_port = src_port;
    e->dst_port = dst_port;
    e->protocol = PROTO_UDP;
    e->tcp_flags = 0;
    e->arp_op = 0;
    e->icmp_type = 0;
    e->icmp_code = 0;
    __builtin_memset(e->arp_sha, 0, 6);
    __builtin_memset(e->arp_tha, 0, 6);

    // Copy first 32 bytes of UDP payload (DNS, etc.)
    __u8 *payload = (__u8 *)(udph + 1);
    __builtin_memset(e->l7_payload, 0, 32);
    
    if ((void *)payload < data_end) {
        __u64 size = (__u64)data_end - (__u64)payload;
        if (size > 0) {
            if (size > 32) size = 32;
            
            #pragma unroll
            for (int i = 0; i < 32; i++) {
                if (i < size && (void *)(payload + i) < data_end) {
                    e->l7_payload[i] = payload[i];
                } else {
                    break;
                }
            }
        }
    }

    bpf_ringbuf_submit(e, 0);
    return TC_ACT_OK;
}

// ------------------- ICMP -------------------
static __always_inline int handle_icmp(struct __sk_buff *skb, struct ethhdr *eth, struct iphdr *iph)
{
    void *data_end = (void *)(long)skb->data_end;
    struct icmp_hdr *icmph = (void *)iph + (iph->ihl * 4);
    if ((void *)(icmph + 1) > data_end) return TC_ACT_OK;

    struct network_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return TC_ACT_OK;

    e->event_type = EVENT_TYPE_ICMP;
    __builtin_memcpy(e->src_mac, eth->h_source, 6);
    __builtin_memcpy(e->dst_mac, eth->h_dest, 6);
    e->src_ip = iph->saddr;
    e->dst_ip = iph->daddr;
    e->protocol = PROTO_ICMP;
    e->icmp_type = icmph->type;
    e->icmp_code = icmph->code;

    e->tcp_flags = 0;
    e->arp_op = 0;
    e->src_port = 0;
    e->dst_port = 0;
    __builtin_memset(e->arp_sha, 0, 6);
    __builtin_memset(e->arp_tha, 0, 6);
    __builtin_memset(e->l7_payload, 0, 32);

    bpf_ringbuf_submit(e, 0);
    return TC_ACT_OK;
}

// ------------------- Classifier -------------------
SEC("classifier")
int xdp_arp_monitor(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;

    __u16 proto = bpf_ntohs(eth->h_proto);

    if (proto == ETH_P_ARP) return handle_arp(skb, eth);
    if (proto == ETH_P_IP) {
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end) return TC_ACT_OK;

        if (iph->protocol == PROTO_TCP) return handle_tcp(skb, eth, iph);
        if (iph->protocol == PROTO_UDP) return handle_udp(skb, eth, iph);
        if (iph->protocol == PROTO_ICMP) return handle_icmp(skb, eth, iph);
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";