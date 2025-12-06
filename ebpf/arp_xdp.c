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

#define EVENT_TYPE_ARP 1
#define EVENT_TYPE_TCP 2
#define EVENT_TYPE_UDP 3

struct arp_hdr {
    __u16 ar_hrd;
    __u16 ar_pro;
    __u8  ar_hln;
    __u8  ar_pln;
    __u16 ar_op;
} __attribute__((packed));


// Union to handle different event types
struct network_event {
    __u8 event_type;     // 1 byte
    __u8 src_mac[6];     // 6 bytes
    __u8 dst_mac[6];     // 6 bytes
    __u32 src_ip;        // 4 bytes
    __u32 dst_ip;        // 4 bytes
    __u16 src_port;      // 2 bytes
    __u16 dst_port;      // 2 bytes
    __u8 protocol;       // 1 byte
    __u8 tcp_flags;      // 1 byte
    __u16 arp_op;        // 2 bytes
    __u8 arp_sha[6];     // 6 bytes
    __u8 arp_tha[6];     // 6 bytes
} __attribute__((packed)); // Total: 1+6+6+4+4+2+2+1+1+2+6+6 = 41 bytes

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

static __always_inline int handle_arp(struct __sk_buff *skb, struct ethhdr *eth)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    struct arp_hdr *arp = (void *)(eth + 1);
    if ((void *)(arp + 1) > data_end)
        return TC_ACT_OK;

    if (bpf_ntohs(arp->ar_hrd) != 1 ||
        bpf_ntohs(arp->ar_pro) != ETH_P_IP ||
        arp->ar_hln != 6 ||
        arp->ar_pln != 4)
        return TC_ACT_OK;

    __u8 *arp_data = (__u8 *)(arp + 1);
    if ((void *)(arp_data + 20) > data_end)
        return TC_ACT_OK;

    struct network_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return TC_ACT_OK;

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

    bpf_ringbuf_submit(e, 0);
    return TC_ACT_OK;
}

static __always_inline int handle_tcp(struct __sk_buff *skb, struct ethhdr *eth, struct iphdr *iph)
{
    void *data_end = (void *)(long)skb->data_end;
    
    struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
    if ((void *)(tcph + 1) > data_end)
        return TC_ACT_OK;

    struct network_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return TC_ACT_OK;

    e->event_type = EVENT_TYPE_TCP;
    __builtin_memcpy(e->src_mac, eth->h_source, 6);
    __builtin_memcpy(e->dst_mac, eth->h_dest, 6);
    e->src_ip = iph->saddr;
    e->dst_ip = iph->daddr;
    e->src_port = bpf_ntohs(tcph->source);
    e->dst_port = bpf_ntohs(tcph->dest);
    e->protocol = PROTO_TCP;
    e->arp_op = 0;
    
    // Extract TCP flags
    __u8 flags = 0;
    if (tcph->syn) flags |= 0x02;
    if (tcph->ack) flags |= 0x10;
    if (tcph->fin) flags |= 0x01;
    if (tcph->rst) flags |= 0x04;
    if (tcph->psh) flags |= 0x08;
    e->tcp_flags = flags;

    __builtin_memset(e->arp_sha, 0, 6);
    __builtin_memset(e->arp_tha, 0, 6);

    bpf_ringbuf_submit(e, 0);
    return TC_ACT_OK;
}

static __always_inline int handle_udp(struct __sk_buff *skb, struct ethhdr *eth, struct iphdr *iph)
{
    void *data_end = (void *)(long)skb->data_end;
    
    struct udphdr *udph = (void *)iph + (iph->ihl * 4);
    if ((void *)(udph + 1) > data_end)
        return TC_ACT_OK;

    struct network_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return TC_ACT_OK;

    e->event_type = EVENT_TYPE_UDP;
    __builtin_memcpy(e->src_mac, eth->h_source, 6);
    __builtin_memcpy(e->dst_mac, eth->h_dest, 6);
    e->src_ip = iph->saddr;
    e->dst_ip = iph->daddr;
    e->src_port = bpf_ntohs(udph->source);
    e->dst_port = bpf_ntohs(udph->dest);
    e->protocol = PROTO_UDP;
    e->tcp_flags = 0;
    e->arp_op = 0;

    __builtin_memset(e->arp_sha, 0, 6);
    __builtin_memset(e->arp_tha, 0, 6);

    bpf_ringbuf_submit(e, 0);
    return TC_ACT_OK;
}

SEC("classifier")
int xdp_arp_monitor(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    __u16 proto = bpf_ntohs(eth->h_proto);

    // Handle ARP
    if (proto == ETH_P_ARP) {
        return handle_arp(skb, eth);
    }
    
    // Handle IPv4
    if (proto == ETH_P_IP) {
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end)
            return TC_ACT_OK;

        // Handle TCP
        if (iph->protocol == PROTO_TCP) {
            return handle_tcp(skb, eth, iph);
        }
        
        // Handle UDP
        if (iph->protocol == PROTO_UDP) {
            return handle_udp(skb, eth, iph);
        }
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";