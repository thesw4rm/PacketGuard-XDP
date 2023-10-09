#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <arpa/inet.h>



SEC("xdp_drop_ipv4")
int capture_packets(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
     __u32 key = 0;
     uint32_t tcp_port;
    struct ethhdr *ether = data;


    if ((void*)(ether + 1) > (void*)ctx->data_end) {
        return XDP_DROP; /* malformed packet */
    }

    if (ether->h_proto != htons(ETH_P_IP)) {
        return XDP_PASS;
    }
    struct iphdr* ip = (struct iphdr*)(ether + 1);
    if ((void*)(ip + 1) > (void*)ctx->data_end) {
        return XDP_DROP; /* malformed packet */
    }

    if (ip->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }
    struct tcphdr* tcp = (struct tcphdr*)(ip + 1);
    if ((void*)(tcp + 1) > (void*)ctx->data_end) {
        return XDP_DROP; /* malformed packet */
    }

    tcp_port = ntohs(tcp->dest);


    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_DROP;

            
    if (tcp_port == 4040) {
        // Packet has IP and TCP headers, and the destination port is 4040.
        // Drop the packet.
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
