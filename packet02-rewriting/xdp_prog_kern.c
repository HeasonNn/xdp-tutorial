/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/tcp.h>
#include <linux/udp.h>

// The parsing helper functions from the packet01 lesson have moved here
#include "../common/parsing_helpers.h"

/* Defines xdp_stats_map */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

/* Pops the outermost VLAN tag off the packet. Returns the popped VLAN ID on
 * success or -1 on failure.
 */
static __always_inline int vlan_tag_pop(struct xdp_md *ctx, struct ethhdr *eth)
{
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr eth_cpy;
    struct vlan_hdr *vlh;
    __be16 h_proto;

    int vlid = -1;

    /* Check if there is a vlan tag to pop */
    if (!proto_is_vlan(eth->h_proto))
        return vlid;

    /* Still need to do bounds checking */
    vlh = (void *)(eth + 1);
    if (vlh + 1 > data_end)
        return -1;

    /* Save vlan ID for returning, h_proto for updating Ethernet header */
    vlid = bpf_ntohs(vlh->h_vlan_TCI);
    h_proto = vlh->h_vlan_encapsulated_proto;

    /* Make a copy of the outer Ethernet header before we cut it off */
    __builtin_memcpy(&eth_cpy, eth, sizeof(eth_cpy));

    /* Actually adjust the head pointer */
    if (bpf_xdp_adjust_head(ctx, (int)sizeof(*vlh)))
        return -1;

    /* Need to re-evaluate data *and* data_end and do new bounds checking
     * after adjusting head
     */
    eth = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    if (eth + 1 > data_end)
        return -1;

    /* Copy back the old Ethernet header and update the proto type */
    __builtin_memcpy(eth, &eth_cpy, sizeof(*eth));
    eth->h_proto = h_proto;

    return vlid;
}

/* Pushes a new VLAN tag after the Ethernet header. Returns 0 on success,
 * -1 on failure.
 */
static __always_inline int vlan_tag_push(struct xdp_md *ctx,
                                         struct ethhdr *eth, int vlid)
{
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr eth_cpy;
    struct vlan_hdr *vlh;

    __builtin_memcpy(&eth_cpy, eth, sizeof(eth_cpy));

    if (bpf_xdp_adjust_head(ctx, 0 - (int)(sizeof(*vlh))))
        return -1;

    data_end = (void *)(long)ctx->data_end;
    eth = (void *)(long)ctx->data;

    if (eth + 1 > data_end)
        return -1;

    __builtin_memcpy(eth, &eth_cpy, sizeof(*eth));

    vlh = (void *)(eth + 1);
    if (vlh + 1 > data_end)
        return -1;

    vlh->h_vlan_encapsulated_proto = eth_cpy.h_proto;
    vlh->h_vlan_TCI = bpf_htons(vlid);

    eth->h_proto = bpf_htons(ETH_P_8021Q);
    return 0;
}

/* Implement assignment 1 in this section */
SEC("xdp")
int xdp_port_rewrite_func(struct xdp_md *ctx)
{
    int action = XDP_PASS;
    int eth_type, ip_type;
    struct ethhdr *eth;
    struct iphdr *iphdr;
    struct ipv6hdr *ipv6hdr;
    struct udphdr *udphdr;
    struct tcphdr *tcphdr;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct hdr_cursor nh = {.pos = data};

    eth_type = parse_ethhdr(&nh, data_end, &eth);
    if (eth_type < 0)
    {
        action = XDP_ABORTED;
        goto out;
    }

    if (eth_type == bpf_htons(ETH_P_IP))
    {
        ip_type = parse_iphdr(&nh, data_end, &iphdr);
    }
    else if (eth_type == bpf_htons(ETH_P_IPV6))
    {
        ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
    }
    else
    {
        goto out;
    }

    if (ip_type == IPPROTO_UDP)
    {
        if (parse_udphdr(&nh, data_end, &udphdr) < 0)
        {
            action = XDP_ABORTED;
            goto out;
        }

        udphdr->dest = bpf_htons(bpf_ntohs(udphdr->dest) - 1);
        udphdr->check += bpf_htons(1);
        if (!udphdr->check)
            udphdr->check += bpf_htons(1);
    }
    else if (ip_type == IPPROTO_TCP)
    {
        if (parse_tcphdr(&nh, data_end, &tcphdr) < 0)
        {
            action = XDP_ABORTED;
            goto out;
        }
        tcphdr->dest = bpf_htons(bpf_ntohs(tcphdr->dest) - 1);
        tcphdr->check += bpf_htons(1);
        if (!tcphdr->check)
            tcphdr->check += bpf_htons(1);
    }
out:
    return xdp_stats_record_action(ctx, action);
}

/* VLAN swapper; will pop outermost VLAN tag if it exists, otherwise push a new
 * one with ID 1. Use this for assignments 2 and 3.
 */
SEC("xdp")
int xdp_vlan_swap_func(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* These keep track of the next header type and iterator pointer */
    struct hdr_cursor nh;
    int nh_type;
    nh.pos = data;

    struct ethhdr *eth;
    nh_type = parse_ethhdr(&nh, data_end, &eth);
    if (nh_type < 0)
        return XDP_PASS;

    /* Assignment 2 and 3 will implement these. For now they do nothing */
    if (proto_is_vlan(eth->h_proto))
        vlan_tag_pop(ctx, eth);
    else
        vlan_tag_push(ctx, eth, 1);

    return XDP_PASS;
}

/* Solution to the parsing exercise in lesson packet01. Handles VLANs and legacy
 * IP (via the helpers in parsing_helpers.h).
 */
SEC("xdp")
int xdp_parser_func(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* Default action XDP_PASS, imply everything we couldn't parse, or that
     * we don't want to deal with, we just pass up the stack and let the
     * kernel deal with it.
     */
    __u32 action = XDP_PASS; /* Default action */

    /* These keep track of the next header type and iterator pointer */
    struct hdr_cursor nh;
    int nh_type;
    nh.pos = data;

    struct ethhdr *eth;

    /* Packet parsing in steps: Get each header one at a time, aborting if
     * parsing fails. Each helper function does sanity checking (is the
     * header type in the packet correct?), and bounds checking.
     */
    nh_type = parse_ethhdr(&nh, data_end, &eth);

    if (nh_type == bpf_htons(ETH_P_IPV6))
    {
        struct ipv6hdr *ip6h;
        struct icmp6hdr *icmp6h;

        nh_type = parse_ip6hdr(&nh, data_end, &ip6h);
        if (nh_type != IPPROTO_ICMPV6)
            goto out;

        nh_type = parse_icmp6hdr(&nh, data_end, &icmp6h);
        if (nh_type != ICMPV6_ECHO_REQUEST)
            goto out;

        if (bpf_ntohs(icmp6h->icmp6_sequence) % 2 == 0)
            action = XDP_DROP;
    }
    else if (nh_type == bpf_htons(ETH_P_IP))
    {
        struct iphdr *iph;
        struct icmphdr *icmph;

        nh_type = parse_iphdr(&nh, data_end, &iph);
        if (nh_type != IPPROTO_ICMP)
            goto out;

        nh_type = parse_icmphdr(&nh, data_end, &icmph);
        if (nh_type != ICMP_ECHO)
            goto out;

        if (bpf_ntohs(icmph->un.echo.sequence) % 2 == 0)
            action = XDP_DROP;
    }
out:
    return xdp_stats_record_action(ctx, action);
}

char _license[] SEC("license") = "GPL";
