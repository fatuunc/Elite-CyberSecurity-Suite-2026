// SPDX-License-Identifier: GPL-2.0
/*
 * AegisWAF-ForensiX - eBPF / XDP High-Speed Packet Capture & TLS ClientHello Inspector
 * Author: Fatih Tunç (Digital Forensics & Network Security Engineering)
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct forensic_frame_event {
    __u64 timestamp_ns;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u16 tcp_window;
    __u8  ip_ttl;
    __u8  tcp_flags;
    __u32 payload_len;
    __u8  raw_sample[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024);
} forensic_ringbuf SEC(".maps");

SEC("xdp")
int aegis_xdp_forensic_hook(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return XDP_PASS;
    if (iph->protocol != IPPROTO_TCP) return XDP_PASS;

    struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
    if ((void *)(tcph + 1) > data_end) return XDP_PASS;

    __u16 dport = bpf_ntohs(tcph->dest);
    if (dport != 80 && dport != 443 && dport != 8080 && dport != 8443)
        return XDP_PASS;

    void *payload = (void *)tcph + (tcph->doff * 4);
    if (payload >= data_end) return XDP_PASS;

    struct forensic_frame_event *evt = bpf_ringbuf_reserve(&forensic_ringbuf, sizeof(*evt), 0);
    if (!evt) return XDP_PASS;

    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->src_ip       = iph->saddr;
    evt->dst_ip       = iph->daddr;
    evt->src_port     = bpf_ntohs(tcph->source);
    evt->dst_port     = dport;
    evt->tcp_window   = bpf_ntohs(tcph->window);
    evt->ip_ttl       = iph->ttl;
    evt->tcp_flags    = ((__u8 *)tcph)[13];
    evt->payload_len  = (__u32)(data_end - payload);

    __u32 copy_len = evt->payload_len < 256 ? evt->payload_len : 256;
    for (__u32 i = 0; i < 256; i++) {
        if (i < copy_len && (payload + i + 1 <= data_end))
            evt->raw_sample[i] = *((__u8 *)payload + i);
        else
            evt->raw_sample[i] = 0;
    }
    bpf_ringbuf_submit(evt, 0);
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
