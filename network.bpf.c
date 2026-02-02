struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);    // source port
    __type(value, __u64);  // packet count
} udp_stats SEC(".maps");

SEC("xdp")
int decode_udp(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    // Check if it's an IP packet (0x0800 = ETH_P_IP)
    if (eth->h_proto != bpf_htons(0x0800))
        return XDP_PASS;
    
    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    
    // Check if it's UDP (17 = IPPROTO_UDP)
    if (ip->protocol != 17)
        return XDP_PASS;
    
    // Parse UDP header
    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    
    // Decode UDP fields
    __u16 src_port = bpf_ntohs(udp->source);
    __u16 dst_port = bpf_ntohs(udp->dest);
    __u16 length = bpf_ntohs(udp->len);
    
    // Access UDP payload
    void *payload = (void *)(udp + 1);
    __u32 payload_size = length - sizeof(struct udphdr);
    
    // Ensure payload is within bounds
    if (payload + payload_size > data_end)
        payload_size = data_end - payload;
    
    // Update statistics
    __u32 key = src_port;
    __u64 *count = bpf_map_lookup_elem(&udp_stats, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 init_val = 1;
        bpf_map_update_elem(&udp_stats, &key, &init_val, BPF_ANY);
    }
    
    // Print information (for debugging)
    bpf_printk("UDP: src=%d dst=%d len=%d\n", src_port, dst_port, length);
    
    return XDP_PASS;
}



