#include "vmlinux.h"
#include "options.h"
#include "bpf_helpers.h"
#include "bpf_endian.h"

struct 
{
	__uint(type, 		BPF_MAP_TYPE_PIFO_XDP);
	__uint(key_size,    sizeof(__u32));
	__uint(value_size,  sizeof(__u32));
	__uint(max_entries, 1024);
	__uint(map_extra, 	8192);
} queue SEC(".maps");


__u16 priority  = 3;
__u32 tgt_iface = 6;

#define DBG(fmt, ...)   \
({						\
	char ____fmt[] = "TEST: " fmt;  \
	bpf_trace_printk(____fmt, sizeof(____fmt), \
			 ##__VA_ARGS__); \
})

SEC("xdp")
int enqueue_program(struct xdp_md* ctx) 
{	
	void* data     = (void*) (__u64) ctx->data;
	void* data_end = (void*) (__u64) ctx->data_end;

	int ret;

	struct ethhdr *eth;

	if (data + sizeof(struct ethhdr) > data_end) {
		return XDP_DROP;
	}

	ret = bpf_redirect_map(&queue, priority, 0);
	if (ret == XDP_REDIRECT) {
		bpf_schedule_iface_dequeue(ctx, tgt_iface, 0);
	}
	return ret;
}

SEC("dequeue")
void *dequeue_program (struct dequeue_ctx *ctx)
{	
	__u64 priority = 0;
	struct xdp_md *pkt;
	pkt = (void*) bpf_packet_dequeue(ctx, &queue, 0, &priority);

	if (pkt) {
		DBG("Pacchetto estratto!\n");
	}

	return pkt;
}

/**
 * Licenza
*/

char _license [] SEC("license") = "GPL";
