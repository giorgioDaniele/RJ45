#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_endian.h"

#ifndef TIME_MODE
#define TIME_MODE 0
#endif

#ifndef STATS_MODE
#define STATS_MODE 0
#endif 

#ifndef TC_VERBOSE
#define TC_VERBOSE 0
#endif

#ifndef XDP_VERBOSE
#define XDP_VERBOSE 0
#endif

#if TC_VERBOSE || XDP_VERBOSE
#define DBG(fmt, ...)                           \
({						\
	char ____fmt[] = "rj45: " fmt;                \
	bpf_trace_printk(____fmt, sizeof(____fmt),    \
			 ##__VA_ARGS__);	      \
})
#else
#endif

#define ETH_ALEN 	6
#define TC_ACT_OK 	0
#define TC_ACT_SHOT	1

struct _route 
{
	__u8 smac[ETH_ALEN];
	__u8 dmac[ETH_ALEN];
	__u8 iface;
#if TIME_MODE
	__u64 time;
#endif
};

struct _session 
{
	__u32 srcip;
	__u32 dstip;
	__u16 sport;
	__u16 dport;
	__u8  proto;
};

struct 
{
	__uint(type, 	BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, 	struct _session);
	__type(value, 	struct _route);
	__uint(pinning, LIBBPF_PIN_BY_NAME);

} routing_table SEC(".maps");

#define IPPROTO_TCP  6
#define IPPROTO_UDP 17

SEC("tc")
int tc_program(struct __sk_buff* ctx) 
{
	void* data     = (void*) (__u64) ctx->data;
	void* data_end = (void*) (__u64) ctx->data_end;

	struct ethhdr	*eth = NULL;
	struct iphdr	*ip4 = NULL;
	struct tcphdr	*tcp = NULL;
	struct udphdr	*udp = NULL;

	struct _session	session = {};
	struct _route	route	= {};

	/* Livello Ethernet */

	if (data + sizeof(struct ethhdr) > data_end)
		goto process_drop;
	eth  = (struct ethhdr*) data;

	__builtin_memcpy(route.smac, eth->h_source,	 ETH_ALEN);
	__builtin_memcpy(route.dmac, eth->h_dest,	 ETH_ALEN);
	route.iface = ctx->ifindex;

	data = data + sizeof(struct ethhdr);

	/* Livello IPv4 */

	if (data + sizeof(struct iphdr) > data_end)
		goto process_drop;
	ip4  = (struct iphdr*) data;

	session.srcip = ip4->saddr;
	session.dstip = ip4->daddr;
	session.proto = ip4->protocol;

	data = data + sizeof(struct iphdr);

	/** Livello TCP/UDP */

	if (ip4->protocol == IPPROTO_TCP) {
		if (data + sizeof(struct tcphdr) > data_end)
			goto process_drop;
		tcp = (struct tcphdr*) data;
		goto process_tcp;
	} else if (ip4->protocol == IPPROTO_UDP) {
		if (data + sizeof(struct udphdr) > data_end)
			goto process_drop;
		udp = (struct udphdr*) data;
		goto process_udp;
	} else {
		goto process_pass; /* Protocollo non supportato */
	}

process_tcp:
	session.sport = tcp->source;
	session.dport = tcp->dest;
	goto update_routing_table;
process_udp:
	session.sport = udp->source;
	session.dport = udp->dest;
	goto update_routing_table;

update_routing_table:
#if TIME_MODE
	route.time = bpf_ktime_get_ns();
#else
#endif
	bpf_map_update_elem(&routing_table, &session, &route, BPF_ANY);
process_pass:
  	return TC_ACT_OK;
process_drop:
	return TC_ACT_SHOT;
}

SEC("xdp")
int xdp_program(struct xdp_md* ctx) 
{	
	void* data     = (void*) (__u64) ctx->data;
	void* data_end = (void*) (__u64) ctx->data_end;

	__u64 sum  = 0;
	__u32 sze  = 0;
	__u16 *ptr = NULL;

	struct ethhdr	*eth = NULL;
	struct iphdr	*ip4 = NULL;
	struct tcphdr	*tcp = NULL;
	struct udphdr	*udp = NULL;

	struct _session	session = {};
	struct _route	*route  = NULL;

	/* Livello Ethernet */

	if (data + sizeof(struct ethhdr) > data_end)
		goto process_drop;
	eth  = (struct ethhdr*) data;
	data = data + sizeof(struct ethhdr);

	/* Livello IPv4 */

	if (data + sizeof(struct iphdr) > data_end)
		goto process_drop;
	ip4  = (struct iphdr*) data;

	session.srcip = ip4->saddr;
	session.dstip = ip4->daddr;
	session.proto = ip4->protocol;

	data = data + sizeof(struct iphdr);

	/** Livello TCP/UDP */

	if (ip4->protocol == IPPROTO_TCP) {
		if (data + sizeof(struct tcphdr) > data_end)
			goto process_drop;
		tcp = (struct tcphdr*) data;
		goto process_tcp;
	} else if (ip4->protocol == IPPROTO_UDP) {
		if (data + sizeof(struct udphdr) > data_end)
			goto process_drop;
		udp = (struct udphdr*) data;
		goto process_udp;
	} else {
		goto process_pass;  /* Protocollo non supportato */
	}

	/* Accelerazione del traffico */

process_tcp:
	session.sport = tcp->source;
	session.dport = tcp->dest;
	goto query_routing_table;

process_udp:
	session.sport = udp->source;
	session.dport = udp->dest;
	goto query_routing_table;

query_routing_table:
	route = bpf_map_lookup_elem(&routing_table, &session);
	if (route) {

		/* Modifica degli indirizzi di livello logico */
		__builtin_memcpy(eth->h_source, route->smac, ETH_ALEN);
		__builtin_memcpy(eth->h_dest, route->dmac,	 ETH_ALEN);

		/* Modifica del parametro TTL */
		ip4->ttl   -=1;
		ip4->check = 0;

		/* Calcolo del nuovo checksum */
		sum = 0;
		sze = sizeof(struct iphdr);
		ptr = (__u16*) ip4;
		while (sze > 1) {
			sum += *ptr;
			ptr++;
			sze -= 2;
		}
		if (sze == 1)
			sum += *(__u8*) ptr;
		sum = (sum & 0xFFFF) + (sum >> 16);
		ip4->check = ~sum;

#if XDP_VERBOSE
		if(udp) {
			DBG("UDP session found - packet 0x%X to 0x%X (XDP_REDIRECT)\n", 
				__bpf_ntohs(udp->source), 
				__bpf_ntohs(udp->dest));
		} 
		if(tcp) {
			DBG("TCP session found - packet 0x%X to 0x%X (XDP_REDIRECT)\n", 
				__bpf_ntohs(tcp->source), 
				__bpf_ntohs(tcp->dest));
		}
#else
#endif

		/* Accelerazione del pacchetto */
		return bpf_redirect(route->iface, 0);
	} else {

	}
#if XDP_VERBOSE
		if(udp) {
			DBG("UDP session not found - packet 0x%X to 0x%X (XDP_PASS)\n", 
				__bpf_ntohs(udp->source), 
				__bpf_ntohs(udp->dest));
		} 
		if(tcp) {
			DBG("TCP session not found - packet 0x%X to 0x%X (XDP_PASS)\n", 
				__bpf_ntohs(tcp->source), 
				__bpf_ntohs(tcp->dest));
		}
#else
#endif
process_pass:
  	return XDP_PASS;
process_drop:
	return XDP_DROP;
}


char _license [] SEC("license") = "GPL";
