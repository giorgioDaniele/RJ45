#include "vmlinux.h"
#include "options.h"
#include "bpf_helpers.h"
#include "bpf_endian.h"

#if TC_VERBOSE || XDP_VERBOSE
#define DBG(fmt, ...)   \
({						\
	char ____fmt[] = "rj45: " fmt;  \
	bpf_trace_printk(____fmt, sizeof(____fmt), \
			 ##__VA_ARGS__); \
})
#else
#endif

/**
 * Definzione delle azioni
 * nel programma TC
*/

#define ETH_ALEN 	6
#define TC_ACT_OK 	0
#define TC_ACT_SHOT	1

struct _route 
{
	__u8 smac[ETH_ALEN];
	__u8 dmac[ETH_ALEN];
	__u8 iface;
#if TIME_BASED_MODE
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

#if STATISTICS_MODE
struct _statistics 
{
	__u64 packets;
	__u64 bytes;
};

struct 
{
	__uint(type, 	BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 1024);
	__type(key, 	struct _session);
	__type(value, 	struct _statistics);
	__uint(pinning, LIBBPF_PIN_BY_NAME);

} statistics_table SEC(".maps");
#else
#endif

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

	__builtin_memcpy(route.smac, eth->h_source, ETH_ALEN);
	__builtin_memcpy(route.dmac, eth->h_dest, ETH_ALEN);
	route.iface = ctx->ifindex;

	data = data + sizeof(struct ethhdr);

	/* Livello IPv4 */

	if (data + sizeof(struct iphdr) > data_end)
		goto process_pass;
	ip4  = (struct iphdr*) data;

	session.srcip = ip4->saddr;
	session.dstip = ip4->daddr;
	session.proto = ip4->protocol;

	data = data + (ip4->ihl << 2);
	
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

		/**
		 * Protocollo livello trasporto
		 * non supportato
		*/

		goto process_pass;
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
#if TIME_BASED_MODE
	route.time = bpf_ktime_get_ns();
#else
#endif

	bpf_map_update_elem(
		&routing_table, &session, 
		&route, BPF_ANY);

#if TC_VERBOSE

		if(udp) {
			DBG("[TC] UDP session - from %u to %u\n", 
				__bpf_ntohs(udp->source), 
				__bpf_ntohs(udp->dest));
		} 
		if(tcp) {
			DBG("[TC] TCP session - from %u to %u\n", 
				__bpf_ntohs(tcp->source), 
				__bpf_ntohs(tcp->dest));
		}
#else
#endif

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

#if STATISTICS_MODE 
	struct _statistics *statistics = NULL;
	struct _statistics  new_statistics = {};
#else
#endif

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

	data = data + (ip4->ihl << 2);

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

		/**
		 * Protocollo livello trasporto
		 * non supportato
		*/

		goto process_pass;
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

	if (route == NULL) {

#if XDP_VERBOSE
		if(udp) {
			DBG("[XDP] UDP session not found - from %u to %u (XDP_PASS)\n", 
				__bpf_ntohs(udp->source), 
				__bpf_ntohs(udp->dest));
		} 
		if(tcp) {
			DBG("[XDP] TCP session not found - from %u to %u (XDP_PASS)\n", 
				__bpf_ntohs(tcp->source), 
				__bpf_ntohs(tcp->dest));
		}
#else
#endif

	} else {

#if XDP_VERBOSE
		if(udp) {
			DBG("[XDP] UDP session found - from %u to %u (XDP_REDIRECT)\n", 
				__bpf_ntohs(udp->source), 
				__bpf_ntohs(udp->dest));
		} 
		if(tcp) {
			DBG("[XDP] TCP session found - from %u to %u (XDP_REDIRECT)\n", 
				__bpf_ntohs(tcp->source), 
				__bpf_ntohs(tcp->dest));
		}
#else
#endif	

		/**
		 * Modifica degli indirizzi 
		 * di livello Ethernet
		*/
	
		__builtin_memcpy(eth->h_source, route->smac, ETH_ALEN);
		__builtin_memcpy(eth->h_dest, route->dmac, ETH_ALEN);

		/**
		 * Messa a punto dei paramentri
		 * intestazione IPv4
		*/
	
		ip4->ttl   -=1;
		ip4->check = 0;

		/**
		 * Calcolo del checksum IPv4
		*/

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

#if STATISTICS_MODE

		/**
		 * Aggiornamento delle statistiche
		*/

		statistics = bpf_map_lookup_elem(&statistics_table, &session);
		if (statistics) {

			/**
			 * Aggiornamento delle statistiche
			 * finora raccolte
			*/

			statistics->packets += (__u64) 1;
			statistics->bytes   += (__u64) (data_end - data);

		} else {

			/**
			 * Aggiunta di un nuovo
			 * elemento all'interno
			 * della mappa
			*/

			new_statistics.packets = (__u64) 1;
			new_statistics.bytes   = (__u64) (data_end - data);
		
			bpf_map_update_elem(
				&statistics_table, &session, 
				&new_statistics, BPF_NOEXIST);
		}
#else
#endif	
		/**
		 * Accelerazione del pacchetto
		 * di rete
		*/

		return bpf_redirect(route->iface, 0);
	}

process_pass:
  	return XDP_PASS;
process_drop:
	return XDP_DROP;
}

/**
 * Licenza
*/

char _license [] SEC("license") = "GPL";
