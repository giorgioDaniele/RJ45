#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_endian.h"

#define TC_VERBOSE  0
#define XDP_VERBOSE 0

#define ETH_ALEN 	6
#define TC_ACT_OK 	0

/**
 * Primitiva per stampare in /sys/kernel/debug/tracing/trace_pipe
 * gli eventi verificatesi durante l'esecuzione dei programmi eBPF
 * di cui sotto
*/
#define DBG(fmt, ...)  \
({			  \
	char ____fmt[] = "[RJ45]: " fmt;  \
	bpf_trace_printk(____fmt, \
	sizeof(____fmt), ##__VA_ARGS__); \
})

/**
 * Definzione del valore utilizzato in associazione con
 * la chiave all'interno della tabellina di instradamento
*/
struct _route 
{
	__u8 smac[ETH_ALEN];
	__u8 dmac[ETH_ALEN];
	__u8 interface;
};

/**
 * Definzione della chiave utilizzata per accedere alla
 * tabellina di instradamento
*/
struct _session 
{
	__u32 srcip;
	__u32 dstip;
	__u16 sport;
	__u16 dport;
	__u8  proto;
};

/**
 * Definzione della mappa (variabile globale) utilizzata
 * come tabellina di instradamento attraverso una mappa
 * eBPF
*/
struct 
{
	__uint(type, 	BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, 	struct _session);
	__type(value, 	struct _route);
	__uint(pinning, LIBBPF_PIN_BY_NAME);

} routing_table SEC(".maps");


SEC("tc")
/**
 * Programma da caricare sul blocco TC, sezione di uscita.
 * Il suo compito è quello di registrare all'interno della
 * mappa di cui sopra, data una sessione TCP oppure UDP,
 * la terna costituita da indirizzo MAC sorgente, indirizzo
 * MAC destinazione e numero della interfaccia di rete
 * di uscita
*/
int tc_program(struct __sk_buff* ctx) 
{	
	
	void* data     = (void*) (__u64) ctx->data;
	void* data_end = (void*) (__u64) ctx->data_end;

	struct ethhdr *eth = NULL;
	struct iphdr  *ip4 = NULL;
	struct tcphdr *tcp = NULL;
	struct udphdr *udp = NULL;

	struct _session	session = {};
	struct _route	route	= {};

	if (data + sizeof(struct ethhdr) > data_end)
		return TC_ACT_OK;

	eth  = (struct ethhdr*) data;

	if (__bpf_ntohs(eth->h_proto) != ETH_P_IP)
		return TC_ACT_OK;

	__builtin_memcpy(route.smac, eth->h_source, ETH_ALEN);
	__builtin_memcpy(route.dmac, eth->h_dest, ETH_ALEN);
	route.interface = ctx->ifindex;

	data = data + sizeof(struct ethhdr);

	if (data + sizeof(struct iphdr) > data_end)
		return TC_ACT_OK;

	ip4  = (struct iphdr*) data;

	session.srcip = ip4->saddr;
	session.dstip = ip4->daddr;
	session.proto = ip4->protocol;

	data = data + (ip4->ihl << 2);
	
	if (ip4->protocol == IPPROTO_TCP) 
	{
		if (data + sizeof(struct tcphdr) > data_end)
			return TC_ACT_OK;

		tcp = (struct tcphdr*) data;
		session.sport = tcp->source;
		session.dport = tcp->dest;
	} 
	else if (ip4->protocol == IPPROTO_UDP) 
	{
		if (data + sizeof(struct udphdr) > data_end)
			return TC_ACT_OK;

		udp = (struct udphdr*) data;
		session.sport = udp->source;
		session.dport = udp->dest;
	} 
	else 
	{
		/**
		 * Protocollo livello trasporto non ancora supportato
		*/
		return TC_ACT_OK;
	}

#if TC_VERBOSE 
	if (udp) 
	{
		DBG("[TC] UDP session - from %u to %u\n", 
			__bpf_ntohs(udp->source), 
			__bpf_ntohs(udp->dest));
	} 
	if (tcp) 
	{
		DBG("[TC] TCP session - from %u to %u\n", 
			__bpf_ntohs(tcp->source), 
			__bpf_ntohs(tcp->dest));
	}
#else
	/**
	 * Nessuna stampa. Scelta consigliata se non occorre svolgere
	 * nessuna attività di ispezione del codice!
	*/
#endif

	/**
	 * Inserimento all'interno della tabellina di instradamento
	 * dell'associazione chiave valore
	*/
	bpf_map_update_elem(&routing_table, &session, &route, BPF_ANY);
	return TC_ACT_OK;
}

SEC("xdp")
/**
 * Programma da caricare sul blocco XDP, sezione di ingresso.
 * Il suo compito è quello di interrogare la tabellina di
 * instradamento, quella popolata dal blocco TC, e inoltrare
 * il pacchetto di rete, sostitudendosi al codice del kernel
 * Linux.
*/
int xdp_program(struct xdp_md* ctx) 
{
	void* data     = (void*) (__u64) ctx->data;
	void* data_end = (void*) (__u64) ctx->data_end;

	struct ethhdr *eth = NULL;
	struct iphdr  *ip4 = NULL;
	struct tcphdr *tcp = NULL;
	struct udphdr *udp = NULL;

	__u64 sum  = 0;
	__u32 sze  = 0;
	__u16 *ptr = NULL;

	struct _session	session = {};
	struct _route	*route;

	if (data + sizeof(struct ethhdr) > data_end)
		return XDP_PASS;

	eth  = (struct ethhdr*) data;

	if (__bpf_ntohs(eth->h_proto) != ETH_P_IP)
		return XDP_PASS;

	data = data + sizeof(struct ethhdr);

	if (data + sizeof(struct iphdr) > data_end)
		return XDP_PASS;

	ip4  = (struct iphdr*) data;

	session.srcip = ip4->saddr;
	session.dstip = ip4->daddr;
	session.proto = ip4->protocol;

	data = data + (ip4->ihl << 2);
	
	if (ip4->protocol == IPPROTO_TCP) 
	{
		if (data + sizeof(struct tcphdr) > data_end)
			return XDP_PASS;

		tcp = (struct tcphdr*) data;
		session.sport = tcp->source;
		session.dport = tcp->dest;
	} 
	else if (ip4->protocol == IPPROTO_UDP) 
	{
		if (data + sizeof(struct udphdr) > data_end)
			return XDP_PASS;

		udp = (struct udphdr*) data;
		session.sport = udp->source;
		session.dport = udp->dest;
	} 
	else 
	{
		/**
		 * Protocollo livello trasporto non ancora supportato
		*/
		return XDP_PASS;
	}

	route = bpf_map_lookup_elem(&routing_table, &session);

	if (route == NULL)
	{
		return XDP_PASS;
	}
	
	__builtin_memcpy(eth->h_source, route->smac, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, route->dmac, ETH_ALEN);

	ip4->ttl -= 1;
	ip4->check = 0;

	sum = 0;
	sze = sizeof(struct iphdr);
	ptr = (__u16 *)ip4;
	while (sze > 1)
	{
		sum += *ptr;
		ptr++;
		sze -= 2;
	}
	if (sze == 1)
	{
		sum += *(__u8 *)ptr;
	}
	sum = (sum & 0xFFFF) + (sum >> 16);
	ip4->check = ~sum;

#if XDP_VERBOSE
	if (udp)
	{
		DBG("[XDP] UDP session found - from %u to %u (XDP_REDIRECT)\n",
			__bpf_ntohs(udp->source),
			__bpf_ntohs(udp->dest));
	}
	if (tcp)
	{
		DBG("[XDP] TCP session found - from %u to %u (XDP_REDIRECT)\n",
			__bpf_ntohs(tcp->source),
			__bpf_ntohs(tcp->dest));
	}
#else
	/**
	 * Nessuna stampa. Scelta consigliata se non occorre svolgere
	 * nessuna attività di ispezione del codice!
	*/
#endif

	return bpf_redirect(route->interface, 0);
}


char _license [] SEC("license") = "GPL";
