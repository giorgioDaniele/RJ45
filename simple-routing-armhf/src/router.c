#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_endian.h"

/**
 * Opzioni di compilazione
 */

#ifndef TC_VERBOSE_MODE
#define TC_VERBOSE_MODE 0
#endif

#ifndef XDP_VERBOSE_MODE
#define XDP_VERBOSE_MODE 1
#endif

#ifndef TIME_MODE
#define TIME_MODE 0
#endif

#ifndef STATS_MODE 
#define STATS_MODE 0
#endif 

/**
 * Costanti varie
 */

#define ETH_ALEN 	6
#define ETH_P_IP	0X0800

#define IPPROTO_TCP 	6
#define IPPROTO_UDP	17


/**
 * Traffic Control Actions
 */

#define TC_ACT_UNSPEC  		(-1)
#define TC_ACT_OK		0
#define TC_ACT_RECLASSIFY 	1
#define TC_ACT_SHOT		2

/**
 * Messaggi di debug
 */

const char eth_rejected [] = 
	"Ethernet packet has been rejected - 0x%x--0x%x (HEX)\n";
const char ip4_rejected [] =
	"IPv4 packet has been rejected - 0x%x--0x%x (HEX)\n";
const char tcp_rejected [] =
	"TCP packet has been rejected - 0x%x--0x%x (HEX)\n";
const char udp_rejected [] =
	"UDP packet has been rejected - 0x%x--0x%x (HEX)\n";

const char pkt_redirected [] =
	"Packet has been redirected - 0x%x--0x%x (HEX)\n";
const char pkt_passed [] =
	"Packet has been passed - 0x%x--0x%x (HEX)\n";

/**
 * Definizione della chiavi e dei valori
 * della mappe utilizzate
 */

struct _route 
{
	__u8 src_mac[ETH_ALEN];
	__u8 dst_mac[ETH_ALEN];
	__u8 interface;
#if TIME_MODE
	__u64 time;
#endif
};

struct _session 
{
	__u32 src_ip;
	__u32 dst_ip;
	__u16 src_pt;
	__u16 dst_pt;
	__u8  proto;
};

struct 
{
	/**
	 * Definizione della mappa utilizzata
	 * come tabellina di instradamento
	 */

	__uint(type, 	BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, 	struct _session);
	__type(value, 	struct _route);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	

} routing_table SEC(".maps");

/** 
 * Funzioni ausiliare
 */

static __always_inline __u16 ip_checksum(__u16* ip4, int size)
{	
	__u64 sum = 0;
	
	while (size > 1)
	{
		sum += *ip4;
		ip4++;
		size -= 2;
	}

	if (size == 1)
		sum += *(__u8*) ip4;

	sum = (sum & 0xFFFF) + (sum >> 16);

	return ~sum; 
}

SEC("tc")
int tc_program(struct __sk_buff* ctx) 
{

	void *data  	= (void*) (__u64) ctx->data;
	void *data_end 	= (void*) (__u64) ctx->data_end;

	struct ethhdr	*eth;
	struct iphdr	*ip4;
	struct tcphdr	*tcp;
	struct udphdr	*udp;

	struct _session	session = {};
	struct _route	route   = {};

	
	/**
	 * Processamento livello Data Link
	 * 
	 * Se il pacchetto non ha una intestazione
	 * Ethernet compatibile con la dimensione
	 * attesa, allora il pacchetto è scartato.
	 * Se il pacchetto non trasporta protocollo
	 * IPv4, allora il pacchetto è scartato
	 */
	
	eth = (struct ethhdr*) data;
	if (
		data + 
		sizeof(struct ethhdr) > data_end)
	{
#if TC_VERBOSE_MODE
		bpf_trace_printk(
				eth_rejected, sizeof(eth_rejected),
				data, data_end);
#else
#endif
			goto tc_pass;
	}
	if (eth->h_proto != __bpf_htons(ETH_P_IP))
	{
		goto tc_pass;
	}

	/**
	 * Memorizzazione degli indirizzi sorgente e
	 * destinazione MAC. In più, salvataggio del
	 * numero di interfaccia di uscita
	*/

	__builtin_memcpy(route.src_mac, eth->h_source,	 ETH_ALEN);
	__builtin_memcpy(route.dst_mac, eth->h_dest,	 ETH_ALEN);
	route.interface = ctx->ifindex;

	/**
	 * Processamento livello Rete
	 *
	 * Se il pacchetto non ha una intestazione
	 * IPv4 conforme alla dimensione attesa,
	 * allora è scartato
	 * Se il pacchetto contiene delle opzioni,
	 * allora è scartato
	 */
	
	ip4 = (struct iphdr*) (data + sizeof(struct ethhdr));
	if (
		data + 
		sizeof(struct ethhdr) + 
		sizeof(struct iphdr)  > data_end)
	{
#if TC_VERBOSE_MODE
		bpf_trace_printk(
				ip4_rejected, sizeof(ip4_rejected),
				data, data_end);
#else
#endif
			goto tc_pass;
	}

	/**
	 * Memorizzazione indirizzi IP sorgente
	 * e destinazione. Salvataggio del
	 * protocollo di livello trasporto.
	 */

	session.src_ip = ip4->saddr;
	session.dst_ip = ip4->daddr;
	session.proto  = ip4->protocol;	
	
	/**
	 * Processamento livello Trasporto
	 *
	 * Se il pacchetto non contiene UDP
	 * oppure TCP, allora è scartato.
	 * Se il pacchetto ha una intestazione
	 * UDP oppure TCP non conforme con la
	 * dimensione attesa, alloar è scartato.
	 */

	if (ip4->protocol == IPPROTO_TCP)
	{	
		tcp = (struct tcphdr*) (data + sizeof(struct ethhdr) + ip4->ihl * 4);
		if (
			data + 
			sizeof(struct ethhdr) + 
			(ip4->ihl * 4) + 
			sizeof(struct tcphdr) > data_end)
		{
#if TC_VERBOSE_MODE
			bpf_trace_printk(
				tcp_rejected, sizeof(tcp_rejected),
				data, data_end);
#else
#endif
			goto tc_pass;
		}

		/**
		 * Memorizzazione delle porte 
		 * sorgente e destinazione 
		 * utilizzate dalla sessione
		 */

		session.src_pt = tcp->source;
		session.dst_pt = tcp->dest;
	} 
	else if (ip4->protocol == IPPROTO_UDP)
	{
		udp = (struct udphdr*) (data + sizeof(struct ethhdr) + ip4->ihl * 4);
		if (
			data + 
			sizeof(struct ethhdr) + 
			(ip4->ihl * 4) + 
			sizeof(struct udphdr) > data_end)
		{
#if TC_VERBOSE_MODE
			bpf_trace_printk(
				udp_rejected, sizeof(udp_rejected),
				data, data_end);
#else
#endif
			goto tc_pass;
		}

		/**
		 * Memorizzazione delle porte
		 * sorgente e destinazione 
		 * utilizzate dalla sessione
		 */
		
		session.src_pt = udp->source;
		session.dst_pt = udp->dest;
	}
    else 
	{	/**
		 * Protocollo livello trasporto
		 *  non supportato
		 */
		goto tc_pass;
	}

#if TIME_MODE
	route.time = bpf_ktime_get_ns();
#else
#endif

	bpf_map_update_elem(&routing_table, &session, &route, BPF_ANY);
tc_pass:
	return TC_ACT_OK;
}

SEC("xdp")
int xdp_program(struct xdp_md* ctx) 
{

	/**
	 * Puntatori al pacchetto ricevuto:
	 * 	packet_s = start of packet;
	 * 	packet_d = end of packet;
	 */

	void *data  	= (void*) (__u64) ctx->data;
	void *data_end 	= (void*) (__u64) ctx->data_end;

	struct ethhdr	*eth;
	struct iphdr	*ip4;
	struct tcphdr	*tcp;
	struct udphdr	*udp;

	struct _session	session = {};
	struct _route	*route;
	
	/**
	 * Processamento livello Data Link
	 * 
	 * Se il pacchetto non ha una intestazione
	 * Ethernet compatibile con la dimensione
	 * attesa, allora il pacchetto è scartato.
	 * Se il pacchetto non trasporta protocollo
	 * IPv4, allora il pacchetto è scartato
	 */
	
	eth = (struct ethhdr*) data;
	if (
		data + 
		sizeof(struct ethhdr) > data_end)
	{
#if XDP_VERBOSE_MODE
		bpf_trace_printk(
				eth_rejected, sizeof(eth_rejected),
				data, data_end);
#else
#endif
		goto xdp_pass;
	}
	if (eth->h_proto != __bpf_htons(ETH_P_IP))
	{
		goto xdp_pass;
	}

	/**
	 * Processamento livello Rete
	 *
	 * Se il pacchetto non ha una intestazione
	 * IPv4 conforme alla dimensione attesa,
	 * allora è scartato
	 * Se il pacchetto contiene delle opzioni,
	 * allora è scartato
	 */
	
	ip4 = (struct iphdr*) (data + sizeof(struct ethhdr));
	if (
		data + 
		sizeof(struct ethhdr) + 
		sizeof(struct iphdr)  > data_end)
	{
#if XDP_VERBOSE_MODE
		bpf_trace_printk(
				ip4_rejected, sizeof(ip4_rejected),
				data, data_end);
#else
#endif
		goto xdp_pass;
	}

	/**
	 * Memorizzazione indirizzi IP sorgente
	 * e destinazione. Salvataggio del
	 * protocollo di livello trasporto.
	 */

	session.src_ip = ip4->saddr;
	session.dst_ip = ip4->daddr;
	session.proto  = ip4->protocol;	
	
	/**
	 * Processamento livello Trasporto
	 *
	 * Se il pacchetto non contiene UDP
	 * oppure TCP, allora è scartato.
	 * Se il pacchetto ha una intestazione
	 * UDP oppure TCP non conforme con la
	 * dimensione attesa, alloar è scartato.
	 */

	if (ip4->protocol == IPPROTO_TCP)
	{	
		tcp = (struct tcphdr*) (data + sizeof(struct ethhdr) + ip4->ihl * 4);
		if (
			data + 
			sizeof(struct ethhdr) + 
			(ip4->ihl * 4) + 
			sizeof(struct tcphdr) > data_end)
		{
#if XDP_VERBOSE_MODE
			bpf_trace_printk(
				tcp_rejected, sizeof(tcp_rejected),
				data, data_end);
#else
#endif
			goto xdp_pass;
		}

		/**
		 * Memorizzazione delle porte 
		 * sorgente e destinazione 
		 * utilizzate dalla sessione
		 */

		session.src_pt = tcp->source;
		session.dst_pt = tcp->dest;
	} 
	else if (ip4->protocol == IPPROTO_UDP)
	{
		udp = (struct udphdr*) (data + sizeof(struct ethhdr) + ip4->ihl * 4);
		if (
			data + 
			sizeof(struct ethhdr) + 
			(ip4->ihl * 4) + 
			sizeof(struct udphdr) > data_end)
		{
#if XDP_VERBOSE_MODE
			bpf_trace_printk(
				udp_rejected, sizeof(udp_rejected),
				data, data_end);
#else
#endif
			goto xdp_pass;
		}

		/**
		 * Memorizzazione delle porte
		 * sorgente e destinazione 
		 * utilizzate dalla sessione
		 */
		
		session.src_pt = udp->source;
		session.dst_pt = udp->dest;
	}
    else 
	{	/**
		 * Protocollo livello trasporto
		 *  non supportato
		 */
		goto xdp_pass;
	}
	
	route = bpf_map_lookup_elem(&routing_table, &session);
#if STATS_MODE
	// TODO
#else
#endif
	if (route) 
	{
#if XDP_VERBOSE_MODE
		bpf_trace_printk(
				pkt_redirected, sizeof(pkt_redirected),
				data, data_end);
#else
#endif
		goto xdp_redirect;
	}
	else
	{
#if XDP_VERBOSE_MODE
		bpf_trace_printk(
				pkt_passed, sizeof(pkt_passed),
				data, data_end);
#else
#endif
		goto xdp_pass;
	}
xdp_redirect:
	/**
	 * Aggiustamento del livello Ethernet
	 */
	__builtin_memcpy(eth->h_source, route->src_mac,	 ETH_ALEN);
	__builtin_memcpy(eth->h_dest, route->dst_mac,	 ETH_ALEN);
	/**
	 * Aggiustamento del livello IPv4
	 */
	ip4->ttl   -=1;
	ip4->check = 0;
	ip4->check = ip_checksum((__u16*)ip4, sizeof(struct iphdr));
	return bpf_redirect(route->interface, 0);
xdp_pass:
  	return XDP_PASS;

}


/**
 * Licenza
 */

char _license [] SEC("license") = "GPL";

/* Fine */
