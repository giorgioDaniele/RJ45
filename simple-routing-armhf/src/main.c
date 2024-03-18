#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <linux/pkt_cls.h>
#include <linux/if_link.h>

#include "skeleton.h"

#define PIN_BASE_DIR "/sys/fs/bpf"
#define PIN_RTABLE_PATH "routing_table"

#define CMD_SIZE 100
#define MAP_PATH 1500

#define DBG(fmt, ...)  \
({	\
	printf("[RJ45]: " fmt, ##__VA_ARGS__); \
})

/**
 * Interfacce di rete. Per aggiungere oppure rimuovere
 * interfacce di rete, è sufficiente modificare il vettore
 * che contiene il nome delle interfacce di rete che si
 * possono visualizzare, ad esempio, attraverso il comando
 * ip -c oppure ifconfig -a
*/
static 
const char *interfaces [] = {
	"eth0",
	"eth1",
	"eth2",
	"eth3",
	"enp3s0",
	"enp4s0",
	"enp5s0",
	/**/
};

enum act { 
	ATTACH, 
	REMOVE,
	/**/
};

enum cmd { 
	START, 
	STOP, 
	EXIT,
 	/**/
};

/**
 * Variabile d'ambiente che consente la terminazione del 
 * programma, ad esempio lanciando il segnale CTRL+C
*/
static volatile 
unsigned char exiting = 1;
static void exit_program (int signal) 
{
    exiting = 0; 
}

static void traffic_control(int fd, 
				enum act action, struct bpf_tc_hook* hooks, 
				struct bpf_tc_opts* hopts)
{
	int i;
	int n;

	n = sizeof(interfaces) / sizeof(interfaces[0]);

	switch (action)
	{
	case ATTACH:
		for (i = 0; i < n; i++)
		{
			hooks[i].ifindex = if_nametoindex(interfaces[i]);
			hooks[i].attach_point = BPF_TC_EGRESS;
			hooks[i].sz = sizeof(struct bpf_tc_hook);
			
			bpf_tc_hook_create(&hooks[i]);

			hooks[i].attach_point = BPF_TC_CUSTOM;
			hooks[i].parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS);
			hopts[i].prog_fd = fd;
			hopts[i].handle = 1;
			hopts[i].priority = 1;
			hopts[i].flags = BPF_TC_F_REPLACE;
			hopts[i].sz = sizeof(struct bpf_tc_opts);

			bpf_tc_attach(&hooks[i], &hopts[i]);
		}
		break;

	case REMOVE:
		for (i = 0; i < n; i++)
		{
			hopts[i].flags = 0;
			hopts[i].prog_fd = 0;
			hopts[i].prog_id = 0;

			bpf_tc_detach(&hooks[i], &hopts[i]);
			
			bpf_tc_hook_destroy(&hooks[i]);
		}
		break;

	default:
		break;
	}
	return;
}

static void express_data_path(int fd, enum act action)
{	
	int i;
	int n;

	n = sizeof(interfaces) / sizeof(interfaces[0]);

	switch (action)
	{
	case ATTACH:
		for (i = 0; i < n; i++)
		{
			bpf_xdp_attach(if_nametoindex(interfaces[i]), fd,
						XDP_FLAGS_UPDATE_IF_NOEXIST,
						NULL);
		}
		/* code */
		break;

	case REMOVE:
		for (i = 0; i < n; i++)
		{
			bpf_xdp_detach(if_nametoindex(interfaces[i]),
						XDP_FLAGS_UPDATE_IF_NOEXIST,
						NULL);
		}
		/* code */
		break;

	default:
		break;
	}
	return;
}


int main (int argc, char **argv)
{	
	int n;

	struct router *r = NULL;

	enum act action;
	enum cmd command;

	char routing_table_path [MAP_PATH];

	struct bpf_tc_hook *hooks = NULL;
	struct bpf_tc_opts *hopts = NULL;
	
	n = sizeof(interfaces) / sizeof(interfaces[0]);

	hooks = (struct bpf_tc_hook*) 
					malloc(n * sizeof(struct bpf_tc_hook));
	hopts = (struct bpf_tc_opts*) 
					malloc(n * sizeof(struct bpf_tc_opts));

	r = router__open_and_load();
	if (r == NULL)
	{
		DBG("%s", "impossibile caricare lo scheletro del programma\n");
	}
	

	signal(SIGINT, exit_program);
	signal(SIGKILL, exit_program);
	signal(SIGTERM, exit_program);

	/**
	 * Installazione del codice eBPF
	*/

	action = ATTACH;

	traffic_control(bpf_program__fd(r->progs.tc_program),
					action, hooks, hopts);
	express_data_path(bpf_program__fd(r->progs.xdp_program),
					action);

	
	DBG("avviato\n");

	while(exiting) 
	{
		sleep(20);
		
		/**
		 * Aggiungere qui qualsivoglia procedura
		 * per leggere le statistiche, se necessario
		*/

	}

	/**
	 * Rimozione del codice eBPF
	*/

	action = REMOVE;

	traffic_control(bpf_program__fd(r->progs.tc_program),
					action, hooks, hopts);
	express_data_path(bpf_program__fd(r->progs.xdp_program),
					action);

	snprintf(routing_table_path, MAP_PATH, "%s/%s", 
					PIN_BASE_DIR, PIN_RTABLE_PATH);

	DBG("terminato\n");

	bpf_map__unpin(r->maps.routing_table,
					routing_table_path);
	router__destroy(r);
	return 0;
}

