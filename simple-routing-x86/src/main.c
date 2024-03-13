#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <linux/pkt_cls.h>
#include <linux/if_link.h>

#include "options.h"
#include "skeleton.h"

#define CMD_SIZE 100
#define MAP_PATH 1500

const char *pin_base_dir 	   = "/sys/fs/bpf";
const char *routing_table_path = "routing_table";

static const char start_cmd [] = "start";
static const char list_cmd  [] = "list";
static const char stop_cmd  [] = "stop";
static const char exit_cmd  [] = "exit";
static const char help_cmd  [] = "help";
static const char stat_cmd  [] = "stats";
static const char *interfaces [] = {
	"eth0",
	"eth1",
	"eth2",
	"eth3",
	/* Aggiungi qui nuove interfacce */
	// "enp2s0",
	"enp3s0",
	"enp4s0",
	"enp5s0",
};

static volatile unsigned char exiting = 1;
static void exit_program (int signal) 
{
       	exiting = 0; 
}

static void tc_program(int fd,
		int action, struct bpf_tc_hook* hooks, struct bpf_tc_opts* hopts)
{
	int i;
	int n;

	n = sizeof(interfaces) / sizeof(interfaces[0]);

	if (action) {
		for (i=0; i<n; i++) {

			hooks[i].ifindex 	  = if_nametoindex(interfaces[i]);
			hooks[i].attach_point = BPF_TC_EGRESS;
			hooks[i].sz 		  = sizeof(struct bpf_tc_hook);

			/**
		 	* Creazione dell'hook
		 	*/

			bpf_tc_hook_create(&hooks[i]);
		
			hooks[i].attach_point = BPF_TC_CUSTOM;
			hooks[i].parent		  = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS);
			hopts[i].prog_fd	  = fd;
			hopts[i].handle 	  = 1;
			hopts[i].priority 	  = 1;
			hopts[i].flags 		  = BPF_TC_F_REPLACE;
			hopts[i].sz 		  = sizeof(struct bpf_tc_opts);

			/*
		 	* Installazione del programma
		 	*/

			bpf_tc_attach(&hooks[i], &hopts[i]);
		}
	} else {
		for (i=0; i<n; i++) {
			
			/**
			 * Rimozione del programma
			 * e rimozione dell'hook
			 * creato
			 */
			
			hopts[i].flags = hopts[i].prog_fd = hopts[i].prog_id = 0;
			bpf_tc_detach(&hooks[i], &hopts[i]);
			bpf_tc_hook_destroy(&hooks[i]);
		}
	}

	return;
}

static void xdp_program(int fd,
		int action)
{
        int i;
        int n;

        n = sizeof(interfaces) / sizeof(interfaces[0]);
	
	if (action) {
		for (i=0; i<n; i++) {
			bpf_xdp_attach(if_nametoindex(interfaces[i]), fd, 
				XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE, 
				NULL);
		}
	} else {
		for (i=0; i<n; i++)	{
			bpf_xdp_detach(if_nametoindex(interfaces[i]),
				XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE, 
				NULL);
		}
	}

	return;
}

#if STATISTICS_MODE
static void read_stats(int map)
{

	// TODO

	return;
}
#else
#endif

int main (int argc, char **argv)
{	
	int  i;
	int  n;
	int  active;

	char cmd [CMD_SIZE];
	
	char rt_map_path [MAP_PATH];

	struct router *r = NULL;

	struct bpf_tc_hook *hooks = NULL;
	struct bpf_tc_opts *hopts = NULL;
	
	n = sizeof(interfaces) / sizeof(interfaces[0]);

	hooks = (struct bpf_tc_hook*) malloc(n * 
		sizeof(struct bpf_tc_hook));
	hopts = (struct bpf_tc_opts*) malloc(n * 
		sizeof(struct bpf_tc_opts));

#if TESTING_MODE
	signal(SIGINT, exit_program);
#else
	printf("############################################\n");
	printf("           		R J - 4 5 		   			\n");
#endif

	if(hooks == NULL || hopts == NULL) {
#if TESTING_MODE
#else
		printf("# errore durante l'avvio\n");
#endif
		goto end;
	}

	r = router__open_and_load();
	if (r == NULL) {
#if TESTING_MODE
#else
		printf("# errore verificatore eBPF\n");
#endif
		goto end;
	}

#if TESTING_MODE

	/**
	 * In modalità testing è possibile 
	 * eseguire il router eBPF in sotto
	 * fondo così da utilizzare altri
	 * strumenti da linea di comando, 
	 * come tools/bpftool per verificare
	 * l'andamento del programma svilup
	 * pato.
	*/

	active = 1;

	tc_program(bpf_program__fd(r->progs.tc_program), 
				active, hooks, hopts);
	xdp_program(bpf_program__fd(r->progs.xdp_program),
			 	active);

	printf("############################################\n");
	printf("Avvio!\n");
	printf("############################################\n");
	while(exiting) {
		sleep(20);
	}

#else

	while (exiting) {

		printf("# ");
		i = 0;
		while ((cmd[i] = getchar()) != '\n' && i<CMD_SIZE - 1) {
			i++;
		}
		cmd[i] = '\0';

		if (strlen(cmd) == 0) {

			/**
			 * Comando non riconosciuto
			*/

			printf("# comando non valido, digita \"help\"\n");

		} else if (strcmp(cmd, start_cmd) == 0) {
			
			/**
			 * Richiesta dell'utente di avviare
			 * il router
			*/

			active = 1;
			tc_program(bpf_program__fd(r->progs.tc_program), 
					active, hooks, hopts);
			xdp_program(bpf_program__fd(r->progs.xdp_program),
			 		active);

		} else if (strcmp(cmd, stop_cmd) == 0) {

			/**
			 * Richiesta dell'utente di fermare
			 * il router
			*/

			active = 0;
			tc_program(bpf_program__fd(r->progs.tc_program), 
					active, hooks, hopts);
			xdp_program(bpf_program__fd(r->progs.xdp_program),
			 		active);

		} else if (strcmp(cmd, list_cmd) == 0) {

			/**
			 * Richiesta dell'utente di stampare a 
			 * video le interfacce di rete
			*/

			n = sizeof(interfaces) / sizeof(interfaces[0]);	
			for (i=0; i<n; i++) {
				printf("\tinterfaccia %s, indice %u\n", 
						interfaces[i], 
						if_nametoindex(interfaces[i]));
			}

		}  else if (strcmp(cmd, stat_cmd) == 0) {
			
			/**
			 * Richiesta dell'utente di stampare
			 * a video le statistiche.
			*/

			// TODO

		} else if (strcmp(cmd, exit_cmd) == 0) {

			/**
			 * Richiesta dell'utente di terminare
			 * il programma
			*/

			exiting = 0;

		} else if (strcmp(cmd, help_cmd) == 0) {

			/**
			 * Richiesta dell'utente di stampare
			 * i comandi disponibili
			*/

			printf("\n\t start - avvia il router");
			printf("\n\t stop  - arresta il router");
			printf("\n\t exit  - esci dal terminale");
			printf("\n\t help  - stampa aiuto comandi");
			printf("\n\t list  - stampa interfacce di rete");
			printf("\n");

		} else {

			/**
			 * Comando non riconosciuto
			*/

			printf("# comando non valido, digita \"help\"\n");

		}
	}
#endif

	/**
	 * Terminazione del programma
	*/

end:

	if(active) {
		active = 0;
		tc_program(bpf_program__fd(r->progs.tc_program), 
					active, hooks, hopts);
		xdp_program(bpf_program__fd(r->progs.xdp_program),
			 		active);
	}

	/**
	 * Rimozione della mappa dal
	 * file system virtuale
	*/

	snprintf(rt_map_path, MAP_PATH, "%s/%s", 
			pin_base_dir, routing_table_path);

#if TESTING_MODE
	printf("Rimozione della mappa %s\n", rt_map_path);
#else
#endif	
	bpf_map__unpin(r->maps.routing_table, rt_map_path);

	printf("\n############################################\n");
	return 0;
}

