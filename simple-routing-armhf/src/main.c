#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <linux/pkt_cls.h>
#include <linux/if_link.h>

#include "skeleton.h"

#define CMD_SIZE 100
#define MAP_PATH 1500

#ifndef TIME_MODE
#define TIME_MODE 1
#endif

const char *pin_base_dir 	   = "/sys/fs/bpf";
const char *routing_table_path = "routing_table";

static const char start_cmd [] = "start";
static const char list_cmd  [] = "list";
static const char stop_cmd  [] = "stop";
static const char exit_cmd  [] = "exit";
static const char help_cmd  [] = "help";
static const char *interfaces [] = {
	"eth0",
	"eth1",
	"eth2",
	"eth3",
	/* Aggiungi qui nuove interfacce */
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
			bpf_xdp_attach(if_nametoindex(interfaces[i]), 
				fd, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
		}
	} else {
		for (i=0; i<n; i++)	{
			bpf_xdp_detach(if_nametoindex(interfaces[i]),
					XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
		}
	}

	return;
}

int main (int argc, char **argv)
{	
	int  i;
	int  n;
	int  active = 0;

	char cmd [CMD_SIZE];
	
	char rt_map_path [MAP_PATH];

	struct router *r = NULL;

	struct bpf_tc_hook *hooks = NULL;
	struct bpf_tc_opts *hopts = NULL;
	
	printf("############################################\n");
	printf("           		R J - 4 5 		   			\n");

	n = sizeof(interfaces) / sizeof(interfaces[0]);

	hooks = (struct bpf_tc_hook*) malloc(n * sizeof(struct bpf_tc_hook));
	hopts = (struct bpf_tc_opts*) malloc(n * sizeof(struct bpf_tc_opts));

	if(hooks == NULL || hopts == NULL) {
		printf("# errore durante l'avvio\n");
		goto end;
	}

	r = router__open_and_load();
	if (r == NULL) {
		printf("# errore verificatore eBPF\n");
		goto end;
	}

	while (exiting) {

		printf("# ");
		i = 0;
		while ((cmd[i] = getchar()) != '\n' && i<CMD_SIZE - 1) {
			i++;
		}
		cmd[i] = '\0';

		if (strlen(cmd) == 0) {
			printf("# comando non valido, digita \"help\"\n");
		} else if (strcmp(cmd, start_cmd) == 0) {
			active = 1;
			tc_program(bpf_program__fd(r->progs.tc_program), 
					active, hooks, hopts);
			xdp_program(bpf_program__fd(r->progs.xdp_program),
			 		active);
		} else if (strcmp(cmd, stop_cmd) == 0) {
			active = 0;
			tc_program(bpf_program__fd(r->progs.tc_program), 
					active, hooks, hopts);
			xdp_program(bpf_program__fd(r->progs.xdp_program),
			 		active);
		} else if (strcmp(cmd, list_cmd) == 0) {
			n = sizeof(interfaces) / sizeof(interfaces[0]);	
			for (i=0; i<n; i++) {
				printf("\tinterfaccia %s, indice %u\n", 
						interfaces[i], 
						if_nametoindex(interfaces[i]));
			}
		} else if (strcmp(cmd, exit_cmd) == 0) {
			exiting = 0;
		} else if (strcmp(cmd, help_cmd) == 0) {
			printf("\n\t start - avvia il router");
			printf("\n\t stop  - arresta il router");
			printf("\n\t exit  - esci dal terminale");
			printf("\n\t help  - stampa aiuto comandi");
			printf("\n\t list  - stampa interfacce di rete");
			printf("\n");
		} else {
			printf("# comando non valido, digita \"help\"\n");
		}
	}
end:

	if(active) {
		active = 0;
		tc_program(bpf_program__fd(r->progs.tc_program), 
					active, hooks, hopts);
		xdp_program(bpf_program__fd(r->progs.xdp_program),
			 		active);
	}

	/**
	 * Rimozione della mappa
	*/
	snprintf(rt_map_path, MAP_PATH, "%s/%s", pin_base_dir, routing_table_path);
	bpf_map__unpin(r->maps.routing_table, rt_map_path);

	printf("############################################\n");
	return 0;
}

