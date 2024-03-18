# Makefile per la compilazione del codice eBPF e del codice in spazio
# utente per controllare il ciclo di vita del codice eBPF stesso

RJ45_ELF=rj45
RJ45_SRC=src/main.c
EBPF_SRC=src/router.c
EBPF_OBJ=obj/router.o
SKELETO=src/skeleton.h
VMLINUX=src/vmlinux.h
BPFTOOL=tools/bpftool

LIBBPF=lib/libbpf.a
LIBELF=lib/libelf.a
LIBZ=lib/libz.a

EC=clang
CC=gcc
CFLAGS=-O2 -Wall
EFLAGS=-O2 -Wall -target bpf

all:  $(VMLINUX) $(EBPF_OBJ) $(SKELETO) $(RJ45_ELF)

$(EBPF_OBJ): $(EBPF_SRC)
	$(EC) $(EFLAGS) -c $(EBPF_SRC) -o $(EBPF_OBJ) -g

$(SKELETO): $(EBPF_OBJ)
	$(BPFTOOL) gen skeleton $(EBPF_OBJ) > $(SKELETO)
	sed -i 's/#include <bpf\/libbpf.h>/#include "libbpf.h"/g' $(SKELETO)

$(VMLINUX): 
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

$(RJ45_ELF): $(EBPF_OBJ) $(SKELETO) $(VMLINUX)
	$(CC) $(CFLAGS) $(RJ45_SRC) -o $(RJ45_ELF) $(LIBBPF) $(LIBELF) $(LIBZ)

clean:
	rm -f $(RJ45_ELF) $(EBPF_OBJ) $(SKELETO) $(VMLINUX)
clear:
	rm -f $(RJ45_ELF) $(EBPF_OBJ) $(SKELETO) $(VMLINUX)

