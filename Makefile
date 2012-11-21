#! /usr/bin/make

TARGETS = napt_proto.o napt.o napt_proto_ip.o napt_proto_tcp.o napt_proto_udp.o napt_proto_icmp.o napt_kill.o

CC=gcc
OPTS = -O -D__KERNEL__ -I/usr/src/linux/include -Wall 
OPTS+= -DMODULE -DMODVERSIONS -DEXPORT_SYMTAB 
OPTS+= -include /usr/src/linux/include/linux/modversions.h -fno-common -c

all : $(TARGETS)

$(TARGETS) : %.o : %.c napt.h
	 $(CC) $(OPTS) $<
