# Makefile for GNU make
# For compilation and linking use Open Watcom wcc and wlink

all: netmount.com

netmount.obj: netmount.c exitcode.h i86.h nettypes.h pktdrv.h ../shared/dos.h ../shared/drvproto.h
	wcc netmount.c -w4 -e25 -zq -za99 -otexan -s -bt=dos -fo=.obj -ms

netmount.com: netmount.obj
	wlink name $@ d all sys dos com op m libf cstart_t.obj op maxe=25 op symf op el FILE netmount.obj

clean:
	rm netmount.com netmount.obj netmount.map netmount.sym
