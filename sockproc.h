#ifndef _PHX_SOCKPROC_H
#define _PHX_SOCKPROC_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <string.h>

#include "misc.h"
#include "types.h"

#define INBOUND 1
#define OUTBOUND 0

/*struct conn {
	int sport;
1	char src[4];
	int dport;
	char dest[4];
};*/

void parse_tcp_line(char* buf,char *s,char *d,unsigned int *sp,unsigned int *dp, unsigned int * sn);
void parse_tcp6_line(char* buf,char *s,char *d,unsigned int *sp,unsigned int *dp, unsigned int * sn);
int get_proc_from_conn(struct phx_conn_data* c,int direction);
int get_pid_from_sock(int socknum);
#endif
