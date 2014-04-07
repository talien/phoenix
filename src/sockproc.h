/*
* Copyright (c) 2008-2014 Viktor Tusa
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU Lesser General Public
* License as published by the Free Software Foundation; either
* version 2.1 of the License, or (at your option) any later version.
*
* This library is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public
* License along with this library; if not, write to the Free Software
* Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
*
*/

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

void parse_tcp_line(char* buf,char *s,char *d,unsigned int *sp,unsigned int *dp, unsigned int * sn);
void parse_tcp6_line(char* buf,char *s,char *d,unsigned int *sp,unsigned int *dp, unsigned int * sn);
int get_proc_from_conn(struct phx_conn_data* c,int direction);
int get_pid_from_sock(int socknum);
int check_pid_exists(int pid);
GString* get_user(guint32 pid);
GString* get_command_line(guint32 pid);
#endif
