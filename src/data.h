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

#include <glib.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include "nfqueue.h"

#ifndef _PHX_DATA_H
#define _PHX_DATA_H

/*typedef struct nf_queue_data
{
   struct nfq_q_handle *in_qhandle, *out_qhandle, *in_pending_qhandle, *out_pending_qhandle;
   struct nfq_handle *in_handle, *out_handle, *in_pending_handle, *out_pending_handle;
   int out_fd, in_fd, in_pending_fd, out_pending_fd;

} nf_queue_data;*/
typedef struct phx_queues
{
  nf_queue_data in;
  nf_queue_data out;
  nf_queue_data in_pending;
  nf_queue_data out_pending;

} phx_queues;

#define PHX_CONF_FILE "/etc/phx.conf"
#define PHX_SOCKET_DIR "/var/run/phx/"

#ifdef _PHX_DAEMON_C

phx_queues global_queue_data;
GAsyncQueue *to_gui;
int pending_conn_count = 0;
int in_pending_count = 0;
GMutex* zone_mutex;

#else

extern phx_queues global_queue_data;
extern GAsyncQueue *to_gui;
extern int pending_conn_count;
extern int in_pending_count;
extern GMutex* zone_mutex;

#endif

#endif
