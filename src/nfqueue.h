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

#ifndef _PHX_NFQUEUE_H
#define _PHX_NFQUEUE_H
#include <stdint.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

typedef struct _nf_queue_data
{
  struct nfq_q_handle *queue_handle;
  struct nfq_handle *handle;
  int fd;
  int direction;
  int pending;
  int queue_number;
} nf_queue_data;

int nf_queue_init(nf_queue_data* qdata, int queue_num, nfq_callback *cb);
void nf_queue_close(nf_queue_data* qdata);
int nf_queue_handle_packet(nf_queue_data* qdata);
#endif
