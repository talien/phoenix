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

#include "nfqueue.h"
#include "misc.h"
#include <glib.h>
#include <errno.h>
#include <string.h>

int nf_queue_init(nf_queue_data* qdata, int queue_num, nfq_callback *cb)
{
  qdata->handle = nfq_open();
  qdata->queue_number = queue_num;

  if (queue_num == 0 || queue_num == 3)
    {
      qdata->direction = OUTBOUND;
    }
  else
    {
      qdata->direction = INBOUND;
    }
  if (queue_num == 2 || queue_num == 3)
    qdata->pending = 1;

  if (!(qdata->handle))
    {
      log_error("Error occured during opening netfilter queue");
      return -1;
    }
  if (nfq_unbind_pf(qdata->handle, AF_INET) < 0)
    {
      log_error("Unbinding, ignoring error");
      return -1;
    }
  log_debug("Binding protocol\n");
  if (nfq_bind_pf(qdata->handle, AF_INET) < 0)
    {
      log_error("Error in nf_queue binding");
      return -1;
    }
  log_debug("Creating netfilter queue\n");
  qdata->queue_handle = nfq_create_queue(qdata->handle, qdata->queue_number, cb, qdata);
  if (!qdata->queue_handle)
    {
      log_error("Error in creating queue, error='%s'\n", strerror(errno));
      return -1;
    }
  log_debug("Setting mode for netfilter queue\n");
  if (nfq_set_mode(qdata->queue_handle, NFQNL_COPY_PACKET, 0) < 0)
    {
      log_error("Error setting netfilter queue mode\n");
      return -1;
    }
  qdata->fd = nfq_fd(qdata->handle);
  log_debug("Netfilter queue fd; fd='%d'\n", qdata->fd);
  return 0;

}

void nf_queue_close(nf_queue_data* qdata)
{
  log_debug("Destroying netfilter queue\n");
  nfq_destroy_queue(qdata->queue_handle);
  log_debug("Destroy netfilter handle\n");
  nfq_close(qdata->handle);
}

const char * get_name_from_queue_number(int queue_num)
{
  if (queue_num == 0) return "out-new";
  if (queue_num == 1) return "in-new";
  if (queue_num == 2) return "in-pending";
  if (queue_num == 3) return "out-pending";
};

int nf_queue_handle_packet(nf_queue_data* qdata)
{
  char buf[65536];
  int rv = recv(qdata->fd, buf, sizeof(buf), MSG_DONTWAIT);
  if (rv > 0)
    {
      log_debug("Packet received in %s queue\n", get_name_from_queue_number(qdata->queue_number));
      nfq_handle_packet(qdata->handle, buf, rv);
      log_debug("Packet handled\n");
      return TRUE;
    }
  return FALSE;

};
