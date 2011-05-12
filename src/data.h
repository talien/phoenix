#include <glib.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <linux/netfilter.h>

#ifndef _PHX_DATA_H
#define _PHX_DATA_H
typedef struct nf_queue_data
{
   struct nfq_q_handle *in_qhandle, *out_qhandle, *in_pending_qhandle, *out_pending_qhandle;
   struct nfq_handle *in_handle, *out_handle, *in_pending_handle, *out_pending_handle;
   int out_fd, in_fd, in_pending_fd, out_pending_fd;

} nf_queue_data;

#define PHX_CONF_FILE "/etc/phx.conf"
#define PHX_SOCKET_DIR "/var/run/phx/"

#ifdef _PHX_DAEMON_C

nf_queue_data qdata;
GAsyncQueue *to_gui;
int pending_conn_count = 0;
int in_pending_count = 0;
GMutex* zone_mutex;

#else

extern nf_queue_data qdata;
extern GAsyncQueue *to_gui;
extern int pending_conn_count;
extern int in_pending_count;
extern GMutex* zone_mutex;

#endif

#endif
