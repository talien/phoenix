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
extern struct nfq_q_handle *in_qhandle, *out_qhandle, *in_pending_qhandle, *out_pending_qhandle;
extern GAsyncQueue *to_gui;
extern int pending_conn_count;
extern int in_pending_count;
extern GMutex* zone_mutex;
#endif
