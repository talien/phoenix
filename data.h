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
static struct nfq_q_handle *in_qhandle, *out_qhandle,/* *in_pending_qhandle,*/ *out_pending_qhandle;
static GData *applist;
static GAsyncQueue *to_gui,*to_daemon;
static int gui_signal = 0;
static int pending_conn_count = 0;
#endif
