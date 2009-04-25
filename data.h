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
static struct nfq_handle *in_handle, *out_handle,*in_pending_handle,*out_pending_handle;
static struct nfq_q_handle *in_qhandle, *out_qhandle,*in_pending_qhandle,*out_pending_qhandle;
static int out_fd,in_fd,in_pending_fd,out_pending_fd,rv;
static char buf[2048];
static GList *app_list = NULL, *deny_list = NULL, *pending_list = NULL;
static GData *applist;
static GAsyncQueue *to_gui,*to_daemon,*wakeup;
//static GStaticMutex timer_mutex = G_STATIC_MUTEX_INIT;
static GList *pack_id_list = NULL;
static int gui_signal = 0;
static int pending_conn_count = 0;
#endif
