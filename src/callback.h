#ifndef _PHx_CALLBACK_H
#define _PHX_CALLBACK_H
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <stdio.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <time.h>
#include <sys/poll.h>
#include <signal.h>

#include "misc.h"
#include "sockproc.h"
#include "types.h"
int out_queue_cb(struct nfq_q_handle *qh,struct nfgenmsg *mfmsg,struct nfq_data *nfad,void* data);
int in_queue_cb(struct nfq_q_handle *qh,struct nfgenmsg *mfmsg,struct nfq_data *nfad,void* data);
int out_pending_cb(struct nfq_q_handle *qh,struct nfgenmsg *mfmsg,struct nfq_data *nfad,void* data);
int in_pending_cb(struct nfq_q_handle *qh,struct nfgenmsg *mfmsg,struct nfq_data *nfad,void* data);
int phx_queue_callback(struct nfq_q_handle *qh,struct nfgenmsg *mfmsg,struct nfq_data *nfad,void* data);
void phx_apptable_init();
struct phx_app_rule* phx_apptable_lookup(GString* appname,guint pid,guint direction, guint32 srczone, guint32 destzone);
void phx_apptable_insert(struct phx_conn_data* cdata,int direction,int verdict, guint32 srczone, guint32 destzone);
void phx_apptable_delete(struct phx_conn_data* cdata,int direction, guint32 srczone, guint32 destzone);
char* phx_apptable_serialize(int* length);
void phx_apptable_clear_invalid();
#endif
