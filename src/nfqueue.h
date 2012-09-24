#ifndef _PHX_NFQUEUE_H
#define _PHX_NFQUEUE_H
#include <libnetfilter_queue/libnetfilter_queue.h>

typedef struct _nf_queue_data
{
    struct nfq_q_handle *queue_handle;
    struct nfq_handle *handle;
    int fd; 
	int callback_data;
} nf_queue_data;

int nf_queue_init(nf_queue_data* qdata, int queue_num, nfq_callback *cb);
void nf_queue_close(nf_queue_data* qdata);
int nf_queue_handle_packet(nf_queue_data* qdata);
#endif
