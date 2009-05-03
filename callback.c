#include "callback.h"
#include "data.h"

GList *app_list = NULL, *deny_list = NULL, *pending_list = NULL;
GHashTable *apptable;

void phx_apptable_insert(struct phx_conn_data* cdata,int direction,int verdict)
{
   
};

int phx_data_extract(unsigned char* payload, struct phx_conn_data *cdata, int direction)
{
  unsigned int headlen;
  headlen = (payload[0] % 16) * 4;
  cdata->sport = (unsigned char)payload[headlen] * 256 + (unsigned char)payload[headlen + 1];
  cdata->dport = (unsigned char)payload[headlen + 2] * 256 + (unsigned char)payload[headlen + 3];
  strncpy(cdata->destip,payload+16,4);
  strncpy(cdata->srcip,payload+12,4);
  return get_proc_from_conn(cdata,direction);
}


gint my_compare_func(gconstpointer A,gconstpointer B)
{
  return (g_string_equal((GString*)A,(GString*)B))?0:1;
}

int out_queue_cb(struct nfq_q_handle *qh,struct nfgenmsg *mfmsg,struct nfq_data *nfad,void* data)
{
	int id = 0;
	int plen = 0, extr_res = 0;
	struct nfqnl_msg_packet_hdr *ph;
	unsigned char* payload;
	char srcip[20];
	char destip[20];
  struct phx_conn_data *conndata, *resdata = NULL;
	printf("==Outbound callback called==\n");
	ph = nfq_get_msg_packet_hdr(nfad);
	id = ntohl(ph->packet_id);
	plen = nfq_get_payload(nfad, (char**)&payload);
	printf("Payload length:%d\n",plen);
  conndata = g_new0(struct phx_conn_data,1);
  extr_res = phx_data_extract(payload,conndata,OUTBOUND);
  if (extr_res == -1)
	{
    printf("Connection timeouted, dropping packet\n");
		return nfq_set_verdict(out_qhandle,id,NF_DROP,plen,payload);	
	} 
	swrite_ip(payload + 12,srcip,0);
	swrite_ip(payload + 16,destip,0);
  printf("%s:%d -> %s:%d\n",srcip,conndata->sport,destip,conndata->dport);
  resdata = g_async_queue_try_pop(to_daemon);
  if (resdata)
	{
		 pending_list = g_list_remove(pending_list,resdata->proc_name);
		 if (resdata->state == ACCEPTED)
		 {
				app_list = g_list_prepend(app_list,resdata->proc_name);
				g_free(resdata);
		 }
     else
		 {
				deny_list = g_list_prepend(deny_list,resdata->proc_name);
				g_free(resdata);
     }
		 gui_signal = 1;
	}
	if (g_list_find_custom(app_list,conndata->proc_name,my_compare_func) != NULL)
	{
		printf("Program %s found in list, accepting\n",conndata->proc_name->str);
		g_string_free(conndata->proc_name,TRUE);
		g_free(conndata);
		return nfq_set_verdict(out_qhandle,id,NF_ACCEPT,plen,payload);
	}
	if (g_list_find_custom(deny_list,conndata->proc_name,my_compare_func) != NULL)
	{
		printf("Program %s found in list, denying\n",conndata->proc_name->str);
		g_string_free(conndata->proc_name,TRUE);
		g_free(conndata);
		return nfq_set_verdict(out_qhandle,id,NF_DROP,plen,payload);
	}
	if (g_list_find_custom(pending_list,conndata->proc_name,my_compare_func) == NULL)
	{
		g_async_queue_push(to_gui,conndata);
		pending_list = g_list_prepend(pending_list,conndata->proc_name);
  }
  printf("Data pushed to queue\n");
  pending_conn_count++;
	return nfq_set_verdict_mark(out_qhandle,id,NF_REPEAT,htonl(0x2),plen,payload);
}

int in_queue_cb(struct nfq_q_handle *qh,struct nfgenmsg *mfmsg,struct nfq_data *nfad,void* data)
{
	struct nfqnl_msg_packet_hdr *ph;
	unsigned char* payload;
	unsigned int id = 0, plen = 0;
	int res;
	char srcip[20], destip[20];
	struct phx_conn_data* conndata;
  printf("==Inbound callback called==\n");
	ph = nfq_get_msg_packet_hdr(nfad);
	id = ntohl(ph->packet_id);
	plen = nfq_get_payload(nfad, (char**)&payload);
  conndata = g_new0(struct phx_conn_data,1);
	res = phx_data_extract(payload,conndata,INBOUND);
	swrite_ip(payload + 12,srcip,0);
	swrite_ip(payload + 16,destip,0);
  if (res != -1)
	{
		printf("Packet received:%s:%d -> %s:%d on program %s\n",srcip,conndata->sport,destip,conndata->dport,conndata->proc_name->str);
		printf("Inbound connection on listening port, accepting (yet)\n");
		return nfq_set_verdict(in_qhandle,id,NF_ACCEPT,plen,payload);	
	}
	else
	{
		printf("Nothing listens on port %d, dropping\n",conndata->dport);
	 	return nfq_set_verdict(in_qhandle,id,NF_DROP,plen,payload);	
	}
}

int out_pending_cb(struct nfq_q_handle *qh, struct nfgenmsg *mfmsg, struct nfq_data *nfad, void* data)
{
  int id = 0, plen = 0, extr_res = 0;
  struct nfqnl_msg_packet_hdr *ph;
	unsigned char* payload;
	char srcip[20];
	char destip[20];
  struct phx_conn_data *conndata;
  printf("==Out pending callback called==\n");
  ph = nfq_get_msg_packet_hdr(nfad);
  id = ntohl(ph->packet_id);
  plen = nfq_get_payload(nfad, (char**) &payload);
  printf("Payload length:%d\n",plen);
  conndata = g_new0(struct phx_conn_data,1);
  extr_res = phx_data_extract(payload,conndata,OUTBOUND);
  if (extr_res == -1)
	{
     printf("Connection timeouted, dropping packet\n");
     return nfq_set_verdict(out_pending_qhandle,id,NF_DROP,plen,payload);	
	}
  write_ip(payload + 12); printf(":%d\n",conndata->sport);
  write_ip(payload + 16); printf(":%d\n",conndata->dport);
  swrite_ip(payload + 12,srcip,0);
  swrite_ip(payload + 16,destip,0);
	if (g_list_find_custom(app_list,conndata->proc_name,my_compare_func) != NULL)
	{
		printf("Program %s found in list, accepting\n",conndata->proc_name->str);
		g_string_free(conndata->proc_name,TRUE);
		g_free(conndata);
	  pending_conn_count--;	
		return nfq_set_verdict(out_pending_qhandle,id,NF_ACCEPT,plen,payload);
	}
	if (g_list_find_custom(deny_list,conndata->proc_name,my_compare_func) != NULL)
	{
		printf("Program %s found in list, denying\n",conndata->proc_name->str);
		g_string_free(conndata->proc_name,TRUE);
		g_free(conndata);
    pending_conn_count--;
		return nfq_set_verdict(out_pending_qhandle,id,NF_DROP,plen,payload);
	}
	return nfq_set_verdict(out_pending_qhandle,id,NF_QUEUE,plen,payload);
}
