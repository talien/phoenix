#include "callback.h"
#include "data.h"
#include "types.h"

GHashTable *apptable;

void phx_apptable_init()
{
   apptable = g_hash_table_new(g_str_hash,g_str_equal);
}

void phx_apptable_insert(struct phx_conn_data* cdata,int direction,int verdict)
{
   struct phx_app_rule *rule = g_new0(struct phx_app_rule,1);
   rule->appname = g_string_new(cdata->proc_name->str);
   rule->pid = cdata->pid;
   rule->verdict = verdict;
   guint hash = g_string_hash(rule->appname);
   g_hash_table_insert(apptable,rule->appname->str,rule);
};

struct phx_app_rule* phx_apptable_lookup(GString* appname)
{
  return g_hash_table_lookup(apptable,appname->str);
}

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
  struct phx_app_rule* rule;
  if (resdata)
	{
     rule = phx_apptable_lookup(resdata->proc_name);
     if (rule)
     {
        g_printf("App found in hashtable!\n");
        rule->verdict = resdata->state;
     }
  }
     g_free(resdata);
		 gui_signal = 1;
	}
  rule = phx_apptable_lookup(conndata->proc_name);
  if (rule)
  {
     if (rule->verdict == ACCEPTED)
     {
			  printf("Program %s found in list, accepting\n",conndata->proc_name->str);
    		g_string_free(conndata->proc_name,TRUE);
    		g_free(conndata);
    		return nfq_set_verdict(out_qhandle,id,NF_ACCEPT,plen,payload);
		 }
     if (rule->verdict = DENIED)
		 {
				 printf("Program %s found in list, denying\n",conndata->proc_name->str);
    		 g_string_free(conndata->proc_name,TRUE);
    		 g_free(conndata);
   			 return nfq_set_verdict(out_qhandle,id,NF_DROP,plen,payload);
		 }
  }
  else
  {
    g_async_queue_push(to_gui,conndata);
    phx_apptable_insert(conndata,OUTBOUND,NEW);
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
  struct phx_app_rule* rule = phx_apptable_lookup(conndata->proc_name);
  if (rule)
  {
    if (rule->verdict == ACCEPTED)
		{
		 	printf("Program %s found in list, accepting\n",conndata->proc_name->str);
    	g_string_free(conndata->proc_name,TRUE);
    	g_free(conndata);
    	pending_conn_count--;
    	return nfq_set_verdict(out_pending_qhandle,id,NF_ACCEPT,plen,payload);	
		}
    if (rule->verdict == DENIED)
    {
			printf("Program %s found in list, denying\n",conndata->proc_name->str);
    	g_string_free(conndata->proc_name,TRUE);
    	g_free(conndata);
    	pending_conn_count--;
    	return nfq_set_verdict(out_pending_qhandle,id,NF_DROP,plen,payload);
    }
  }
	return nfq_set_verdict(out_pending_qhandle,id,NF_QUEUE,plen,payload);
}
