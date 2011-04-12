#include "callback.h"
#include "data.h"
#include "types.h"

GHashTable *apptable;

GMutex *apptable_lock;

void phx_apptable_init()
{
	apptable = g_hash_table_new(g_str_hash, g_str_equal);
	apptable_lock = g_mutex_new();
}

void
phx_apptable_insert(struct phx_conn_data *cdata, int direction, int verdict)
{
	struct phx_app_rule *rule = g_new0(struct phx_app_rule, 1);

	rule->appname = g_string_new(cdata->proc_name->str);
	rule->pid = cdata->pid;
	rule->verdict = verdict;
	//guint hash = rule->pid * 4 + direction;
	guint *hash = g_new0(guint, 1);

	*hash = 0 * 4 + direction;
	g_mutex_lock(apptable_lock);
	GHashTable *chain =
	    g_hash_table_lookup(apptable, cdata->proc_name->str);

	if (!chain)
	{
		chain = g_hash_table_new(g_int_hash, g_int_equal);
		g_hash_table_insert(chain, hash, rule);
		g_hash_table_insert(apptable, rule->appname->str, chain);
	} else
	{
		g_hash_table_insert(chain, hash, rule);
	}
	g_mutex_unlock(apptable_lock);
};

int phx_rule_count_size(struct phx_app_rule* rule)
{
	//pid:int, verdict:int, string_size:int, strng: char*)
	return 12+rule->appname->len;
}

int phx_chain_count_size(GHashTable* chain)
{
	//number of directions: int
	int result = 4;
	struct phx_app_rule* rule;
	int i;
	for (i=0; i<=1; i++)
	{
		// hash value: int, rule size:variable
		rule = (struct phx_app_rule*) g_hash_table_lookup(chain, &i);
		if (rule != NULL)
			result += 4 + phx_rule_count_size(rule);
	}
	return result;
}

void phx_apptable_count_func(gpointer key, gpointer value, gpointer user_data)
{
	int *size = (int*) user_data;
	(*size) += phx_chain_count_size((GHashTable*)value);
}

int phx_apptable_count_size(GHashTable* apptable)
{
	// number of chains: int
	int size = 4;
	g_hash_table_foreach(apptable, phx_apptable_count_func, &size);
	return size;
}

int phx_rule_serialize(struct phx_app_rule* rule, char* buffer)
{
	int len = rule->appname->len;
	memcpy(buffer, &(rule->pid), sizeof(rule->pid));
	memcpy(buffer+4, &(rule->verdict), sizeof(rule->verdict));
	memcpy(buffer+8, &len, sizeof(len));
	memcpy(buffer+12, rule->appname->str, len);
	return 12 + len;
}

int phx_chain_serialize(GHashTable* chain, char* buffer)
{
	int dir_num = g_hash_table_size(chain);
	// hash numbers: int
	memcpy(buffer,&dir_num, sizeof(dir_num));
	struct phx_app_rule* rule;
	int position = 4, i;
    for (i=0; i<=1; i++)
    {
        // hash value: int, rule size:variable
        rule = (struct phx_app_rule*) g_hash_table_lookup(chain, &i);
		if (rule != NULL)
		{
			memcpy(buffer+position, &i, sizeof(i));
			position += 4 + phx_rule_serialize(rule, buffer+position+4);
			
		}
    }
	return position;
}

char* phx_apptable_serialize(int* length)
{
	g_mutex_lock(apptable_lock);
	int chains_num = g_hash_table_size(apptable);
    int table_size = phx_apptable_count_size(apptable);
	char* result = g_new(char, table_size);
	int position = 4;
	GList* values = g_hash_table_get_values(apptable);
	//chain num: int, chains: variable
	memcpy(result, &chains_num, sizeof(chains_num));
	while (values)
	{
		position += phx_chain_serialize((GHashTable*) values->data, result+position);
		values = values->next;
	}
	g_mutex_unlock(apptable_lock);
	log_debug("Apptable serialized size, chain_num='%d', expected='%d', real='%d'\n",chains_num, table_size, position);
	g_assert(table_size == position);
	if (length)
		(*length) = table_size;
	return result;
}

struct phx_app_rule *phx_apptable_lookup(GString * appname, guint pid,
					 guint direction)
{
	log_debug
	    ("Looking for app in hashtable, app='%s', pid='%d', direction='%d'\n",
	     appname->str, pid, direction);
	g_mutex_lock(apptable_lock);
	GHashTable *chain = g_hash_table_lookup(apptable, appname->str);

	if (!chain)
	{
		log_debug("Chain not found for app: app='%s'\n", appname->str);
		g_mutex_unlock(apptable_lock);
		return NULL;
	}
	log_debug("Chain found, app='%s'\n", appname->str);
	guint hash = 0 * 4 + direction;

	struct phx_app_rule *rule = g_hash_table_lookup(chain, &hash);

	if (rule)
	{
		g_mutex_unlock(apptable_lock);
		return rule;
	}
	hash = pid * 4 + direction;
	rule = g_hash_table_lookup(chain, &hash);
	g_mutex_unlock(apptable_lock);
	return rule;
}

int
phx_data_extract(unsigned char *payload, struct phx_conn_data *cdata,
		 int direction)
{
	unsigned int headlen;

	headlen = (payload[0] % 16) * 4;
	cdata->sport =
	    (unsigned char)payload[headlen] * 256 +
	    (unsigned char)payload[headlen + 1];
	cdata->dport =
	    (unsigned char)payload[headlen + 2] * 256 +
	    (unsigned char)payload[headlen + 3];
	strncpy(cdata->destip, payload + 16, 4);
	strncpy(cdata->srcip, payload + 12, 4);
	cdata->direction = direction;
	return get_proc_from_conn(cdata, direction);
}

int
out_queue_cb(struct nfq_q_handle *qh, struct nfgenmsg *mfmsg,
	     struct nfq_data *nfad, void *data)
{
	int id = 0;

	int plen = 0, extr_res = 0;

	struct nfqnl_msg_packet_hdr *ph;

	unsigned char *payload;

	GString *srcip = NULL;

	GString *destip = NULL;

	struct phx_app_rule *rule;

	struct phx_conn_data *conndata = NULL, *resdata = NULL;

	log_debug("==Outbound callback called==\n");

	ph = nfq_get_msg_packet_hdr(nfad);
	id = ntohl(ph->packet_id);
	plen = nfq_get_payload(nfad, (char **)&payload);
	log_debug("Payload length:%d\n", plen);

	conndata = g_new0(struct phx_conn_data, 1);
	extr_res = phx_data_extract(payload, conndata, OUTBOUND);
	//swrite_ip(payload + 12,srcip,0);
//  srcip = phx_dns_lookup(payload + 12);
//      destip = phx_dns_lookup(payload + 16);

	if (destip == NULL)
		destip = phx_write_ip(payload + 16);

	if (srcip == NULL)
		srcip = phx_write_ip(payload + 12);

	log_debug("%s:%d -> %s:%d\n", srcip->str, conndata->sport, destip->str,
		  conndata->dport);
	g_string_free(srcip, TRUE);
	g_string_free(destip, TRUE);

	if (conndata->proc_name == 0)
	{
		log_debug("Couldn't determine process name, dropping packet\n");
		g_free(conndata);
		return nfq_set_verdict(out_qhandle, id, NF_DROP, plen, payload);
	}

	// connection lookup failed under /proc
	if (extr_res == -1)
	{
		log_debug("Connection timeouted, dropping packet\n");
		return nfq_set_verdict(out_qhandle, id, NF_DROP, plen, payload);
	}


	// rule lookup about connection data
	rule =
	    phx_apptable_lookup(conndata->proc_name, conndata->pid, OUTBOUND);

	log_debug("Printing procname: %s\n", conndata->proc_name->str);

	if (rule)
	{
		if (rule->verdict == ACCEPTED)
		{
			log_debug("Program %s found in list, accepting\n",
				  conndata->proc_name->str);
			g_string_free(conndata->proc_name, TRUE);
			g_free(conndata);
			return nfq_set_verdict(out_qhandle, id, NF_ACCEPT, plen,
					       payload);
		}
		if (rule->verdict == DENIED)
		{
			log_debug("Program %s found in list, denying\n",
				  conndata->proc_name->str);
			g_string_free(conndata->proc_name, TRUE);
			g_free(conndata);
			return nfq_set_verdict(out_qhandle, id, NF_DROP, plen,
					       payload);
		}
		if (rule->verdict == ASK)
		{
			log_debug("Program %s found in list, asking again\n",
				  conndata->proc_name->str);
			g_async_queue_push(to_gui, conndata);
			//This code is needed here, because i have to "jump over" the next DENY_CONN section
			log_debug
			    ("Data pushed to queue in outbound section, verdict ASK, marking 0x2\n");
			pending_conn_count++;
			return nfq_set_verdict_mark(out_qhandle, id, NF_REPEAT,
						    htonl(0x2), plen, payload);
		}
		if (rule->verdict == DENY_CONN)
		{
			log_debug("%d\n", conndata->proc_name);
			log_debug
			    ("Program %s found in list, denying for this time\n",
			     conndata->proc_name->str);
			g_string_free(conndata->proc_name, TRUE);
			g_free(conndata);
			pending_conn_count--;
			rule->verdict = ASK;
			return nfq_set_verdict(out_qhandle, id, NF_DROP, plen,
					       payload);
		}
	} else
	{
		phx_apptable_insert(conndata, OUTBOUND, NEW);
		g_async_queue_push(to_gui, conndata);
	}
	log_debug
	    ("Data pushed to queue in outbound section, no verdict, marking 0x2\n");
	pending_conn_count++;
	return nfq_set_verdict_mark(out_qhandle, id, NF_REPEAT, htonl(0x2),
				    plen, payload);
}

int
in_queue_cb(struct nfq_q_handle *qh, struct nfgenmsg *mfmsg,
	    struct nfq_data *nfad, void *data)
{
	struct nfqnl_msg_packet_hdr *ph;

	unsigned char *payload;

	unsigned int id = 0, plen = 0;

	int res;

	char srcip[20], destip[20];

	struct phx_conn_data *conndata;

	log_debug("==Inbound callback called==\n");
	ph = nfq_get_msg_packet_hdr(nfad);
	id = ntohl(ph->packet_id);
	plen = nfq_get_payload(nfad, (char **)&payload);
	conndata = g_new0(struct phx_conn_data, 1);

	res = phx_data_extract(payload, conndata, INBOUND);
	swrite_ip(payload + 12, srcip, 0);
	swrite_ip(payload + 16, destip, 0);
	if (res != -1)
	{
		log_debug("Packet received:%s:%d -> %s:%d on program %s\n",
			  srcip, conndata->sport, destip, conndata->dport,
			  conndata->proc_name->str);
		log_debug("Inbound connection on listening port\n");
		struct phx_app_rule *rule =
		    phx_apptable_lookup(conndata->proc_name, conndata->pid,
					INBOUND);
		if (rule)
		{
			if (rule->verdict == ACCEPTED)
			{
				log_debug("Accepting inbound connection\n");
				return nfq_set_verdict(in_qhandle, id,
						       NF_ACCEPT, plen,
						       payload);
			}
			if (rule->verdict == DENIED)
			{
				log_debug("Denying inbound connection\n");
				return nfq_set_verdict(in_qhandle, id, NF_DROP,
						       plen, payload);
			}
		} else
		{
			phx_apptable_insert(conndata, INBOUND, NEW);
			g_async_queue_push(to_gui, conndata);
		}
		in_pending_count++;
		return nfq_set_verdict_mark(in_qhandle, id, NF_REPEAT,
					    htonl(0x1), plen, payload);
	} else
	{
		log_debug("Nothing listens on port %d, dropping\n",
			  conndata->dport);
		return nfq_set_verdict(in_qhandle, id, NF_DROP, plen, payload);
	}
}

int
out_pending_cb(struct nfq_q_handle *qh, struct nfgenmsg *mfmsg,
	       struct nfq_data *nfad, void *data)
{
	int id = 0, plen = 0, extr_res = 0;

	struct nfqnl_msg_packet_hdr *ph;

	unsigned char *payload;

	char srcip[20];

	char destip[20];

	struct phx_conn_data *conndata;

	log_debug("==Out pending callback called==\n");
	ph = nfq_get_msg_packet_hdr(nfad);
	id = ntohl(ph->packet_id);
	plen = nfq_get_payload(nfad, (char **)&payload);
	log_debug("Payload length:%d\n", plen);
	conndata = g_new0(struct phx_conn_data, 1);

	extr_res = phx_data_extract(payload, conndata, OUTBOUND);
//	write_ip(payload + 12);
//	printf(":%d\n", conndata->sport);
//	write_ip(payload + 16);
//	printf(":%d\n", conndata->dport);
	swrite_ip(payload + 12, srcip, 0);
	swrite_ip(payload + 16, destip, 0);
	if (extr_res == -1)
	{
		log_debug("Connection timeouted, dropping packet\n");
		return nfq_set_verdict(out_pending_qhandle, id, NF_DROP, plen,
				       payload);
	}
	struct phx_app_rule *rule =
	    phx_apptable_lookup(conndata->proc_name, conndata->pid, OUTBOUND);
	if (rule)
	{
		if (rule->verdict == ACCEPTED)
		{
			log_debug("Program %s found in list, accepting\n",
				  conndata->proc_name->str);
			g_string_free(conndata->proc_name, TRUE);
			g_free(conndata);
			pending_conn_count--;
			return nfq_set_verdict(out_pending_qhandle, id,
					       NF_ACCEPT, plen, payload);
		}
		if (rule->verdict == DENIED)
		{
			log_debug("Program %s found in list, denying\n",
				  conndata->proc_name->str);
			g_string_free(conndata->proc_name, TRUE);
			g_free(conndata);
			pending_conn_count--;
			return nfq_set_verdict(out_pending_qhandle, id, NF_DROP,
					       plen, payload);
		}
		if (rule->verdict == DENY_CONN)
		{
			log_debug
			    ("Program %s found in list, denying for this time\n",
			     conndata->proc_name->str);
			g_string_free(conndata->proc_name, TRUE);
			g_free(conndata);
			pending_conn_count--;
			rule->verdict = ASK;
			return nfq_set_verdict(out_pending_qhandle, id, NF_DROP,
					       plen, payload);
		}
	}
	log_debug("No applicable verdict found, pushing back to the queue\n");
	return nfq_set_verdict(out_pending_qhandle, id, NF_QUEUE, plen,
			       payload);
}

int
in_pending_cb(struct nfq_q_handle *qh, struct nfgenmsg *mfmsg,
	      struct nfq_data *nfad, void *data)
{
	int id = 0, plen = 0, extr_res = 0;

	struct nfqnl_msg_packet_hdr *ph;

	unsigned char *payload;

	char srcip[20];

	char destip[20];

	struct phx_conn_data *conndata;

	log_debug("==In pending callback called==\n");
	ph = nfq_get_msg_packet_hdr(nfad);
	id = ntohl(ph->packet_id);
	plen = nfq_get_payload(nfad, (char **)&payload);
	log_debug("Payload length:%d\n", plen);
	conndata = g_new0(struct phx_conn_data, 1);

	extr_res = phx_data_extract(payload, conndata, INBOUND);
	if (extr_res == -1)
	{
		log_debug("Connection timeouted, dropping packet\n");
		return nfq_set_verdict(in_pending_qhandle, id, NF_DROP, plen,
				       payload);
	}
	write_ip(payload + 12);
	printf(":%d\n", conndata->sport);
	write_ip(payload + 16);
	printf(":%d\n", conndata->dport);
	swrite_ip(payload + 12, srcip, 0);
	swrite_ip(payload + 16, destip, 0);
	struct phx_app_rule *rule =
	    phx_apptable_lookup(conndata->proc_name, conndata->pid, INBOUND);
	if (rule)
	{
		if (rule->verdict == ACCEPTED)
		{
			log_debug("Program %s found in list, accepting\n",
				  conndata->proc_name->str);
			g_string_free(conndata->proc_name, TRUE);
			g_free(conndata);
			pending_conn_count--;
			return nfq_set_verdict(in_pending_qhandle, id,
					       NF_ACCEPT, plen, payload);
		}
		if (rule->verdict == DENIED)
		{
			log_debug("Program %s found in list, denying\n",
				  conndata->proc_name->str);
			g_string_free(conndata->proc_name, TRUE);
			g_free(conndata);
			pending_conn_count--;
			return nfq_set_verdict(in_pending_qhandle, id, NF_DROP,
					       plen, payload);
		}
	}
	return nfq_set_verdict(in_pending_qhandle, id, NF_QUEUE, plen, payload);
}
