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

int phx_extract_nfq_pkt_data(struct nfq_data *nfad, int* id, char** payload)
{
	struct nfqnl_msg_packet_hdr *ph;
	int len;
	ph = nfq_get_msg_packet_hdr(nfad);
	*id = ntohl(ph->packet_id);
	len = nfq_get_payload(nfad, payload);
	return len;
}


int phx_queue_callback(struct nfq_q_handle *qh, struct nfgenmsg *mfmsg,
	      struct nfq_data *nfad, void *data)
{
	int id, pkt_len, queue_num, direction, extr_res, pending = 0;
	char* payload;
	struct phx_conn_data *conndata;
	struct phx_app_rule *rule;
	guint32 nfq_verdict, mark;

	log_debug("General callback called\n");
	
	// extracting packet metainfo from nfqueue packet header
	pkt_len = phx_extract_nfq_pkt_data(nfad, &id, &payload);
	log_debug("Packet info: id='%d', len='%d'\n", id, pkt_len);

	conndata = phx_conn_data_new();

	//deciding if connection is inbound, very hackish, need rewrite
	queue_num = *((int*)data);

	if (queue_num == 0 || queue_num == 3) { 
		direction = OUTBOUND;
	} else { 
		direction = INBOUND;
	}
	if (queue_num == 2 || queue_num == 3)
		pending = 1;

	// extracting connection data from payload
	extr_res = phx_data_extract(payload, conndata, direction);
	if (extr_res == -1)
	{
		log_debug("Connection timeouted, dropping packet\n");
		return nfq_set_verdict(qh, id, NF_DROP, pkt_len,
				       payload);
	}

	rule = phx_apptable_lookup(conndata->proc_name, conndata->pid, direction);
	if (rule)
	{
		log_debug("Rule found for program\n");
		if (rule->verdict == ACCEPTED)
		{
			log_debug("Program %s found in list, accepting\n",
				  conndata->proc_name->str);
			nfq_verdict = NF_ACCEPT;
		}
		if (rule->verdict == DENIED)
		{
			log_debug("Program %s found in list, denying\n",
				  conndata->proc_name->str);
			nfq_verdict = NF_DROP;
		}
		if (rule->verdict == ASK)
		{
			log_debug("Program %s found in list, asking again\n",
				  conndata->proc_name->str);
			g_async_queue_push(to_gui, conndata);
			//This code is needed here, because i have to "jump over" the next DENY_CONN section
			mark = direction == OUTBOUND ? 0x2 : 0x1;
			nfq_verdict = NF_REPEAT;
		}
		if (rule->verdict == DENY_CONN)
		{
			log_debug("%d\n", conndata->proc_name);
			log_debug
			    ("Program %s found in list, denying for this time\n",
			     conndata->proc_name->str);
			pending_conn_count--;
			rule->verdict = ASK;
			nfq_verdict = NF_DROP;
		}
		if (rule->verdict == NEW)
		{
			if (pending)
			{
				log_debug("Rule found with new verdict in pending, pushing back to same queue, program='%s'\n",conndata->proc_name->str);
				nfq_verdict = NF_QUEUE;
			}
			else
			{
				log_debug("Rule found with new verdict in non-pending, pushing to pending, program='%s'\n", conndata->proc_name->str);
				mark = direction == OUTBOUND ? 0x2 : 0x1;
				nfq_verdict = NF_REPEAT;
			}
		}

	} else
	{
		log_debug("No rule found for program\n");
		if (pending)
		{
			//no rule in pending queue, what should i do? pushing back doesn't hurt...
			nfq_verdict = NF_QUEUE;
		}
		else
		{
			// no rule in non-pending queue, creating one and pushing to queue
			log_debug("No rule found, inserting a new one for program, program='%s'\n",conndata->proc_name->str);
			phx_conn_data_ref(conndata);
			phx_apptable_insert(conndata, direction, NEW);
			phx_conn_data_ref(conndata);
			g_async_queue_push(to_gui, conndata);
			//sending to pending queue
			mark = direction == OUTBOUND ? 0x2: 0x1;
			nfq_verdict = NF_REPEAT;
		}
	}
	phx_conn_data_unref(conndata);

	// increasing/decresing pending_conn_count, very hackish, need rework
	if (pending)
	{
		if (nfq_verdict == NF_ACCEPT || nfq_verdict == NF_DROP)
		{
			if (direction == INBOUND)
			{
				in_pending_count--;
			}
			else
			{
				pending_conn_count--;
			}
		}
	}
	else
	{
		if (nfq_verdict == NF_REPEAT)
			if (direction == INBOUND)
			{
				in_pending_count++;
			}
			else
			{
				pending_conn_count++;
			}
		
	}

	if (mark != 0)
	{
		return nfq_set_verdict_mark(qh, id, nfq_verdict, htonl(mark),
				    pkt_len, payload);
	}
	else
	{
		return nfq_set_verdict(qh, id, nfq_verdict, pkt_len, payload);
	}

}

