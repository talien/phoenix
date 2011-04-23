#include "callback.h"
#include "data.h"
#include "types.h"
#include "zones.h"
#include "serialize.h"

GHashTable *apptable;

GMutex *apptable_lock;


//can we somehow avoid extern?
extern radix_bit* zones;
extern GString* zone_names[256];

void phx_apptable_init()
{
	apptable = g_hash_table_new(g_str_hash, g_str_equal);
	apptable_lock = g_mutex_new();
}

guint64 phx_apptable_hash(guint32 direction, guint32 pid, guint32 srczone, guint32 destzone)
{
    //FIXME: assert on srczone/dstzone > 256
    //FIXME: pid handling -> hash should be guint64?
	return (( ( pid * (guint64)256 + (guint64)srczone) * (guint64)256) + (guint64)destzone) * (guint64)2 + (guint64)direction;
}

void
phx_apptable_insert(struct phx_conn_data *cdata, int direction, int verdict, guint32 srczone, guint32 destzone)
{
	struct phx_app_rule *rule = g_new0(struct phx_app_rule, 1);

	rule->appname = g_string_new(cdata->proc_name->str);
	rule->pid = cdata->pid;
	rule->verdict = verdict;
	rule->srczone = srczone;
	rule->destzone = destzone;
	rule->direction = direction;
	//guint hash = rule->pid * 4 + direction;
	guint64 *hash = g_new0(guint64, 1);

	*hash = phx_apptable_hash(rule->direction, rule->pid, rule->srczone, rule->destzone);
	g_mutex_lock(apptable_lock);
	GHashTable *chain =
	    g_hash_table_lookup(apptable, cdata->proc_name->str);

	if (!chain)
	{
		chain = g_hash_table_new(g_int64_hash, g_int64_equal);
		g_hash_table_insert(chain, hash, rule);
		g_hash_table_insert(apptable, rule->appname->str, chain);
	} else
	{
		g_hash_table_insert(chain, hash, rule);
	}
	g_mutex_unlock(apptable_lock);
};

void phx_apptable_delete(struct phx_conn_data *cdata, int direction, guint32 srczone, guint32 destzone)
{
	g_mutex_lock(apptable_lock);
	GHashTable *chain = g_hash_table_lookup(apptable, cdata->proc_name->str);
	if (!chain)
	{
		g_mutex_unlock(apptable_lock);
		return;
	}
	guint64 hash = phx_apptable_hash(direction, cdata->pid, srczone, destzone);
	struct phx_app_rule* rule = g_hash_table_lookup(chain, &hash);
	if (!rule)
	{
		g_mutex_unlock(apptable_lock);
		return;
	}
	g_hash_table_remove(chain, &hash);
	g_mutex_unlock(apptable_lock);
};

void phx_rule_count_size(gpointer key G_GNUC_UNUSED, gpointer value, gpointer user_data)
{
	//hash: int, pid:int, verdict:int, string_size:int, strng: char*, int srczone, int destzone
	struct phx_app_rule* rule = (struct phx_app_rule*) value;
	int* size = (int*) user_data;
	(*size) += 24 + rule->appname->len;
}

int phx_chain_count_size(GHashTable* chain)
{
	//number of directions: int
	int result = 4;
//	struct phx_app_rule* rule;
//	int i;
	/*for (i=0; i<=1; i++)
	{
		// hash value: int, rule size:variable
		rule = (struct phx_app_rule*) g_hash_table_lookup(chain, &i);
		if (rule != NULL)
			result += 4 + phx_rule_count_size(rule);
	}*/
	g_hash_table_foreach(chain, phx_rule_count_size, &result);
	log_debug("Chain size counted, size='%d'\n", result);
	return result;
}

void phx_apptable_count_func(gpointer key G_GNUC_UNUSED, gpointer value, gpointer user_data)
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
//	int len = rule->appname->len;
	/*memcpy(buffer, &(rule->pid), sizeof(rule->pid));
	memcpy(buffer+4, &(rule->verdict), sizeof(rule->verdict));
	memcpy(buffer+8, &len, sizeof(len));
	memcpy(buffer+12, rule->appname->str, len);*/
	int size = phx_pack_data("iiiiiS", buffer, &(rule->pid), &(rule->verdict), &(rule->srczone), &(rule->destzone), &(rule->direction), rule->appname, NULL);
	log_debug("Rule serialized, size='%d, program='%s'\n",size,rule->appname->str);
	return size;
}

int phx_chain_serialize(GHashTable* chain, char* buffer)
{
	int dir_num = g_hash_table_size(chain);
	// hash numbers: int
	log_debug("Serializing chain, entry number='%d'\n", dir_num);
	struct phx_app_rule* rule;
	int position = 4;
	GList* values = g_hash_table_get_values(chain);
	memcpy(buffer,&dir_num, sizeof(dir_num));
    while (values)
    {
        // rule size:variable
		// no need to store hash.
        /*rule = (struct phx_app_rule*) g_hash_table_lookup(chain, &i);
		if (rule != NULL)
		{
						
		}*/
		rule = (struct phx_app_rule*) values->data;		
//		i = phx_apptable_hash(rule->direction, rule->srczone, rule->destzone);
//		memcpy(buffer+position, &i, sizeof(i));
		position += phx_rule_serialize(rule, buffer+position);
		values = values->next;
    }
	log_debug("Chain serialized, size='%d'\n", position);
	g_list_free(values);
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
	log_debug("Serializing apptable, num_chains='%d', expected_length='%d'\n",chains_num, table_size);
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
	g_list_free(values);
	return result;
}

struct phx_app_rule *phx_apptable_hash_lookup(GHashTable* chain, int direction, int pid, guint32 srczone, guint32 destzone)
{
	struct phx_app_rule* rule;
	guint64 hash = phx_apptable_hash(direction, pid, srczone, destzone);
	rule = g_hash_table_lookup(chain, &hash);
	return rule;
}

struct phx_app_rule *phx_apptable_lookup(GString * appname, guint pid,
					 guint direction, guint32 srczone, guint32 destzone)
{
	log_debug
	    ("Looking for app in hashtable, app='%s', pid='%d', direction='%d', srczone='%d', destzone='%d' \n",
	     appname->str, pid, direction, srczone, destzone);
	g_mutex_lock(apptable_lock);
	GHashTable *chain = g_hash_table_lookup(apptable, appname->str);

	if (!chain)
	{
		log_debug("Chain not found for app: app='%s'\n", appname->str);
		g_mutex_unlock(apptable_lock);
		return NULL;
	}
	log_debug("Chain found, app='%s'\n", appname->str);
//	guint64 hash = phx_apptable_hash(direction, pid, srczone, destzone);

	struct phx_app_rule *rule;
	if ( !(rule = phx_apptable_hash_lookup(chain, direction, pid, srczone, destzone) ) )
	if ( !(rule = phx_apptable_hash_lookup(chain, direction, pid, 0, destzone) ) )
	if ( !(rule = phx_apptable_hash_lookup(chain, direction, pid, srczone, 0) ) )
	if ( !(rule = phx_apptable_hash_lookup(chain, direction, pid, 0, 0) ) )
	if ( !(rule = phx_apptable_hash_lookup(chain, direction, 0, srczone, destzone) ) )
	if ( !(rule = phx_apptable_hash_lookup(chain, direction, 0, 0, destzone) ) )
	if ( !(rule = phx_apptable_hash_lookup(chain, direction, 0, srczone, 0) ) )
	if ( !(rule = phx_apptable_hash_lookup(chain, direction, 0, 0, 0) ) )
	rule = NULL;

	g_mutex_unlock(apptable_lock);
	return rule;
}

int
phx_data_extract(const char *payload, struct phx_conn_data *cdata,
		 int direction)
{
	guint32 headlen;

	headlen = (payload[0] % 16) * 4;
	cdata->sport =
	    (unsigned char)payload[headlen] * 256 +
	    (unsigned char)payload[headlen + 1];
	cdata->dport =
	    (unsigned char)payload[headlen + 2] * 256 +
	    (unsigned char)payload[headlen + 3];
	strncpy((char*)cdata->destip, (char*)payload + 16, 4);
	strncpy((char*)cdata->srcip, (char*)payload + 12, 4);
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


int phx_queue_callback(struct nfq_q_handle *qh, struct nfgenmsg *mfmsg G_GNUC_UNUSED,
	      struct nfq_data *nfad, void *data)
{
	int id, pkt_len, queue_num, direction, extr_res, pending = 0, srczone, dstzone;
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
	if (extr_res <= 0)
	{
		GString *sip = phx_write_ip((char*)conndata->srcip);
		GString *dip = phx_write_ip((char*)conndata->destip);
		if (direction == OUTBOUND)
		{
			log_debug("Connection timeouted, dropping packet, srcip='%s', srcport='%d', destip='%s', destport='%d' \n", sip->str, conndata->sport, dip->str, conndata->dport);
		}
		else
		{
			log_debug("Nothing listens on port %d, dropping packet, srcip='%s', srcport='%d', destip='%s', destport='%d' \n", conndata->dport, sip->str, conndata->sport, dip->str, conndata->dport);

		}
		g_string_free(sip,TRUE);
		g_string_free(dip,TRUE);
		phx_conn_data_unref(conndata);
		return nfq_set_verdict(qh, id, NF_DROP, pkt_len,
				       (guchar*)payload);
	}
	
	//zone lookup
	srczone = zone_lookup(zones, conndata->srcip);
	dstzone = zone_lookup(zones, conndata->destip);

	conndata->srczone = srczone;
	conndata->destzone = dstzone;

	log_debug("Connection zone lookup finished, srczone='%s', dstzone='%s'\n", zone_names[srczone]->str, zone_names[dstzone]->str);

	//rule lookup
	rule = phx_apptable_lookup(conndata->proc_name, conndata->pid, direction, srczone, dstzone);
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
			if (direction == OUTBOUND)
			{
				nfq_verdict = NF_REPEAT;
				mark = 0x3;
			}
			else
			{
				nfq_verdict = NF_DROP;
			}
		}
		if (rule->verdict == ASK)
		{
			log_debug("Program %s found in list, asking again\n",
				  conndata->proc_name->str);
			phx_conn_data_ref(conndata);
			g_async_queue_push(to_gui, conndata);
			//This code is needed here, because i have to "jump over" the next DENY_CONN section
			mark = direction == OUTBOUND ? 0x2 : 0x1;
			nfq_verdict = NF_REPEAT;
		}
		if (rule->verdict == DENY_CONN)
		{
			log_debug
			    ("Program %s found in list, denying for this time\n",
			     conndata->proc_name->str);
			pending_conn_count--;
			rule->verdict = ASK;
			if (direction == OUTBOUND)
			{
				nfq_verdict = NF_REPEAT;
				mark = 0x3;
			}
			else
			{
				nfq_verdict = NF_DROP;
			}
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
			phx_apptable_insert(conndata, direction, NEW, srczone, dstzone);
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
		{
			if (direction == INBOUND)
			{
				in_pending_count++;
			}
			else
			{
				pending_conn_count++;
			}
		}
		
	}

	if (mark != 0)
	{
		return nfq_set_verdict_mark(qh, id, nfq_verdict, htonl(mark),
				    pkt_len, (guchar*)payload);
	}
	else
	{
		return nfq_set_verdict(qh, id, nfq_verdict, pkt_len, (guchar*)payload);
	}

}

