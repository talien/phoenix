#include "callback.h"
#include "data.h"
#include "types.h"
#include "zones.h"
#include "serialize.h"
#include "apptable.h"

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
	memcpy((char*)cdata->destip, (char*)payload + 16, 4);
	memcpy((char*)cdata->srcip, (char*)payload + 12, 4);
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

void phx_modify_conn_count(guint32 nfq_verdict, guint32 direction, guint32 pending)
{
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

	log_debug("Callback info; pending='%d', direction='%d'\n", pending, direction);

	// extracting connection data from payload
	extr_res = phx_data_extract(payload, conndata, direction);
	if (extr_res <= 0)
	{
		GString *sip = phx_write_ip((char*)conndata->srcip);
		GString *dip = phx_write_ip((char*)conndata->destip);
		if (direction == OUTBOUND)
		{
			log_operation("Connection timeouted, dropping packet, srcip='%s', srcport='%d', destip='%s', destport='%d' \n", sip->str, conndata->sport, dip->str, conndata->dport);
		}
		else
		{
			log_operation("Nothing listens on port %d, dropping packet, srcip='%s', srcport='%d', destip='%s', destport='%d' \n", conndata->dport, sip->str, conndata->sport, dip->str, conndata->dport);

		}
		g_string_free(sip,TRUE);
		g_string_free(dip,TRUE);
		phx_conn_data_unref(conndata);
		phx_modify_conn_count(NF_DROP, direction, pending);
		return nfq_set_verdict(qh, id, NF_DROP, pkt_len,
				       (guchar*)payload);
	}
	if (!pending)
	{
		GString *sip = phx_write_ip((char*)conndata->srcip);
		GString *dip = phx_write_ip((char*)conndata->destip);

		if (direction == OUTBOUND)
		{
			log_operation("Handling outgoing connection, srcip='%s', srcport='%d', destip='%s', destport='%d', program='%s' \n", sip->str, conndata->sport, dip->str, conndata->dport, conndata->proc_name->str);
		}
		else
		{
			log_operation("Handling incoming connection, srcip='%s', srcport='%d', destip='%s', destport='%d', program='%s' \n", sip->str, conndata->sport, dip->str, conndata->dport, conndata->proc_name->str);
		}
		g_string_free(sip,TRUE);
		g_string_free(dip,TRUE);
	}

	
	//zone lookup
	srczone = zone_lookup(global_cfg->zones, conndata->srcip);
	dstzone = zone_lookup(global_cfg->zones, conndata->destip);

	conndata->srczone = srczone;
	conndata->destzone = dstzone;

	log_debug("Connection zone lookup finished, srczone='%s', dstzone='%s'\n", global_cfg->zone_names[srczone]->str, global_cfg->zone_names[dstzone]->str);

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
		if (rule->verdict == WAIT_FOR_ANSWER)
		{
			log_debug("Program %s found in list, question to GUI already asked, sending to pending\n", conndata->proc_name->str);
			if (!pending)
			{
				nfq_verdict = NF_REPEAT;
				mark = direction == OUTBOUND ? 0x2 : 0x1;
			}
			else
			{
				nfq_verdict = NF_QUEUE;
			}
		}
		if (rule->verdict == ASK)
		{
			log_debug("Program %s found in list, asking again\n",
				  conndata->proc_name->str);
			phx_conn_data_ref(conndata);
			g_async_queue_push(to_gui, conndata);
			rule->verdict = WAIT_FOR_ANSWER;
			//This code is needed here, because i have to "jump over" the next DENY_CONN section
			//pending_conn_count++;
			mark = direction == OUTBOUND ? 0x2 : 0x1;
			nfq_verdict = NF_REPEAT;
		}
		if (rule->verdict == DENY_CONN)
		{
			log_debug
			    ("Program %s found in list, denying for this time\n",
			     conndata->proc_name->str);
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
			log_debug("No rule found in pending queue, hoping that pushing back doesn't hurt\n");
			nfq_verdict = NF_QUEUE;
		}
		else
		{
			// no rule in non-pending queue, creating one and pushing to queue
			log_debug("No rule found, inserting a new one for program, program='%s'\n",conndata->proc_name->str);
			phx_conn_data_ref(conndata);
			phx_apptable_insert(conndata->proc_name, conndata->pid, direction, NEW, srczone, dstzone);
			phx_conn_data_ref(conndata);
			g_async_queue_push(to_gui, conndata);
			//sending to pending queue
			mark = direction == OUTBOUND ? 0x2: 0x1;
			nfq_verdict = NF_REPEAT;
		}
	}
	phx_conn_data_unref(conndata);

	// increasing/decresing pending_conn_count, very hackish, need rework
	phx_modify_conn_count(nfq_verdict, direction, pending);

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

