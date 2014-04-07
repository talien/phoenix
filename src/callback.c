/*
* Copyright (c) 2008-2014 Viktor Tusa
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU Lesser General Public
* License as published by the Free Software Foundation; either
* version 2.1 of the License, or (at your option) any later version.
*
* This library is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public
* License along with this library; if not, write to the Free Software
* Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
*
*/

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
  guint32 headlen, result;

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

  result = get_proc_from_conn(cdata, direction);
  //FIXME: sane error handling
  cdata->cmd_line = get_command_line(cdata->pid);
  return result;
}

typedef struct _nf_packet {
  int id;
  char* payload;
  guint32 verdict;
  guint32 mark;
  int packet_length;
} nf_packet;


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

int phx_set_verdict(struct nfq_q_handle *qh, nf_packet *packet, nf_queue_data *queue)
{
  phx_modify_conn_count(packet->verdict, queue->direction, queue->pending);
  if (packet->mark != 0)
    {
      return nfq_set_verdict_mark(qh, packet->id, packet->verdict, htonl(packet->mark),
                                  packet->packet_length, packet->payload);
    }
  else
    {
      return nfq_set_verdict(qh, packet->id, packet->verdict, packet->packet_length, packet->payload);
    }
}

static void
phx_log_invalid_connection(struct phx_conn_data *conndata, int direction)
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

}

static void
phx_log_valid_connection(struct phx_conn_data *conndata, int direction)
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

void phx_policy_apply_rule(struct phx_conn_data *conndata, struct phx_app_rule *rule, nf_queue_data *queue, nf_packet *packet)
{
  log_debug("Rule found for program\n");
  if (rule->verdict == ACCEPTED)
    {
      log_debug("Program %s found in list, accepting\n", conndata->proc_name->str);
      packet->verdict = NF_ACCEPT;
    }
  if (rule->verdict == DENIED)
    {
      log_debug("Program %s found in list, denying\n", conndata->proc_name->str);
      if (queue->direction == OUTBOUND)
        {
          if (global_cfg->outbound_deny)
            {
              packet->verdict = NF_REPEAT;
              packet->mark = 0x3;
            }
          else
            packet->verdict = NF_DROP;

        }
      else
        {
          if (global_cfg->inbound_deny)
            {
              packet->verdict = NF_REPEAT;
              packet->mark = 0x4;
            }
          else
            packet->verdict = NF_DROP;
        }
    }
  if (rule->verdict == WAIT_FOR_ANSWER)
    {
      if (!queue->pending)
        {
          log_debug("Program %s found in list, question to GUI already asked, sending to pending\n", conndata->proc_name->str);
          packet->verdict = NF_REPEAT;
          packet->mark = queue->direction == OUTBOUND ? 0x2 : 0x1;
        }
      else
        {
          log_debug("Program %s found in list, question to GUI already asked, skipping in pending queue\n", conndata->proc_name->str);
          packet->verdict = NF_QUEUE | ( ( OUTBOUND ? 3 : 2 ) << 16);
        }
    }
  if (rule->verdict == ASK)
    {
      log_debug("Program %s found in list, asking again\n", conndata->proc_name->str);
      phx_conn_data_ref(conndata);
      g_async_queue_push(to_gui, conndata);
      rule->verdict = WAIT_FOR_ANSWER;
      //This code is needed here, because i have to "jump over" the next DENY_CONN section
      //pending_conn_count++;
      packet->mark = queue->direction == OUTBOUND ? 0x2 : 0x1;
      packet->verdict = NF_REPEAT;
    }
  if (rule->verdict == DENY_CONN)
    {
      log_debug("Program %s found in list, denying for this time\n", conndata->proc_name->str);
      rule->verdict = ASK;
      if (queue->direction == OUTBOUND)
        {
          if (global_cfg->outbound_deny)
            {
              packet->verdict = NF_REPEAT;
              packet->mark = 0x3;
            }
          else
            packet->verdict = NF_DROP;
        }
      else
        {
          if (global_cfg->inbound_deny)
            {
              packet->verdict = NF_REPEAT;
              packet->mark = 0x4;
            }
          else
            packet->verdict = NF_DROP;
        }

    }

};

void
phx_policy_handle_missing_rule(struct phx_conn_data *conndata, nf_queue_data *queue, nf_packet *packet)
{
  log_debug("No rule found for program\n");
  if (queue->pending)
    {
      //no rule in pending queue, what should i do? pushing back doesn't hurt...
      log_debug("No rule found in pending queue, hoping that pushing back doesn't hurt\n");
      packet->verdict = NF_QUEUE | ( ( OUTBOUND ? 3 : 2 ) << 16);

    }
  else
    {
      // no rule in non-pending queue, creating one and pushing to queue
      log_debug("No rule found, inserting a new one for program, program='%s'\n",conndata->proc_name->str);
      phx_conn_data_ref(conndata);
      phx_apptable_insert(conndata->proc_name, conndata->pid, queue->direction, WAIT_FOR_ANSWER, conndata->srczone, conndata->destzone);
      phx_conn_data_ref(conndata);
      g_async_queue_push(to_gui, conndata);
      //sending to pending queue
      packet->mark = queue->direction == OUTBOUND ? 0x2: 0x1;
      packet->verdict = NF_REPEAT;
    }
}

int phx_queue_callback(struct nfq_q_handle *qh, struct nfgenmsg *mfmsg G_GNUC_UNUSED,
                       struct nfq_data *nfad, void *data)
{
  int extr_res;
  nf_packet packet;
  struct phx_conn_data *conndata;
  struct phx_app_rule *rule;
  nf_queue_data *queue;

  queue = (nf_queue_data *)data;

  log_debug("Policy callback for queue; pending='%d', direction='%d'\n", queue->pending, queue->direction);

  // extracting packet metainfo from nfqueue packet header
  packet.packet_length = phx_extract_nfq_pkt_data(nfad, &packet.id, &packet.payload);
  log_debug("Packet info: id='%d', len='%d'\n", packet.id, packet.packet_length);

  // extracting connection data from payload
  conndata = phx_conn_data_new();

  extr_res = phx_data_extract(packet.payload, conndata, queue->direction);
  if (extr_res <= 0)
    {
      phx_log_invalid_connection(conndata, queue->direction);
      phx_conn_data_unref(conndata);
      packet.verdict = NF_DROP;
      return phx_set_verdict(qh, &packet, queue);
    }
  if (!queue->pending)
    {
      phx_log_valid_connection(conndata, queue->direction);
    }

  //zone lookup
  conndata->srczone = zone_lookup(global_cfg->zones, conndata->srcip);
  conndata->destzone = zone_lookup(global_cfg->zones, conndata->destip);

  log_debug("Connection zone lookup finished, srczone='%s', dstzone='%s'\n", global_cfg->zone_names[conndata->srczone]->str, global_cfg->zone_names[conndata->destzone]->str);

  //rule lookup
  rule = phx_apptable_lookup(conndata->proc_name, conndata->pid, queue->direction, conndata->srczone, conndata->destzone);
  if (rule)
    {
      phx_policy_apply_rule(conndata, rule, queue, &packet);
    }
  else
    {
      phx_policy_handle_missing_rule(conndata, queue, &packet);
    }

  phx_conn_data_unref(conndata);

  return phx_set_verdict(qh, &packet, queue);
}

