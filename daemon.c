#include <sys/un.h>
#include "serialize.h"
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
#include <sys/un.h>
#include <signal.h>
#include <ctype.h>

#include <glib.h>

#include "misc.h"
#include "sockproc.h"
#include "types.h"
#include "callback.h"
#include "serialize.h"
#include "zones.h"

struct nfq_q_handle *in_qhandle, *out_qhandle, *in_pending_qhandle,
    *out_pending_qhandle;

GAsyncQueue *to_gui;

int pending_conn_count = 0, in_pending_count = 0;

struct nfq_handle *in_handle, *out_handle, *in_pending_handle,
    *out_pending_handle;
static int out_fd, in_fd, in_pending_fd, out_pending_fd, rv;

char buf[2048];

char phx_buf[2048];

GString* zone_names[256];

GThread *gui_thread, *pending_thread, *control_thread;

GCond *pending_cond;

GMutex *cond_mutex;

GMutex *zone_mutex;

radix_bit *zones;

GHashTable* aliases;

int end = 0;

#define PHX_STATE_RULE 1
#define PHX_STATE_ZONE 2
#define PHX_STATE_ALIAS 3

char get_first_char(const char* line)
{
    int i = 0;	
	for (i = 0; isspace(line[i]) && line[i] != '\0'; i++)
	{
		
	}
	return line[i];
}

int parse_key_value(const char* line, char* key, char* value)
{
	//FIXME: watch for buffer overflows, limit key/value/line len.
	int invar1 = 0, invar2 = 0, wasvar1 = 0;
	int j = 0, i;
	value[0] = '\0';
	for (i = 0; line[i] != '\0'; i++)
	{
		if (!isspace(line[i]))
		{
			if ((!invar1) && (!invar2) && (!wasvar1)
				&& (line[i] != '['))
			{
				invar1 = 1;
				j = 0;
			}
			if ((!invar1) && (!invar2) && (wasvar1))
			{
				invar2 = 1;
				j = 0;
			}
			if ((line[i] == '='))
			{
				invar1 = 0;
				wasvar1 = 1;
				key[j] = '\0';
			}
			if (invar1)
			{
				key[j] = line[i];
				j++;
			}
			if (invar2)
			{
				value[j] = line[i];
				j++;
			}
		}
	}		
	if (invar2)
	{
		value[j] = '\0';
	}
	
	if (!invar2 && !wasvar1)
	{
		return FALSE;
	}
	else
	{
		return TRUE;
	}

}

int parse_section(const char* line, char* section)
{
	int invar1 = 0, wasvar1 = 0;
	int j = 0, i;
	section[0] = '\0';
	for (i = 0; line[i] != '\0'; i++)
	{
		if (!isspace(line[i]))
		{
			if ((line[i] == '['))
			{
				invar1 = 1;
				j = 0;
			}
			if ((line[i] == ']'))
			{
				invar1 = 0;
				wasvar1 = 1;
				section[j] = '\0';
			}
			if (invar1 && line[i] != '[')
			{
				section[j] = line[i];
				j++;
			}
		}
	}
	if (!wasvar1)
		return FALSE;
	return TRUE;

}

int parse_config(const char* filename)
{
	char fbuf[512], var1[128], var2[128];

	struct phx_conn_data *rule = 0;
	int verdict, direction = OUTBOUND;
	int state = 0;
	int zoneid = 1;
	guchar buf[4];
	guint32 mask;	
	FILE* conffile;
	aliases = g_hash_table_new((GHashFunc)g_string_hash, (GEqualFunc)g_string_equal);

	if (filename == NULL)
	{
		conffile = fopen("phx.conf", "r");
	}
	else
	{
		conffile = fopen(filename, "r");
	}

	zones = g_new0(radix_bit, 1);
	if (!conffile)
		return FALSE;

	while (fgets(fbuf, sizeof(fbuf), conffile) != NULL)
	{
		if (get_first_char(fbuf) == '[')
		{
			parse_section(fbuf, var1);
			log_debug("Conf section: section='%s'\n", var1);
			if (rule)
			{
				log_debug("Inserting rule\n");
				phx_apptable_insert(rule, direction, verdict, 0, 0);
			}
			if (!strncmp(var1, "rule", 128))
			{
				rule = g_new0(struct phx_conn_data, 1);
				state = PHX_STATE_RULE;
			}
			if (!strncmp(var1, "zones", 128))
			{
				rule = NULL;
				state = PHX_STATE_ZONE;
			}	
			if (!strncmp(var1, "alias", 128))
			{
				rule = NULL;
				state = PHX_STATE_ALIAS;	
			}
		}
		else if (get_first_char(fbuf) == '#')
		{
			log_debug("Comment found\n");
			continue;
		}
		else if (get_first_char(fbuf) == '\0')
		{
			continue;
		}
		else 
		{
			parse_key_value(fbuf, var1, var2);
			log_debug("Variable1: %s Variable2:%s state='%d' \n", var1, var2, state);
			if (state == PHX_STATE_RULE)
			{
				if (!strncmp(var1, "program", 128))
				{
					rule->proc_name = g_string_new(var2);
					rule->pid = 0;
				}
				if (!strncmp(var1, "verdict", 128))
				{
					if (!strncmp(var2, "deny", 128))
					{
						verdict = DENIED;
					}
					if (!strncmp(var2, "accept", 128))
					{
						verdict = ACCEPTED;
					}
				}
			}
			else if (state == PHX_STATE_ZONE)
			{
				log_debug("Adding zone: name='%s', network='%s', zoneid='%d' \n", var1, var2, zoneid);
				parse_network(var2, buf, &mask);
				zone_add(zones, buf, mask, zoneid);
				zone_names[zoneid] = g_string_new(var1);
				zoneid += 1;
			}
			else if (state == PHX_STATE_ALIAS)
			{
				log_debug("Adding alias: name='%s', alias='%s' \n",var1, var2);
				GString *name, *alias;
				name = g_string_new(var1);
				alias = g_string_new(var2);
				g_hash_table_insert(aliases, name, alias);
			}
		}
	}
	if (rule)
	{
		log_debug("Inserting rule\n");
		phx_apptable_insert(rule, direction, verdict, 0, 0);
	}
	fclose(conffile);
	return TRUE;
}

int init_daemon_socket()
{
	struct sockaddr_un local;

	int len;
	int daemon_socket = socket(AF_UNIX, SOCK_STREAM, 0);
	local.sun_family = AF_UNIX;
	strcpy(local.sun_path,"phxdsock");
	len = strlen(local.sun_path) + sizeof(local.sun_family);
	unlink(local.sun_path);
	if (bind(daemon_socket, (struct sockaddr *)&local, len) == -1)
	{
		perror("Error on binding daemon socket");
		exit(1);
	}
	if (listen(daemon_socket, 5) == -1)
	{
		perror("Error on listening daemon socket");
		exit(1);
	}
	return daemon_socket;

}

void control_handle_query(int sock)
// GUI sends its uid to daemon, the the connection will be permanent until gui exists
{
	char* buffer;
	char command[4096];
	int data_len = 0;

	int hs_len = recv(sock, command, 1024, 0);
	log_debug("Data got: length='%d', data='%s'\n", hs_len, command);
	if (!strncmp(command,"GET",3))
	{
		//sending serialized rule table
		buffer = phx_apptable_serialize(&data_len);
		send(sock, buffer, data_len, 0);
		free(buffer);
	}
	else if (!strncmp(command,"GZN",3))
	{
		buffer = g_new(char,8192);
		data_len = phx_serialize_zones(buffer, zones);
		log_debug("Get zone request received, sending zones, size='%d'\n", data_len);
		send(sock, buffer, data_len, 0);
		g_free(buffer);
	}
	else if (!strncmp(command,"SZN",3))
	{
		log_debug("Zone setting request got, len='%d'\n", hs_len-3);
	 	phx_deserialize_zones(command+3, hs_len - 3, &zones);
		send(sock,"ACK",4,0);
	}
	close(sock);
	
}

gpointer daemon_socket_thread(gpointer data G_GNUC_UNUSED)
{

	struct sockaddr_un remote;

	int remote_sock, daemon_socket;
	socklen_t rsock_len;
	daemon_socket = init_daemon_socket();
	log_debug("Starting daemon control socket thread\n");
	while (1)
	{
		remote_sock = accept(daemon_socket, (struct sockaddr*)&remote, &rsock_len);
		log_debug("Connection accepted, handling data\n");
		control_handle_query(remote_sock);
	};
	close(daemon_socket);
}

struct phx_conn_data *send_conn_data(struct phx_conn_data *data)
{
	int dlen = phx_serialize_data(data, phx_buf);

	int s, len;
	guint32 verdict, srczone, destzone, pid;

	struct sockaddr_un remote;

	if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
	{
		log_debug("Error creating socket to client\n");
		data->state = DENY_CONN;
		return data;
	}
	log_debug("Connecting to GUI socket\n");
	remote.sun_family = AF_UNIX;
	GString *uname = get_user(data->pid);
	GString *aname;

	if (uname == NULL)
	{
		log_debug("Cannot determine process user, assuming root\n");
		uname = g_string_new("root");
	}

	//lookup username in aliases
	aname = g_hash_table_lookup(aliases, uname);
	if (aname == NULL)
	{
		uname = g_string_prepend(uname, "phxsock-");
	}
	else
	{
		aname = g_string_new(aname->str);
		log_debug("Resolving user alias from %s to %s\n", uname->str, aname->str);
		g_string_free(uname, TRUE);
		uname = g_string_prepend(aname, "phxsock-");
	}
	strcpy(remote.sun_path, uname->str);
	len = strlen(remote.sun_path) + sizeof(remote.sun_family);
	if (connect(s, (struct sockaddr *)&remote, len) == -1)
	{
		log_debug("Connection failed to client socket:%s!\n",
			  uname->str);

		data->state = DENY_CONN;
		close(s);
		g_string_free(uname, TRUE);
		return data;
	}
	g_string_free(uname, TRUE);
	log_debug("Sending %d bytes of data to GUI\n", dlen);
	if (send(s, phx_buf, dlen, 0) == -1)
	{
		log_debug("Error sending to GUI IPC socket\n");

		data->state = DENY_CONN;
		close(s);
		return data;
	}
	int recvd;

	if ((recvd = recv(s, phx_buf, sizeof(phx_buf), 0)) <= 0)
	{
		log_debug("Error receiving from GUI IPC socket\n");
		data->state = DENY_CONN;
		close(s);
		return data;
	}
	log_debug("Got data from GUI on IPC, len:%d\n", recvd);
	phx_deserialize_data(phx_buf, &verdict, &srczone, &destzone, &pid);
	phx_apptable_delete(data, data->direction, data->srczone, data->destzone);
	data->state = verdict;
	data->srczone = srczone;
	data->destzone = destzone;
	data->pid = pid;
	phx_apptable_insert(data, data->direction, pid, srczone, destzone);
	log_debug ("Data from GUI: verdict='%d', srczone='%d', destzone='%d'\n", data->state, data->srczone, data->destzone);
	close(s);
	return data;
}

void signal_pending()
{
	g_cond_signal(pending_cond);
}

int process_gui_queue(struct phx_conn_data* resdata)
{
	struct phx_app_rule *rule;

	if (resdata)
	{
		log_debug("Processing gui queue\n");
		if (resdata->proc_name == 0)
		{
			log_debug
			    ("Found NULL process name, something went wrong\n");
			return 0;
		}
		rule =
		    phx_apptable_lookup(resdata->proc_name, resdata->pid,
					resdata->direction, resdata->srczone, resdata->destzone);
		if (rule)
		{
			log_debug("App found in hashtable!\n");
			rule->verdict = resdata->state;
		}
		else
		{
			log_debug("Unknown app found, adding to hashtable, name='%s', direction='%d', state='%d'\n",resdata->proc_name->str, resdata->direction, resdata->state);
			phx_apptable_insert(resdata, resdata->direction, resdata->state, resdata->srczone, resdata->destzone);
			
		}
		phx_conn_data_unref(resdata);
		signal_pending();
		log_debug("Signalling pending queue\n");
		return 1;
	} else
	{
		return 0;
	}
}


gpointer gui_ipc_thread(gpointer data G_GNUC_UNUSED)
{
	g_async_queue_ref(to_gui);
	while (1)
	{
		log_debug("Waiting for data in gui_ipc_thread\n");
		struct phx_conn_data *data = g_async_queue_pop(to_gui);

		send_conn_data(data);

		log_debug("Starting to process gui queue\n");
		process_gui_queue(data);
	}
}

struct pollfd polls[4];

struct timespec ival;

//main processing iteration, processing normal queues (inbound, and outbound)
gint main_loop_iterate()
{
	int ret;

	polls[0].fd = out_fd;
	polls[0].events = POLLIN | POLLPRI;
	polls[1].fd = in_fd;
	polls[1].events = POLLIN | POLLPRI;
	ret = poll(polls, 2, -1);
	if (ret > 0)
	{
		if ((polls[0].revents & POLLIN) || (polls[0].revents & POLLPRI))
		{
			while ((rv =
				recv(out_fd, buf, sizeof(buf),
				     MSG_DONTWAIT)) && rv > 0)
			{
				log_debug("Packet received on out_fd\n");
				nfq_handle_packet(out_handle, buf, rv);
				log_debug("Packet handled on out_fd\n");
			}
		}
		if ((polls[1].revents & POLLIN) || (polls[1].revents & POLLPRI))
		{
			while ((rv =
				recv(in_fd, buf, sizeof(buf), MSG_DONTWAIT))
			       && rv > 0)
			{
				log_debug("Packet received on in_fd\n");
				nfq_handle_packet(in_handle, buf, rv);
				log_debug("Packet handled on in_fd\n");
			}
		}

	}
	return 1;
}

/*
thread, which processes pending packets in pending queues
pending queue only processed, when data received from gui.
then we process all packet from queue, sorts out, which has matching non-pending rule,
then put back the others
we can only(?) estimate the size of the pending queue
*/
gpointer pending_thread_run(gpointer data G_GNUC_UNUSED)
{
	cond_mutex = g_mutex_new();
	pending_cond = g_cond_new();
	while (!end)
	{
		g_cond_wait(pending_cond, cond_mutex);
		log_debug("Waking pending thread\n");
		int i;

		int ret;

		polls[0].fd = out_pending_fd;
		polls[0].events = POLLIN | POLLPRI;
		polls[1].fd = in_pending_fd;
		polls[1].events = POLLIN | POLLPRI;
		log_debug("Polling in pending thread\n");
		ret = poll(polls, 2, 0);
		log_debug("Poll finished in pending thread\n");
		if (ret > 0)
		{
			if (((polls[0].revents & POLLIN)
			     || (polls[0].revents & POLLPRI)))
			{
				for (i = 0; i < pending_conn_count; i++)
				{
					rv = recv(out_pending_fd, buf,
						  sizeof(buf), MSG_DONTWAIT);
					if (rv > 0)
					{
						log_debug
						    ("Packet received in outbound pending queue\n");
						nfq_handle_packet
						    (out_pending_handle,
						     buf, rv);
						log_debug("Packet handled\n");
					}
				}
			}
			if (((polls[1].revents & POLLIN)
			     || (polls[1].revents & POLLPRI)))
			{
				for (i = 0; i < in_pending_count; i++)
				{
					rv = recv(in_pending_fd, buf,
						  sizeof(buf), MSG_DONTWAIT);
					if (rv > 0)
					{
						log_debug
						    ("Packet received in inbound pending queue\n");
						nfq_handle_packet
						    (in_pending_handle,
						     buf, rv);
						log_debug("Packet handled\n");
					}
				}
			}
		}
	}
	return NULL;
}

/* initializing netlink queues
4 queues - 2 onbound, 2 outbound (normal+pending per direction)
pendign queues are for packets, which hasn't been confirmed from gui */
void
init_queue(struct nfq_handle **handle, struct nfq_q_handle **qhandle,
	   int *fd, nfq_callback * cb, int queue_num)
{
	int *data;
	data = g_new0(int,1);
	*data = queue_num;
	(*handle) = nfq_open();
	if (!(*handle))
	{
		perror("Error occured during opening queue");
		exit(1);
	}
	if (nfq_unbind_pf((*handle), AF_INET) < 0)
	{
		perror("Unbinding, ignoring error");
		/*exit(1); */
	}
	log_debug("Binding protocol\n");
	if (nfq_bind_pf((*handle), AF_INET) < 0)
	{
		perror("Binding");
		exit(1);
	}
	log_debug("Creating queue\n");
	(*qhandle) = nfq_create_queue((*handle), queue_num, cb, data);
	if (!(*qhandle))
	{
		perror("Creating queue");
		exit(1);
	}
	log_debug("Setting mode\n");
	if (nfq_set_mode((*qhandle), NFQNL_COPY_PACKET, 0) < 0)
	{
		perror("Error setting queue mode");
	}
	(*fd) = nfq_fd((*handle));
	log_debug("Fd: %d\n", (*fd));

}

void close_queue(struct nfq_handle *handle, struct nfq_q_handle *qhandle)
{
	log_debug("Destroy queue\n");
	nfq_destroy_queue(qhandle);
	log_debug("Destroy handle\n");
	nfq_close(handle);
}

void signal_quit(int signum G_GNUC_UNUSED)
{
	end = 1;    
};

int main(int argc, char **argv)
{

	log_debug("Opening netlink connections\n");

	init_queue(&in_handle, &in_qhandle, &in_fd, phx_queue_callback, 1);
	init_queue(&out_handle, &out_qhandle, &out_fd, phx_queue_callback, 0);
	init_queue(&out_pending_handle, &out_pending_qhandle, &out_pending_fd,
		   phx_queue_callback, 3);
	init_queue(&in_pending_handle, &in_pending_qhandle, &in_pending_fd,
		   phx_queue_callback, 2);

	signal(SIGTERM, signal_quit);
	signal(SIGINT, signal_quit);
	g_thread_init(NULL);

	zone_mutex = g_mutex_new();

	pending_cond = g_cond_new();
	to_gui = g_async_queue_new();

	phx_apptable_init();

	if (!parse_config((argc == 2) ? argv[1] : NULL))
	{
		log_debug("Error occured during parsing config, exiting!\n");
		goto exit;
	}

	log_debug("Starting threads\n");

	gui_thread = g_thread_create(gui_ipc_thread, NULL, 1, NULL);
	pending_thread = g_thread_create(pending_thread_run, NULL, 1, NULL);
	control_thread = g_thread_create(daemon_socket_thread, NULL, 1, NULL);

    // some kind of "Main Loop"
	while (!end)
	{
		main_loop_iterate();
//		sleep(0);
	};
	signal_pending();
	
exit:

	log_debug("Closing netlink connections\n");

	close_queue(out_handle, out_qhandle);
	close_queue(in_handle, in_qhandle);
	close_queue(out_pending_handle, out_pending_qhandle);
	close_queue(in_pending_handle, in_pending_qhandle);

	log_debug("Thread exited!\n");
	g_thread_join(pending_thread);

	g_cond_free(pending_cond);

	g_async_queue_unref(to_gui);

	return 0;

}
