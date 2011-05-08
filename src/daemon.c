#define _PHX_DAEMON_C
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
#include "config.h"
#include "data.h"

GCond *pending_cond;

GMutex *cond_mutex;

int end = 0;

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
		log_error("Error on binding daemon socket");
		return -1;
	}
	if (listen(daemon_socket, 5) == -1)
	{
		log_error("Error on listening daemon socket");
		return -1;
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
		data_len = phx_serialize_zones(buffer, global_cfg->zones);
		log_debug("Get zone request received, sending zones, size='%d'\n", data_len);
		send(sock, buffer, data_len, 0);
		g_free(buffer);
	}
	else if (!strncmp(command,"SZN",3))
	{
		log_debug("Zone setting request got, len='%d'\n", hs_len-3);
	 	phx_deserialize_zones(command+3, hs_len - 3, &global_cfg->zones);
		send(sock,"ACK",4,0);
	}
	else if (!strncmp(command,"SET",3))
	{
		log_debug("Rule setting request got, len='%d'\n", hs_len-3);
		phx_update_rules(command+3, hs_len - 3);
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
	if (daemon_socket == -1)
		return -1;
	while (1)
	{
		remote_sock = accept(daemon_socket, (struct sockaddr*)&remote, &rsock_len);
		log_debug("Connection accepted, handling data\n");
		control_handle_query(remote_sock);
	};
	close(daemon_socket);
}

GString* resolv_user_alias(GString* username)
{
	GString *result, *star;
	result = g_hash_table_lookup(global_cfg->aliases, username);
	if (result == NULL)
	{
	
		star = g_string_new("*");
		result = g_hash_table_lookup(global_cfg->aliases, star);
		g_string_free(star, TRUE);
		if (result == NULL)
		{
			return g_string_new(username->str);
		}
	}
	log_debug("Resolving user alias from %s to %s\n", username->str, result->str);
	return g_string_new(result->str);

}

struct phx_conn_data *send_conn_data(struct phx_conn_data *data)
{
	char phx_buf[4096];
	int dlen = phx_serialize_conn_data(data, phx_buf);
	phx_app_rule* rule;
	int s, len;
	guint32 verdict, srczone, destzone, pid;

	struct sockaddr_un remote;

	log_debug("Looking up rule before sending to GUI socket\n");
	rule = phx_apptable_lookup(data->proc_name, data->pid, data->direction, data->srczone, data->destzone);
	if (( rule == NULL) || (rule != NULL && (rule->verdict == ACCEPTED || rule->verdict == DENIED)))
	{
		log_debug("No need for asking verdict on GUI, already has a matching rule with decision\n");
		return NULL;
	}
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
		log_warning("Cannot determine process user, assuming root\n");
		uname = g_string_new("root");
	}

	//lookup username in aliases
	aname = resolv_user_alias(uname);
	g_string_free(uname, TRUE);
	aname = g_string_prepend(aname, "phxsock-");

	strcpy(remote.sun_path, aname->str);
	len = strlen(remote.sun_path) + sizeof(remote.sun_family);
	if (connect(s, (struct sockaddr *)&remote, len) == -1)
	{
		log_warning("Connection failed to client socket:%s!\n",
			  aname->str);

		data->state = DENY_CONN;
		close(s);
		g_string_free(aname, TRUE);
		return data;
	}
	g_string_free(aname, TRUE);
	log_debug("Sending %d bytes of data to GUI\n", dlen);
	if (send(s, phx_buf, dlen, 0) == -1)
	{
		log_warning("Error sending to GUI IPC socket\n");

		data->state = DENY_CONN;
		close(s);
		return data;
	}
	int recvd;

	if ((recvd = recv(s, phx_buf, sizeof(phx_buf), 0)) <= 0)
	{
		log_warning("Error receiving from GUI IPC socket\n");
		data->state = DENY_CONN;
		close(s);
		return data;
	}
	log_debug("Got data from GUI on IPC, len:%d\n", recvd);
	phx_deserialize_data(phx_buf, &verdict, &srczone, &destzone, &pid);
	data->state = verdict;
	data->srczone = srczone;
	data->destzone = destzone;
	data->pid = pid;
	phx_apptable_merge_rule(data->proc_name, data->direction, data->pid, data->srczone, data->destzone, data->state);
	log_debug ("Data from GUI: verdict='%d', srczone='%d', destzone='%d', pid='%d'\n", data->state, data->srczone, data->destzone, data->pid);
	phx_conn_data_unref(data);
	close(s);
	return data;
}

void signal_pending()
{
	log_debug("Signalling pending queue\n");
	g_cond_signal(pending_cond);
}

gpointer clear_invalid_rule_thread(gpointer data G_GNUC_UNUSED)
{
	while (1)
	{
		sleep(30);
		log_debug("Clearing non-existent pids from rule table\n");
		phx_apptable_clear_invalid();
	}
}

gpointer gui_ipc_thread(gpointer data G_GNUC_UNUSED)
{
	g_async_queue_ref(to_gui);
	while (1)
	{
		log_debug("Waiting for data in gui_ipc_thread\n");
		struct phx_conn_data *data = g_async_queue_pop(to_gui);

		data = send_conn_data(data);

		signal_pending();
	}
}

struct pollfd polls[4];

struct timespec ival;

//main processing iteration, processing normal queues (inbound, and outbound)
gint main_loop_iterate()
{
	char buf[4096];
	int ret, rv;

	polls[0].fd = qdata.out_fd;
	polls[0].events = POLLIN | POLLPRI;
	polls[1].fd = qdata.in_fd;
	polls[1].events = POLLIN | POLLPRI;
	ret = poll(polls, 2, -1);
	if (ret > 0)
	{
		if ((polls[0].revents & POLLIN) || (polls[0].revents & POLLPRI))
		{
			while ((rv =
				recv(qdata.out_fd, buf, sizeof(buf),
				     MSG_DONTWAIT)) && rv > 0)
			{
				log_debug("Packet received on out_fd\n");
				nfq_handle_packet(qdata.out_handle, buf, rv);
				log_debug("Packet handled on out_fd\n");
			}
		}
		if ((polls[1].revents & POLLIN) || (polls[1].revents & POLLPRI))
		{
			while ((rv =
				recv(qdata.in_fd, buf, sizeof(buf), MSG_DONTWAIT))
			       && rv > 0)
			{
				log_debug("Packet received on in_fd\n");
				nfq_handle_packet(qdata.in_handle, buf, rv);
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
	char buf[4096];
	int rv;
	cond_mutex = g_mutex_new();
	pending_cond = g_cond_new();
	while (!end)
	{
		g_cond_wait(pending_cond, cond_mutex);
		log_debug("Waking pending thread, out_pending_count='%d', in_pending_count='%d' \n",pending_conn_count, in_pending_count);
		if (end) continue;
		int i;

		int ret;
		int now_count;

		polls[0].fd = qdata.out_pending_fd;
		polls[0].events = POLLIN | POLLPRI;
		polls[1].fd = qdata.in_pending_fd;
		polls[1].events = POLLIN | POLLPRI;
		log_debug("Polling in pending thread\n");
		ret = poll(polls, 2, 0);
		log_debug("Poll finished in pending thread\n");
		if (ret > 0)
		{
			if (((polls[0].revents & POLLIN)
			     || (polls[0].revents & POLLPRI)))
			{
				now_count = pending_conn_count;
				for (i = 0; i < now_count; i++)
				{
					rv = recv(qdata.out_pending_fd, buf,
						  sizeof(buf), MSG_DONTWAIT);
					if (rv > 0)
					{
						log_debug
						    ("Packet received in outbound pending queue\n");
						nfq_handle_packet
						    (qdata.out_pending_handle,
						     buf, rv);
						log_debug("Packet handled\n");
					}
				}
			}
			if (((polls[1].revents & POLLIN)
			     || (polls[1].revents & POLLPRI)))
			{
				now_count = in_pending_count;
				for (i = 0; i < now_count; i++)
				{
					rv = recv(qdata.in_pending_fd, buf,
						  sizeof(buf), MSG_DONTWAIT);
					if (rv > 0)
					{
						log_debug
						    ("Packet received in inbound pending queue\n");
						nfq_handle_packet
						    (qdata.in_pending_handle,
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
int
init_queue(struct nfq_handle **handle, struct nfq_q_handle **qhandle,
	   int *fd, nfq_callback * cb, int queue_num)
{
	int *data;
	data = g_new0(int,1);
	*data = queue_num;
	(*handle) = nfq_open();
	if (!(*handle))
	{
		log_error("Error occured during opening netfilter queue");
		return -1;
	}
	if (nfq_unbind_pf((*handle), AF_INET) < 0)
	{
		log_error("Unbinding, ignoring error");
		return -1;
	}
	log_debug("Binding protocol\n");
	if (nfq_bind_pf((*handle), AF_INET) < 0)
	{
		log_error("Error in nf_queue binding");
		return -1;
	}
	log_debug("Creating netfilter queue\n");
	(*qhandle) = nfq_create_queue((*handle), queue_num, cb, data);
	if (!(*qhandle))
	{
		log_error("Error in creating queue");
		return -1;
	}
	log_debug("Setting mode for netfilter queue\n");
	if (nfq_set_mode((*qhandle), NFQNL_COPY_PACKET, 0) < 0)
	{
		log_error("Error setting netfilter queue mode");
		return -1;
	}
	(*fd) = nfq_fd((*handle));
	log_debug("Netfilter queue fd; fd='%d'\n", (*fd));
	return 0;

}

void close_queue(struct nfq_handle *handle, struct nfq_q_handle *qhandle)
{
	log_debug("Destroying netfilter queue\n");
	nfq_destroy_queue(qhandle);
	log_debug("Destroy netfilter handle\n");
	nfq_close(handle);
}

void signal_quit(int signum G_GNUC_UNUSED)
{
	end = 1;    
};

int main(int argc, char **argv)
{
	GThread *gui_thread, *pending_thread = NULL, *control_thread, *clear_thread;
	phx_init_config(&argc, &argv);
	log_error("phoenix firewall starting up\n");
	log_debug("Opening netlink connections\n");

	init_queue(&qdata.in_handle, &qdata.in_qhandle, &qdata.in_fd, phx_queue_callback, 1);
	init_queue(&qdata.out_handle, &qdata.out_qhandle, &qdata.out_fd, phx_queue_callback, 0);
	init_queue(&qdata.out_pending_handle, &qdata.out_pending_qhandle, &qdata.out_pending_fd,
		   phx_queue_callback, 3);
	init_queue(&qdata.in_pending_handle, &qdata.in_pending_qhandle, &qdata.in_pending_fd,
		   phx_queue_callback, 2);

	log_debug("Netlink connections opened\n");

	signal(SIGTERM, signal_quit);
	signal(SIGINT, signal_quit);
	g_thread_init(NULL);

	zone_mutex = g_mutex_new();

	pending_cond = g_cond_new();
	to_gui = g_async_queue_new();

	phx_apptable_init();

	log_warning("Parsing configuration\n");

	if (!phx_parse_config(global_cfg->conf_file))
	{
		log_error("Error occured during parsing config, exiting!\n");
		goto exit;
	}

	log_warning("Starting threads\n");

	gui_thread = g_thread_create(gui_ipc_thread, NULL, 1, NULL);
	pending_thread = g_thread_create(pending_thread_run, NULL, 1, NULL);
	control_thread = g_thread_create(daemon_socket_thread, NULL, 1, NULL);
	clear_thread = g_thread_create(clear_invalid_rule_thread, NULL, 1, NULL);

	log_error("phoenix firewall started up\n");
    // some kind of "Main Loop"
	while (!end)
	{
		main_loop_iterate();
	};
	signal_pending();
	
exit:

	log_debug("Closing netlink connections\n");

	close_queue(qdata.out_handle, qdata.out_qhandle);
	close_queue(qdata.in_handle, qdata.in_qhandle);
	close_queue(qdata.out_pending_handle, qdata.out_pending_qhandle);
	close_queue(qdata.in_pending_handle, qdata.in_pending_qhandle);

	log_debug("Thread exited!\n");
	if (pending_thread)
		g_thread_join(pending_thread);

	g_cond_free(pending_cond);

	g_async_queue_unref(to_gui);

	log_error("phoenix firewall exited\n");

	return 0;

}
