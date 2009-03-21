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
#include <signal.h>

#include <gtk/gtk.h>
#include <glib.h>

#include "misc.h"
#include "sockproc.h"
#include "types.h"

struct nfq_handle *in_handle, *out_handle;
struct nfq_q_handle *in_qhandle, *out_qhandle;
int out_fd,in_fd,rv;
char buf[2048];
GList *app_list = NULL, *deny_list = NULL, *pending_list = NULL;
GData *applist;
GAsyncQueue *to_gui,*to_daemon,*wakeup;
static GStaticMutex timer_mutex = G_STATIC_MUTEX_INIT;
GList *pack_id_list = NULL;

int phx_data_extract(char* payload, struct phx_conn_data *cdata)
{
  unsigned int headlen, sport, dport ;
	headlen = (payload[0] % 16) * 4;
  cdata->sport = (unsigned char)payload[headlen] * 256 + (unsigned char)payload[headlen + 1];
	cdata->dport = (unsigned char)payload[headlen + 2] * 256 + (unsigned char)payload[headlen + 3];
	strncpy(cdata->destip,payload+16,4);
	strncpy(cdata->srcip,payload+12,4);
	return get_proc_from_conn(cdata,OUTBOUND);
};

int my_compare_func(GString *A,GString *B)
{
	return (g_string_equal(A,B))?0:1;
}

void signal_quit(int signum)
{
	printf("Signal caught, exiting...");
	gtk_main_quit();
}

int queue_cb(struct nfq_q_handle *qh,struct nfgenmsg *mfmsg,struct nfq_data *nfad,void* data)
{
	int id = 0;
	int plen = 0;
	struct nfqnl_msg_packet_hdr *ph;
	char* payload;
//	char rbuf[1024];
//	unsigned int dport, sport;
//	char name[1024];
	char srcip[20];
	char destip[20];
//	int* res;
  struct phx_conn_data *conndata, *resdata = NULL;
	//GString *pr_name;
	printf("Callback called\n");
	ph = nfq_get_msg_packet_hdr(nfad);
	id = ntohl(ph->packet_id);
	plen = nfq_get_payload(nfad, &payload);
	printf("Payload length:%d\n",plen);
  conndata = g_new0(struct phx_conn_data,1);
  phx_data_extract(payload,conndata);
	//dumphex(payload,plen);
//	printf("Header len:%u bytes\n", headlen);
	write_ip(payload + 12); printf(":%d\n",conndata->sport);
//	printf(":%u ->", sport);
	write_ip(payload + 16); printf(":%d\n",conndata->dport);
//	printf(":%u\n", dport);
	//cn.sport = sport;
	//cn.dport = dport;
	//strncpy(cn.dest,payload+16,4);
	//strncpy(cn.src,payload+12,4);
	//get_proc_from_conn(&cn,name,sizeof(name),OUTBOUND);
	swrite_ip(payload + 12,srcip,0);
	swrite_ip(payload + 16,destip,0);
	//pr_name = g_string_new(conndata->proc_name->str);
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
	//res = (int*)g_async_queue_pop(to_daemon);
	/*if ((*res) == 1)
	{
		app_list = g_list_prepend(app_list,pr_name);
		free(res);
		return nfq_set_verdict(out_qhandle,id,NF_ACCEPT,plen,payload);	
	}
	else
	{
		deny_list = g_list_prepend(deny_list,pr_name);
		free(res);
		return nfq_set_verdict(out_qhandle,id,NF_DROP,plen,payload);
	}*/
	return nfq_set_verdict(out_qhandle,id,NF_REPEAT,plen,payload);
};

int in_queue_cb(struct nfq_q_handle *qh,struct nfgenmsg *mfmsg,struct nfq_data *nfad,void* data)
{
	struct nfqnl_msg_packet_hdr *ph;
	char* payload;
	unsigned int id = 0, plen = 0, headlen, dport, sport;
	int res;
	char name[100], srcip[20], destip[20];
	struct phx_conn_data* conndata;
  printf("Callback called\n");
	ph = nfq_get_msg_packet_hdr(nfad);
	id = ntohl(ph->packet_id);
	plen = nfq_get_payload(nfad, &payload);
  conndata = g_new0(struct phx_conn_data,1);
	/*headlen = (payload[0] % 16) * 4;
	sport = (unsigned char)payload[headlen] * 256 + (unsigned char)payload[headlen + 1];
	dport = (unsigned char)payload[headlen + 2] * 256 + (unsigned char)payload[headlen + 3];
	write_ip(payload + 12);
	printf(":%u ->", sport);
	write_ip(payload + 16);
	printf(":%u\n", dport);
	cn.sport = sport;
	cn.dport = dport;
	strncpy(cn.dest,payload+16,4);
	strncpy(cn.src,payload+12,4);
	res = get_proc_from_conn(&cn,name,sizeof(name),INBOUND);*/
	res = phx_data_extract(payload,conndata);
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
		printf("Nothing listens on this port, dropping\n");
	 	return nfq_set_verdict(in_qhandle,id,NF_DROP,plen,payload);	
	}
};


struct pollfd polls[2];
struct timespec ival;
gint timer_callback(gpointer data)
{
		int i;
		ival.tv_sec = 0;
		ival.tv_nsec = 1000;
	  polls[0].fd = out_fd;
		polls[0].events = POLLIN | POLLPRI;
		polls[1].fd = in_fd;
		polls[1].events = POLLIN | POLLPRI;
		poll(polls,2,1);
		if ( (polls[0].revents & POLLIN) || (polls[0].revents & POLLPRI) )
		{
			while ((rv = recv(out_fd,buf,sizeof(buf),MSG_DONTWAIT)) && rv > 0)
  		{
    		printf("Packet received\n");
    		nfq_handle_packet(out_handle,buf,rv);
				printf("Packet handled\n");
  		}
		}
		if ( (polls[1].revents & POLLIN) || (polls[1].revents & POLLPRI) )
		{
			while ((rv = recv(in_fd,buf,sizeof(buf),MSG_DONTWAIT)) && rv > 0)
  		{
    		printf("Packet received\n");
    		nfq_handle_packet(in_handle,buf,rv);
				printf("Packet handled\n");
  		}
		}
	return 1;
};

int init_queue(struct nfq_handle **handle, struct nfq_q_handle **qhandle,int *fd,nfq_callback *cb,int queue_num)
{
	(*handle) = nfq_open();
	if (!(*handle))
	{
		perror("Error occured during opening queue");
		exit(1);
	}
	if (nfq_unbind_pf((*handle),AF_INET) < 0)
	{
		perror("Unbinding");
		exit(1);
	}
	printf("Binding protocol\n");
	if (nfq_bind_pf((*handle),AF_INET)<0)
	{
		perror("Binding");
		exit(1);
	}
	printf("Creating queue\n");
	(*qhandle)=nfq_create_queue((*handle),queue_num,cb,NULL);
	if (!(*qhandle))
	{
		perror("Creating queue");
		exit(1);
	}
	printf("Setting mode\n");
	if (nfq_set_mode((*qhandle),NFQNL_COPY_PACKET,0) < 0)
	{
		perror("Error setting queue mode");
	}
	(*fd) = nfq_fd((*handle));
	printf("Fd: %d\n",(*fd));

}

int close_queue(struct nfq_handle *handle,struct nfq_q_handle *qhandle)
{
 printf("Destroy queue\n");
	nfq_destroy_queue(qhandle);
	printf("Destroy handle\n");
  nfq_close(handle);  
}

gpointer daemon_thread(gpointer data)
{
	g_async_queue_ref(to_gui);
	g_async_queue_ref(to_daemon);	
	while(1)
	{
    timer_callback(NULL);
		sleep(1);
	};
  printf("Thread exited!\n");
	g_async_queue_unref(to_gui);
	g_async_queue_unref(to_daemon);
	return 0;

};

gpointer gui_timer_callback(gpointer data)
{
//	gpointer qdata;
//	GString *strdata;
	//int* response;
  struct phx_conn_data *conndata;
	conndata = (struct phx_conn_data*)g_async_queue_try_pop(to_gui);
	if (!conndata) return 1;
	g_printf("Data got:%s\n",conndata->proc_name);
	GtkMessageDialog* dialog;
	dialog = gtk_message_dialog_new(NULL,GTK_DIALOG_DESTROY_WITH_PARENT,GTK_MESSAGE_WARNING,GTK_BUTTONS_YES_NO,
//								"A program %s wants to reach internet\n %s:%d -> %s:%d",name,srcip,sport,destip,dport);
										"A program %s wants to reach internet\n :%d -> :%d",conndata->proc_name->str,conndata->sport,conndata->dport);
	gint resp = gtk_dialog_run(GTK_DIALOG(dialog));
	gtk_widget_destroy(dialog);	
 // response = malloc(sizeof(int));
 	if (resp == GTK_RESPONSE_YES)
	{
		conndata->state = ACCEPTED;
	}
	else
	{
		conndata->state = DENIED;
	}
	g_async_queue_push(to_daemon,conndata);
  return 1;
}

GThread* gui_th;

int main(int argc, char** argv)
{
	
	int htimeout;
	gpointer my_callback_data;
	gtk_init(&argc,&argv);
	g_thread_init(NULL);
	to_gui = g_async_queue_new();
	to_daemon = g_async_queue_new();
	gui_th = g_thread_create(daemon_thread,NULL,1,NULL);
	g_datalist_init(&applist);
	signal(SIGTERM,signal_quit);
	signal(SIGINT,signal_quit);
	htimeout=g_timeout_add((guint32)1,gui_timer_callback, my_callback_data);
	printf("Opening connection\n");
 	init_queue(&in_handle,&in_qhandle,&in_fd,in_queue_cb,1);
	init_queue(&out_handle,&out_qhandle,&out_fd,queue_cb,0);
	gtk_main();
	g_source_remove(htimeout);
	close_queue(out_handle,out_qhandle);
	close_queue(in_handle,in_qhandle);
	g_async_queue_unref(to_gui);
	g_async_queue_unref(to_daemon);
	printf("Finished\n");
	exit(0);
};
