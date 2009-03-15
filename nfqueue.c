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

struct nfq_handle *in_handle, *out_handle;
struct nfq_q_handle *in_qhandle, *out_qhandle;
int out_fd,in_fd,rv;
char buf[2048];
GList *app_list = NULL, *deny_list = NULL;
GData *applist;


int my_compare_func(GString *A,GString *B)
{
	return (g_string_equal(A,B))?0:1;
}

void signal_quit(int signum)
{
	printf("Exiting...");
	gtk_main_quit();
}

int queue_cb(struct nfq_q_handle *qh,struct nfgenmsg *mfmsg,struct nfq_data *nfad,void* data)
{
	int id = 0;
	int plen = 0;
	struct nfqnl_msg_packet_hdr *ph;
	char* payload;
	char rbuf[1024];
	unsigned int dport, sport, headlen;
	char name[1024];
	char srcip[20];
	char destip[20];
	struct conn cn;
	GString *pr_name;
	printf("Callback called\n");
	ph = nfq_get_msg_packet_hdr(nfad);
	id = ntohl(ph->packet_id);
	plen = nfq_get_payload(nfad, &payload);
	printf("Payload length:%d\n",plen);
	//dumphex(payload,plen);
	headlen = (payload[0] % 16) * 4;
	sport = (unsigned char)payload[headlen] * 256 + (unsigned char)payload[headlen + 1];
	dport = (unsigned char)payload[headlen + 2] * 256 + (unsigned char)payload[headlen + 3];
	printf("Header len:%u bytes\n", headlen);
	write_ip(payload + 12);
	printf(":%u ->", sport);
	write_ip(payload + 16);
	printf(":%u\n", dport);
	cn.sport = sport;
	cn.dport = dport;
	strncpy(cn.dest,payload+16,4);
	strncpy(cn.src,payload+12,4);
	get_proc_from_conn(&cn,name,sizeof(name),OUTBOUND);
	swrite_ip(payload + 12,srcip,0);
	swrite_ip(payload + 16,destip,0);
	pr_name = g_string_new(name);
	if (g_list_find_custom(app_list,pr_name,my_compare_func) != NULL)
	{
		printf("Program %s found in list, accepting\n",name);
		return nfq_set_verdict(out_qhandle,id,NF_ACCEPT,plen,payload);
	}
	if (g_list_find_custom(deny_list,pr_name,my_compare_func) != NULL)
	{
		printf("Program %s found in list, denying\n",name);
		return nfq_set_verdict(out_qhandle,id,NF_DROP,plen,payload);
	}
	GtkMessageDialog* dialog;
	dialog = gtk_message_dialog_new(NULL,GTK_DIALOG_DESTROY_WITH_PARENT,GTK_MESSAGE_WARNING,GTK_BUTTONS_YES_NO,
								"A program %s wants to reach internet\n %s:%d -> %s:%d",name,srcip,sport,destip,dport);
	gint resp = gtk_dialog_run(GTK_DIALOG(dialog));
	gtk_widget_destroy(dialog);
	if (resp == GTK_RESPONSE_YES)
	{
		app_list = g_list_prepend(app_list,pr_name);
		return nfq_set_verdict(out_qhandle,id,NF_ACCEPT,plen,payload);	
	}
	else
	{
		deny_list = g_list_prepend(deny_list,pr_name);
		return nfq_set_verdict(out_qhandle,id,NF_DROP,plen,payload);
	}
};

int in_queue_cb(struct nfq_q_handle *qh,struct nfgenmsg *mfmsg,struct nfq_data *nfad,void* data)
{
	struct nfqnl_msg_packet_hdr *ph;
	char* payload;
	unsigned int id = 0, plen = 0, headlen, dport, sport;
	int res;
	struct conn cn;
	char name[100], srcip[20], destip[20];
  printf("Callback called\n");
	ph = nfq_get_msg_packet_hdr(nfad);
	id = ntohl(ph->packet_id);
	plen = nfq_get_payload(nfad, &payload);
	headlen = (payload[0] % 16) * 4;
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
	res = get_proc_from_conn(&cn,name,sizeof(name),INBOUND);
	swrite_ip(payload + 12,srcip,0);
	swrite_ip(payload + 16,destip,0);
  if (res != -1)
	{
		printf("Packet received:%s:%d -> %s:%d on program %s\n",srcip,sport,destip,dport,name);
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
  		}
		}
		if ( (polls[1].revents & POLLIN) || (polls[1].revents & POLLPRI) )
		{
			while ((rv = recv(in_fd,buf,sizeof(buf),MSG_DONTWAIT)) && rv > 0)
  		{
    		printf("Packet received\n");
    		nfq_handle_packet(in_handle,buf,rv);
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

int main(int argc, char** argv)
{
	int htimeout;
	gpointer my_callback_data;
	gtk_init(&argc,&argv);
	g_datalist_init(&applist);
	signal(SIGTERM,signal_quit);
	signal(SIGINT,signal_quit);
	htimeout=g_timeout_add((guint32)1,timer_callback, my_callback_data);
	printf("Opening connection\n");
 /* in_handle=nfq_open();
	if (!in_handle)
	{
		perror("Error occured at opening queue:");
		exit(1);
	}
	if (nfq_unbind_pf(in_handle,AF_INET)<0)
	{
		perror("Unbinding");
		exit(1);
	}
	printf("Binding protocol\n");
	if (nfq_bind_pf(in_handle,AF_INET)<0)
	{
		perror("Binding");
		exit(1);
	}
	printf("Creating queue\n");
	in_qhandle=nfq_create_queue(in_handle,0,queue_cb,NULL);
	if (!in_qhandle)
	{
		perror("Creating queue");
		exit(1);
	}
	printf("Setting mode\n");
	if (nfq_set_mode(in_qhandle,NFQNL_COPY_PACKET,0) < 0)
	{
		perror("Error setting queue mode");
	}
	in_fd = nfq_fd(in_handle);
	printf("Fd: %d\n",in_fd);*/
	init_queue(&in_handle,&in_qhandle,&in_fd,in_queue_cb,1);
	init_queue(&out_handle,&out_qhandle,&out_fd,queue_cb,0);
	/*while ((rv = recv(fd,buf,sizeof(buf),0)) && rv>=0)
	{
		printf("Packet received\n");
		nfq_handle_packet(handle,buf,rv);
	}*/
/*	while (1)
	{
		
		nanosleep(&ival, NULL);
		timer++;
		if (timer == 1000)
		{
			printf("Second leaped!\n");
			timer = 0;
		}
	}*/
	gtk_main();
	g_source_remove(htimeout);
	close_queue(out_handle,out_qhandle);
	close_queue(in_handle,in_qhandle);
	printf("Finished\n");
	exit(0);
};
