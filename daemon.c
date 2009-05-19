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

#include <glib.h>

#include "misc.h"
#include "sockproc.h"
#include "types.h"
#include "callback.h"
#include "serialize.h"


struct nfq_q_handle *in_qhandle, *out_qhandle, *in_pending_qhandle, *out_pending_qhandle;
//GData *applist;
GAsyncQueue *to_gui,*to_daemon;
int gui_signal = 0;
int pending_conn_count = 0, in_pending_count = 0;
struct nfq_handle *in_handle, *out_handle,*in_pending_handle,*out_pending_handle;
static int out_fd,in_fd,in_pending_fd,out_pending_fd,rv;
char buf[2048];
char phx_buf[2048];
GThread* gui_thread;

struct phx_conn_data* send_conn_data(struct phx_conn_data* data)
{
	int dlen = phx_serialize_data(data,phx_buf);
	int s, t, len;
	struct sockaddr_un remote;
	char str[100];
	if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		exit(1);
	}
	printf("Connecting to GUI socket\n");
	remote.sun_family = AF_UNIX;
	strcpy(remote.sun_path, "sock-client");
	len = strlen(remote.sun_path) + sizeof(remote.sun_family);
	if (connect(s, (struct sockaddr *)&remote, len) == -1) {
     printf("Connection failed to client socket!\n");
     struct phx_conn_data *conndata = phx_deserialize_data(phx_buf,dlen);
     conndata->state = DENIED;
     return conndata;
  }
  if (send(s, phx_buf, dlen, 0) == -1) {
            perror("send");
            exit(1);
        }
  int recvd;
  g_free(data);
  if ( (recvd = recv(s,phx_buf,sizeof(phx_buf),0)) == -1)
  {
     perror("Error receiving from GUI IPC socket\n");
  } 
  printf("Got data from GUI on IPC, len:%d\n",recvd);
  struct phx_conn_data *conndata = phx_deserialize_data(phx_buf,recvd);
  close(s);
  return conndata;
}

gpointer gui_ipc(gpointer data)
{
  g_async_queue_ref(to_daemon);
  g_async_queue_ref(to_gui);
  while(1)
  {
     struct phx_conn_data* data = g_async_queue_pop(to_gui);
     struct phx_conn_data* newdata = send_conn_data(data);
     g_free(data);
     g_async_queue_push(to_daemon,newdata);
  }   
}

void process_gui_queue()
{
  struct phx_conn_data *resdata = g_async_queue_try_pop(to_daemon);
  struct phx_app_rule* rule;
  if (resdata)
	{
     printf("Processing gui queue\n");
     if ( resdata->proc_name == 0)
     {
       printf("Found NULL process name, something went wrong\n");
       return;
     }
     rule = phx_apptable_lookup(resdata->proc_name, resdata->pid, resdata->direction);
     if (rule)
     {
        g_printf("App found in hashtable!\n");
        rule->verdict = resdata->state;
     }
     g_free(resdata);
		 gui_signal = 1;
	}
}

struct pollfd polls[4];
struct timespec ival;
gint timer_callback(gpointer data)
{
	int i;
  int ret;
  polls[0].fd = out_fd;
	polls[0].events = POLLIN | POLLPRI;
	polls[1].fd = in_fd;
	polls[1].events = POLLIN | POLLPRI;
  polls[2].fd = out_pending_fd;
  polls[2].events = POLLIN | POLLPRI;
  polls[3].fd = in_pending_fd;
  polls[3].events = POLLIN | POLLPRI;
	ret = poll(polls,4,20);
	if (ret > 0)
	{
    process_gui_queue();
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
		if ( ((polls[2].revents & POLLIN) || (polls[2].revents & POLLPRI) ) && (gui_signal == 1) )
		{
      gui_signal = 0;
			for (i = 0; i < pending_conn_count; i++)
  		{
				rv = recv(out_pending_fd,buf,sizeof(buf),MSG_DONTWAIT);
				if (rv > 0)
				{
    			printf("Packet received\n");
    			nfq_handle_packet(out_pending_handle,buf,rv);
					printf("Packet handled\n");
				}
  		}
		 }
    if ( ((polls[3].revents & POLLIN) || (polls[3].revents & POLLPRI) ) && (gui_signal == 1) )
    {
      gui_signal = 0;
      for (i = 0; i < in_pending_count; i++)
      {
        rv = recv(in_pending_fd,buf,sizeof(buf),MSG_DONTWAIT);
        if (rv > 0)
        {
          printf("Packet received\n");
          nfq_handle_packet(in_pending_handle,buf,rv);
          printf("Packet handled\n");
        }
      }
     }
			

   }
	return 1;
}

void init_queue(struct nfq_handle **handle, struct nfq_q_handle **qhandle,int *fd,nfq_callback *cb,int queue_num)
{
	(*handle) = nfq_open();
	if (!(*handle))
	{
		perror("Error occured during opening queue");
		exit(1);
	}
	if (nfq_unbind_pf((*handle),AF_INET) < 0)
	{
		perror("Unbinding, ignoring error");
		/*exit(1);*/
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

void close_queue(struct nfq_handle *handle,struct nfq_q_handle *qhandle)
{
 printf("Destroy queue\n");
	nfq_destroy_queue(qhandle);
	printf("Destroy handle\n");
  nfq_close(handle);  
}

int end = 0;

int main(int argc,char** argv)
{
  printf("Opening netlink connections\n");
 	init_queue(&in_handle,&in_qhandle,&in_fd,in_queue_cb,1);
	init_queue(&out_handle,&out_qhandle,&out_fd,out_queue_cb,0);
  init_queue(&out_pending_handle,&out_pending_qhandle,&out_pending_fd,out_pending_cb,3);
  init_queue(&in_pending_handle,&in_pending_qhandle,&in_pending_fd,in_pending_cb,2);
  g_thread_init(NULL);
  to_gui = g_async_queue_new();
  to_daemon = g_async_queue_new();
  gui_thread = g_thread_create(gui_ipc,NULL,1,NULL);
  phx_apptable_init();
	while(!end)
	{
    timer_callback(NULL);
		sleep(0);
	};
  printf("Closing netlink connections\n");
  close_queue(out_handle,out_qhandle);
	close_queue(in_handle,in_qhandle);
  close_queue(out_pending_handle,out_pending_qhandle);
  close_queue(in_pending_handle,in_pending_qhandle);
  printf("Thread exited!\n");
	g_async_queue_unref(to_gui);
	g_async_queue_unref(to_daemon);
	return 0;

}


