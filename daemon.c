#include "daemon.h"

struct nfq_q_handle *in_qhandle, *out_qhandle, *in_pending_qhandle, *out_pending_qhandle;
//GData *applist;
extern GAsyncQueue *to_gui,*to_daemon;
int gui_signal = 0;
int pending_conn_count = 0, in_pending_count = 0;
struct nfq_handle *in_handle, *out_handle,*in_pending_handle,*out_pending_handle;
static int out_fd,in_fd,in_pending_fd,out_pending_fd,rv;
char buf[2048];

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

gpointer daemon_thread(gpointer data)
{
  printf("Opening netlink connections\n");
 	init_queue(&in_handle,&in_qhandle,&in_fd,in_queue_cb,1);
	init_queue(&out_handle,&out_qhandle,&out_fd,out_queue_cb,0);
  init_queue(&out_pending_handle,&out_pending_qhandle,&out_pending_fd,out_pending_cb,3);
  init_queue(&in_pending_handle,&in_pending_qhandle,&in_pending_fd,in_pending_cb,2);
  phx_apptable_init();
	g_async_queue_ref(to_gui);
	g_async_queue_ref(to_daemon);	
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

