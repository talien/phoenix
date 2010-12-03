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
#include <pwd.h>
#include <netdb.h>

#include <gtk/gtk.h>
#include <glib.h>

#include "misc.h"
#include "sockproc.h"
#include "types.h"
#include "callback.h"
#include "serialize.h"

//GAsyncQueue *to_gui,*to_daemon;
char buf[2048];
int ipc_socket, ipc_client, len, t;
struct sockaddr_un local, remote;

void signal_quit(int signum)
{
	printf("Signal caught, exiting...\n");
	gtk_main_quit();
}

int end = 0;

void setup_socket()
{
  GString* uname = get_user(getpid());
  printf("Username : %s\n",uname->str);
  uname = g_string_prepend(uname,"phxsock-");
  ipc_socket = socket(AF_UNIX,SOCK_STREAM,0);
  local.sun_family = AF_UNIX;
  strcpy(local.sun_path,uname->str);
  unlink(local.sun_path);
  len = strlen(local.sun_path) + sizeof(local.sun_family);
  if (bind(ipc_socket, (struct sockaddr *)&local, len) == -1) {
       perror("Error on binding IPC socket");
       exit(1);
  }
  if (listen(ipc_socket, 5) == -1) {
       perror("Error on listening IPC socket");
       exit(1);
  }
}

struct pollfd daemonfd[1];

gboolean gui_timer_callback(gpointer data)
{
  struct phx_conn_data *conndata = 0;
  daemonfd[0].fd = ipc_socket;
  daemonfd[0].events = POLLPRI | POLLIN;
  poll(daemonfd,1,0);
  if ( (daemonfd[0].revents & POLLPRI) || (daemonfd[0].revents & POLLIN) )
  {
     printf("Connection waiting from daemon, accepting\n");
     t = sizeof(remote);
     ipc_client = accept(ipc_socket,(struct sockaddr*) &remote, &t);
     int recvd = recv(ipc_client,buf,sizeof(buf),0);
     printf("Got data on IPC, len:%d\n",recvd);
     conndata = phx_deserialize_data(buf,recvd);
  }
	//conndata = (struct phx_conn_data*)g_async_queue_try_pop(to_gui);
	if (!conndata) return (gboolean)1;
	g_print("Data got:%s\n",conndata->proc_name->str);
	GtkMessageDialog* dialog;
  if (conndata->direction == OUTBOUND)
  {
    GString* srcip = phx_write_ip(conndata->srcip);
    GString* destip = NULL; //phx_dns_lookup(conndata->destip);
    if (destip == NULL)
      destip = phx_write_ip(conndata->destip);
		dialog = gtk_message_dialog_new((GtkWindow*) NULL,GTK_DIALOG_DESTROY_WITH_PARENT,GTK_MESSAGE_WARNING,GTK_BUTTONS_YES_NO,
										"A program %s wants to reach internet\n %s:%d -> %s:%d",conndata->proc_name->str,srcip->str,conndata->sport,destip->str,conndata->dport);
		g_string_free(srcip,TRUE);
		g_string_free(destip,TRUE);
  }
  else
  {	
    dialog = gtk_message_dialog_new((GtkWindow*) NULL,GTK_DIALOG_DESTROY_WITH_PARENT,GTK_MESSAGE_WARNING,GTK_BUTTONS_YES_NO,
										"A program %s wants to accept connections from internet on port: %d \n",conndata->proc_name->str,conndata->dport);
  }
	gint resp = gtk_dialog_run(GTK_DIALOG(dialog));
	gtk_widget_destroy((GtkWidget*)dialog);	
 	if (resp == GTK_RESPONSE_YES)
	{
		conndata->state = ACCEPTED;
	}
	else
	{
		conndata->state = DENIED;
	}
	//g_async_queue_push(to_daemon,conndata);
  int forsend = phx_serialize_data(conndata,buf);
  send(ipc_client,buf,forsend,0);
  close(ipc_client);
  return (gboolean)1;
}


int main(int argc, char** argv)
{
	
	int htimeout;
	gpointer my_callback_data;
	gtk_init(&argc,&argv);
	signal(SIGTERM,signal_quit);
	signal(SIGINT,signal_quit);
  setup_socket();
	htimeout=g_timeout_add((guint32)10,gui_timer_callback, my_callback_data);
	gtk_main();
	g_source_remove(htimeout);
  end = 1;
  close(ipc_socket);
	printf("Finished\n");
	exit(0);
}
