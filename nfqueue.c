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
#include "callback.h"
#include "daemon.h"

GAsyncQueue *to_gui,*to_daemon;
char buf[2048];

void signal_quit(int signum)
{
	printf("Signal caught, exiting...\n");
	gtk_main_quit();
}

int end = 0;

gboolean gui_timer_callback(gpointer data)
{
  struct phx_conn_data *conndata;
	conndata = (struct phx_conn_data*)g_async_queue_try_pop(to_gui);
	if (!conndata) return (gboolean)1;
	g_print("Data got:%s\n",conndata->proc_name->str);
	GtkMessageDialog* dialog;
	dialog = gtk_message_dialog_new((GtkWindow*) NULL,GTK_DIALOG_DESTROY_WITH_PARENT,GTK_MESSAGE_WARNING,GTK_BUTTONS_YES_NO,
										"A program %s wants to reach internet\n :%d -> :%d",conndata->proc_name->str,conndata->sport,conndata->dport);
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
	g_async_queue_push(to_daemon,conndata);
  return (gboolean)1;
}

GThread* daemon_th;

int main(int argc, char** argv)
{
	
	int htimeout;
	gpointer my_callback_data;
	gtk_init(&argc,&argv);
	g_thread_init(NULL);
	to_gui = g_async_queue_new();
	to_daemon = g_async_queue_new();
	daemon_th = g_thread_create(daemon_thread,NULL,1,NULL);
	signal(SIGTERM,signal_quit);
	signal(SIGINT,signal_quit);
	htimeout=g_timeout_add((guint32)5,gui_timer_callback, my_callback_data);
	gtk_main();
	g_source_remove(htimeout);
  end = 1;
  g_thread_join(daemon_th);
	g_async_queue_unref(to_gui);
	g_async_queue_unref(to_daemon);
	printf("Finished\n");
	exit(0);
}
