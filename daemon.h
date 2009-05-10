#ifndef _PHX_DAEMON_H
#define _PHX_DAEMON_H
#include <glib.h>
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

#include "misc.h"
#include "sockproc.h"
#include "types.h"
#include "callback.h"

extern int end;
gpointer daemon_thread(gpointer data);

#endif
