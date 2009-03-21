#include <glib.h>

#ifndef _PHX_TYPES_H
#define _PHX_TYPES_H

#define NEW 0
#define ACCEPTED 1
#define DENIED 2

struct phx_conn_data
{
   GString* proc_name;
   guint pid;
   guchar srcip[4];
   guint sport;
   guchar destip[4];
   guint dport;
	 guint state;
};

#endif
