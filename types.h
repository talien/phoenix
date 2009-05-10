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
   gchar srcip[4];
   guint sport;
   gchar destip[4];
   guint dport;
	 guint state;
};

struct phx_app_rule
{
  GString* appname;
  guint pid;
  guint verdict;
  guint direction;
};



#endif
