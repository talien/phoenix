#include <glib.h>

#ifndef _PHX_TYPES_H
#define _PHX_TYPES_H

#define NEW 0
#define ACCEPTED 1
#define DENIED 2
#define DENY_CONN 3
#define DENY_INST 4
#define ACCEPT_CONN 5
#define ACCEPT_INST 6
#define ASK 7

struct phx_conn_data
{
   GString* proc_name;
   guint32 pid;
   gchar srcip[4];
   guint32 sport;
   gchar destip[4];
   guint32 dport;
   guint32 state;
   guint32 direction;
};

struct phx_app_rule
{
  GString* appname;
  guint32 pid;
  guint32 verdict;
  guint32 direction;
};



#endif
