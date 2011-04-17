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

typedef struct phx_conn_data
{
   GString* proc_name;
   guint32 pid;
   guchar srcip[4];
   guint32 sport;
   guchar destip[4];
   guint32 dport;
   guint32 state;
   guint32 direction;
   guint32 refcnt;
   guint32 srczone;
   guint32 destzone;
} phx_conn_data;

struct phx_app_rule
{
  GString* appname;
  guint32 pid;
  guint32 verdict;
  guint32 direction;
  guint32 srczone;
  guint32 destzone;
};

phx_conn_data* phx_conn_data_new();
void phx_conn_data_ref(phx_conn_data* cdata);
void phx_conn_data_unref(phx_conn_data* cdata);

#endif
