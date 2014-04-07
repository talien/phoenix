/*
* Copyright (c) 2008-2014 Viktor Tusa
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU Lesser General Public
* License as published by the Free Software Foundation; either
* version 2.1 of the License, or (at your option) any later version.
*
* This library is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public
* License along with this library; if not, write to the Free Software
* Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
*
*/

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
#define WAIT_FOR_ANSWER 8

#define OUTBOUND 0
#define INBOUND 1

typedef struct phx_conn_data
{
  GString* proc_name;
  GString* cmd_line;
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

typedef struct phx_app_rule
{
  GString* appname;
  guint32 pid;
  guint32 verdict;
  guint32 direction;
  guint32 srczone;
  guint32 destzone;
  guint32 refcnt;
} phx_app_rule;


phx_conn_data* phx_conn_data_new();
void phx_conn_data_ref(phx_conn_data* cdata);
void phx_conn_data_unref(phx_conn_data* cdata);

phx_app_rule* phx_rule_new();
void phx_rule_ref(phx_app_rule* rule);
void phx_rule_unref(phx_app_rule* rule);

#endif
