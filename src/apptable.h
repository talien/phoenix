#ifndef _PHx_APPTABLE_H
#define _PHX_APPTABLE_H
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <sys/poll.h>

#include "misc.h"
#include "sockproc.h"
#include "types.h"


void phx_apptable_init();
struct phx_app_rule* phx_apptable_lookup(GString* appname,guint pid,guint direction, guint32 srczone, guint32 destzone);
void phx_apptable_insert(GString* appname, guint32 pid,int direction,int verdict, guint32 srczone, guint32 destzone);
void phx_apptable_delete(GString* appname, guint32 pid,int direction, guint32 srczone, guint32 destzone);
char* phx_apptable_serialize(int* length);
void phx_apptable_clear_invalid();
void phx_apptable_merge_rule(GString* appname, guint32 direction, guint32 pid, guint32 srczone, guint32 destzone, guint32 verdict);
void phx_update_rules(char* buffer, int length);
#endif
