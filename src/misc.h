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

#ifndef _PHX_MISC_H
#define _PHX_MISC_H
#include <stdio.h>
#include <glib.h>
#include "config.h"

#define PHX_LOG_ERROR 1
#define PHX_LOG_WARNING 2
#define PHX_LOG_OPERATIONAL 3
#define PHX_LOG_DEBUG 4

#define log_debug(...) if (global_cfg->debug_level >= PHX_LOG_DEBUG) _log_trace(global_cfg->debug_level,__PRETTY_FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)
#define log_error(...) if (global_cfg->debug_level >= PHX_LOG_ERROR) _log_trace(global_cfg->debug_level,__PRETTY_FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)
#define log_warning(...) if (global_cfg->debug_level >= PHX_LOG_WARNING) _log_trace(global_cfg->debug_level,__PRETTY_FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)
#define log_operation(...) if (global_cfg->debug_level >= PHX_LOG_OPERATIONAL) _log_trace(global_cfg->debug_level,__PRETTY_FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)

int get_val_from_hex(char hex);
GString* phx_write_ip(char ip[4]);
GString* phx_dns_lookup(char ip[4]);
int parse_network(char* str, guchar* nw, guint32 *mask);
void _log_trace(int debug,  const char* function, const char* file, int line, gchar* format, ...);
void phx_init_log();
void phx_close_log();
void save_iptables();
void restore_iptables();
void setup_iptables();

#endif
