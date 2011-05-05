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
int parse_network(const char* str, guchar* nw, guint32 *mask);
void _log_trace(int debug,  const char* function, const char* file, int line, gchar* format, ...);
void phx_init_log();
void phx_close_log();


#endif
