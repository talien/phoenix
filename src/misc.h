#ifndef _PHX_MISC_H
#define _PHX_MISC_H
#include <stdio.h>
#include <glib.h>

#define PHX_LOG_ERROR 1
#define PHX_LOG_WARNING 2
#define PHX_LOG_OPERATIONAL 3
#define PHX_LOG_DEBUG 4

#ifdef _PHX_DAEMON_C
int debug_level = PHX_LOG_DEBUG;
#else
extern int debug_level;
#endif

#define log_debug(...) if (debug_level == PHX_LOG_DEBUG) _log_trace(__PRETTY_FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)

void write_ip(unsigned char* buffer);
void swrite_ip(unsigned char* buffer,char* out, int buflen);
int get_val_from_hex(char hex);
void dumphex(unsigned char* buffer, int len);
void dumpascii(unsigned char* buffer,int len);
GString* get_user(guint32 pid);
GString* phx_write_ip(char ip[4]);
GString* phx_dns_lookup(char ip[4]);
int parse_network(const char* str, guchar* nw, guint32 *mask);
void _log_trace( const char* function, const char* file, int line, gchar* format, ...);
//void log_debug(gchar* format, ...);

#endif
