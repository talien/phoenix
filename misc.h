#ifndef _PHX_MISC_H
#define _PHX_MISC_H
#include <stdio.h>
#include <glib.h>

#define log_debug(...) _log_trace(__PRETTY_FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)

void write_ip(unsigned char* buffer);
void swrite_ip(unsigned char* buffer,char* out, int buflen);
int get_val_from_hex(char hex);
void dumphex(unsigned char* buffer, int len);
void dumpascii(unsigned char* buffer,int len);
GString* get_user(guint32 pid);
GString* phx_write_ip(char ip[4]);
GString* phx_dns_lookup(char ip[4]);
//void log_debug(gchar* format, ...);

#endif
