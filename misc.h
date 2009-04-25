#ifndef _PHX_MISC_H
#define _PHX_MISC_H
#include <stdio.h>

void write_ip(unsigned char* buffer);
void swrite_ip(unsigned char* buffer,char* out, int buflen);
int get_val_from_hex(char hex);
void dumphex(unsigned char* buffer, int len);
void dumpascii(unsigned char* buffer,int len);
#endif
