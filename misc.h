#ifndef _PHX_MISC_H
#define _PHX_MISC_H
#include <stdio.h>


static char hex[16]={'0','1','2','3','4','5','6','7',
                 '8','9','A','B','C','D','E','F' };

void write_ip(unsigned char* buffer);
void swrite_ip(unsigned char* buffer,char* out, int buflen);
int get_val_from_hex(char hex);
void dumphex(unsigned char* buffer, int len);
void dumpascii(unsigned char* buffer,int len);
#endif
