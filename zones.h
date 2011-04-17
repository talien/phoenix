#ifndef _PHX_ZONES_H
#define _PHX_ZONES_H

#include <glib.h>
//FIXME:byte should b really byte, or char

typedef struct radix_byte
{
	int byte;
	struct radix_byte** children;
	struct radix_bit* bits;
	int zoneid;
} radix_byte;

typedef struct radix_bit
{
	int bit;
	struct radix_bit *zero;
	struct radix_bit *one;
	int zoneid;
} radix_bit;


int zone_lookup(radix_bit* zone_tree, guchar* ip);
int zone_add(radix_bit* zone_tree, guchar* ip, guint32 mask, int id);
radix_byte* radix_byte_new(int value, int needchild);
#endif
