#include "zones.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>

#include <glib.h>
#include "misc.h"

guchar bin[8] = {1,2,4,8,16,32,64,128};

radix_byte* radix_byte_new(int value, int needchild)
{
	radix_byte *result = g_new0(radix_byte, 1);
	result->byte = value;
	result->bits = NULL;
	if (needchild)
	{
		result->children = g_new0(radix_byte*, 256);
	}
	return result;
}

int zone_add(radix_bit* zone_tree, guchar* ip, guint32 mask, int id)
{
	radix_bit* bit = zone_tree;
	int bits = mask;
	int bitno = 0;
	while (bitno < bits)
	{
		if (bin[7-(bitno % 8)] & ip[bitno / 8])
		//bit is one
		{
			if (bit->one == NULL)
			{
				bit->one = g_new0(radix_bit,1);
				bit->one->bit = 1;
				bit->one->parent = bit;
			}
			bit = bit->one;
		}
		else
		// bit is zero
		{
			if (bit->zero == NULL)
			{
				bit->zero = g_new0(radix_bit,1);
				bit->zero->bit = 0;
				bit->zero->parent = bit;
			}
			bit = bit->zero;
		}
		bitno = bitno + 1;
	}
	bit->zoneid = id;
	return TRUE;
}

int zone_lookup(radix_bit* zone_tree, guchar* ip)
{
	int level = 0;	
	radix_bit *tree_item = zone_tree;
    int lastzone = 0;
	log_debug("Looking up zone for ip: %u.%u.%u.%u \n", ip[0], ip[1], ip[2], ip[3]);
	while (level < 32 && tree_item != NULL)
	{
		if (tree_item->zoneid != 0)
		{
			lastzone = tree_item->zoneid;
		}

		if (bin[7-(level % 8)] & ip[level / 8])
		{
			tree_item = tree_item->one;
		}
		else
		{
			tree_item = tree_item->zero;
		}
		level++;
	}
	return lastzone;
}
