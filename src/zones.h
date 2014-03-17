#ifndef _PHX_ZONES_H
#define _PHX_ZONES_H

#include <glib.h>
//FIXME:byte should b really byte, or char

typedef struct radix_bit
{
  int bit;
  struct radix_bit *zero;
  struct radix_bit *one;
  struct radix_bit *parent;
  int zoneid;
} radix_bit;


int zone_lookup(radix_bit* zone_tree, guchar* ip);
int zone_add(radix_bit* zone_tree, guchar* ip, guint32 mask, int id);
void zone_free(radix_bit* zone_tree);
radix_bit* zone_new();
#endif
