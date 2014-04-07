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
