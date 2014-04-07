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

#include <glib.h>
#include "serialize.h"
#include <string.h>
#include "misc.h"
#include "zones.h"
#include "data.h"

extern guchar bin[8];

int
phx_serialize_conn_data (struct phx_conn_data *data, char *buffer)
{
  return phx_pack_data("Si4ci4ciiiiSSS", buffer, data->proc_name, &data->pid, data->srcip, &data->sport, data->destip, &data->dport, &data->direction, &data->srczone, &data->destzone,
                       global_cfg->zone_names[data->srczone], global_cfg->zone_names[data->destzone], data->cmd_line, NULL);
}

void phx_deserialize_data(char* buffer, guint32* verdict, guint32* srczone, guint32* destzone, guint32* pid)
{
  phx_unpack_data("iiii",buffer,verdict, srczone, destzone, pid, NULL);
}

int phx_pack_data(const char* format, char* buffer, ...)
{
  va_list ap;
  guint32 format_pointer = 0, buffer_pointer = 0, len, amount;
  GString* str;
  gboolean newarg;
  va_start(ap, buffer);
  void* arg = va_arg(ap, void*);
  amount = 0;
  while (arg != NULL)
    {
      newarg = TRUE;
      switch(format[format_pointer])
        {
        case 'S':
          str = (GString*) arg;
          len = str->len;
          *((guint32*)(buffer+buffer_pointer)) = len;
          buffer_pointer += sizeof(guint32);
          memcpy(buffer+buffer_pointer, str->str, len);
          buffer_pointer += len;
          break;

        case 'i':
          *((guint32*)(buffer+buffer_pointer)) = *(int*)arg;
          buffer_pointer += sizeof(guint32);
          break;

        case '0'...'9':
          amount = amount * 10 + (format[format_pointer]-48);
          newarg = FALSE;
          break;

        case 'c':
          memcpy(buffer+buffer_pointer, arg, amount);
          buffer_pointer += amount;
          amount = 0;
          break;

        }
      if (newarg)
        arg = va_arg(ap, void*);
      format_pointer++;
    }
  va_end(ap);
  return buffer_pointer;
}

int phx_unpack_data(const char* format, char* buffer, ...)
{
  va_list ap;
  guint32 format_pointer = 0, buffer_pointer = 0, len, amount;
  GString* str;
  gboolean newarg;
  va_start(ap, buffer);
  void* arg = va_arg(ap, void*);
  amount = 0;
  while (arg != NULL)
    {
      newarg = TRUE;
      switch(format[format_pointer])
        {
        case 'S':
          str = (GString*) arg;
          len = *((guint32*)(buffer+buffer_pointer));
          buffer_pointer += sizeof(guint32);
          g_string_assign(str, "");
          g_string_append_len(str, buffer+buffer_pointer, len);
          buffer_pointer += len;
          break;

        case 'i':
          *(int*)arg = *((guint32*)(buffer+buffer_pointer));
          buffer_pointer += sizeof(guint32);
          break;

        case '0'...'9':
          amount = amount * 10 + (format[format_pointer]-48);
          newarg = FALSE;
          break;

        case 'c':
          memcpy(arg, buffer+buffer_pointer, amount);
          buffer_pointer += amount;
          amount = 0;
          break;

        }
      if (newarg)
        arg = va_arg(ap, void*);
      format_pointer++;
    }
  va_end(ap);
  return buffer_pointer;

};

int serialize_zone_recursive(char* buffer, radix_bit* zones, char* ip, int level)
{
  int size1 = 0, size2 = 0, size3 = 0;
  GString* network;
  if (zones != NULL)
    {
      level = level + 1;
      ip[level / 8] = ip[level / 8] & ~bin[7 - (level % 8)];
      size1 = serialize_zone_recursive(buffer, zones->zero, ip, level);
      ip[level / 8] = ip[level / 8] | bin[7 - (level % 8)];
      size2 = serialize_zone_recursive(buffer+size1, zones->one, ip, level);
      ip[level / 8] = ip[level / 8] & ~bin[7 - level % 8];
      level = level - 1;
      if (zones->zoneid != 0)
        {
          log_debug("Zone found at depth %d, zone_id='%d', ip='%d.%d.%d.%d'\n", level + 1, zones->zoneid,(guchar)ip[0], (guchar)ip[1], (guchar)ip[2], (guchar)ip[3]);
          network = g_string_new("");
          g_string_printf(network, "%d.%d.%d.%d/%d", (guchar)ip[0], (guchar)ip[1], (guchar)ip[2], (guchar)ip[3], level + 1);
          size3 = phx_pack_data("SiS",buffer+size1+size2+4,global_cfg->zone_names[zones->zoneid], &zones->zoneid, network, NULL);
          phx_pack_data("i",buffer+size1+size2, &size3, NULL);
          size3 += 4;
          g_string_free(network, TRUE);
        }
    }
  return size1 + size2 + size3;
}

int phx_serialize_zones(char* buffer, radix_bit* zones)
{
  int buffer_length;
  char* ip = g_new0(char,4);
  buffer_length = serialize_zone_recursive(buffer, zones, ip, -1);
  log_debug("Zones serialized, length = '%d'\n", buffer_length);
  g_free(ip);
  return buffer_length;
}

int phx_deserialize_zones(char* buffer, int len, radix_bit** zones)
{
  radix_bit* oldzone;
  radix_bit* zone = g_new0(radix_bit,1);
  int buf_pos = 0;
  guchar ip[4];
  guint32 mask;
  GString** names;
  int i;
  names = g_new0(GString*,256);
  while ( buf_pos < len)
    {
      GString* zone_name = g_string_new("");
      GString* network = g_string_new("");
      int id;
      buf_pos += phx_unpack_data("SiS", buffer+buf_pos, zone_name, &id, network, NULL);
      log_debug("Zone deserialized, name='%s', id='%d', network='%s'\n", zone_name->str, id, network->str);
      parse_network(network->str, ip, &mask);
      zone_add(zone, ip, mask, id);
      g_string_free(network, TRUE);
      names[id] = zone_name;
    }
  oldzone = *zones;
  g_mutex_lock(zone_mutex);
  *zones = zone;
  for (i = 0; i < 256; i++)
    {
      if (global_cfg->zone_names[i] != NULL)
        {
          g_string_free(global_cfg->zone_names[i], TRUE);
        }
      global_cfg->zone_names[i] = names[i];
    }
  g_mutex_unlock(zone_mutex);
  zone_free(oldzone);
  return buf_pos;
}
