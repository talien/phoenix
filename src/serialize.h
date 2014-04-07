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

#ifndef _PHX_SERIALIZE_H
#define _PHX_SERIALIZE_H
#include "types.h"
#include "zones.h"

int phx_serialize_conn_data(struct phx_conn_data* data,char* buffer);
//struct phx_conn_data* phx_deserialize_data(char* buffer, int buflen);
int phx_pack_data(const char* format, char* buffer, ...);
int phx_unpack_data(const char* format, char* buffer, ...);
void phx_deserialize_data(char* buffer, guint32* verdict, guint32* srczone, guint32* destzone, guint32* pid);
int phx_serialize_zones(char* buffer, radix_bit* zones);
int phx_deserialize_zones(char* buffer, int len, radix_bit** zones);
#endif
