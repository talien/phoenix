#ifndef _PHX_SERIALIZE_H
#define _PHX_SERIALIZE_H
#include "types.h"
#include "zones.h"

int phx_serialize_data(struct phx_conn_data* data,char* buffer);
//struct phx_conn_data* phx_deserialize_data(char* buffer, int buflen);
int phx_pack_data(const char* format, char* buffer, ...);
int phx_unpack_data(const char* format, char* buffer, ...);
void phx_deserialize_data(char* buffer, guint32* verdict, guint32* srczone, guint32* destzone);
int phx_serialize_zones(char* buffer, radix_bit* zones);
#endif
