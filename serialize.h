#ifndef _PHX_SERIALIZE_H
#define _PHX_SERIALIZE_H
#include "types.h"

int phx_serialize_data(struct phx_conn_data* data,char* buffer);
struct phx_conn_data* phx_deserialize_data(char* buffer, int buflen);
int phx_pack_data(const char* format, char* buffer, ...);

#endif
