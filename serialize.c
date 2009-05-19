#include <glib.h>
#include "serialize.h"
#include <string.h>
#include "misc.h"

int phx_serialize_data(struct phx_conn_data* data,char* buffer)
{
   guint32* tmp;
   guint32 slen = data->proc_name->len;
   int buflen = 0;
   tmp = (guint32*) buffer; //Little Indian, Big Indian, think it over!
   *tmp = slen;
   buflen = buflen + sizeof(guint32);
   strncpy(buffer+buflen,data->proc_name->str,slen);
   buflen = buflen + slen;
   int restsize = sizeof(struct phx_conn_data) - sizeof(GString*);
   memcpy(buffer+buflen,(char*)data+4,restsize);
   buflen = buflen + restsize;
   return buflen;
}

struct phx_conn_data* phx_deserialize_data(char* buffer, int buflen)
{
   struct phx_conn_data* result = g_new0(struct phx_conn_data,1);
   guint32 namelen = *((int*)buffer);
   memcpy(&(result->pid),buffer+4+namelen,buflen-4-namelen);
   result->proc_name = g_string_new_len(buffer+4,namelen);
   return result;
}

