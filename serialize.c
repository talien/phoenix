#include <glib.h>
#include "serialize.h"
#include <string.h>
#include "misc.h"

extern GString* zone_names[256];

int
phx_serialize_data (struct phx_conn_data *data, char *buffer)
{
	return phx_pack_data("Si4ci4ciiiiSS", buffer, data->proc_name, &data->pid, data->srcip, &data->sport, data->destip, &data->dport, &data->direction, &data->srczone, &data->destzone, 
			zone_names[data->srczone], zone_names[data->destzone], NULL);
}

void phx_deserialize_data2(char* buffer, guint32* verdict, guint32* srczone, guint32* destzone)
{
	*(verdict) = *((int*) buffer);
	*(srczone) = *((int*) (buffer+4));
	*(destzone) = *((int*) (buffer+8));

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
			case 'S': str = (GString*) arg;
				      len = str->len;
					  *((guint32*)(buffer+buffer_pointer)) = len;
					  buffer_pointer += sizeof(guint32);
					  memcpy(buffer+buffer_pointer, str->str, len);
					  buffer_pointer += len;
					  break;

			case 'i': *((guint32*)(buffer+buffer_pointer)) = *(int*)arg;
					  buffer_pointer += sizeof(guint32);
					  break;

			case '0'...'9': amount = amount * 10 + (format[format_pointer]-48);
					  newarg = FALSE;
					  break;

			case 'c': memcpy(buffer+buffer_pointer, arg, amount);
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

/*int phx_unpack_data(const char* format, char* buffer, ...)
{
	va_list ap;	
};*/
