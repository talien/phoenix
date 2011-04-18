#include <glib.h>
#include "serialize.h"
#include <string.h>
#include "misc.h"
#include "zones.h"

extern GString* zone_names[256];
extern guchar bin[8];

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

int phx_rec_zone(char* buffer, radix_bit* zones, char* ip, int level)
{
	int size1 = 0, size2 = 0, size3 = 0;
	GString* network;
	if (zones != NULL)
	{
		level = level + 1;
		ip[level / 8] = ip[level / 8] & ~bin[7 - (level % 8)];
		size1 = phx_rec_zone(buffer, zones->zero, ip, level);
		ip[level / 8] = ip[level / 8] | bin[7 - (level % 8)];
		size2 = phx_rec_zone(buffer+size1, zones->one, ip, level);
		ip[level / 8] = ip[level / 8] & ~bin[7 - level % 8];
		level = level - 1;
		if (zones->zoneid != 0)
		{
			log_debug("Zone found at depth %d, zone_id='%d', ip='%d.%d.%d.%d'\n", level + 1, zones->zoneid,(guchar)ip[0], (guchar)ip[1], (guchar)ip[2], (guchar)ip[3]);
			network = g_string_new("");
			g_string_printf(network, "%d.%d.%d.%d/%d", (guchar)ip[0], (guchar)ip[1], (guchar)ip[2], (guchar)ip[3], level + 1);
			size3 = phx_pack_data("SiS",buffer+size1+size2+4,zone_names[zones->zoneid], &zones->zoneid, network, NULL);
			phx_pack_data("i",buffer+size1+size2, &size3, NULL);
			size3 += 4;
			g_string_free(network, TRUE);
		}
	}
	return size1 + size2 + size3;
}

int phx_serialize_zones(char* buffer, radix_bit* zones)
{
	radix_bit* zone = zones;
	int buffer_length;
	char* ip = g_new0(char,4);
	buffer_length = phx_rec_zone(buffer, zones, ip, -1);
	log_debug("Zones serialized, length = '%d'\n", buffer_length);
	g_free(ip);
	return buffer_length;
}

/*int phx_unpack_data(const char* format, char* buffer, ...)
{
	va_list ap;	
};*/
