#ifndef _PHX_CONFIG_H
#define _PHX_CONFIG_H
#include "types.h"
#include <stdlib.h>

#define PHX_CFG_LOG_SYSLOG 0
#define PHX_CFG_LOG_FILE 1
#define PHX_CFG_LOG_STDERR 2

typedef struct phx_config
{
	int debug_level;
	int logging_mode;
	int enable_core;
    int log_file_fd;
	gchar* conf_file;
    gchar* log_file_name;
	GString* zone_file;
	GString* rule_file;
	struct radix_bit* zones;
	GString** zone_names;
	GHashTable* aliases;
	gboolean inbound_deny, outbound_deny;
} phx_config;

#ifdef _PHX_CONFIG_C
	phx_config* global_cfg;
#else
	extern phx_config* global_cfg;
#endif

void phx_init_config(int* argc, char*** argv);
int phx_parse_config(const char* filename);
phx_config* phx_config_new();

#endif
