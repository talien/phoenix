#define _PHX_CONFIG_C
#include "config.h"
#include "misc.h"
#include "zones.h"
#include <glib.h>
#include <sys/resource.h>
#include <errno.h>

#define PHX_STATE_RULE 1
#define PHX_STATE_ZONE 2
#define PHX_STATE_ALIAS 3
#define PHX_STATE_SETTINGS 4

static gboolean syslog = FALSE;
static gboolean lstderr = FALSE;
static gint loglevel = -1;
static gboolean core = FALSE;
static gboolean version = FALSE;
static gchar* filename = NULL;
static gchar* logfilename = NULL;

static GOptionEntry entries[] = 
{
  {	"syslog", 'l', 0, G_OPTION_ARG_NONE, &syslog, "Log to syslog", NULL },
  {	"stderr", 'e', 0, G_OPTION_ARG_NONE, &lstderr, "Log to stderr", NULL },
  { "log-file", 'F', 0, G_OPTION_ARG_FILENAME, &logfilename, "Log to file", "filename"},
  {	"loglevel", 'v', 0, G_OPTION_ARG_INT, &loglevel, "Log level, level=D", "D" },
  { "version", 'V', 0, G_OPTION_ARG_NONE, &version, "Printing version and exiting", NULL },
  { "enable-core", 0, 0, G_OPTION_ARG_NONE, &core, "Enabling core dumps", NULL },
  { "conffile",'f', 0, G_OPTION_ARG_FILENAME, &filename,  "Configuration file name", "filename"},
  { NULL }
};

void phx_parse_command_line(int* argc, char*** argv)
{
	GError *error = NULL;
	GOptionContext* context;
	struct rlimit limit;
	context = g_option_context_new("firewall application");
	g_option_context_add_main_entries(context, entries, NULL);
	if (!g_option_context_parse(context, argc, argv, &error))
	{
		printf("Error parsing command line!\n");
		exit(1);
	}
	if (version)
	{
		printf("Phoenix firewall daemon, version unreleased\nCopyright by Viktor Tusa\n");
		exit(1);
	}
	if (core)
	{
		limit.rlim_cur = limit.rlim_max = RLIM_INFINITY;
        if (setrlimit(RLIMIT_CORE, &limit) < 0)
  	       printf("Error setting core limit to infinity; error='%s'", g_strerror(errno));

	}
	if (syslog)
	{
		global_cfg->logging_mode = PHX_CFG_LOG_SYSLOG;
	}
	else if (lstderr)
	{
		global_cfg->logging_mode = PHX_CFG_LOG_STDERR;
	}
	if (loglevel > -1)
	{
		global_cfg->debug_level = loglevel;
	}
	if (filename)
	{
		global_cfg->conf_file = filename;
	}
    if (logfilename)
    {
    	global_cfg->logging_mode = PHX_CFG_LOG_FILE;
        global_cfg->log_file_name = logfilename;
    }
}

char get_first_char(const char* line)
{
    int i = 0;	
	for (i = 0; isspace(line[i]) && line[i] != '\0'; i++)
	{
		
	}
	return line[i];
}

int parse_key_value(const char* line, char* key, char* value)
{
	//FIXME: watch for buffer overflows, limit key/value/line len.
	int invar1 = 0, invar2 = 0, wasvar1 = 0;
	int j = 0, i;
	value[0] = '\0';
	for (i = 0; (line[i] != '\0') && (i < 512) && (line[i] != '#'); i++)
	{
		if (!isspace(line[i]))
		{
			if ((!invar1) && (!invar2) && (!wasvar1)
				&& (line[i] != '['))
			{
				invar1 = 1;
				j = 0;
			}
			if ((!invar1) && (!invar2) && (wasvar1))
			{
				invar2 = 1;
				j = 0;
			}
			if ((line[i] == '='))
			{
				invar1 = 0;
				wasvar1 = 1;
				key[j] = '\0';
			}
			if (invar1)
			{
				key[j] = line[i];
				j++;
			}
			if (invar2)
			{
				value[j] = line[i];
				j++;
			}
		}
	}		
	if (invar2)
	{
		value[j] = '\0';
	}
	
	if (!invar2 && !wasvar1)
	{
		return FALSE;
	}
	else
	{
		return TRUE;
	}

}

int parse_section(const char* line, char* section)
{
	int invar1 = 0, wasvar1 = 0;
	int j = 0, i;
	section[0] = '\0';
	for (i = 0; line[i] != '\0'; i++)
	{
		if (!isspace(line[i]))
		{
			if ((line[i] == '['))
			{
				invar1 = 1;
				j = 0;
			}
			if ((line[i] == ']'))
			{
				invar1 = 0;
				wasvar1 = 1;
				section[j] = '\0';
			}
			if (invar1 && line[i] != '[')
			{
				section[j] = line[i];
				j++;
			}
		}
	}
	if (!wasvar1)
		return FALSE;
	return TRUE;

}

struct config_state {
  int state, waszone, wasrule;
  phx_conn_data *rule;
  gboolean finalized;
} cfg_state;

int finalize_section()
{
	int oldstate = cfg_state.state;
	if (cfg_state.finalized) return TRUE;
	cfg_state.finalized = TRUE;
	if (cfg_state.rule)
	{
		log_debug("Inserting rule\n");
		phx_apptable_insert(cfg_state.rule->proc_name, cfg_state.rule->pid, cfg_state.rule->direction, cfg_state.rule->state, 0, 0);
		phx_conn_data_unref(cfg_state.rule);
		cfg_state.rule = NULL;
	}
	if (oldstate == PHX_STATE_SETTINGS && global_cfg->zone_file != NULL)
	{
		log_debug("Parsing zone file, file='%s'\n",global_cfg->zone_file->str);
		if (!phx_parse_config(global_cfg->zone_file->str))
			return FALSE;
	}
	if (oldstate == PHX_STATE_SETTINGS && global_cfg->rule_file != NULL)
	{
		log_debug("Parsing rule file, file='%s'\n",global_cfg->rule_file->str);
		if (!phx_parse_config(global_cfg->rule_file->str))
			return FALSE;
	}
	return TRUE;
}

int process_section(char* section_name)
{
	if (!finalize_section())
		return FALSE;
	cfg_state.finalized = FALSE;
	if (!strncmp(section_name, "rule", 128))
	{
		cfg_state.state = PHX_STATE_RULE;
		cfg_state.rule = phx_conn_data_new();
		cfg_state.wasrule = TRUE;
	}
	else if (!strncmp(section_name, "zones", 128))
	{
		if (cfg_state.wasrule)
		{
			log_error("Zone declaration should preceed rule declaration!\n");
			return FALSE;
		}
		cfg_state.state = PHX_STATE_ZONE;
		cfg_state.waszone = TRUE;
	}	
	else if (!strncmp(section_name, "alias", 128))
	{
		cfg_state.state = PHX_STATE_ALIAS;	
	}
	else if (!strncmp(section_name, "settings", 128))
	{
		if (cfg_state.wasrule || cfg_state.waszone)
		{
			log_error("Global settings should preceed zone and rule declaration!\n");
		}
		cfg_state.state = PHX_STATE_SETTINGS;
	}
	else 
	{
		log_error("Unknown section in config file!\n");
		return FALSE;
	}
	return TRUE;
}

int phx_parse_config(const char* filename)
{
	char fbuf[512], var1[128], var2[128];

	int zoneid = 1;
	guchar buf[4];
	guint32 mask;	
	FILE* conffile;

	if (filename == NULL)
	{
		conffile = fopen("phx.conf", "r");
	}
	else
	{
		conffile = fopen(filename, "r");
	}

	if (!conffile)
		return FALSE;

	while (fgets(fbuf, sizeof(fbuf), conffile) != NULL)
	{
		if (get_first_char(fbuf) == '[')
		{
			parse_section(fbuf, var1);
			log_debug("Parsing config section: section='%s'\n", var1);
			if (!process_section(var1))
				return FALSE;
		}
		else if (get_first_char(fbuf) == '#')
		{
			log_debug("Comment found\n");
			continue;
		}
		else if (get_first_char(fbuf) == '\0')
		{
			continue;
		}
		else 
		{
			if (!parse_key_value(fbuf, var1, var2))
			{
				log_error("Wrong key-value pair in config!\n");
				return FALSE;
			}
			log_debug("Parsing config key-value pair, key='%s' value='%s' state='%d' \n", var1, var2, cfg_state.state);
			if (cfg_state.state == PHX_STATE_SETTINGS)
			{
				if (!strncmp(var1, "zone_file", 128))
				{
					global_cfg->zone_file = g_string_new(var2);
				}	
				else if (!strncmp(var1, "rule_file", 128))
				{
					global_cfg->rule_file = g_string_new(var2);
				}
				else if (!strncmp(var1, "inbound_deny", 128)) 
				{
					if (!strncmp(var2, "drop", 128))
					{
						global_cfg->inbound_deny = FALSE;
					}
					else if (!strncmp(var2, "reject", 128))
					{
						global_cfg->inbound_deny = TRUE;
					}
					else
					{
						log_error("Wrong deny value in inbound_deny\n");
						return FALSE;
					}
				}
				else if (!strncmp(var1, "outbound_deny", 128))
				{
					if (!strncmp(var2, "drop", 128))
					{
						global_cfg->outbound_deny = FALSE;
					}
					else if (!strncmp(var2, "reject", 128))
					{
						global_cfg->outbound_deny = TRUE;
					}
					else
					{
						log_error("Wrong deny value in outbound_deny\n");
						return FALSE;
					}

				}
				else
				{
					log_error("Unknown key in settings section, key='%s'\n", var1);
					return FALSE;
				}
			
			}
			if (cfg_state.state == PHX_STATE_RULE)
			{
				if (!strncmp(var1, "program", 128))
				{
					cfg_state.rule->proc_name = g_string_new(var2);
					cfg_state.rule->pid = 0;
				}
				else if (!strncmp(var1, "verdict", 128))
				{
					if (!strncmp(var2, "deny", 128))
					{
						cfg_state.rule->state = DENIED;
					}
					if (!strncmp(var2, "accept", 128))
					{
						cfg_state.rule->state = ACCEPTED;
					}
				}
				else if (!strncmp(var1, "pid", 128))
				{
					cfg_state.rule->pid = atoi(var1);
				}
				else if (!strncmp(var1, "direction", 128))
				{
					if (!strncmp(var2, "out", 128))
					{		
						cfg_state.rule->direction = OUTBOUND;
					}
					else if (!strncmp(var2, "in", 128))
					{
						cfg_state.rule->direction = INBOUND;

					}
					else
					{
						log_error("Wrong direction in rules section, direction='%s'\n", var2);
					}
				}
				else 
				{
					log_error("Unknown key-value pair in rule section, key='%s'\n", var1);
					return FALSE;
				}
			}
			else if (cfg_state.state == PHX_STATE_ZONE)
			{
				log_debug("Adding zone: name='%s', network='%s', zoneid='%d' \n", var1, var2, zoneid);
				if (!parse_network(var2, buf, &mask))
				{
					log_error("Invalid network in zone file!\n");
					return FALSE;
				}
				zone_add(global_cfg->zones, buf, mask, zoneid);
				global_cfg->zone_names[zoneid] = g_string_new(var1);
				zoneid += 1;
			}
			else if (cfg_state.state == PHX_STATE_ALIAS)
			{
				log_debug("Adding alias: name='%s', alias='%s' \n",var1, var2);
				GString *name, *alias;
				name = g_string_new(var1);
				alias = g_string_new(var2);
				g_hash_table_insert(global_cfg->aliases, name, alias);
			}
		}
	}
	finalize_section();
	fclose(conffile);
	return TRUE;
}

phx_config* phx_config_new()
{
    phx_config* cfg; 
    cfg = g_new0(phx_config,1);
	cfg->logging_mode = PHX_CFG_LOG_STDERR;
	cfg->zone_names = g_new0(GString*, 256);
	cfg->inbound_deny = FALSE;
	cfg->outbound_deny = TRUE;
	cfg->aliases = g_hash_table_new((GHashFunc)g_string_hash, (GEqualFunc)g_string_equal);
	cfg->zones = zone_new();
	return cfg;
}

void phx_init_config(int* argc, char*** argv)
{
    global_cfg = phx_config_new();
	phx_parse_command_line(argc, argv);
	phx_init_log();
	save_iptables();
	setup_iptables();
};
