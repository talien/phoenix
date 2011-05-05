#define _PHX_CONFIG_C
#include "config.h"
#include "misc.h"
#include <glib.h>
#include <sys/resource.h>
#include <errno.h>

#define PHX_STATE_RULE 1
#define PHX_STATE_ZONE 2
#define PHX_STATE_ALIAS 3

static gboolean syslog = FALSE;
static gboolean lstderr = FALSE;
static gint loglevel = -1;
static gboolean core = FALSE;
static gboolean version = FALSE;
static gchar* filename = NULL;

static GOptionEntry entries[] = 
{
  {	"syslog", 'l', 0, G_OPTION_ARG_NONE, &syslog, "Log to syslog", NULL },
  {	"stderr", 'e', 0, G_OPTION_ARG_NONE, &lstderr, "Log to stderr", NULL },
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

int phx_parse_config(const char* filename)
{
	char fbuf[512], var1[128], var2[128];

	struct phx_conn_data *rule = 0;
	int verdict, direction = OUTBOUND;
	int state = 0;
	int zoneid = 1;
	guchar buf[4];
	guint32 mask;	
	FILE* conffile;
	global_cfg->aliases = g_hash_table_new((GHashFunc)g_string_hash, (GEqualFunc)g_string_equal);

	if (filename == NULL)
	{
		conffile = fopen("phx.conf", "r");
	}
	else
	{
		conffile = fopen(filename, "r");
	}

	global_cfg->zones = zone_new();
	if (!conffile)
		return FALSE;

	while (fgets(fbuf, sizeof(fbuf), conffile) != NULL)
	{
		if (get_first_char(fbuf) == '[')
		{
			parse_section(fbuf, var1);
			log_debug("Conf section: section='%s'\n", var1);
			if (rule)
			{
				log_debug("Inserting rule\n");
				phx_apptable_insert(rule->proc_name, rule->pid, direction, verdict, 0, 0);
			}
			if (!strncmp(var1, "rule", 128))
			{
				rule = phx_conn_data_new();
				state = PHX_STATE_RULE;
			}
			if (!strncmp(var1, "zones", 128))
			{
				phx_conn_data_unref(rule);
				rule = NULL;
				state = PHX_STATE_ZONE;
			}	
			if (!strncmp(var1, "alias", 128))
			{
				phx_conn_data_unref(rule);
				rule = NULL;
				state = PHX_STATE_ALIAS;	
			}
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
			parse_key_value(fbuf, var1, var2);
			log_debug("Variable1: %s Variable2:%s state='%d' \n", var1, var2, state);
			if (state == PHX_STATE_RULE)
			{
				if (!strncmp(var1, "program", 128))
				{
					rule->proc_name = g_string_new(var2);
					rule->pid = 0;
				}
				if (!strncmp(var1, "verdict", 128))
				{
					if (!strncmp(var2, "deny", 128))
					{
						verdict = DENIED;
					}
					if (!strncmp(var2, "accept", 128))
					{
						verdict = ACCEPTED;
					}
				}
			}
			else if (state == PHX_STATE_ZONE)
			{
				log_debug("Adding zone: name='%s', network='%s', zoneid='%d' \n", var1, var2, zoneid);
				parse_network(var2, buf, &mask);
				zone_add(global_cfg->zones, buf, mask, zoneid);
				global_cfg->zone_names[zoneid] = g_string_new(var1);
				zoneid += 1;
			}
			else if (state == PHX_STATE_ALIAS)
			{
				log_debug("Adding alias: name='%s', alias='%s' \n",var1, var2);
				GString *name, *alias;
				name = g_string_new(var1);
				alias = g_string_new(var2);
				g_hash_table_insert(global_cfg->aliases, name, alias);
			}
		}
	}
	if (rule)
	{
		log_debug("Inserting rule\n");
		phx_apptable_insert(rule->proc_name, rule->pid, direction, verdict, 0, 0);
		phx_conn_data_unref(rule);
	}
	fclose(conffile);
	return TRUE;
}


void phx_init_config(int* argc, char*** argv)
{
	global_cfg = g_new0(phx_config,1);
	global_cfg->logging_mode = PHX_CFG_LOG_STDERR;
	global_cfg->zone_names = g_new0(GString*, 256);
	phx_parse_command_line(argc, argv);
	phx_init_log();
};
