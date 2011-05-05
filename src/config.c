#define _PHX_CONFIG_C
#include "config.h"
#include "misc.h"
#include <glib.h>
#include <sys/resource.h>
#include <errno.h>

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
void phx_init_config(int* argc, char*** argv)
{
	global_cfg = g_new0(phx_config,1);
	global_cfg->logging_mode = PHX_CFG_LOG_STDERR;
	global_cfg->zone_names = g_new0(GString*, 256);
	phx_parse_command_line(argc, argv);
	phx_init_log();
};
