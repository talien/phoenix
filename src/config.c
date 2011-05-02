#define _PHX_CONFIG_C
#include "config.h"
#include "misc.h"
#include <glib.h>

static gboolean syslog = FALSE;
static gboolean lstderr = FALSE;
static gint loglevel = -1;


static GOptionEntry entries[] = 
{
  {	"syslog", 'l', 0, G_OPTION_ARG_NONE, &syslog, "Log to syslog", NULL },
  {	"stderr", 'e', 0, G_OPTION_ARG_NONE, &lstderr, "Log to stderr", NULL },
  {	"loglevel", 'v', 0, G_OPTION_ARG_INT, &loglevel, "Log level, level=D", "D" },
  { NULL }
};

void phx_parse_command_line(int* argc, char*** argv)
{
	GError *error = NULL;
	GOptionContext* context;
	context = g_option_context_new("firewall application");
	g_option_context_add_main_entries(context, entries, NULL);
	if (!g_option_context_parse(context, argc, argv, &error))
	{
		exit(1);
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
		global_cfg->debug_level = loglevel;
}

void phx_init_config(int* argc, char*** argv)
{
	global_cfg = g_new0(phx_config,1);
	global_cfg->logging_mode = PHX_CFG_LOG_STDERR;
	phx_parse_command_line(argc, argv);
	phx_init_log();
};
