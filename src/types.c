/*
* Copyright (c) 2008-2014 Viktor Tusa
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU Lesser General Public
* License as published by the Free Software Foundation; either
* version 2.1 of the License, or (at your option) any later version.
*
* This library is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public
* License along with this library; if not, write to the Free Software
* Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
*
*/

#include "types.h"
#include "misc.h"
#include <glib.h>

phx_conn_data* phx_conn_data_new()
{
  phx_conn_data* result = g_new0(phx_conn_data,1);
  result->refcnt = 1;
  return result;
}

void phx_conn_data_ref(phx_conn_data* cdata)
{
  g_assert(cdata->refcnt != 0);
  cdata->refcnt = cdata->refcnt + 1;
}

void phx_conn_data_unref(phx_conn_data* cdata)
{
//	log_debug("Unrefing conndata, proc_name='%s'\n", cdata->proc_name->str);
  if (!cdata )
    return;
  cdata->refcnt = cdata->refcnt - 1;
  if (cdata->refcnt == 0)
    {
      if (cdata->proc_name)
        g_string_free(cdata->proc_name, TRUE);
      if (cdata->cmd_line)
        g_string_free(cdata->cmd_line, TRUE);
      g_free(cdata);
    }
}

phx_app_rule* phx_rule_new()
{
  phx_app_rule* result = g_new0(phx_app_rule, 1);
  result->refcnt = 1;
  return result;
}

void phx_rule_ref(phx_app_rule* rule)
{
  g_assert(rule->refcnt != 0);
  rule->refcnt = rule->refcnt + 1;
}

void phx_rule_unref(phx_app_rule* rule)
{
  if (!rule)
    return;
  rule->refcnt = rule->refcnt - 1;
  if (rule->refcnt == 0)
    {
      if (rule->appname)
        {
          g_string_free(rule->appname, TRUE);
        }
      g_free(rule);
    }
}
