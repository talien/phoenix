#include "types.h"

phx_conn_data* phx_conn_data_new()
{
	phx_conn_data* result = g_new0(phx_conn_data,1);
	result->refcnt = 1;
	return result;
}

void phx_conn_data_ref(phx_conn_data* cdata)
{
	cdata->refcnt = cdata->refcnt + 1;
}

void phx_conn_data_unref(phx_conn_data* cdata)
{
	cdata->refcnt = cdata->refcnt - 1;
	if (cdata->refcnt == 0)
	{
		if (cdata->proc_name)
			g_string_free(cdata->proc_name, TRUE);
		g_free(cdata);
	}
}
