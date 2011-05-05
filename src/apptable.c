#include "apptable.h"
#include "types.h"
#include "zones.h"

GHashTable *apptable;

GStaticRWLock apptable_lock = G_STATIC_RW_LOCK_INIT;

void phx_apptable_lock_read()
{
	g_static_rw_lock_reader_lock(&apptable_lock);
}

void phx_apptable_unlock_read()
{
	g_static_rw_lock_reader_unlock(&apptable_lock);

}

void phx_apptable_lock_write()
{
	g_static_rw_lock_writer_lock(&apptable_lock);

}

void phx_apptable_unlock_write()
{
	g_static_rw_lock_writer_unlock(&apptable_lock);
}

void phx_apptable_init()
{
	apptable = g_hash_table_new(g_str_hash, g_str_equal);
}

guint64 phx_apptable_hash(guint32 direction, guint32 pid, guint32 srczone, guint32 destzone)
{
    //FIXME: assert on srczone/dstzone > 256
	return (( ( pid * (guint64)256 + (guint64)srczone) * (guint64)256) + (guint64)destzone) * (guint64)2 + (guint64)direction;
}

void
phx_apptable_insert(GString* appname, guint32 pid, int direction, int verdict, guint32 srczone, guint32 destzone)
{
	struct phx_app_rule *rule = g_new0(struct phx_app_rule, 1);

	rule->appname = g_string_new(appname->str);
	rule->pid = pid;
	rule->verdict = verdict;
	rule->srczone = srczone;
	rule->destzone = destzone;
	rule->direction = direction;
	guint64 *hash = g_new0(guint64, 1);

	*hash = phx_apptable_hash(rule->direction, rule->pid, rule->srczone, rule->destzone);
	phx_apptable_lock_write();
	GHashTable *chain =
	    g_hash_table_lookup(apptable, appname->str);

	if (!chain)
	{
		chain = g_hash_table_new(g_int64_hash, g_int64_equal);
		g_hash_table_insert(chain, hash, rule);
		g_hash_table_insert(apptable, rule->appname->str, chain);
	} else
	{
		g_hash_table_insert(chain, hash, rule);
	}
	phx_apptable_unlock_write();
};

void phx_apptable_delete(GString* appname, guint32 pid, int direction, guint32 srczone, guint32 destzone)
{
	phx_apptable_lock_write();
	GHashTable *chain = g_hash_table_lookup(apptable, appname->str);
	if (!chain)
	{
		phx_apptable_unlock_write();
		return;
	}
	guint64 hash = phx_apptable_hash(direction, pid, srczone, destzone);
	struct phx_app_rule* rule = g_hash_table_lookup(chain, &hash);
	if (!rule)
	{
		phx_apptable_unlock_write();
		return;
	}
	g_hash_table_remove(chain, &hash);
	phx_apptable_unlock_write();
};

gboolean phx_apptable_clear_inv_rule(gpointer key, gpointer value, gpointer user_data)
{
	struct phx_app_rule* rule = (struct phx_app_rule*) value;
	if (rule->pid != 0)
	{
		return !check_pid_exists(rule->pid);
	}
	else
	{
		return FALSE;
	}
}

void phx_apptable_clear_inv_app(gpointer key, gpointer value, gpointer user_data)
{
	GHashTable* chain = (GHashTable*) value;
	g_hash_table_foreach_remove(chain, phx_apptable_clear_inv_rule, NULL);
}

void phx_apptable_clear_invalid()
{
	phx_apptable_lock_write();
	g_hash_table_foreach(apptable, phx_apptable_clear_inv_app, NULL);
	phx_apptable_unlock_write();
}

void phx_rule_count_size(gpointer key G_GNUC_UNUSED, gpointer value, gpointer user_data)
{
	//hash: int, pid:int, verdict:int, string_size:int, strng: char*, int srczone, int destzone
	struct phx_app_rule* rule = (struct phx_app_rule*) value;
	int* size = (int*) user_data;
	(*size) += 24 + rule->appname->len;
}

int phx_chain_count_size(GHashTable* chain)
{
	//number of rules in chain: int
	int result = 4;
	g_hash_table_foreach(chain, phx_rule_count_size, &result);
	log_debug("Chain size counted, size='%d'\n", result);
	return result;
}

void phx_apptable_count_func(gpointer key G_GNUC_UNUSED, gpointer value, gpointer user_data)
{
	int *size = (int*) user_data;
	(*size) += phx_chain_count_size((GHashTable*)value);
}

int phx_apptable_count_size(GHashTable* apptable)
{
	// number of chains: int
	int size = 4;
	g_hash_table_foreach(apptable, phx_apptable_count_func, &size);
	return size;
}

int phx_rule_serialize(struct phx_app_rule* rule, char* buffer)
{
	int size = phx_pack_data("iiiiiS", buffer, &(rule->pid), &(rule->verdict), &(rule->srczone), &(rule->destzone), &(rule->direction), rule->appname, NULL);
	log_debug("Rule serialized, size='%d, program='%s'\n",size,rule->appname->str);
	return size;
}

int phx_chain_serialize(GHashTable* chain, char* buffer)
{
	int dir_num = g_hash_table_size(chain);
	// hash numbers: int
	log_debug("Serializing chain, entry number='%d'\n", dir_num);
	struct phx_app_rule* rule;
	int position = 4;
	GList* values = g_hash_table_get_values(chain);
	memcpy(buffer,&dir_num, sizeof(dir_num));
    while (values)
    {
        // rule size:variable
		// no need to store hash.
   		rule = (struct phx_app_rule*) values->data;		
		position += phx_rule_serialize(rule, buffer+position);
		values = values->next;
    }
	log_debug("Chain serialized, size='%d'\n", position);
	g_list_free(values);
	return position;
}

char* phx_apptable_serialize(int* length)
{
	phx_apptable_lock_read();
	int chains_num = g_hash_table_size(apptable);
    int table_size = phx_apptable_count_size(apptable);
	char* result = g_new(char, table_size);
	int position = 4;
	GList* values = g_hash_table_get_values(apptable);
	//chain num: int, chains: variable
	memcpy(result, &chains_num, sizeof(chains_num));
	log_debug("Serializing apptable, num_chains='%d', expected_length='%d'\n",chains_num, table_size);
	while (values)
	{
		position += phx_chain_serialize((GHashTable*) values->data, result+position);
		values = values->next;
	}
	phx_apptable_unlock_read();
	log_debug("Apptable serialized size, chain_num='%d', expected='%d', real='%d'\n",chains_num, table_size, position);
	g_assert(table_size == position);
	if (length)
		(*length) = table_size;
	g_list_free(values);
	return result;
}

phx_app_rule* phx_rule_deserialize(char* buffer, int* len)
{
	int rlen;
	phx_app_rule *rule = g_new0(phx_app_rule,1);
	rule->appname = g_string_new("");
	rlen = phx_unpack_data("Siiiii",buffer,rule->appname, &rule->pid, &rule->direction, &rule->verdict, &rule->srczone, &rule->destzone, NULL);
	log_debug("Rule deserialized, len='%d'\n", rlen);
	*len = rlen;
	return rule;
}

struct phx_app_rule *phx_apptable_hash_lookup(GHashTable* chain, int direction, int pid, guint32 srczone, guint32 destzone)
{
	struct phx_app_rule* rule;
	guint64 hash = phx_apptable_hash(direction, pid, srczone, destzone);
	rule = g_hash_table_lookup(chain, &hash);
	return rule;
}

struct phx_app_rule *phx_apptable_lookup(GString * appname, guint pid,
					 guint direction, guint32 srczone, guint32 destzone)
{
	log_debug
	    ("Looking for app in hashtable, app='%s', pid='%d', direction='%d', srczone='%d', destzone='%d' \n",
	     appname->str, pid, direction, srczone, destzone);
    phx_apptable_lock_read();
	GHashTable *chain = g_hash_table_lookup(apptable, appname->str);

	if (!chain)
	{
		log_debug("Chain not found for app: app='%s'\n", appname->str);
		phx_apptable_unlock_read();
		return NULL;
	}
	log_debug("Chain found, app='%s'\n", appname->str);

	struct phx_app_rule *rule;
	if ( !(rule = phx_apptable_hash_lookup(chain, direction, pid, srczone, destzone) ) )
	if ( !(rule = phx_apptable_hash_lookup(chain, direction, pid, 0, destzone) ) )
	if ( !(rule = phx_apptable_hash_lookup(chain, direction, pid, srczone, 0) ) )
	if ( !(rule = phx_apptable_hash_lookup(chain, direction, pid, 0, 0) ) )
	if ( !(rule = phx_apptable_hash_lookup(chain, direction, 0, srczone, destzone) ) )
	if ( !(rule = phx_apptable_hash_lookup(chain, direction, 0, 0, destzone) ) )
	if ( !(rule = phx_apptable_hash_lookup(chain, direction, 0, srczone, 0) ) )
	if ( !(rule = phx_apptable_hash_lookup(chain, direction, 0, 0, 0) ) )
	rule = NULL;

	phx_apptable_unlock_read();
	return rule;
}

gboolean phx_apptable_merge_rule_foreach(gpointer key, gpointer value, gpointer user_data)
{
	phx_app_rule* chain_rule = (phx_app_rule*) value;
	phx_app_rule* rule = (phx_app_rule*) user_data;
	gboolean covered = TRUE;
	if ((chain_rule->verdict == ACCEPTED) || (chain_rule->verdict == DENIED))
	{
		covered &= (chain_rule->verdict == rule->verdict);
	}
	covered &= ( (chain_rule->pid == rule->pid) || (rule->pid == 0) );
	covered &= ( (chain_rule->destzone == rule->destzone) || (rule->destzone == 0) );
	covered &= ( (chain_rule->srczone == rule->srczone) || (rule->srczone == 0) );
	log_debug("Rule coverage, covered='%d', pid='%d', verdict='%d', srczone='%d', destzone='%d' \n", covered, chain_rule->pid, chain_rule->verdict, chain_rule->srczone, chain_rule->destzone);
    return covered;
};

void phx_apptable_merge_rule(GString* appname, guint32 direction, guint32 pid, guint32 srczone, guint32 destzone, guint32 verdict)
{
	log_debug("Merging rule, appname='%s', pid='%d', verdict='%d' srczone='%d', destzone='%d' \n", appname->str, pid, verdict, srczone, destzone);
	phx_apptable_lock_write();
	GHashTable* chain = (GHashTable*) g_hash_table_lookup(apptable, appname->str);
	if (chain == NULL)
	{
		phx_apptable_unlock_write();
		phx_apptable_insert(appname, pid, direction, verdict, srczone, destzone);
		return;
	}
	phx_app_rule* rule = g_new0(phx_app_rule,1);
	rule->appname = g_string_new(appname->str);
	rule->pid = pid;
	rule->direction = direction;
	rule->srczone = srczone;
	rule->destzone = destzone;
	g_hash_table_foreach_remove(chain, phx_apptable_merge_rule_foreach, rule);
 	guint64 *hash = g_new0(guint64, 1);
	*hash = phx_apptable_hash(rule->direction, rule->pid, rule->srczone, rule->destzone);
	g_hash_table_insert(chain, hash, rule);	
	phx_apptable_unlock_write();
}

void phx_update_rules(char* buffer, int length)
{
	int position = 0, mode, chain_num;
	int len;
	phx_app_rule* rule;
	position += phx_unpack_data("i",buffer, &chain_num, NULL);
	log_debug("Updating rules, rule_num='%d'\n", chain_num);
	while (position < length)
	{
		position += phx_unpack_data("i", buffer+position, &mode, NULL);
		rule = phx_rule_deserialize(buffer + position, &len);
		log_debug("Change request got, mode='%d', position='%d', len='%d' \n",mode,position,len);
		position += len;
		switch (mode) 
		{
			case 0: // ADD
					phx_apptable_merge_rule(rule->appname, rule->direction, rule->pid, rule->srczone, rule->destzone, rule->verdict);
					break;
			case 1: // DELETE
					phx_apptable_delete(rule->appname, rule->pid, rule->direction, rule->srczone, rule->destzone);
					break;
		}
		g_string_free(rule->appname, TRUE);
		g_free(rule);
	}
}

