#include "nm-connection.h"

static GHashTable *registered_setting_creators = NULL;

static void
register_default_creators (void)
{
	int i;
	const struct {
		const char *name;
		NMSettingCreateFn fn;
	} default_map[] = {
		{ "info",            nm_setting_info_new_from_hash      },
		{ "802-3-ethernet",  nm_setting_wired_new_from_hash     },
		{ "802-11-wireless", nm_setting_wireless_new_from_hash  },
		{ NULL, NULL}
	};

	for (i = 0; default_map[i].name; i++)
		nm_setting_parser_register (default_map[i].name, default_map[i].fn);
}

void
nm_setting_parser_register (const char *name, NMSettingCreateFn creator)
{
	g_return_if_fail (name != NULL);
	g_return_if_fail (creator != NULL);
	
	if (!registered_setting_creators)
		registered_setting_creators = g_hash_table_new_full (g_str_hash, g_str_equal,
															 (GDestroyNotify) g_free, NULL);

	if (g_hash_table_lookup (registered_setting_creators, name))
		g_warning ("Already have a creator function for '%s', overriding", name);

	g_hash_table_insert (registered_setting_creators, g_strdup (name), creator);
}

void
nm_setting_parser_unregister (const char *name)
{
	if (registered_setting_creators)
		g_hash_table_remove (registered_setting_creators, name);
}

static void
parse_one_setting (gpointer key, gpointer value, gpointer user_data)
{
	NMConnection *connection = (NMConnection *) user_data;
	NMSettingCreateFn fn;
	NMSetting *setting;

	fn = (NMSettingCreateFn) g_hash_table_lookup (registered_setting_creators, key);
	if (fn) {
		setting = fn ((GHashTable *) value);
		if (setting)
			nm_connection_add_setting (connection, setting);
	} else
		g_warning ("Unknown setting '%s'", (char *) key);
}

NMConnection *
nm_connection_new (void)
{
	NMConnection *connection;

	if (!registered_setting_creators)
		register_default_creators ();

	connection = g_slice_new0 (NMConnection);
	connection->settings = g_hash_table_new (g_str_hash, g_str_equal);

	return connection;
}

NMConnection *
nm_connection_new_from_hash (GHashTable *hash)
{
	NMConnection *connection;

	g_return_val_if_fail (hash != NULL, NULL);

	if (!registered_setting_creators)
		register_default_creators ();

	connection = nm_connection_new ();
	g_hash_table_foreach (hash, parse_one_setting, connection);

	if (g_hash_table_size (connection->settings) < 1) {
		g_warning ("No settings found.");
		nm_connection_destroy (connection);
		return NULL;
	}

	if (!nm_settings_verify (connection->settings)) {
		nm_connection_destroy (connection);
		return NULL;
	}

	return connection;
}

void
nm_connection_add_setting (NMConnection *connection, NMSetting *setting)
{
	g_return_if_fail (connection != NULL);
	g_return_if_fail (setting != NULL);

	g_hash_table_insert (connection->settings, setting->name, setting);
}

NMSetting *
nm_connection_get_setting (NMConnection *connection, const char *setting_name)
{
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (setting_name != NULL, NULL);

	return (NMSetting *) g_hash_table_lookup (connection->settings, setting_name);
}

static void
add_one_setting_to_hash (gpointer key, gpointer data, gpointer user_data)
{
	NMSetting *setting = (NMSetting *) data;
	GHashTable *connection_hash = (GHashTable *) user_data;
	GHashTable *setting_hash;

	setting_hash = nm_setting_to_hash (setting);
	if (setting_hash)
		g_hash_table_insert (connection_hash,
							 g_strdup (setting->name),
							 setting_hash);
}

GHashTable *
nm_connection_to_hash (NMConnection *connection)
{
	GHashTable *connection_hash;

	g_return_val_if_fail (connection != NULL, NULL);

	connection_hash = g_hash_table_new_full (g_str_hash, g_str_equal,
											 (GDestroyNotify) g_free,
											 (GDestroyNotify) g_hash_table_destroy);

	g_hash_table_foreach (connection->settings, add_one_setting_to_hash, connection_hash);

	/* Don't send empty hashes */
	if (g_hash_table_size (connection_hash) < 1) {
		g_hash_table_destroy (connection_hash);
		connection_hash = NULL;
	}

	return connection_hash;
}

void
nm_connection_destroy (NMConnection *connection)
{
	g_return_if_fail (connection != NULL);

	g_hash_table_destroy (connection->settings);
	g_slice_free (NMConnection, connection);
}
