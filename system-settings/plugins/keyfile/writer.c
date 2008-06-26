/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <dbus/dbus-glib.h>
#include <nm-setting.h>
#include <nm-setting-connection.h>
#include <nm-setting-ip4-config.h>
#include <nm-utils.h>
#include <string.h>
#include <arpa/inet.h>

#include "nm-dbus-glib-types.h"
#include "writer.h"

static gboolean
write_array_of_uint (GKeyFile *file,
                     NMSetting *setting,
                     const char *key,
                     const GValue *value)
{
	GArray *array;
	int i;

	array = (GArray *) g_value_get_boxed (value);
	if (!array || !array->len)
		return TRUE;

	if (NM_IS_SETTING_IP4_CONFIG (setting) && !strcmp (key, NM_SETTING_IP4_CONFIG_DNS)) {
		char **list;

		list = g_new0 (char *, array->len + 1);

		for (i = 0; i < array->len; i++) {
			char buf[INET_ADDRSTRLEN + 1];
			struct in_addr addr;

			addr.s_addr = g_array_index (array, guint32, i);
			if (!inet_ntop (AF_INET, &addr, buf, sizeof (buf))) {
				nm_warning ("%s: error converting IP4 address 0x%X",
				            __func__, ntohl (addr.s_addr));
				list[i] = NULL;
			} else {
				list[i] = g_strdup (buf);
			}
		}

		g_key_file_set_string_list (file, setting->name, key, (const char **) list, array->len);
		g_strfreev (list);
	} else {
		int *tmp_array;

		tmp_array = g_new (gint, array->len);
		for (i = 0; i < array->len; i++)
			tmp_array[i] = g_array_index (array, int, i);

		g_key_file_set_integer_list (file, setting->name, key, tmp_array, array->len);
		g_free (tmp_array);
	}

	return TRUE;
}

static gboolean
write_array_of_array_of_uint (GKeyFile *file,
                              NMSetting *setting,
                              const char *key,
                              const GValue *value)
{
	GPtrArray *array;
	int i, j;

	/* Only handle IPv4 addresses for now */
	if (   !NM_IS_SETTING_IP4_CONFIG (setting)
	    || strcmp (key, NM_SETTING_IP4_CONFIG_ADDRESSES))
	    return FALSE;

	array = (GPtrArray *) g_value_get_boxed (value);
	if (!array || !array->len)
		return TRUE;

	for (i = 0, j = 0; i < array->len; i++, j++) {
		GArray *tuple = g_ptr_array_index (array, i);
		char buf[INET_ADDRSTRLEN + 1];
		struct in_addr addr;
		char *list[3] = { NULL, NULL, NULL };
		char *key_name;

		addr.s_addr = g_array_index (tuple, guint32, 0);
		if (!inet_ntop (AF_INET, &addr, buf, sizeof (buf))) {
			nm_warning ("%s: error converting IP4 address 0x%X",
			            __func__, ntohl (addr.s_addr));
			list[0] = NULL;
		} else {
			list[0] = g_strdup (buf);
		}

		addr.s_addr = g_array_index (tuple, guint32, 1);
		if (!inet_ntop (AF_INET, &addr, buf, sizeof (buf))) {
			nm_warning ("%s: error converting IP4 address 0x%X",
			            __func__, ntohl (addr.s_addr));
			list[1] = NULL;
		} else {
			list[1] = g_strdup (buf);
		}

		addr.s_addr = g_array_index (tuple, guint32, 2);
		if (addr.s_addr) {
			if (!inet_ntop (AF_INET, &addr, buf, sizeof (buf))) {
				nm_warning ("%s: error converting IP4 address 0x%X",
					        __func__, ntohl (addr.s_addr));
				list[2] = NULL;
			} else {
				list[2] = g_strdup (buf);
			}
		}

		key_name = g_strdup_printf ("address%d", j + 1);
		g_key_file_set_string_list (file, setting->name, key_name, (const char **) list, list[2] ? 3 : 2);
		g_free (key_name);

		g_free (list[0]);
		g_free (list[1]);
		g_free (list[2]);
	}

	return TRUE;
}

static void
write_setting_value (NMSetting *setting,
				 const char *key,
				 const GValue *value,
				 gboolean secret,
				 gpointer user_data)
{
	GKeyFile *file = (GKeyFile *) user_data;
	GType type;

	type = G_VALUE_TYPE (value);

	/* Setting name gets picked up from the keyfile's section name instead */
	if (!strcmp (key, NM_SETTING_NAME))
		return;

	if (type == G_TYPE_STRING) {
		const char *str;

		str = g_value_get_string (value);
		if (str)
			g_key_file_set_string (file, setting->name, key, str);
	} else if (type == G_TYPE_UINT)
		g_key_file_set_integer (file, setting->name, key, (int) g_value_get_uint (value));
	else if (type == G_TYPE_INT)
		g_key_file_set_integer (file, setting->name, key, g_value_get_int (value));
	else if (type == G_TYPE_UINT64) {
		char *numstr;

		numstr = g_strdup_printf ("%" G_GUINT64_FORMAT, g_value_get_uint64 (value));
		g_key_file_set_value (file, setting->name, key, numstr);
		g_free (numstr);
	} else if (type == G_TYPE_BOOLEAN) {
		g_key_file_set_boolean (file, setting->name, key, g_value_get_boolean (value));
	} else if (type == G_TYPE_CHAR) {
		g_key_file_set_integer (file, setting->name, key, (int) g_value_get_char (value));
	} else if (type == DBUS_TYPE_G_UCHAR_ARRAY) {
		GByteArray *array;

		array = (GByteArray *) g_value_get_boxed (value);
		if (array && array->len > 0) {
			int *tmp_array;
			int i;

			tmp_array = g_new (gint, array->len);
			for (i = 0; i < array->len; i++)
				tmp_array[i] = (int) array->data[i];

			g_key_file_set_integer_list (file, setting->name, key, tmp_array, array->len);
			g_free (tmp_array);
		}
	} else if (type == dbus_g_type_get_collection ("GSList", G_TYPE_STRING)) {
		GSList *list;
		GSList *iter;

		list = (GSList *) g_value_get_boxed (value);
		if (list) {
			char **array;
			int i = 0;

			array = g_new (char *, g_slist_length (list));
			for (iter = list; iter; iter = iter->next)
				array[i++] = iter->data;

			g_key_file_set_string_list (file, setting->name, key, (const gchar **const) array, i);
			g_free (array);
		}
	} else if (type == dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, G_TYPE_VALUE)) {
		/* FIXME */
		g_warning ("Implement me");
	} else if (type == DBUS_TYPE_G_UINT_ARRAY) {
		if (!write_array_of_uint (file, setting, key, value)) {
			g_warning ("Unhandled setting property type (write) '%s/%s' : '%s'", 
					 setting->name, key, g_type_name (type));
		}
	} else if (type == DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UINT) {
		if (!write_array_of_array_of_uint (file, setting, key, value)) {
			g_warning ("Unhandled setting property type (write) '%s/%s' : '%s'", 
					 setting->name, key, g_type_name (type));
		}
	} else {
		g_warning ("Unhandled setting property type (write) '%s/%s' : '%s'", 
				 setting->name, key, g_type_name (type));
	}
}

gboolean
write_connection (NMConnection *connection)
{
	NMSettingConnection *s_con;
	GKeyFile *key_file;
	char *data;
	gsize len;
	gboolean success = FALSE;
	GError *err = NULL;

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	if (!s_con)
		return success;

	key_file = g_key_file_new ();
	nm_connection_for_each_setting_value (connection, write_setting_value, key_file);
	data = g_key_file_to_data (key_file, &len, &err);

	if (!err) {
		char *filename;

		filename = g_build_filename (KEYFILE_DIR, s_con->id, NULL);
		g_file_set_contents (filename, data, len, &err);
		chmod (filename, S_IRUSR | S_IWUSR);
		if (chown (filename, 0, 0) < 0) {
			g_warning ("Error chowning '%s': %d", filename, errno);
			unlink (filename);
		} else
			success = TRUE;

		g_free (filename);
	}

	if (err) {
		g_warning ("Error while saving connection: %s", err->message);
		g_error_free (err);
	}

	g_free (data);
	g_key_file_free (key_file);

	return success;
}
