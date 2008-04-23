/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <dbus/dbus-glib.h>
#include <nm-setting.h>
#include <nm-setting-connection.h>

#include "writer.h"

#define DBUS_TYPE_G_ARRAY_OF_UINT          (dbus_g_type_get_collection ("GArray", G_TYPE_UINT))
#define DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UINT (dbus_g_type_get_collection ("GPtrArray", DBUS_TYPE_G_ARRAY_OF_UINT))

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
		GArray *array;

		array = (GArray *) g_value_get_boxed (value);
		if (array && array->len > 0) {
			int *tmp_array;
			int i;

			tmp_array = g_new (gint, array->len);
			for (i = 0; i < array->len; i++)
				tmp_array[i] = (int) array->data[i];

			g_key_file_set_integer_list (file, setting->name, key, tmp_array, array->len);
			g_free (tmp_array);
		}
	} else if (type == DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UINT) {
		GPtrArray *array;
		
		array = (GPtrArray *) g_value_get_boxed (value);
		if (array && array->len > 0) {
			int i, j;
			int* list;

			list = g_new (int, array->len * 3);

			for (i = 0, j = 0; i < array->len; i++) {
				GArray *tuple = g_ptr_array_index (array, i);

				list[j++] = g_array_index (tuple, guint32, 0);
				list[j++] = g_array_index (tuple, guint32, 1);
				list[j++] = tuple->len == 3 ? g_array_index (tuple, guint32, 2) : 0;
			}

			g_key_file_set_integer_list (file, setting->name, key, list, j);
			g_free (list);
		}
	} else
		g_warning ("Unhandled setting property type (write) '%s/%s' : '%s'", 
				 setting->name, key, g_type_name (type));
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
