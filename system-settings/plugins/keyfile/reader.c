/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <dbus/dbus-glib.h>
#include <nm-setting.h>
#include <nm-setting-ip4-config.h>
#include <arpa/inet.h>
#include <string.h>

#include "nm-dbus-glib-types.h"
#include "reader.h"

static gboolean
read_array_of_uint (GKeyFile *file,
                    NMSetting *setting,
                    const char *key)
{
	GArray *array = NULL;
	gsize length;
	int i;

	if (NM_IS_SETTING_IP4_CONFIG (setting) && !strcmp (key, NM_SETTING_IP4_CONFIG_DNS)) {
		char **list, **iter;
		int ret;

		list = g_key_file_get_string_list (file, setting->name, key, &length, NULL);
		if (!list || !g_strv_length (list))
			return TRUE;

		array = g_array_sized_new (FALSE, FALSE, sizeof (guint32), length);
		for (iter = list; *iter; iter++) {
			struct in_addr addr;

			ret = inet_pton (AF_INET, *iter, &addr);
			if (ret <= 0) {
				g_warning ("%s: ignoring invalid DNS server address '%s'", __func__, *iter);
				continue;
			}

			g_array_append_val (array, addr.s_addr);			
		}
	} else {
		gint *tmp;

		tmp = g_key_file_get_integer_list (file, setting->name, key, &length, NULL);

		array = g_array_sized_new (FALSE, FALSE, sizeof (guint32), length);
		for (i = 0; i < length; i++)
			g_array_append_val (array, tmp[i]);
	}

	if (array) {
		g_object_set (setting, key, array, NULL);
		g_array_free (array, TRUE);
	}

	return TRUE;
}

static void
free_one_address (gpointer data, gpointer user_data)
{
	g_array_free ((GArray *) data, TRUE);
}

static gboolean
read_array_of_array_of_uint (GKeyFile *file,
                             NMSetting *setting,
                             const char *key)
{
	GPtrArray *addresses;
	int i = 0;

	/* Only handle IPv4 addresses for now */
	if (   !NM_IS_SETTING_IP4_CONFIG (setting)
	    || strcmp (key, NM_SETTING_IP4_CONFIG_ADDRESSES))
	    return FALSE;

	addresses = g_ptr_array_sized_new (3);

	/* Look for individual addresses */
	while (i++ < 1000) {
		gchar **tmp, **iter;
		char *key_name;
		gsize length = 0;
		int ret;
		GArray *address;
		guint32 empty = 0;
		int j;

		key_name = g_strdup_printf ("address%d", i);
		tmp = g_key_file_get_string_list (file, setting->name, key_name, &length, NULL);
		g_free (key_name);

		if (!tmp || !length)
			break; /* all done */

		if ((length < 2) || (length > 3)) {
			g_warning ("%s: ignoring invalid IPv4 address item '%s'", __func__, key_name);
			goto next;
		}

		/* convert the string array into IP addresses */
		address = g_array_sized_new (FALSE, TRUE, sizeof (guint32), 3);
		for (iter = tmp, j = 0; *iter; iter++, j++) {
			struct in_addr addr;

			if (j == 1) {
				/* prefix */
				long tmp_prefix;
				guint32 prefix;

				errno = 0;
				tmp_prefix = strtol (*iter, NULL, 10);
				if (errno || (tmp_prefix < 0) || (tmp_prefix > 32)) {
					g_warning ("%s: ignoring invalid IPv4 %s prefix '%s'", __func__, key_name, *iter);
					g_array_free (address, TRUE);
					goto next;
				}
				prefix = (guint32) tmp_prefix;
				g_array_append_val (address, prefix);
			} else {
				/* address and gateway */
				ret = inet_pton (AF_INET, *iter, &addr);
				if (ret <= 0) {
					g_warning ("%s: ignoring invalid IPv4 %s element '%s'", __func__, key_name, *iter);
					g_array_free (address, TRUE);
					goto next;
				}
				g_array_append_val (address, addr.s_addr);
			}
		}

		/* fill in blank gateway if not specified */
		if (address->len == 2)
			g_array_append_val (address, empty);

		g_ptr_array_add (addresses, address);

next:
		g_strfreev (tmp);
	}

	g_object_set (setting, key, addresses, NULL);

	g_ptr_array_foreach (addresses, free_one_address, NULL);
	g_ptr_array_free (addresses, TRUE);
	return TRUE;
}

static void
read_one_setting_value (NMSetting *setting,
				    const char *key,
				    const GValue *value,
				    gboolean secret,
				    gpointer user_data)
{
	GKeyFile *file = (GKeyFile *) user_data;
	GType type;
	GError *err = NULL;
	gboolean check_for_key = TRUE;

	/* Setting name gets picked up from the keyfile's section name instead */
	if (!strcmp (key, NM_SETTING_NAME))
		return;

	/* IPv4 addresses don't have the exact key name */
	if (NM_IS_SETTING_IP4_CONFIG (setting) && !strcmp (key, NM_SETTING_IP4_CONFIG_ADDRESSES))
		check_for_key = FALSE;

	if (check_for_key && !g_key_file_has_key (file, setting->name, key, &err)) {
		if (err) {
			g_warning ("Error loading setting '%s' value: %s", setting->name, err->message);
			g_error_free (err);
		}

		return;
	}

	type = G_VALUE_TYPE (value);

	if (type == G_TYPE_STRING) {
		char *str_val;

		str_val = g_key_file_get_string (file, setting->name, key, NULL);
		g_object_set (setting, key, str_val, NULL);
		g_free (str_val);
	} else if (type == G_TYPE_UINT) {
		int int_val;

		int_val = g_key_file_get_integer (file, setting->name, key, NULL);
		if (int_val < 0)
			g_warning ("Casting negative value (%i) to uint", int_val);
		g_object_set (setting, key, int_val, NULL);
	} else if (type == G_TYPE_INT) {
		int int_val;

		int_val = g_key_file_get_integer (file, setting->name, key, NULL);
		g_object_set (setting, key, int_val, NULL);
	} else if (type == G_TYPE_BOOLEAN) {
		gboolean bool_val;

		bool_val = g_key_file_get_boolean (file, setting->name, key, NULL);
		g_object_set (setting, key, bool_val, NULL);
	} else if (type == G_TYPE_CHAR) {
		int int_val;

		int_val = g_key_file_get_integer (file, setting->name, key, NULL);
		if (int_val < G_MININT8 || int_val > G_MAXINT8)
			g_warning ("Casting value (%i) to char", int_val);

		g_object_set (setting, key, int_val, NULL);
	} else if (type == G_TYPE_UINT64) {
		char *tmp_str;
		guint64 uint_val;

		tmp_str = g_key_file_get_value (file, setting->name, key, NULL);
		uint_val = g_ascii_strtoull (tmp_str, NULL, 10);
		g_free (tmp_str);
		g_object_set (setting, key, uint_val, NULL);
 	} else if (type == DBUS_TYPE_G_UCHAR_ARRAY) {
		gint *tmp;
		GByteArray *array;
		gsize length;
		int i;

		tmp = g_key_file_get_integer_list (file, setting->name, key, &length, NULL);

		array = g_byte_array_sized_new (length);
		for (i = 0; i < length; i++) {
			int val = tmp[i];
			unsigned char v = (unsigned char) (val & 0xFF);

			if (val < 0 || val > 255)
				g_warning ("Value out of range for a byte value");
			else
				g_byte_array_append (array, (const unsigned char *) &v, sizeof (v));
		}

		g_object_set (setting, key, array, NULL);
		g_byte_array_free (array, TRUE);
		g_free (tmp);
 	} else if (type == dbus_g_type_get_collection ("GSList", G_TYPE_STRING)) {
		gchar **sa;
		gsize length;
		int i;
		GSList *list = NULL;

		sa = g_key_file_get_string_list (file, setting->name, key, &length, NULL);
		for (i = 0; i < length; i++)
			list = g_slist_prepend (list, sa[i]);

		list = g_slist_reverse (list);
		g_object_set (setting, key, list, NULL);

		g_slist_free (list);
		g_strfreev (sa);
	} else if (type == dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, G_TYPE_VALUE)) {
		/* FIXME */
		g_warning ("Implement me");
	} else if (type == DBUS_TYPE_G_UINT_ARRAY) {
		if (!read_array_of_uint (file, setting, key)) {
			g_warning ("Unhandled setting property type (read): '%s/%s' : '%s'",
					 setting->name, key, G_VALUE_TYPE_NAME (value));
		}
	} else if (type == DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UINT) {
		if (!read_array_of_array_of_uint (file, setting, key)) {
			g_warning ("Unhandled setting property type (read): '%s/%s' : '%s'",
					 setting->name, key, G_VALUE_TYPE_NAME (value));
		}
	} else {
		g_warning ("Unhandled setting property type (read): '%s/%s' : '%s'",
				 setting->name, key, G_VALUE_TYPE_NAME (value));
	}
}

static NMSetting *
read_setting (GKeyFile *file, const char *name)
{
	NMSetting *setting;

	setting = nm_connection_create_setting (name);
	if (setting) {
		nm_setting_enumerate_values (setting, read_one_setting_value, file);
	} else
		g_warning ("Invalid setting name '%s'", name);

	return setting;
}

NMConnection *
connection_from_file (const char *filename)
{
	GKeyFile *key_file;
	struct stat statbuf;
	gboolean bad_owner, bad_permissions;
	NMConnection *connection = NULL;
	GError *err = NULL;

	if (stat (filename, &statbuf) != 0 || !S_ISREG (statbuf.st_mode))
		return NULL;

	bad_owner = getuid () != statbuf.st_uid;
	bad_permissions = statbuf.st_mode & 0077;

    if (bad_owner || bad_permissions) {
	    g_warning ("Ignorning insecure configuration file '%s'", filename);
	    return NULL;
    }

	key_file = g_key_file_new ();
	if (g_key_file_load_from_file (key_file, filename, G_KEY_FILE_NONE, &err)) {
		gchar **groups;
		gsize length;
		int i;

		connection = nm_connection_new ();

		groups = g_key_file_get_groups (key_file, &length);
		for (i = 0; i < length; i++) {
			NMSetting *setting;

			setting = read_setting (key_file, groups[i]);
			if (setting)
				nm_connection_add_setting (connection, setting);
		}

		g_strfreev (groups);
	} else {
		g_warning ("Error parsing file '%s': %s", filename, err->message);
		g_error_free (err);
	}

	g_key_file_free (key_file);

	return connection;
}
