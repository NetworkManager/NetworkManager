/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <dbus/dbus-glib.h>
#include <nm-setting.h>
#include <nm-setting-ip4-config.h>
#include <nm-setting-vpn.h>
#include <nm-setting-connection.h>
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

		list = g_key_file_get_string_list (file, nm_setting_get_name (setting), key, &length, NULL);
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

		tmp = g_key_file_get_integer_list (file, nm_setting_get_name (setting), key, &length, NULL);

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

static gboolean
get_one_int (const char *str, guint32 max_val, const char *key_name, guint32 *out)
{
	long tmp;

	errno = 0;
	tmp = strtol (str, NULL, 10);
	if (errno || (tmp < 0) || (tmp > max_val)) {
		g_warning ("%s: ignoring invalid IPv4 %s item '%s'", __func__, key_name, str);
		return FALSE;
	}

	*out = (guint32) tmp;
	return TRUE;
}

static void
free_one_address (gpointer data, gpointer user_data)
{
	g_array_free ((GArray *) data, TRUE);
}

static GPtrArray *
read_addresses (GKeyFile *file,
			    const char *setting_name,
			    const char *key)
{
	GPtrArray *addresses;
	int i = 0;

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

		key_name = g_strdup_printf ("%s%d", key, i);
		tmp = g_key_file_get_string_list (file, setting_name, key_name, &length, NULL);
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
				guint32 prefix = 0;

				/* prefix */
				if (!get_one_int (*iter, 32, key_name, &prefix)) {
					g_array_free (address, TRUE);
					goto next;
				}

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

	if (addresses->len < 1) {
		g_ptr_array_free (addresses, TRUE);
		addresses = NULL;
	}

	return addresses;
}

static void
free_one_route (gpointer data, gpointer user_data)
{
	g_array_free ((GArray *) data, TRUE);
}

static GPtrArray *
read_routes (GKeyFile *file,
			 const char *setting_name,
			 const char *key)
{
	GPtrArray *routes;
	int i = 0;

	routes = g_ptr_array_sized_new (3);

	/* Look for individual routes */
	while (i++ < 1000) {
		gchar **tmp, **iter;
		char *key_name;
		gsize length = 0;
		int ret;
		GArray *route;
		int j;

		key_name = g_strdup_printf ("%s%d", key, i);
		tmp = g_key_file_get_string_list (file, setting_name, key_name, &length, NULL);
		g_free (key_name);

		if (!tmp || !length)
			break; /* all done */

		if (length != 4) {
			g_warning ("%s: ignoring invalid IPv4 route item '%s'", __func__, key_name);
			goto next;
		}

		/* convert the string array into IP addresses */
		route = g_array_sized_new (FALSE, TRUE, sizeof (guint32), 4);
		for (iter = tmp, j = 0; *iter; iter++, j++) {
			struct in_addr addr;

			if (j == 1) {
				guint32 prefix = 0;

				/* prefix */
				if (!get_one_int (*iter, 32, key_name, &prefix)) {
					g_array_free (route, TRUE);
					goto next;
				}

				g_array_append_val (route, prefix);
			} else if (j == 3) {
				guint32 metric = 0;

				/* prefix */
				if (!get_one_int (*iter, G_MAXUINT32, key_name, &metric)) {
					g_array_free (route, TRUE);
					goto next;
				}

				g_array_append_val (route, metric);
			} else {
				/* address and next hop */
				ret = inet_pton (AF_INET, *iter, &addr);
				if (ret <= 0) {
					g_warning ("%s: ignoring invalid IPv4 %s element '%s'", __func__, key_name, *iter);
					g_array_free (route, TRUE);
					goto next;
				}
				g_array_append_val (route, addr.s_addr);
			}
		}
		g_ptr_array_add (routes, route);

next:
		g_strfreev (tmp);
	}

	if (routes->len < 1) {
		g_ptr_array_free (routes, TRUE);
		routes = NULL;
	}

	return routes;
}

static gboolean
read_array_of_array_of_uint (GKeyFile *file,
                             NMSetting *setting,
                             const char *key)
{
	gboolean success = FALSE;
	const char *setting_name;

	/* Only handle IPv4 addresses and routes for now */
	if (!NM_IS_SETTING_IP4_CONFIG (setting))
		return FALSE;

	setting_name = nm_setting_get_name (setting);

	if (!strcmp (key, NM_SETTING_IP4_CONFIG_ADDRESSES)) {
		GPtrArray *addresses;

		addresses = read_addresses (file, setting_name, key);

		/* Work around for previous syntax */
		if (!addresses && !strcmp (key, NM_SETTING_IP4_CONFIG_ADDRESSES))
			addresses = read_addresses (file, setting_name, "address");

		if (addresses) {
			g_object_set (setting, key, addresses, NULL);
			g_ptr_array_foreach (addresses, free_one_address, NULL);
			g_ptr_array_free (addresses, TRUE);
		}
		success = TRUE;
	} else if (!strcmp (key, NM_SETTING_IP4_CONFIG_ROUTES)) {
		GPtrArray *routes;

		routes = read_routes (file, setting_name, key);
		if (routes) {
			g_object_set (setting, key, routes, NULL);
			g_ptr_array_foreach (routes, free_one_route, NULL);
			g_ptr_array_free (routes, TRUE);
		}
		success = TRUE;
	}

	return success;
}

static void
read_hash_of_string (GKeyFile *file, NMSetting *setting, const char *key)
{
	char **keys, **iter;
	char *value;
	const char *setting_name = nm_setting_get_name (setting);

	keys = g_key_file_get_keys (file, setting_name, NULL, NULL);
	if (!keys || !*keys)
		return;

	for (iter = keys; *iter; iter++) {
		value = g_key_file_get_string (file, setting_name, *iter, NULL);
		if (!value)
			continue;

		if (NM_IS_SETTING_VPN (setting)) {
			if (strcmp (*iter, NM_SETTING_VPN_SERVICE_TYPE))
				nm_setting_vpn_add_data_item (NM_SETTING_VPN (setting), *iter, value);
		}
		g_free (value);
	}
	g_strfreev (keys);
}

typedef struct {
	GKeyFile *keyfile;
	gboolean secrets;
} ReadSettingInfo;

static void
read_one_setting_value (NMSetting *setting,
				    const char *key,
				    const GValue *value,
				    gboolean secret,
				    gpointer user_data)
{
	ReadSettingInfo *info = (ReadSettingInfo *) user_data;
	GKeyFile *file = info->keyfile;
	const char *setting_name;
	GType type;
	GError *err = NULL;
	gboolean check_for_key = TRUE;

	/* Setting name gets picked up from the keyfile's section name instead */
	if (!strcmp (key, NM_SETTING_NAME))
		return;

	/* Don't read in secrets unless we want to */
	if (secret && !info->secrets)
		return;

	/* Don't read the NMSettingConnection object's 'read-only' property */
	if (   NM_IS_SETTING_CONNECTION (setting)
	    && !strcmp (key, NM_SETTING_CONNECTION_READ_ONLY))
		return;

	setting_name = nm_setting_get_name (setting);

	/* IPv4 addresses and VPN properties don't have the exact key name */
	if (NM_IS_SETTING_IP4_CONFIG (setting) && !strcmp (key, NM_SETTING_IP4_CONFIG_ADDRESSES))
		check_for_key = FALSE;
	else if (NM_IS_SETTING_VPN (setting))
		check_for_key = FALSE;

	if (check_for_key && !g_key_file_has_key (file, setting_name, key, &err)) {
		if (err) {
			g_warning ("Error loading setting '%s' value: %s", setting_name, err->message);
			g_error_free (err);
		}

		return;
	}

	type = G_VALUE_TYPE (value);

	if (type == G_TYPE_STRING) {
		char *str_val;

		str_val = g_key_file_get_string (file, setting_name, key, NULL);
		g_object_set (setting, key, str_val, NULL);
		g_free (str_val);
	} else if (type == G_TYPE_UINT) {
		int int_val;

		int_val = g_key_file_get_integer (file, setting_name, key, NULL);
		if (int_val < 0)
			g_warning ("Casting negative value (%i) to uint", int_val);
		g_object_set (setting, key, int_val, NULL);
	} else if (type == G_TYPE_INT) {
		int int_val;

		int_val = g_key_file_get_integer (file, setting_name, key, NULL);
		g_object_set (setting, key, int_val, NULL);
	} else if (type == G_TYPE_BOOLEAN) {
		gboolean bool_val;

		bool_val = g_key_file_get_boolean (file, setting_name, key, NULL);
		g_object_set (setting, key, bool_val, NULL);
	} else if (type == G_TYPE_CHAR) {
		int int_val;

		int_val = g_key_file_get_integer (file, setting_name, key, NULL);
		if (int_val < G_MININT8 || int_val > G_MAXINT8)
			g_warning ("Casting value (%i) to char", int_val);

		g_object_set (setting, key, int_val, NULL);
	} else if (type == G_TYPE_UINT64) {
		char *tmp_str;
		guint64 uint_val;

		tmp_str = g_key_file_get_value (file, setting_name, key, NULL);
		uint_val = g_ascii_strtoull (tmp_str, NULL, 10);
		g_free (tmp_str);
		g_object_set (setting, key, uint_val, NULL);
 	} else if (type == DBUS_TYPE_G_UCHAR_ARRAY) {
		gint *tmp;
		GByteArray *array;
		gsize length;
		int i;

		tmp = g_key_file_get_integer_list (file, setting_name, key, &length, NULL);

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
 	} else if (type == DBUS_TYPE_G_LIST_OF_STRING) {
		gchar **sa;
		gsize length;
		int i;
		GSList *list = NULL;

		sa = g_key_file_get_string_list (file, setting_name, key, &length, NULL);
		for (i = 0; i < length; i++)
			list = g_slist_prepend (list, sa[i]);

		list = g_slist_reverse (list);
		g_object_set (setting, key, list, NULL);

		g_slist_free (list);
		g_strfreev (sa);
	} else if (type == DBUS_TYPE_G_MAP_OF_STRING) {
		read_hash_of_string (file, setting, key);
	} else if (type == DBUS_TYPE_G_UINT_ARRAY) {
		if (!read_array_of_uint (file, setting, key)) {
			g_warning ("Unhandled setting property type (read): '%s/%s' : '%s'",
					 setting_name, key, G_VALUE_TYPE_NAME (value));
		}
	} else if (type == DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UINT) {
		if (!read_array_of_array_of_uint (file, setting, key)) {
			g_warning ("Unhandled setting property type (read): '%s/%s' : '%s'",
					 setting_name, key, G_VALUE_TYPE_NAME (value));
		}
	} else {
		g_warning ("Unhandled setting property type (read): '%s/%s' : '%s'",
				 setting_name, key, G_VALUE_TYPE_NAME (value));
	}
}

static NMSetting *
read_setting (GKeyFile *file, const char *name, gboolean secrets)
{
	NMSetting *setting;
	ReadSettingInfo info;

	info.keyfile = file;
	info.secrets = secrets;

	setting = nm_connection_create_setting (name);
	if (setting)
		nm_setting_enumerate_values (setting, read_one_setting_value, &info);
	else
		g_warning ("Invalid setting name '%s'", name);

	return setting;
}

static void
read_vpn_secrets (GKeyFile *file, NMSettingVPN *s_vpn)
{
	char **keys, **iter;

	keys = g_key_file_get_keys (file, VPN_SECRETS_GROUP, NULL, NULL);
	for (iter = keys; *iter; iter++) {
		char *secret;

		secret = g_key_file_get_string (file, VPN_SECRETS_GROUP, *iter, NULL);
		if (secret) {
			nm_setting_vpn_add_secret (s_vpn, *iter, secret);
			g_free (secret);
		}
	}
	g_strfreev (keys);
}

NMConnection *
connection_from_file (const char *filename, gboolean secrets)
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
		gboolean vpn_secrets = FALSE;

		connection = nm_connection_new ();

		groups = g_key_file_get_groups (key_file, &length);
		for (i = 0; i < length; i++) {
			NMSetting *setting;

			/* Only read out secrets when needed */
			if (!strcmp (groups[i], VPN_SECRETS_GROUP)) {
				vpn_secrets = TRUE;
				continue;
			}

			setting = read_setting (key_file, groups[i], secrets);
			if (setting)
				nm_connection_add_setting (connection, setting);
		}

		/* Handle vpn secrets after the 'vpn' setting was read */
		if (secrets && vpn_secrets) {
			NMSettingVPN *s_vpn;

			s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);
			if (s_vpn)
				read_vpn_secrets (key_file, s_vpn);
		}

		g_strfreev (groups);
	} else {
		g_warning ("Error parsing file '%s': %s", filename, err->message);
		g_error_free (err);
	}

	g_key_file_free (key_file);

	return connection;
}
