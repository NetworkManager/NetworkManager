/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service - keyfile plugin
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2008 Novell, Inc.
 * Copyright (C) 2008 - 2012 Red Hat, Inc.
 */

#include "config.h"

#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

#include <nm-setting.h>
#include <nm-setting-connection.h>
#include <nm-setting-ip4-config.h>
#include <nm-setting-ip6-config.h>
#include <nm-setting-vpn.h>
#include <nm-setting-wired.h>
#include <nm-setting-wireless.h>
#include <nm-setting-ip4-config.h>
#include <nm-setting-bluetooth.h>
#include <nm-setting-8021x.h>
#include <nm-utils.h>
#include <string.h>
#include <arpa/inet.h>

#include "nm-glib-compat.h"
#include "nm-logging.h"
#include "writer.h"
#include "common.h"
#include "utils.h"

/* Some setting properties also contain setting names, such as
 * NMSettingConnection's 'type' property (which specifies the base type of the
 * connection, eg ethernet or wifi) or the 802-11-wireless setting's
 * 'security' property which specifies whether or not the AP requires
 * encrpytion.  This function handles translating those properties' values
 * from the real setting name to the more-readable alias.
 */
static void
setting_alias_writer (GKeyFile *file,
                      const char *keyfile_dir,
                      const char *uuid,
                      NMSetting *setting,
                      const char *key,
                      const GValue *value)
{
	const char *str, *alias;

	str = g_value_get_string (value);
	alias = nm_keyfile_plugin_get_alias_for_setting_name (str);
	nm_keyfile_plugin_kf_set_string (file,
	                                 nm_setting_get_name (setting),
	                                 key,
	                                 alias ? alias : str);
}

static gboolean
write_array_of_uint (GKeyFile *file,
                     NMSetting *setting,
                     const char *key,
                     const GValue *value)
{
	GArray *array;
	int i;
	int *tmp_array;

	array = (GArray *) g_value_get_boxed (value);
	if (!array || !array->len)
		return TRUE;

	tmp_array = g_new (gint, array->len);
	for (i = 0; i < array->len; i++)
		tmp_array[i] = g_array_index (array, int, i);

	nm_keyfile_plugin_kf_set_integer_list (file, nm_setting_get_name (setting), key, tmp_array, array->len);
	g_free (tmp_array);
	return TRUE;
}

static void
dns_writer (GKeyFile *file,
            const char *keyfile_dir,
            const char *uuid,
            NMSetting *setting,
            const char *key,
            const GValue *value)
{
	char **list;

	list = g_value_get_boxed (value);
	if (list && list[0]) {
		nm_keyfile_plugin_kf_set_string_list (file, nm_setting_get_name (setting), key,
		                                      (const char **) list, g_strv_length (list));
	}
}

static void
write_ip_values (GKeyFile *file,
                 const char *setting_name,
                 GPtrArray *array,
                 const char *gateway,
                 gboolean is_route)
{
	GString *output;
	int family, i;
	const char *addr, *gw;
	guint32 plen, metric;
	char key_name[30], *key_name_idx;

	if (!array->len)
		return;

	family = !strcmp (setting_name, NM_SETTING_IP4_CONFIG_SETTING_NAME) ? AF_INET : AF_INET6;

	strcpy (key_name, is_route ? "route" : "address");
	key_name_idx = key_name + strlen (key_name);

	output = g_string_sized_new (2*INET_ADDRSTRLEN + 10);
	for (i = 0; i < array->len; i++) {
		if (is_route) {
			NMIPRoute *route = array->pdata[i];

			addr = nm_ip_route_get_dest (route);
			plen = nm_ip_route_get_prefix (route);
			gw = nm_ip_route_get_next_hop (route);
			metric = MAX (0, nm_ip_route_get_metric (route));
		} else {
			NMIPAddress *address = array->pdata[i];

			addr = nm_ip_address_get_address (address);
			plen = nm_ip_address_get_prefix (address);
			gw = i == 0 ? gateway : NULL;
			metric = 0;
		}

		g_string_set_size (output, 0);
		g_string_append_printf (output, "%s/%u", addr, plen);
		if (metric || gw) {
			/* Older versions of the plugin do not support the form
			 * "a.b.c.d/plen,,metric", so, we always have to write the
			 * gateway, even if there isn't one.
			 * The current version supports reading of the above form.
			 */
			if (!gw) {
				if (family == AF_INET)
					gw = "0.0.0.0";
				else
					gw = "::";
			}

			g_string_append_printf (output, ",%s", gw);
			if (metric)
				g_string_append_printf (output, ",%lu", (unsigned long) metric);
		}

		sprintf (key_name_idx, "%d", i + 1);
		nm_keyfile_plugin_kf_set_string (file, setting_name, key_name, output->str);
	}
	g_string_free (output, TRUE);
}

static void
addr_writer (GKeyFile *file,
             const char *keyfile_dir,
             const char *uuid,
             NMSetting *setting,
             const char *key,
             const GValue *value)
{
	GPtrArray *array;
	const char *setting_name = nm_setting_get_name (setting);
	const char *gateway = nm_setting_ip_config_get_gateway (NM_SETTING_IP_CONFIG (setting));

	array = (GPtrArray *) g_value_get_boxed (value);
	if (array && array->len)
		write_ip_values (file, setting_name, array, gateway, FALSE);
}

static void
ip4_addr_label_writer (GKeyFile *file,
                       const char *keyfile_dir,
                       const char *uuid,
                       NMSetting *setting,
                       const char *key,
                       const GValue *value)
{
	/* skip */
}

static void
gateway_writer (GKeyFile *file,
                const char *keyfile_dir,
                const char *uuid,
                NMSetting *setting,
                const char *key,
                const GValue *value)
{
	/* skip */
}

static void
route_writer (GKeyFile *file,
              const char *keyfile_dir,
              const char *uuid,
              NMSetting *setting,
              const char *key,
              const GValue *value)
{
	GPtrArray *array;
	const char *setting_name = nm_setting_get_name (setting);

	array = (GPtrArray *) g_value_get_boxed (value);
	if (array && array->len)
		write_ip_values (file, setting_name, array, NULL, TRUE);
}

static void
write_hash_of_string (GKeyFile *file,
                      NMSetting *setting,
                      const char *key,
                      const GValue *value)
{
	GHashTableIter iter;
	const char *property = NULL, *data = NULL;
	const char *group_name = nm_setting_get_name (setting);
	gboolean vpn_secrets = FALSE;

	/* Write VPN secrets out to a different group to keep them separate */
	if (NM_IS_SETTING_VPN (setting) && !strcmp (key, NM_SETTING_VPN_SECRETS)) {
		group_name = VPN_SECRETS_GROUP;
		vpn_secrets = TRUE;
	}

	g_hash_table_iter_init (&iter, (GHashTable *) g_value_get_boxed (value));
	while (g_hash_table_iter_next (&iter, (gpointer *) &property, (gpointer *) &data)) {
		gboolean write_item = TRUE;

		/* Handle VPN secrets specially; they are nested in the property's hash;
		 * we don't want to write them if the secret is not saved, not required,
		 * or owned by a user's secret agent.
		 */
		if (vpn_secrets) {
			NMSettingSecretFlags secret_flags = NM_SETTING_SECRET_FLAG_NONE;

			nm_setting_get_secret_flags (setting, property, &secret_flags, NULL);
			if (secret_flags != NM_SETTING_SECRET_FLAG_NONE)
				write_item = FALSE;
		}

		if (write_item)
			nm_keyfile_plugin_kf_set_string (file, group_name, property, data);
	}
}

static void
ssid_writer (GKeyFile *file,
             const char *keyfile_dir,
             const char *uuid,
             NMSetting *setting,
             const char *key,
             const GValue *value)
{
	GBytes *bytes;
	const guint8 *ssid_data;
	gsize ssid_len;
	const char *setting_name = nm_setting_get_name (setting);
	gboolean new_format = TRUE;
	unsigned int semicolons = 0;
	int i, *tmp_array;
	char *ssid;

	g_return_if_fail (G_VALUE_HOLDS (value, G_TYPE_BYTES));

	bytes = g_value_get_boxed (value);
	if (!bytes)
		return;
	ssid_data = g_bytes_get_data (bytes, &ssid_len);
	if (ssid_len == 0)
		return;

	/* Check whether each byte is printable.  If not, we have to use an
	 * integer list, otherwise we can just use a string.
	 */
	for (i = 0; i < ssid_len; i++) {
		char c = ssid_data[i] & 0xFF;
		if (!g_ascii_isprint (c)) {
			new_format = FALSE;
			break;
		}
		if (c == ';')
			semicolons++;
	}

	if (new_format) {
		ssid = g_malloc0 (ssid_len + semicolons + 1);
		if (semicolons == 0)
			memcpy (ssid, ssid_data, ssid_len);
		else {
			/* Escape semicolons with backslashes to make strings
			 * containing ';', such as '16;17;' unambiguous */
			int j = 0;
			for (i = 0; i < ssid_len; i++) {
				if (ssid_data[i] == ';')
					ssid[j++] = '\\';
				ssid[j++] = ssid_data[i];
			}
		}
		nm_keyfile_plugin_kf_set_string (file, setting_name, key, ssid);
		g_free (ssid);
	} else {
		tmp_array = g_new (gint, ssid_len);
		for (i = 0; i < ssid_len; i++)
			tmp_array[i] = (int) ssid_data[i];
		nm_keyfile_plugin_kf_set_integer_list (file, setting_name, key, tmp_array, ssid_len);
		g_free (tmp_array);
	}
}

static void
password_raw_writer (GKeyFile *file,
                     const char *keyfile_dir,
                     const char *uuid,
                     NMSetting *setting,
                     const char *key,
                     const GValue *value)
{
	const char *setting_name = nm_setting_get_name (setting);
	GBytes *array;
	int *tmp_array;
	gsize i, len;
	const char *data;

	g_return_if_fail (G_VALUE_HOLDS (value, G_TYPE_BYTES));

	array = (GBytes *) g_value_get_boxed (value);
	if (!array)
		return;
	data = g_bytes_get_data (array, &len);
	if (!data || !len)
		return;

	tmp_array = g_new (gint, len);
	for (i = 0; i < len; i++)
		tmp_array[i] = (int) data[i];
	nm_keyfile_plugin_kf_set_integer_list (file, setting_name, key, tmp_array, len);
	g_free (tmp_array);
}

typedef struct ObjectType {
	const char *key;
	const char *suffix;
	const char *privkey_pw_prop;
	NMSetting8021xCKScheme (*scheme_func) (NMSetting8021x *setting);
	NMSetting8021xCKFormat (*format_func) (NMSetting8021x *setting);
	const char *           (*path_func)   (NMSetting8021x *setting);
	GBytes *               (*blob_func)   (NMSetting8021x *setting);
} ObjectType;

static const ObjectType objtypes[10] = {
	{ NM_SETTING_802_1X_CA_CERT,
	  "ca-cert",
	  NULL,
	  nm_setting_802_1x_get_ca_cert_scheme,
	  NULL,
	  nm_setting_802_1x_get_ca_cert_path,
	  nm_setting_802_1x_get_ca_cert_blob },

	{ NM_SETTING_802_1X_PHASE2_CA_CERT,
	  "inner-ca-cert",
	  NULL,
	  nm_setting_802_1x_get_phase2_ca_cert_scheme,
	  NULL,
	  nm_setting_802_1x_get_phase2_ca_cert_path,
	  nm_setting_802_1x_get_phase2_ca_cert_blob },

	{ NM_SETTING_802_1X_CLIENT_CERT,
	  "client-cert",
	  NULL,
	  nm_setting_802_1x_get_client_cert_scheme,
	  NULL,
	  nm_setting_802_1x_get_client_cert_path,
	  nm_setting_802_1x_get_client_cert_blob },

	{ NM_SETTING_802_1X_PHASE2_CLIENT_CERT,
	  "inner-client-cert",
	  NULL,
	  nm_setting_802_1x_get_phase2_client_cert_scheme,
	  NULL,
	  nm_setting_802_1x_get_phase2_client_cert_path,
	  nm_setting_802_1x_get_phase2_client_cert_blob },

	{ NM_SETTING_802_1X_PRIVATE_KEY,
	  "private-key",
	  NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD,
	  nm_setting_802_1x_get_private_key_scheme,
	  nm_setting_802_1x_get_private_key_format,
	  nm_setting_802_1x_get_private_key_path,
	  nm_setting_802_1x_get_private_key_blob },

	{ NM_SETTING_802_1X_PHASE2_PRIVATE_KEY,
	  "inner-private-key",
	  NM_SETTING_802_1X_PHASE2_PRIVATE_KEY_PASSWORD,
	  nm_setting_802_1x_get_phase2_private_key_scheme,
	  nm_setting_802_1x_get_phase2_private_key_format,
	  nm_setting_802_1x_get_phase2_private_key_path,
	  nm_setting_802_1x_get_phase2_private_key_blob },

	{ NULL },
};

static gboolean
write_cert_key_file (const char *path,
                     const guint8 *data,
                     gsize data_len,
                     GError **error)
{
	char *tmppath;
	int fd = -1, written;
	gboolean success = FALSE;

	tmppath = g_malloc0 (strlen (path) + 10);
	g_assert (tmppath);
	memcpy (tmppath, path, strlen (path));
	strcat (tmppath, ".XXXXXX");

	errno = 0;
	fd = mkstemp (tmppath);
	if (fd < 0) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Could not create temporary file for '%s': %d",
		             path, errno);
		goto out;
	}

	/* Only readable by root */
	errno = 0;
	if (fchmod (fd, S_IRUSR | S_IWUSR) != 0) {
		close (fd);
		unlink (tmppath);
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Could not set permissions for temporary file '%s': %d",
		             path, errno);
		goto out;
	}

	errno = 0;
	written = write (fd, data, data_len);
	if (written != data_len) {
		close (fd);
		unlink (tmppath);
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Could not write temporary file for '%s': %d",
		             path, errno);
		goto out;
	}
	close (fd);

	/* Try to rename */
	errno = 0;
	if (rename (tmppath, path) == 0)
		success = TRUE;
	else {
		unlink (tmppath);
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Could not rename temporary file to '%s': %d",
		             path, errno);
	}

out:
	g_free (tmppath);
	return success;
}

static void
cert_writer (GKeyFile *file,
             const char *keyfile_dir,
             const char *uuid,
             NMSetting *setting,
             const char *key,
             const GValue *value)
{
	const char *setting_name = nm_setting_get_name (setting);
	NMSetting8021xCKScheme scheme;
	NMSetting8021xCKFormat format;
	const char *path = NULL, *ext = "pem";
	const ObjectType *objtype = NULL;
	int i;

	for (i = 0; i < G_N_ELEMENTS (objtypes) && objtypes[i].key; i++) {
		if (g_strcmp0 (objtypes[i].key, key) == 0) {
			objtype = &objtypes[i];
			break;
		}
	}
	if (!objtype) {
		g_return_if_fail (objtype);
		return;
	}

	scheme = objtype->scheme_func (NM_SETTING_802_1X (setting));
	if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH) {
		path = objtype->path_func (NM_SETTING_802_1X (setting));
		g_assert (path);

		/* If the path is rooted in the keyfile directory, just use a
		 * relative path instead of an absolute one.
		 */
		if (g_str_has_prefix (path, keyfile_dir)) {
			path += strlen (keyfile_dir);
			while (*path == '/')
				path++;
		}

		nm_keyfile_plugin_kf_set_string (file, setting_name, key, path);
	} else if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB) {
		GBytes *blob;
		const guint8 *blob_data;
		gsize blob_len;
		gboolean success;
		GError *error = NULL;
		char *new_path;

		blob = objtype->blob_func (NM_SETTING_802_1X (setting));
		g_assert (blob);
		blob_data = g_bytes_get_data (blob, &blob_len);

		if (objtype->format_func) {
			/* Get the extension for a private key */
			format = objtype->format_func (NM_SETTING_802_1X (setting));
			if (format == NM_SETTING_802_1X_CK_FORMAT_PKCS12)
				ext = "p12";
		} else {
			/* DER or PEM format certificate? */
			if (blob_len > 2 && blob_data[0] == 0x30 && blob_data[1] == 0x82)
				ext = "der";
		}

		/* Write the raw data out to the standard file so that we can use paths
		 * from now on instead of pushing around the certificate data.
		 */
		new_path = g_strdup_printf ("%s/%s-%s.%s", keyfile_dir, uuid, objtype->suffix, ext);
		g_assert (new_path);

		success = write_cert_key_file (new_path, blob_data, blob_len, &error);
		if (success) {
			/* Write the path value to the keyfile */
			nm_keyfile_plugin_kf_set_string (file, setting_name, key, new_path);
		} else {
			nm_log_warn (LOGD_SETTINGS, "Failed to write certificate/key %s: %s",
			             new_path, error->message);
			g_error_free (error);
		}
		g_free (new_path);
	} else
		g_assert_not_reached ();
}

typedef struct {
	const char *setting_name;
	const char *key;
	void (*writer) (GKeyFile *keyfile,
	                const char *keyfile_dir,
	                const char *uuid,
	                NMSetting *setting,
	                const char *key,
	                const GValue *value);
} KeyWriter;

/* A table of keys that require further parsing/conversion because they are
 * stored in a format that can't be automatically read using the key's type.
 * i.e. IPv4 addresses, which are stored in NetworkManager as guint32, but are
 * stored in keyfiles as strings, eg "10.1.1.2" or IPv6 addresses stored 
 * in struct in6_addr internally, but as string in keyfiles.
 */
static KeyWriter key_writers[] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME,
	  NM_SETTING_CONNECTION_TYPE,
	  setting_alias_writer },
	{ NM_SETTING_IP4_CONFIG_SETTING_NAME,
	  NM_SETTING_IP_CONFIG_ADDRESSES,
	  addr_writer },
	{ NM_SETTING_IP4_CONFIG_SETTING_NAME,
	  "address-labels",
	  ip4_addr_label_writer },
	{ NM_SETTING_IP6_CONFIG_SETTING_NAME,
	  NM_SETTING_IP_CONFIG_ADDRESSES,
	  addr_writer },
	{ NM_SETTING_IP4_CONFIG_SETTING_NAME,
	  NM_SETTING_IP_CONFIG_GATEWAY,
	  gateway_writer },
	{ NM_SETTING_IP6_CONFIG_SETTING_NAME,
	  NM_SETTING_IP_CONFIG_GATEWAY,
	  gateway_writer },
	{ NM_SETTING_IP4_CONFIG_SETTING_NAME,
	  NM_SETTING_IP_CONFIG_ROUTES,
	  route_writer },
	{ NM_SETTING_IP6_CONFIG_SETTING_NAME,
	  NM_SETTING_IP_CONFIG_ROUTES,
	  route_writer },
	{ NM_SETTING_IP4_CONFIG_SETTING_NAME,
	  NM_SETTING_IP_CONFIG_DNS,
	  dns_writer },
	{ NM_SETTING_IP6_CONFIG_SETTING_NAME,
	  NM_SETTING_IP_CONFIG_DNS,
	  dns_writer },
	{ NM_SETTING_WIRELESS_SETTING_NAME,
	  NM_SETTING_WIRELESS_SSID,
	  ssid_writer },
	{ NM_SETTING_802_1X_SETTING_NAME,
	  NM_SETTING_802_1X_PASSWORD_RAW,
	  password_raw_writer },
	{ NM_SETTING_802_1X_SETTING_NAME,
	  NM_SETTING_802_1X_CA_CERT,
	  cert_writer },
	{ NM_SETTING_802_1X_SETTING_NAME,
	  NM_SETTING_802_1X_CLIENT_CERT,
	  cert_writer },
	{ NM_SETTING_802_1X_SETTING_NAME,
	  NM_SETTING_802_1X_PRIVATE_KEY,
	  cert_writer },
	{ NM_SETTING_802_1X_SETTING_NAME,
	  NM_SETTING_802_1X_PHASE2_CA_CERT,
	  cert_writer },
	{ NM_SETTING_802_1X_SETTING_NAME,
	  NM_SETTING_802_1X_PHASE2_CLIENT_CERT,
	  cert_writer },
	{ NM_SETTING_802_1X_SETTING_NAME,
	  NM_SETTING_802_1X_PHASE2_PRIVATE_KEY,
	  cert_writer },
	{ NULL, NULL, NULL }
};

typedef struct {
	GKeyFile *keyfile;
	const char *keyfile_dir;
	const char *uuid;
} WriteInfo;

static void
write_setting_value (NMSetting *setting,
                     const char *key,
                     const GValue *value,
                     GParamFlags flag,
                     gpointer user_data)
{
	WriteInfo *info = user_data;
	const char *setting_name;
	GType type = G_VALUE_TYPE (value);
	KeyWriter *writer = &key_writers[0];
	GParamSpec *pspec;

	/* Setting name gets picked up from the keyfile's section name instead */
	if (!strcmp (key, NM_SETTING_NAME))
		return;

	/* Don't write the NMSettingConnection object's 'read-only' property */
	if (   NM_IS_SETTING_CONNECTION (setting)
	    && !strcmp (key, NM_SETTING_CONNECTION_READ_ONLY))
		return;

	setting_name = nm_setting_get_name (setting);

	/* If the value is the default value, remove the item from the keyfile */
	pspec = g_object_class_find_property (G_OBJECT_GET_CLASS (setting), key);
	if (pspec) {
		if (g_param_value_defaults (pspec, (GValue *) value)) {
			g_key_file_remove_key (info->keyfile, setting_name, key, NULL);
			return;
		}
	}

	/* Don't write secrets that are owned by user secret agents or aren't
	 * supposed to be saved.  VPN secrets are handled specially though since
	 * the secret flags there are in a third-level hash in the 'secrets'
	 * property.
	 */
	if (pspec && (pspec->flags & NM_SETTING_PARAM_SECRET) && !NM_IS_SETTING_VPN (setting)) {
		NMSettingSecretFlags secret_flags = NM_SETTING_SECRET_FLAG_NONE;

		if (!nm_setting_get_secret_flags (setting, key, &secret_flags, NULL))
			g_assert_not_reached ();
		if (secret_flags != NM_SETTING_SECRET_FLAG_NONE)
			return;
	}

	/* Look through the list of handlers for non-standard format key values */
	while (writer->setting_name) {
		if (!strcmp (writer->setting_name, setting_name) && !strcmp (writer->key, key)) {
			(*writer->writer) (info->keyfile, info->keyfile_dir, info->uuid, setting, key, value);
			return;
		}
		writer++;
	}

	if (type == G_TYPE_STRING) {
		const char *str;

		str = g_value_get_string (value);
		if (str)
			nm_keyfile_plugin_kf_set_string (info->keyfile, setting_name, key, str);
	} else if (type == G_TYPE_UINT)
		nm_keyfile_plugin_kf_set_integer (info->keyfile, setting_name, key, (int) g_value_get_uint (value));
	else if (type == G_TYPE_INT)
		nm_keyfile_plugin_kf_set_integer (info->keyfile, setting_name, key, g_value_get_int (value));
	else if (type == G_TYPE_UINT64) {
		char *numstr;

		numstr = g_strdup_printf ("%" G_GUINT64_FORMAT, g_value_get_uint64 (value));
		nm_keyfile_plugin_kf_set_value (info->keyfile, setting_name, key, numstr);
		g_free (numstr);
	} else if (type == G_TYPE_INT64) {
		char *numstr;

		numstr = g_strdup_printf ("%" G_GINT64_FORMAT, g_value_get_int64 (value));
		nm_keyfile_plugin_kf_set_value (info->keyfile, setting_name, key, numstr);
		g_free (numstr);
	} else if (type == G_TYPE_BOOLEAN) {
		nm_keyfile_plugin_kf_set_boolean (info->keyfile, setting_name, key, g_value_get_boolean (value));
	} else if (type == G_TYPE_CHAR) {
		nm_keyfile_plugin_kf_set_integer (info->keyfile, setting_name, key, (int) g_value_get_schar (value));
	} else if (type == G_TYPE_BYTES) {
		GBytes *bytes;
		const guint8 *data;
		gsize len = 0;

		bytes = g_value_get_boxed (value);
		data = bytes ? g_bytes_get_data (bytes, &len) : NULL;

		if (data != NULL && len > 0) {
			int *tmp_array;
			int i;

			tmp_array = g_new (gint, len);
			for (i = 0; i < len; i++)
				tmp_array[i] = (int) data[i];

			nm_keyfile_plugin_kf_set_integer_list (info->keyfile, setting_name, key, tmp_array, len);
			g_free (tmp_array);
		}
	} else if (type == G_TYPE_STRV) {
		char **array;

		array = (char **) g_value_get_boxed (value);
		nm_keyfile_plugin_kf_set_string_list (info->keyfile, setting_name, key, (const gchar **const) array, g_strv_length (array));
	} else if (type == G_TYPE_HASH_TABLE) {
		write_hash_of_string (info->keyfile, setting, key, value);
	} else if (type == G_TYPE_ARRAY) {
		if (!write_array_of_uint (info->keyfile, setting, key, value)) {
			nm_log_warn (LOGD_SETTINGS, "Unhandled setting property type (write) '%s/%s' : '%s'", 
			             setting_name, key, g_type_name (type));
		}
	} else if (G_VALUE_HOLDS_FLAGS (value)) {
		/* Flags are guint but GKeyFile has no uint reader, just uint64 */
		nm_keyfile_plugin_kf_set_uint64 (info->keyfile, setting_name, key, (guint64) g_value_get_flags (value));
	} else if (G_VALUE_HOLDS_ENUM (value))
		nm_keyfile_plugin_kf_set_integer (info->keyfile, setting_name, key, (gint) g_value_get_enum (value));
	else {
		nm_log_warn (LOGD_SETTINGS, "Unhandled setting property type (write) '%s/%s' : '%s'", 
		             setting_name, key, g_type_name (type));
	}
}

static gboolean
_internal_write_connection (NMConnection *connection,
                            const char *keyfile_dir,
                            uid_t owner_uid,
                            pid_t owner_grp,
                            const char *existing_path,
                            char **out_path,
                            GError **error)
{
	GKeyFile *key_file;
	char *data;
	gsize len;
	gboolean success = FALSE;
	char *path;
	const char *id;
	WriteInfo info;
	GError *local_err = NULL;

	g_return_val_if_fail (!out_path || !*out_path, FALSE);

	if (!nm_connection_verify (connection, error))
		g_return_val_if_reached (FALSE);

	id = nm_connection_get_id (connection);
	g_assert (id && *id);

	info.keyfile = key_file = g_key_file_new ();
	info.keyfile_dir = keyfile_dir;
	info.uuid = nm_connection_get_uuid (connection);
	g_assert (info.uuid);
	nm_connection_for_each_setting_value (connection, write_setting_value, &info);
	data = g_key_file_to_data (key_file, &len, error);
	if (!data)
		goto out;

	/* If we have existing file path, use it. Else generate one from
	 * connection's ID.
	 */
	if (existing_path != NULL) {
		path = g_strdup (existing_path);
	} else {
		char *filename_escaped = nm_keyfile_plugin_utils_escape_filename (id);

		path = g_build_filename (keyfile_dir, filename_escaped, NULL);
		g_free (filename_escaped);
	}

	/* If a file with this path already exists (but isn't the existing path
	 * of the connection) then we need another name.  Multiple connections
	 * can have the same ID (ie if two connections with the same ID are visible
	 * to different users) but of course can't have the same path.  Yeah,
	 * there's a race here, but there's not a lot we can do about it, and
	 * we shouldn't get more than one connection with the same UUID either.
	 */
	if (g_strcmp0 (path, existing_path) != 0 && g_file_test (path, G_FILE_TEST_EXISTS)) {
		guint i;
		gboolean name_found = FALSE;

		/* A keyfile with this connection's ID already exists. Pick another name. */
		for (i = 0; i < 100; i++) {
			char *filename, *filename_escaped;

			if (i == 0)
				filename = g_strdup_printf ("%s-%s", id, nm_connection_get_uuid (connection));
			else
				filename = g_strdup_printf ("%s-%s-%u", id, nm_connection_get_uuid (connection), i);

			filename_escaped = nm_keyfile_plugin_utils_escape_filename (filename);

			g_free (path);
			path = g_strdup_printf ("%s/%s", keyfile_dir, filename_escaped);
			g_free (filename);
			g_free (filename_escaped);
			if (g_strcmp0 (path, existing_path) == 0 || !g_file_test (path, G_FILE_TEST_EXISTS)) {
				name_found = TRUE;
				break;
			}
		}
		if (!name_found) {
			if (existing_path == NULL) {
				/* this really should not happen, we tried hard to find an unused name... bail out. */
				g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
				                    "could not find suitable keyfile file name (%s already used)", path);
				g_free (path);
				goto out;
			}
			/* Both our preferred path based on connection id and id-uuid are taken.
			 * Fallback to @existing_path */
			g_free (path);
			path = g_strdup (existing_path);
		}
	}

	/* In case of updating the connection and changing the file path,
	 * we need to remove the old one, not to end up with two connections.
	 */
	if (existing_path != NULL && strcmp (path, existing_path) != 0)
		unlink (existing_path);

	g_file_set_contents (path, data, len, &local_err);
	if (local_err) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "%s.%d: error writing to file '%s': %s", __FILE__, __LINE__,
		             path, local_err->message);
		g_error_free (local_err);
		g_free (path);
		goto out;
	}

	if (chown (path, owner_uid, owner_grp) < 0) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "%s.%d: error chowning '%s': %d", __FILE__, __LINE__,
		             path, errno);
		unlink (path);
	} else {
		if (chmod (path, S_IRUSR | S_IWUSR) < 0) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
			             "%s.%d: error setting permissions on '%s': %d", __FILE__,
			             __LINE__, path, errno);
			unlink (path);
		} else {
			if (out_path && g_strcmp0 (existing_path, path)) {
				*out_path = path;  /* pass path out to caller */
				path = NULL;
			}
			success = TRUE;
		}
	}
	g_free (path);

out:
	g_free (data);
	g_key_file_free (key_file);
	return success;
}

gboolean
nm_keyfile_plugin_write_connection (NMConnection *connection,
                                    const char *existing_path,
                                    char **out_path,
                                    GError **error)
{
	return _internal_write_connection (connection,
	                                   KEYFILE_DIR,
	                                   0, 0,
	                                   existing_path,
	                                   out_path,
	                                   error);
}

gboolean
nm_keyfile_plugin_write_test_connection (NMConnection *connection,
                                         const char *keyfile_dir,
                                         uid_t owner_uid,
                                         pid_t owner_grp,
                                         char **out_path,
                                         GError **error)
{
	return _internal_write_connection (connection,
	                                   keyfile_dir,
	                                   owner_uid, owner_grp,
	                                   NULL,
	                                   out_path,
	                                   error);
}

