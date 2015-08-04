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
 * Copyright (C) 2008 - 2015 Red Hat, Inc.
 */

#include "config.h"

#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <arpa/inet.h>
#include <string.h>

#include "nm-default.h"
#include "nm-setting.h"
#include "nm-setting-connection.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-ip6-config.h"
#include "nm-setting-vpn.h"
#include "nm-setting-wired.h"
#include "nm-setting-wireless.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-bluetooth.h"
#include "nm-setting-8021x.h"
#include "nm-utils.h"

#include "nm-keyfile-internal.h"
#include "nm-keyfile-utils.h"

typedef struct {
	NMConnection *connection;
	GKeyFile *keyfile;
	GError *error;
	NMKeyfileWriteHandler handler;
	void *user_data;
} KeyfileWriterInfo;


/* Some setting properties also contain setting names, such as
 * NMSettingConnection's 'type' property (which specifies the base type of the
 * connection, eg ethernet or wifi) or the 802-11-wireless setting's
 * 'security' property which specifies whether or not the AP requires
 * encrpytion.  This function handles translating those properties' values
 * from the real setting name to the more-readable alias.
 */
static void
setting_alias_writer (KeyfileWriterInfo *info,
                      NMSetting *setting,
                      const char *key,
                      const GValue *value)
{
	const char *str, *alias;

	str = g_value_get_string (value);
	alias = nm_keyfile_plugin_get_alias_for_setting_name (str);
	nm_keyfile_plugin_kf_set_string (info->keyfile,
	                                 nm_setting_get_name (setting),
	                                 key,
	                                 alias ? alias : str);
}

static void
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
		return;

	tmp_array = g_new (gint, array->len);
	for (i = 0; i < array->len; i++)
		tmp_array[i] = g_array_index (array, int, i);

	nm_keyfile_plugin_kf_set_integer_list (file, nm_setting_get_name (setting), key, tmp_array, array->len);
	g_free (tmp_array);
}

static void
dns_writer (KeyfileWriterInfo *info,
            NMSetting *setting,
            const char *key,
            const GValue *value)
{
	char **list;

	list = g_value_get_boxed (value);
	if (list && list[0]) {
		nm_keyfile_plugin_kf_set_string_list (info->keyfile, nm_setting_get_name (setting), key,
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
addr_writer (KeyfileWriterInfo *info,
             NMSetting *setting,
             const char *key,
             const GValue *value)
{
	GPtrArray *array;
	const char *setting_name = nm_setting_get_name (setting);
	const char *gateway = nm_setting_ip_config_get_gateway (NM_SETTING_IP_CONFIG (setting));

	array = (GPtrArray *) g_value_get_boxed (value);
	if (array && array->len)
		write_ip_values (info->keyfile, setting_name, array, gateway, FALSE);
}

static void
ip4_addr_label_writer (KeyfileWriterInfo *info,
                       NMSetting *setting,
                       const char *key,
                       const GValue *value)
{
	/* skip */
}

static void
gateway_writer (KeyfileWriterInfo *info,
                NMSetting *setting,
                const char *key,
                const GValue *value)
{
	/* skip */
}

static void
route_writer (KeyfileWriterInfo *info,
              NMSetting *setting,
              const char *key,
              const GValue *value)
{
	GPtrArray *array;
	const char *setting_name = nm_setting_get_name (setting);

	array = (GPtrArray *) g_value_get_boxed (value);
	if (array && array->len)
		write_ip_values (info->keyfile, setting_name, array, NULL, TRUE);
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
ssid_writer (KeyfileWriterInfo *info,
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
		nm_keyfile_plugin_kf_set_string (info->keyfile, setting_name, key, ssid);
		g_free (ssid);
	} else {
		tmp_array = g_new (gint, ssid_len);
		for (i = 0; i < ssid_len; i++)
			tmp_array[i] = (int) ssid_data[i];
		nm_keyfile_plugin_kf_set_integer_list (info->keyfile, setting_name, key, tmp_array, ssid_len);
		g_free (tmp_array);
	}
}

static void
password_raw_writer (KeyfileWriterInfo *info,
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
	nm_keyfile_plugin_kf_set_integer_list (info->keyfile, setting_name, key, tmp_array, len);
	g_free (tmp_array);
}

typedef struct ObjectType {
	const char *key;
	const char *suffix;
	NMSetting8021xCKScheme (*scheme_func) (NMSetting8021x *setting);
	NMSetting8021xCKFormat (*format_func) (NMSetting8021x *setting);
	const char *           (*path_func)   (NMSetting8021x *setting);
	GBytes *               (*blob_func)   (NMSetting8021x *setting);
} ObjectType;

static const ObjectType objtypes[10] = {
	{ NM_SETTING_802_1X_CA_CERT,
	  "ca-cert",
	  nm_setting_802_1x_get_ca_cert_scheme,
	  NULL,
	  nm_setting_802_1x_get_ca_cert_path,
	  nm_setting_802_1x_get_ca_cert_blob },

	{ NM_SETTING_802_1X_PHASE2_CA_CERT,
	  "inner-ca-cert",
	  nm_setting_802_1x_get_phase2_ca_cert_scheme,
	  NULL,
	  nm_setting_802_1x_get_phase2_ca_cert_path,
	  nm_setting_802_1x_get_phase2_ca_cert_blob },

	{ NM_SETTING_802_1X_CLIENT_CERT,
	  "client-cert",
	  nm_setting_802_1x_get_client_cert_scheme,
	  NULL,
	  nm_setting_802_1x_get_client_cert_path,
	  nm_setting_802_1x_get_client_cert_blob },

	{ NM_SETTING_802_1X_PHASE2_CLIENT_CERT,
	  "inner-client-cert",
	  nm_setting_802_1x_get_phase2_client_cert_scheme,
	  NULL,
	  nm_setting_802_1x_get_phase2_client_cert_path,
	  nm_setting_802_1x_get_phase2_client_cert_blob },

	{ NM_SETTING_802_1X_PRIVATE_KEY,
	  "private-key",
	  nm_setting_802_1x_get_private_key_scheme,
	  nm_setting_802_1x_get_private_key_format,
	  nm_setting_802_1x_get_private_key_path,
	  nm_setting_802_1x_get_private_key_blob },

	{ NM_SETTING_802_1X_PHASE2_PRIVATE_KEY,
	  "inner-private-key",
	  nm_setting_802_1x_get_phase2_private_key_scheme,
	  nm_setting_802_1x_get_phase2_private_key_format,
	  nm_setting_802_1x_get_phase2_private_key_path,
	  nm_setting_802_1x_get_phase2_private_key_blob },

	{ NULL },
};

/**************************************************************************/

static void
cert_writer_default (NMConnection *connection,
                     GKeyFile *file,
                     NMKeyfileWriteTypeDataCert *cert_data)
{
	const char *setting_name = nm_setting_get_name (NM_SETTING (cert_data->setting));
	NMSetting8021xCKScheme scheme;

	scheme = cert_data->scheme_func (cert_data->setting);
	if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH) {
		const char *path;
		char *path_free = NULL, *tmp;
		gs_free char *base_dir = NULL;

		path = cert_data->path_func (cert_data->setting);
		g_assert (path);

		/* If the path is relative, make it an absolute path.
		 * Relative paths make a keyfile not easily usable in another
		 * context. */
		if (path[0] && path[0] != '/') {
			base_dir = g_get_current_dir ();
			path = path_free = g_strconcat (base_dir, "/", path, NULL);
		} else
			base_dir = g_path_get_dirname (path);

		/* path cannot start with "file://" or "data:;base64,", because it is an absolute path.
		 * Still, make sure that a prefix-less path will be recognized. This can happen
		 * for example if the path is longer then 500 chars. */
		tmp = nm_keyfile_detect_unqualified_path_scheme (base_dir, path, -1, FALSE, NULL);
		if (tmp)
			g_clear_pointer (&tmp, g_free);
		else
			path = tmp = g_strconcat (NM_KEYFILE_CERT_SCHEME_PREFIX_PATH, path, NULL);

		/* Path contains at least a '/', hence it cannot be recognized as the old
		 * binary format consisting of a list of integers. */

		nm_keyfile_plugin_kf_set_string (file, setting_name, cert_data->property_name, path);
		g_free (tmp);
		g_free (path_free);
	} else if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB) {
		GBytes *blob;
		const guint8 *blob_data;
		gsize blob_len;
		char *blob_base64, *val;

		blob = cert_data->blob_func (cert_data->setting);
		g_assert (blob);
		blob_data = g_bytes_get_data (blob, &blob_len);

		blob_base64 = g_base64_encode (blob_data, blob_len);
		val = g_strconcat (NM_KEYFILE_CERT_SCHEME_PREFIX_BLOB, blob_base64, NULL);

		nm_keyfile_plugin_kf_set_string (file, setting_name, cert_data->property_name, val);
		g_free (val);
		g_free (blob_base64);
	} else {
		/* scheme_func() returns UNKNOWN in all other cases. The only valid case
		 * where a scheme is allowed to be UNKNOWN, is unsetting the value. In this
		 * case, we don't expect the writer to be called, because the default value
		 * will not be serialized.
		 * The only other reason for the scheme to be UNKNOWN is an invalid cert.
		 * But our connection verifies, so that cannot happen either. */
		g_return_if_reached ();
	}
}

static void
cert_writer (KeyfileWriterInfo *info,
             NMSetting *setting,
             const char *key,
             const GValue *value)
{
	const ObjectType *objtype = NULL;
	guint i;
	NMKeyfileWriteTypeDataCert type_data = { 0 };

	for (i = 0; i < G_N_ELEMENTS (objtypes) && objtypes[i].key; i++) {
		if (g_strcmp0 (objtypes[i].key, key) == 0) {
			objtype = &objtypes[i];
			break;
		}
	}
	if (!objtype)
		g_return_if_reached ();

	type_data.setting = NM_SETTING_802_1X (setting);
	type_data.property_name = key;
	type_data.suffix = objtype->suffix;
	type_data.scheme_func = objtype->scheme_func;
	type_data.format_func = objtype->format_func;
	type_data.path_func = objtype->path_func;
	type_data.blob_func = objtype->blob_func;

	if (info->handler) {
		if (info->handler (info->connection,
		                   info->keyfile,
		                   NM_KEYFILE_WRITE_TYPE_CERT,
		                   &type_data,
		                   info->user_data,
		                   &info->error))
			return;
		if (info->error)
			return;
	}

	cert_writer_default (info->connection, info->keyfile, &type_data);
}

/**************************************************************************/

typedef struct {
	const char *setting_name;
	const char *key;
	void (*writer) (KeyfileWriterInfo *info,
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

static void
write_setting_value (NMSetting *setting,
                     const char *key,
                     const GValue *value,
                     GParamFlags flag,
                     gpointer user_data)
{
	KeyfileWriterInfo *info = user_data;
	const char *setting_name;
	GType type = G_VALUE_TYPE (value);
	KeyWriter *writer = &key_writers[0];
	GParamSpec *pspec;

	if (info->error)
		return;

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
			(*writer->writer) (info, setting, key, value);
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
		write_array_of_uint (info->keyfile, setting, key, value);
	} else if (G_VALUE_HOLDS_FLAGS (value)) {
		/* Flags are guint but GKeyFile has no uint reader, just uint64 */
		nm_keyfile_plugin_kf_set_uint64 (info->keyfile, setting_name, key, (guint64) g_value_get_flags (value));
	} else if (G_VALUE_HOLDS_ENUM (value))
		nm_keyfile_plugin_kf_set_integer (info->keyfile, setting_name, key, (gint) g_value_get_enum (value));
	else
		g_warn_if_reached ();
}

GKeyFile *
nm_keyfile_write (NMConnection *connection,
                  NMKeyfileWriteHandler handler,
                  void *user_data,
                  GError **error)
{
	KeyfileWriterInfo info = { 0 };

	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);
	g_return_val_if_fail (!error || !*error, NULL);

	if (!nm_connection_verify (connection, error))
		return NULL;

	info.connection = connection;
	info.keyfile = g_key_file_new ();
	info.error = NULL;
	info.handler = handler;
	info.user_data = user_data;
	nm_connection_for_each_setting_value (connection, write_setting_value, &info);

	if (info.error) {
		g_propagate_error (error, info.error);
		g_key_file_unref (info.keyfile);
		return NULL;
	}
	return info.keyfile;
}

