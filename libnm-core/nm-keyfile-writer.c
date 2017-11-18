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
 * Copyright (C) 2008 - 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-keyfile-internal.h"

#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <arpa/inet.h>
#include <string.h>

#include "nm-core-internal.h"
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
 * encryption.  This function handles translating those properties' values
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
	guint i;
	gs_free int *tmp_array = NULL;

	array = (GArray *) g_value_get_boxed (value);
	if (!array || !array->len)
		return;

	g_return_if_fail (g_array_get_element_size (array) == sizeof (guint));

	tmp_array = g_new (gint, array->len);
	for (i = 0; i < array->len; i++) {
		guint v = g_array_index (array, guint, i);

		if (v > G_MAXINT)
			g_return_if_reached ();
		tmp_array[i] = (int) v;
	}

	nm_keyfile_plugin_kf_set_integer_list (file, nm_setting_get_name (setting), key, tmp_array, array->len);
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
ip6_addr_gen_mode_writer (KeyfileWriterInfo *info,
                          NMSetting *setting,
                          const char *key,
                          const GValue *value)
{
	NMSettingIP6ConfigAddrGenMode addr_gen_mode;
	gs_free char *str = NULL;

	addr_gen_mode = (NMSettingIP6ConfigAddrGenMode) g_value_get_int (value);
	str = nm_utils_enum_to_str (nm_setting_ip6_config_addr_gen_mode_get_type (),
	                            addr_gen_mode);
	nm_keyfile_plugin_kf_set_string (info->keyfile,
	                                 nm_setting_get_name (setting),
	                                 key,
	                                 str);
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
	guint32 plen;
	char key_name[64], *key_name_idx;

	if (!array->len)
		return;

	family = !strcmp (setting_name, NM_SETTING_IP4_CONFIG_SETTING_NAME) ? AF_INET : AF_INET6;

	strcpy (key_name, is_route ? "route" : "address");
	key_name_idx = key_name + strlen (key_name);

	output = g_string_sized_new (2*INET_ADDRSTRLEN + 10);
	for (i = 0; i < array->len; i++) {
		gint64 metric = -1;

		if (is_route) {
			NMIPRoute *route = array->pdata[i];

			addr = nm_ip_route_get_dest (route);
			plen = nm_ip_route_get_prefix (route);
			gw = nm_ip_route_get_next_hop (route);
			metric = nm_ip_route_get_metric (route);
		} else {
			NMIPAddress *address = array->pdata[i];

			addr = nm_ip_address_get_address (address);
			plen = nm_ip_address_get_prefix (address);
			gw = i == 0 ? gateway : NULL;
		}

		g_string_set_size (output, 0);
		g_string_append_printf (output, "%s/%u", addr, plen);
		if (   metric != -1
		    || gw) {
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
			if (is_route && metric != -1)
				g_string_append_printf (output, ",%lu", (unsigned long) metric);
		}

		sprintf (key_name_idx, "%d", i + 1);
		nm_keyfile_plugin_kf_set_string (file, setting_name, key_name, output->str);

		if (is_route) {
			gs_free char *attributes = NULL;
			GHashTable *hash;

			hash = _nm_ip_route_get_attributes_direct (array->pdata[i]);
			attributes = nm_utils_format_variant_attributes (hash, ',', '=');
			if (attributes) {
				g_strlcat (key_name, "_options", sizeof (key_name));
				nm_keyfile_plugin_kf_set_string (file, setting_name, key_name, attributes);
			}
		}
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
qdisc_writer (KeyfileWriterInfo *info,
              NMSetting *setting,
              const char *key,
              const GValue *value)
{
	gsize i;
	GPtrArray *array;

	array = (GPtrArray *) g_value_get_boxed (value);
	if (!array || !array->len)
		return;

	for (i = 0; i < array->len; i++) {
		NMTCQdisc *qdisc = array->pdata[i];
		GString *key_name = g_string_sized_new (16);
		GString *value_str = g_string_sized_new (60);

		g_string_append (key_name, "qdisc.");
		_nm_utils_string_append_tc_parent (key_name, NULL,
		                                   nm_tc_qdisc_get_parent (qdisc));
		_nm_utils_string_append_tc_qdisc_rest (value_str, qdisc);

		nm_keyfile_plugin_kf_set_string (info->keyfile,
		                                 NM_SETTING_TC_CONFIG_SETTING_NAME,
		                                 key_name->str,
		                                 value_str->str);

		g_string_free (key_name, TRUE);
		g_string_free (value_str, TRUE);
	}
}

static void
tfilter_writer (KeyfileWriterInfo *info,
              NMSetting *setting,
              const char *key,
              const GValue *value)
{
	gsize i;
	GPtrArray *array;

	array = (GPtrArray *) g_value_get_boxed (value);
	if (!array || !array->len)
		return;

	for (i = 0; i < array->len; i++) {
		NMTCTfilter *tfilter = array->pdata[i];
		GString *key_name = g_string_sized_new (16);
		GString *value_str = g_string_sized_new (60);

		g_string_append (key_name, "tfilter.");
		_nm_utils_string_append_tc_parent (key_name, NULL,
		                                   nm_tc_tfilter_get_parent (tfilter));
		_nm_utils_string_append_tc_tfilter_rest (value_str, tfilter, NULL);

		nm_keyfile_plugin_kf_set_string (info->keyfile,
		                                 NM_SETTING_TC_CONFIG_SETTING_NAME,
		                                 key_name->str,
		                                 value_str->str);

		g_string_free (key_name, TRUE);
		g_string_free (value_str, TRUE);
	}
}

static void
write_hash_of_string (GKeyFile *file,
                      NMSetting *setting,
                      const char *key,
                      const GValue *value)
{
	GHashTable *hash;
	const char *group_name = nm_setting_get_name (setting);
	gboolean vpn_secrets = FALSE;
	gs_free const char **keys = NULL;
	guint i, l;

	/* Write VPN secrets out to a different group to keep them separate */
	if (NM_IS_SETTING_VPN (setting) && !strcmp (key, NM_SETTING_VPN_SECRETS)) {
		group_name = NM_KEYFILE_GROUP_VPN_SECRETS;
		vpn_secrets = TRUE;
	}

	hash = g_value_get_boxed (value);
	keys = (const char **) g_hash_table_get_keys_as_array (hash, &l);
	if (!keys)
		return;

	g_qsort_with_data (keys, l, sizeof (const char *), nm_strcmp_p_with_data, NULL);

	for (i = 0; keys[i]; i++) {
		const char *property, *data;
		gboolean write_item = TRUE;

		property = keys[i];

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

		if (write_item) {
			gs_free char *to_free = NULL;

			data = g_hash_table_lookup (hash, property);
			nm_keyfile_plugin_kf_set_string (file, group_name,
			                                 nm_keyfile_key_encode (property, &to_free),
			                                 data);
		}
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
	gsize semicolons = 0;
	gsize i;

	g_return_if_fail (G_VALUE_HOLDS (value, G_TYPE_BYTES));

	bytes = g_value_get_boxed (value);
	if (!bytes)
		return;
	ssid_data = g_bytes_get_data (bytes, &ssid_len);
	if (!ssid_data || !ssid_len) {
		nm_keyfile_plugin_kf_set_string (info->keyfile, setting_name, key, "");
		return;
	}

	/* Check whether each byte is printable.  If not, we have to use an
	 * integer list, otherwise we can just use a string.
	 */
	for (i = 0; i < ssid_len; i++) {
		const char c = ssid_data[i];

		if (!g_ascii_isprint (c)) {
			new_format = FALSE;
			break;
		}
		if (c == ';')
			semicolons++;
	}

	if (new_format) {
		gs_free char *ssid = NULL;

		if (semicolons == 0)
			ssid = g_strndup ((char *) ssid_data, ssid_len);
		else {
			/* Escape semicolons with backslashes to make strings
			 * containing ';', such as '16;17;' unambiguous */
			gsize j = 0;

			ssid = g_malloc (ssid_len + semicolons + 1);
			for (i = 0; i < ssid_len; i++) {
				if (ssid_data[i] == ';')
					ssid[j++] = '\\';
				ssid[j++] = ssid_data[i];
			}
			ssid[j] = '\0';
		}
		nm_keyfile_plugin_kf_set_string (info->keyfile, setting_name, key, ssid);
	} else
		nm_keyfile_plugin_kf_set_integer_list_uint8 (info->keyfile, setting_name, key, ssid_data, ssid_len);
}

static void
password_raw_writer (KeyfileWriterInfo *info,
                     NMSetting *setting,
                     const char *key,
                     const GValue *value)
{
	const char *setting_name = nm_setting_get_name (setting);
	GBytes *array;
	gsize len;
	const guint8 *data;

	g_return_if_fail (G_VALUE_HOLDS (value, G_TYPE_BYTES));

	array = (GBytes *) g_value_get_boxed (value);
	if (!array)
		return;
	data = g_bytes_get_data (array, &len);
	if (!data)
		len = 0;
	nm_keyfile_plugin_kf_set_integer_list_uint8 (info->keyfile, setting_name, key, data, len);
}

/*****************************************************************************/

static void
cert_writer_default (NMConnection *connection,
                     GKeyFile *file,
                     NMKeyfileWriteTypeDataCert *cert_data)
{
	const char *setting_name = nm_setting_get_name (NM_SETTING (cert_data->setting));
	NMSetting8021xCKScheme scheme;

	scheme = cert_data->vtable->scheme_func (cert_data->setting);
	if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH) {
		const char *path;
		char *path_free = NULL, *tmp;
		gs_free char *base_dir = NULL;

		path = cert_data->vtable->path_func (cert_data->setting);
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

		nm_keyfile_plugin_kf_set_string (file, setting_name, cert_data->vtable->setting_key, path);
		g_free (tmp);
		g_free (path_free);
	} else if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB) {
		GBytes *blob;
		const guint8 *blob_data;
		gsize blob_len;
		char *blob_base64, *val;

		blob = cert_data->vtable->blob_func (cert_data->setting);
		g_assert (blob);
		blob_data = g_bytes_get_data (blob, &blob_len);

		blob_base64 = g_base64_encode (blob_data, blob_len);
		val = g_strconcat (NM_KEYFILE_CERT_SCHEME_PREFIX_BLOB, blob_base64, NULL);

		nm_keyfile_plugin_kf_set_string (file, setting_name, cert_data->vtable->setting_key, val);
		g_free (val);
		g_free (blob_base64);
	} else if (scheme == NM_SETTING_802_1X_CK_SCHEME_PKCS11) {
		nm_keyfile_plugin_kf_set_string (file, setting_name, cert_data->vtable->setting_key,
		                                 cert_data->vtable->uri_func (cert_data->setting));
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
	const NMSetting8021xSchemeVtable *objtype = NULL;
	guint i;
	NMKeyfileWriteTypeDataCert type_data = { 0 };

	for (i = 0; nm_setting_8021x_scheme_vtable[i].setting_key; i++) {
		if (g_strcmp0 (nm_setting_8021x_scheme_vtable[i].setting_key, key) == 0) {
			objtype = &nm_setting_8021x_scheme_vtable[i];
			break;
		}
	}
	if (!objtype)
		g_return_if_reached ();

	type_data.setting = NM_SETTING_802_1X (setting);
	type_data.vtable = objtype;

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

static void
null_writer (KeyfileWriterInfo *info,
             NMSetting *setting,
             const char *key,
             const GValue *value)
{
	/* skip */
}

/*****************************************************************************/

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
	{ NM_SETTING_IP6_CONFIG_SETTING_NAME,
	  NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE,
	  ip6_addr_gen_mode_writer },
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
	{ NM_SETTING_TC_CONFIG_SETTING_NAME,
	  NM_SETTING_TC_CONFIG_QDISCS,
	  qdisc_writer },
	{ NM_SETTING_TC_CONFIG_SETTING_NAME,
	  NM_SETTING_TC_CONFIG_TFILTERS,
	  tfilter_writer },
	{ NM_SETTING_TEAM_SETTING_NAME,
	  NM_SETTING_TEAM_NOTIFY_PEERS_COUNT,
	  null_writer},
	{ NM_SETTING_TEAM_SETTING_NAME,
	  NM_SETTING_TEAM_NOTIFY_PEERS_INTERVAL,
	  null_writer},
	{ NM_SETTING_TEAM_SETTING_NAME,
	  NM_SETTING_TEAM_MCAST_REJOIN_COUNT,
	  null_writer},
	{ NM_SETTING_TEAM_SETTING_NAME,
	  NM_SETTING_TEAM_MCAST_REJOIN_INTERVAL,
	  null_writer},
	{ NM_SETTING_TEAM_SETTING_NAME,
	  NM_SETTING_TEAM_RUNNER,
	  null_writer},
	{ NM_SETTING_TEAM_SETTING_NAME,
	  NM_SETTING_TEAM_RUNNER_HWADDR_POLICY,
	  null_writer},
	{ NM_SETTING_TEAM_SETTING_NAME,
	  NM_SETTING_TEAM_RUNNER_TX_HASH,
	  null_writer},
	{ NM_SETTING_TEAM_SETTING_NAME,
	  NM_SETTING_TEAM_RUNNER_TX_BALANCER,
	  null_writer},
	{ NM_SETTING_TEAM_SETTING_NAME,
	  NM_SETTING_TEAM_RUNNER_TX_BALANCER_INTERVAL,
	  null_writer},
	{ NM_SETTING_TEAM_SETTING_NAME,
	  NM_SETTING_TEAM_RUNNER_ACTIVE,
	  null_writer},
	{ NM_SETTING_TEAM_SETTING_NAME,
	  NM_SETTING_TEAM_RUNNER_FAST_RATE,
	  null_writer},
	{ NM_SETTING_TEAM_SETTING_NAME,
	  NM_SETTING_TEAM_RUNNER_SYS_PRIO,
	  null_writer},
	{ NM_SETTING_TEAM_SETTING_NAME,
	  NM_SETTING_TEAM_RUNNER_MIN_PORTS,
	  null_writer},
	{ NM_SETTING_TEAM_SETTING_NAME,
	  NM_SETTING_TEAM_RUNNER_AGG_SELECT_POLICY,
	  null_writer},
	{ NM_SETTING_TEAM_SETTING_NAME,
	  NM_SETTING_TEAM_LINK_WATCHERS,
	  null_writer},
	{ NM_SETTING_TEAM_PORT_SETTING_NAME,
	  NM_SETTING_TEAM_PORT_QUEUE_ID,
	  null_writer},
	{ NM_SETTING_TEAM_PORT_SETTING_NAME,
	  NM_SETTING_TEAM_PORT_PRIO,
	  null_writer},
	{ NM_SETTING_TEAM_PORT_SETTING_NAME,
	  NM_SETTING_TEAM_PORT_STICKY,
	  null_writer},
	{ NM_SETTING_TEAM_PORT_SETTING_NAME,
	  NM_SETTING_TEAM_PORT_LACP_PRIO,
	  null_writer},
	{ NM_SETTING_TEAM_PORT_SETTING_NAME,
	  NM_SETTING_TEAM_PORT_LACP_KEY,
	  null_writer},
	{ NM_SETTING_TEAM_PORT_SETTING_NAME,
	  NM_SETTING_TEAM_PORT_LINK_WATCHERS,
	  null_writer},
	{ NULL, NULL, NULL }
};

static gboolean
can_omit_default_value (NMSetting *setting, const char *property)
{
	if (NM_IS_SETTING_VLAN (setting)) {
		if (!strcmp (property, NM_SETTING_VLAN_FLAGS))
			return FALSE;
	} else if (NM_IS_SETTING_IP6_CONFIG (setting)) {
		if (!strcmp (property, NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE))
			return FALSE;
	}

	return TRUE;
}

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
		if (   can_omit_default_value (setting, key)
		    && g_param_value_defaults (pspec, (GValue *) value)) {
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

		if (data != NULL && len > 0)
			nm_keyfile_plugin_kf_set_integer_list_uint8 (info->keyfile, setting_name, key, data, len);
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

