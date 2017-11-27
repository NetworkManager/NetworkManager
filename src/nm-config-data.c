/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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
 * Copyright (C) 2011 Red Hat, Inc.
 * Copyright (C) 2013 Thomas Bechtold <thomasbechtold@jpberlin.de>
 */

#include "nm-default.h"

#include "nm-config-data.h"

#include <string.h>

#include "nm-config.h"
#include "devices/nm-device.h"
#include "nm-core-internal.h"
#include "nm-keyfile-internal.h"

/*****************************************************************************/

typedef struct {
	char *group_name;
	gboolean stop_match;
	struct {
		/* have a separate boolean field @has, because a @spec with
		 * value %NULL does not necessarily mean, that the property
		 * "match-device" was unspecified. */
		gboolean has;
		GSList *spec;
	} match_device;
} MatchSectionInfo;

struct _NMGlobalDnsDomain {
	char *name;
	char **servers;
	char **options;
};

struct _NMGlobalDnsConfig {
	char **searches;
	char **options;
	GHashTable *domains;
	char **domain_list;
	gboolean internal;
};

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_CONFIG_MAIN_FILE,
	PROP_CONFIG_DESCRIPTION,
	PROP_KEYFILE_USER,
	PROP_KEYFILE_INTERN,
	PROP_CONNECTIVITY_ENABLED,
	PROP_CONNECTIVITY_URI,
	PROP_CONNECTIVITY_INTERVAL,
	PROP_CONNECTIVITY_RESPONSE,
	PROP_NO_AUTO_DEFAULT,
);

typedef struct {
	char *config_main_file;
	char *config_description;

	GKeyFile *keyfile;
	GKeyFile *keyfile_user;
	GKeyFile *keyfile_intern;

	/* A zero-terminated list of pre-processed information from the
	 * [connection] sections. This is to speed up lookup. */
	MatchSectionInfo *connection_infos;

	/* A zero-terminated list of pre-processed information from the
	 * [device] sections. This is to speed up lookup. */
	MatchSectionInfo *device_infos;

	struct {
		gboolean enabled;
		char *uri;
		char *response;
		guint interval;
	} connectivity;

	int autoconnect_retries_default;

	struct {
		char **arr;
		GSList *specs;
		GSList *specs_config;
	} no_auto_default;

	GSList *ignore_carrier;
	GSList *assume_ipv6ll_only;

	char *dns_mode;
	char *rc_manager;

	NMGlobalDnsConfig *global_dns;
} NMConfigDataPrivate;

struct _NMConfigData {
	GObject parent;
	NMConfigDataPrivate _priv;
};

struct _NMConfigDataClass {
	GObjectClass parent;
};

G_DEFINE_TYPE (NMConfigData, nm_config_data, G_TYPE_OBJECT)

#define NM_CONFIG_DATA_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMConfigData, NM_IS_CONFIG_DATA)

/*****************************************************************************/

#define _HAS_PREFIX(str, prefix) \
	({ \
		const char *_str = (str); \
		g_str_has_prefix ( _str, ""prefix"") && _str[NM_STRLEN(prefix)] != '\0'; \
	})

/*****************************************************************************/

const char *
nm_config_data_get_config_main_file (const NMConfigData *self)
{
	g_return_val_if_fail (self, NULL);

	return NM_CONFIG_DATA_GET_PRIVATE (self)->config_main_file;
}

const char *
nm_config_data_get_config_description (const NMConfigData *self)
{
	g_return_val_if_fail (self, NULL);

	return NM_CONFIG_DATA_GET_PRIVATE (self)->config_description;
}

gboolean
nm_config_data_has_group (const NMConfigData *self, const char *group)
{
	g_return_val_if_fail (NM_IS_CONFIG_DATA (self), FALSE);
	g_return_val_if_fail (group && *group, FALSE);

	return g_key_file_has_group (NM_CONFIG_DATA_GET_PRIVATE (self)->keyfile, group);
}

char *
nm_config_data_get_value (const NMConfigData *self, const char *group, const char *key, NMConfigGetValueFlags flags)
{
	g_return_val_if_fail (NM_IS_CONFIG_DATA (self), NULL);
	g_return_val_if_fail (group && *group, NULL);
	g_return_val_if_fail (key && *key, NULL);

	return nm_config_keyfile_get_value (NM_CONFIG_DATA_GET_PRIVATE (self)->keyfile, group, key, flags);
}

gboolean
nm_config_data_has_value (const NMConfigData *self, const char *group, const char *key, NMConfigGetValueFlags flags)
{
	gs_free char *value = NULL;

	g_return_val_if_fail (NM_IS_CONFIG_DATA (self), FALSE);
	g_return_val_if_fail (group && *group, FALSE);
	g_return_val_if_fail (key && *key, FALSE);

	value = nm_config_keyfile_get_value (NM_CONFIG_DATA_GET_PRIVATE (self)->keyfile, group, key, flags);
	return !!value;
}

gint
nm_config_data_get_value_boolean (const NMConfigData *self, const char *group, const char *key, gint default_value)
{
	char *str;
	gint value = default_value;

	g_return_val_if_fail (NM_IS_CONFIG_DATA (self), default_value);
	g_return_val_if_fail (group && *group, default_value);
	g_return_val_if_fail (key && *key, default_value);

	/* when parsing the boolean, base it on the raw value from g_key_file_get_value(). */
	str = nm_config_keyfile_get_value (NM_CONFIG_DATA_GET_PRIVATE (self)->keyfile, group, key, NM_CONFIG_GET_VALUE_RAW);
	if (str) {
		value = nm_config_parse_boolean (str, default_value);
		g_free (str);
	}
	return value;
}

gint64
nm_config_data_get_value_int64 (const NMConfigData *self, const char *group, const char *key, guint base, gint64 min, gint64 max, gint64 fallback)
{
	int errsv;
	gint64 val;
	char *str;

	g_return_val_if_fail (NM_IS_CONFIG_DATA (self), fallback);
	g_return_val_if_fail (group && *group, fallback);
	g_return_val_if_fail (key && *key, fallback);

	str = nm_config_keyfile_get_value (NM_CONFIG_DATA_GET_PRIVATE (self)->keyfile, group, key, NM_CONFIG_GET_VALUE_NONE);
	val = _nm_utils_ascii_str_to_int64 (str, base, min, max, fallback);
	if (str) {
		/* preserve errno from the parsing. */
		errsv = errno;
		g_free (str);
		errno = errsv;
	}
	return val;
}

char **
nm_config_data_get_plugins (const NMConfigData *self, gboolean allow_default)
{
	const NMConfigDataPrivate *priv;
	char **list;

	g_return_val_if_fail (self, NULL);

	priv = NM_CONFIG_DATA_GET_PRIVATE (self);

	list = g_key_file_get_string_list (priv->keyfile, NM_CONFIG_KEYFILE_GROUP_MAIN, "plugins", NULL, NULL);
	if (!list && allow_default) {
		gs_unref_keyfile GKeyFile *kf = nm_config_create_keyfile ();

		/* let keyfile split the default string according to it's own escaping rules. */
		g_key_file_set_value (kf, NM_CONFIG_KEYFILE_GROUP_MAIN, "plugins", NM_CONFIG_DEFAULT_MAIN_PLUGINS);
		list = g_key_file_get_string_list (kf, NM_CONFIG_KEYFILE_GROUP_MAIN, "plugins", NULL, NULL);
	}
	return _nm_utils_strv_cleanup (list, TRUE, TRUE, TRUE);
}

gboolean
nm_config_data_get_connectivity_enabled (const NMConfigData *self)
{
	g_return_val_if_fail (self, FALSE);

	return NM_CONFIG_DATA_GET_PRIVATE (self)->connectivity.enabled;
}

const char *
nm_config_data_get_connectivity_uri (const NMConfigData *self)
{
	g_return_val_if_fail (self, NULL);

	return NM_CONFIG_DATA_GET_PRIVATE (self)->connectivity.uri;
}

guint
nm_config_data_get_connectivity_interval (const NMConfigData *self)
{
	g_return_val_if_fail (self, 0);

	return NM_CONFIG_DATA_GET_PRIVATE (self)->connectivity.interval;
}

const char *
nm_config_data_get_connectivity_response (const NMConfigData *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return NM_CONFIG_DATA_GET_PRIVATE (self)->connectivity.response;
}

int
nm_config_data_get_autoconnect_retries_default (const NMConfigData *self)
{
	g_return_val_if_fail (self, FALSE);

	return NM_CONFIG_DATA_GET_PRIVATE (self)->autoconnect_retries_default;
}

const char *const*
nm_config_data_get_no_auto_default (const NMConfigData *self)
{
	g_return_val_if_fail (self, FALSE);

	return (const char *const*) NM_CONFIG_DATA_GET_PRIVATE (self)->no_auto_default.arr;
}

gboolean
nm_config_data_get_no_auto_default_for_device (const NMConfigData *self, NMDevice *device)
{
	const NMConfigDataPrivate *priv;

	g_return_val_if_fail (NM_IS_CONFIG_DATA (self), FALSE);
	g_return_val_if_fail (NM_IS_DEVICE (device), FALSE);

	priv = NM_CONFIG_DATA_GET_PRIVATE (self);
	return    nm_device_spec_match_list (device, priv->no_auto_default.specs)
	       || nm_device_spec_match_list (device, priv->no_auto_default.specs_config);
}

const char *
nm_config_data_get_dns_mode (const NMConfigData *self)
{
	g_return_val_if_fail (self, NULL);

	return NM_CONFIG_DATA_GET_PRIVATE (self)->dns_mode;
}

const char *
nm_config_data_get_rc_manager (const NMConfigData *self)
{
	g_return_val_if_fail (self, NULL);

	return NM_CONFIG_DATA_GET_PRIVATE (self)->rc_manager;
}

gboolean
nm_config_data_get_ignore_carrier (const NMConfigData *self, NMDevice *device)
{
	gs_free char *value = NULL;
	gboolean has_match;
	int m;

	g_return_val_if_fail (NM_IS_CONFIG_DATA (self), FALSE);
	g_return_val_if_fail (NM_IS_DEVICE (device), FALSE);

	value = nm_config_data_get_device_config (self, NM_CONFIG_KEYFILE_KEY_DEVICE_IGNORE_CARRIER, device, &has_match);
	if (has_match)
		m = nm_config_parse_boolean (value, -1);
	else
		m = nm_device_spec_match_list_full (device, NM_CONFIG_DATA_GET_PRIVATE (self)->ignore_carrier, -1);

	if (NM_IN_SET (m, TRUE, FALSE))
		return m;

	/* if ignore-carrier is not explicitly configed, then it depends on the device (type). */
	return nm_device_ignore_carrier_by_default (device);
}

gboolean
nm_config_data_get_assume_ipv6ll_only (const NMConfigData *self, NMDevice *device)
{
	g_return_val_if_fail (NM_IS_CONFIG_DATA (self), FALSE);
	g_return_val_if_fail (NM_IS_DEVICE (device), FALSE);

	return nm_device_spec_match_list (device, NM_CONFIG_DATA_GET_PRIVATE (self)->assume_ipv6ll_only);
}

GKeyFile *
nm_config_data_clone_keyfile_intern (const NMConfigData *self)
{
	const NMConfigDataPrivate *priv;
	GKeyFile *keyfile;

	g_return_val_if_fail (NM_IS_CONFIG_DATA (self), FALSE);

	priv = NM_CONFIG_DATA_GET_PRIVATE (self);

	keyfile = nm_config_create_keyfile ();
	if (priv->keyfile_intern)
		_nm_keyfile_copy (keyfile, priv->keyfile_intern);
	return keyfile;
}

GKeyFile *
_nm_config_data_get_keyfile (const NMConfigData *self)
{
	return NM_CONFIG_DATA_GET_PRIVATE (self)->keyfile;
}

GKeyFile *
_nm_config_data_get_keyfile_intern (const NMConfigData *self)
{
	return NM_CONFIG_DATA_GET_PRIVATE (self)->keyfile_intern;
}

GKeyFile *
_nm_config_data_get_keyfile_user (const NMConfigData *self)
{
	return NM_CONFIG_DATA_GET_PRIVATE (self)->keyfile_user;
}

/*****************************************************************************/

/**
 * nm_config_data_get_groups:
 * @self: the #NMConfigData instance
 *
 * Returns: (transfer full): the list of groups in the configuration. The order
 * of the section is undefined, as the configuration gets merged from multiple
 * sources.
 */
char **
nm_config_data_get_groups (const NMConfigData *self)
{
	g_return_val_if_fail (NM_IS_CONFIG_DATA (self), NULL);

	return g_key_file_get_groups (NM_CONFIG_DATA_GET_PRIVATE (self)->keyfile, NULL);
}

char **
nm_config_data_get_keys (const NMConfigData *self, const char *group)
{
	g_return_val_if_fail (NM_IS_CONFIG_DATA (self), NULL);
	g_return_val_if_fail (group && *group, NULL);

	return g_key_file_get_keys (NM_CONFIG_DATA_GET_PRIVATE (self)->keyfile, group, NULL, NULL);
}

/**
 * nm_config_data_is_intern_atomic_group:
 * @self:
 * @group: name of the group to check.
 *
 * whether a configuration group @group exists and is entirely overwritten
 * by internal configuration, i.e. whether it is an atomic group that is
 * overwritten.
 *
 * It doesn't say, that there actually is a user setting that was overwritten. That
 * means there could be no corresponding section defined in user configuration
 * that required overwriting.
 *
 * Returns: %TRUE if @group exists and is an atomic group set via internal configuration.
 */
gboolean
nm_config_data_is_intern_atomic_group (const NMConfigData *self, const char *group)
{
	const NMConfigDataPrivate *priv;

	g_return_val_if_fail (NM_IS_CONFIG_DATA (self), FALSE);
	g_return_val_if_fail (group && *group, FALSE);

	priv = NM_CONFIG_DATA_GET_PRIVATE (self);

	if (   !priv->keyfile_intern
	    || !g_key_file_has_key (priv->keyfile_intern, group, NM_CONFIG_KEYFILE_KEY_ATOMIC_SECTION_WAS, NULL))
		return FALSE;

	/* we have a .was entry for the section. That means that the section would be overwritten
	 * from user configuration. But it doesn't mean that the merged configuration contains this
	 * groups, because the internal setting could hide the user section.
	 * Only return TRUE, if we actually have such a group in the merged configuration.*/
	return g_key_file_has_group (priv->keyfile, group);
}

/*****************************************************************************/

static GKeyFile *
_merge_keyfiles (GKeyFile *keyfile_user, GKeyFile *keyfile_intern)
{
	gs_strfreev char **groups = NULL;
	guint g, k;
	GKeyFile *keyfile;
	gsize ngroups;

	keyfile = nm_config_create_keyfile ();
	if (keyfile_user)
		_nm_keyfile_copy (keyfile, keyfile_user);
	if (!keyfile_intern)
		return keyfile;

	groups = g_key_file_get_groups (keyfile_intern, &ngroups);
	if (!groups)
		return keyfile;

	/* we must reverse the order of the connection settings so that we
	 * have lowest priority last. */
	_nm_config_sort_groups (groups, ngroups);
	for (g = 0; groups[g]; g++) {
		const char *group = groups[g];
		gs_strfreev char **keys = NULL;
		gboolean is_intern, is_atomic = FALSE;

		keys = g_key_file_get_keys (keyfile_intern, group, NULL, NULL);
		if (!keys)
			continue;

		is_intern = g_str_has_prefix (group, NM_CONFIG_KEYFILE_GROUPPREFIX_INTERN);
		if (   !is_intern
		    && g_key_file_has_key (keyfile_intern, group, NM_CONFIG_KEYFILE_KEY_ATOMIC_SECTION_WAS, NULL)) {
			/* the entire section is atomically overwritten by @keyfile_intern. */
			g_key_file_remove_group (keyfile, group, NULL);
			is_atomic = TRUE;
		}

		for (k = 0; keys[k]; k++) {
			const char *key = keys[k];
			gs_free char *value = NULL;

			if (is_atomic && strcmp (key, NM_CONFIG_KEYFILE_KEY_ATOMIC_SECTION_WAS) == 0)
				continue;

			if (   !is_intern && !is_atomic
			    && _HAS_PREFIX (key, NM_CONFIG_KEYFILE_KEYPREFIX_WAS)) {
				const char *key_base = &key[NM_STRLEN (NM_CONFIG_KEYFILE_KEYPREFIX_WAS)];

				if (!g_key_file_has_key (keyfile_intern, group, key_base, NULL))
					g_key_file_remove_key (keyfile, group, key_base, NULL);
				continue;
			}
			if (!is_intern && !is_atomic && _HAS_PREFIX (key, NM_CONFIG_KEYFILE_KEYPREFIX_SET))
				continue;

			value = g_key_file_get_value (keyfile_intern, group, key, NULL);
			g_key_file_set_value (keyfile, group, key, value);
		}
	}
	return keyfile;
}

/*****************************************************************************/

static int
_nm_config_data_log_sort (const char **pa, const char **pb, gpointer dummy)
{
	gboolean a_is_connection, b_is_connection;
	gboolean a_is_device, b_is_device;
	gboolean a_is_intern, b_is_intern;
	gboolean a_is_main, b_is_main;
	const char *a = *pa;
	const char *b = *pb;

	/* we sort intern groups to the end. */
	a_is_intern = g_str_has_prefix (a, NM_CONFIG_KEYFILE_GROUPPREFIX_INTERN);
	b_is_intern = g_str_has_prefix (b, NM_CONFIG_KEYFILE_GROUPPREFIX_INTERN);

	if (a_is_intern && b_is_intern)
		return 0;
	if (a_is_intern)
		return 1;
	if (b_is_intern)
		return -1;

	/* we sort connection groups before intern groups (to the end). */
	a_is_connection = a && g_str_has_prefix (a, NM_CONFIG_KEYFILE_GROUPPREFIX_CONNECTION);
	b_is_connection = b && g_str_has_prefix (b, NM_CONFIG_KEYFILE_GROUPPREFIX_CONNECTION);

	if (a_is_connection && b_is_connection) {
		/* if both are connection groups, we want the explicit [connection] group first. */
		a_is_connection = a[NM_STRLEN (NM_CONFIG_KEYFILE_GROUPPREFIX_CONNECTION)] == '\0';
		b_is_connection = b[NM_STRLEN (NM_CONFIG_KEYFILE_GROUPPREFIX_CONNECTION)] == '\0';

		if (a_is_connection != b_is_connection) {
			if (a_is_connection)
				return -1;
			return 1;
		}
		/* the sections are ordered lowest-priority first. Reverse their order. */
		return pa < pb ? 1 : -1;
	}
	if (a_is_connection && !b_is_connection)
		return 1;
	if (b_is_connection && !a_is_connection)
		return -1;

	/* we sort device groups before connection groups (to the end). */
	a_is_device = a && g_str_has_prefix (a, NM_CONFIG_KEYFILE_GROUPPREFIX_DEVICE);
	b_is_device = b && g_str_has_prefix (b, NM_CONFIG_KEYFILE_GROUPPREFIX_DEVICE);

	if (a_is_device && b_is_device) {
		/* if both are device groups, we want the explicit [device] group first. */
		a_is_device = a[NM_STRLEN (NM_CONFIG_KEYFILE_GROUPPREFIX_DEVICE)] == '\0';
		b_is_device = b[NM_STRLEN (NM_CONFIG_KEYFILE_GROUPPREFIX_DEVICE)] == '\0';

		if (a_is_device != b_is_device) {
			if (a_is_device)
				return -1;
			return 1;
		}
		/* the sections are ordered lowest-priority first. Reverse their order. */
		return pa < pb ? 1 : -1;
	}
	if (a_is_device && !b_is_device)
		return 1;
	if (b_is_device && !a_is_device)
		return -1;

	a_is_main = nm_streq0 (a, "main");
	b_is_main = nm_streq0 (b, "main");
	if (a_is_main != b_is_main)
		return a_is_main ? -1 : 1;

	return g_strcmp0 (a, b);
}

static const struct {
	const char *group;
	const char *key;
	const char *value;
} default_values[] = {
	{ NM_CONFIG_KEYFILE_GROUP_MAIN,    "plugins",                              NM_CONFIG_DEFAULT_MAIN_PLUGINS },
	{ NM_CONFIG_KEYFILE_GROUP_MAIN,    "rc-manager",                           NM_CONFIG_DEFAULT_MAIN_RC_MANAGER },
	{ NM_CONFIG_KEYFILE_GROUP_MAIN,    NM_CONFIG_KEYFILE_KEY_MAIN_AUTH_POLKIT, NM_CONFIG_DEFAULT_MAIN_AUTH_POLKIT },
	{ NM_CONFIG_KEYFILE_GROUP_MAIN,    NM_CONFIG_KEYFILE_KEY_MAIN_DHCP,        NM_CONFIG_DEFAULT_MAIN_DHCP },
	{ NM_CONFIG_KEYFILE_GROUP_LOGGING, "backend",                              NM_CONFIG_DEFAULT_LOGGING_BACKEND },
	{ NM_CONFIG_KEYFILE_GROUP_LOGGING, "audit",                                NM_CONFIG_DEFAULT_LOGGING_AUDIT },
};

void
nm_config_data_log (const NMConfigData *self,
                    const char *prefix,
                    const char *key_prefix,
                    /* FILE* */ gpointer print_stream)
{
	const NMConfigDataPrivate *priv;
	gs_strfreev char **groups = NULL;
	gsize ngroups;
	guint g, k, i;
	FILE *stream = print_stream;
	gs_unref_ptrarray GPtrArray *groups_full = NULL;
	gboolean print_default = !!stream;

	g_return_if_fail (NM_IS_CONFIG_DATA (self));

	if (!stream && !nm_logging_enabled (LOGL_DEBUG, LOGD_CORE))
		return;

	if (!prefix)
		prefix = "";
	if (!key_prefix)
		key_prefix = "";

#define _LOG(stream, prefix, ...) \
	G_STMT_START { \
		if (!stream) \
			_nm_log (LOGL_DEBUG, LOGD_CORE, 0, NULL, NULL, "%s"_NM_UTILS_MACRO_FIRST(__VA_ARGS__)"%s", prefix _NM_UTILS_MACRO_REST (__VA_ARGS__), ""); \
		else \
			fprintf (stream, "%s"_NM_UTILS_MACRO_FIRST(__VA_ARGS__)"%s", prefix _NM_UTILS_MACRO_REST (__VA_ARGS__), "\n"); \
	} G_STMT_END

	priv = NM_CONFIG_DATA_GET_PRIVATE (self);

	groups = g_key_file_get_groups (priv->keyfile, &ngroups);
	if (!groups)
		ngroups = 0;

	groups_full = g_ptr_array_sized_new (ngroups + 5);

	if (ngroups) {
		g_ptr_array_set_size (groups_full, ngroups);
		memcpy (groups_full->pdata, groups, sizeof (groups[0]) * ngroups);
		g_ptr_array_sort_with_data (groups_full, (GCompareDataFunc) _nm_config_data_log_sort, NULL);
	}

	if (print_default) {
		for (g = 0; g < G_N_ELEMENTS (default_values); g++) {
			const char *group = default_values[g].group;
			gssize idx;

			idx = _nm_utils_array_find_binary_search ((gconstpointer *) groups_full->pdata,
			                                          sizeof (char *),
			                                          groups_full->len,
			                                          &group,
			                                          (GCompareDataFunc) _nm_config_data_log_sort,
			                                          NULL);
			if (idx < 0)
				g_ptr_array_insert (groups_full, (~idx), (gpointer) group);
		}
	}

	if (!stream)
		_LOG (stream, prefix, "config-data[%p]: %u groups", self, groups_full->len);

	for (g = 0; g < groups_full->len; g++) {
		const char *group = groups_full->pdata[g];
		gs_strfreev char **keys = NULL;
		gboolean is_atomic;

		is_atomic = nm_config_data_is_intern_atomic_group (self, group);

		_LOG (stream, prefix, "");
		_LOG (stream, prefix, "[%s]%s", group, is_atomic && !stream ? " # atomic section" : "");

		/* Print default values as comments */
		if (print_default) {
			for (i = 0; i < G_N_ELEMENTS (default_values); i++) {
				if (   nm_streq (default_values[i].group, group)
				    && !g_key_file_has_key (priv->keyfile, group, default_values[i].key, NULL)) {
					_LOG (stream, prefix, "%s# %s=%s", key_prefix, default_values[i].key,
					      default_values[i].value);
				}
			}
		}

		keys = g_key_file_get_keys (priv->keyfile, group, NULL, NULL);
		for (k = 0; keys && keys[k]; k++) {
			const char *key = keys[k];
			gs_free char *value = NULL;

			value = g_key_file_get_value (priv->keyfile, group, key, NULL);
			_LOG (stream, prefix, "%s%s=%s", key_prefix, key, value);
		}
	}

#undef _LOG
}

/*****************************************************************************/

const char *const *
nm_global_dns_config_get_searches (const NMGlobalDnsConfig *dns)
{
	g_return_val_if_fail (dns, NULL);

	return (const char *const *) dns->searches;
}

const char *const *
nm_global_dns_config_get_options (const NMGlobalDnsConfig *dns)
{
	g_return_val_if_fail (dns, NULL);

	return (const char *const *) dns->options;
}

guint
nm_global_dns_config_get_num_domains (const NMGlobalDnsConfig *dns)
{
	g_return_val_if_fail (dns, 0);
	g_return_val_if_fail (dns->domains, 0);

	return g_hash_table_size (dns->domains);
}

NMGlobalDnsDomain *
nm_global_dns_config_get_domain (const NMGlobalDnsConfig *dns, guint i)
{
	NMGlobalDnsDomain *domain;

	g_return_val_if_fail (dns, NULL);
	g_return_val_if_fail (dns->domains, NULL);
	g_return_val_if_fail (dns->domain_list, NULL);
	g_return_val_if_fail (i < g_strv_length (dns->domain_list), NULL);

	domain = g_hash_table_lookup (dns->domains, dns->domain_list[i]);
	g_return_val_if_fail (domain, NULL);

	return domain;
}

NMGlobalDnsDomain *nm_global_dns_config_lookup_domain (const NMGlobalDnsConfig *dns, const char *name)
{
	g_return_val_if_fail (dns, NULL);
	g_return_val_if_fail (dns->domains, NULL);
	g_return_val_if_fail (name, NULL);

	return g_hash_table_lookup (dns->domains, name);
}

const char *
nm_global_dns_domain_get_name (const NMGlobalDnsDomain *domain)
{
	g_return_val_if_fail (domain, NULL);

	return (const char *) domain->name;
}

const char *const *
nm_global_dns_domain_get_servers (const NMGlobalDnsDomain *domain)
{
	g_return_val_if_fail (domain, NULL);

	return (const char *const *) domain->servers;
}

const char *const *
nm_global_dns_domain_get_options (const NMGlobalDnsDomain *domain)
{
	g_return_val_if_fail (domain, NULL);
	return (const char *const *) domain->options;
}

gboolean
nm_global_dns_config_is_internal (const NMGlobalDnsConfig *dns)
{
	return dns->internal;
}

gboolean
nm_global_dns_config_is_empty (const NMGlobalDnsConfig *dns)
{
	g_return_val_if_fail (dns, TRUE);
	g_return_val_if_fail (dns->domains, TRUE);

	return    (!dns->searches || g_strv_length (dns->searches) == 0)
	       && (!dns->options || g_strv_length (dns->options) == 0)
	       && g_hash_table_size (dns->domains) == 0;
}

void
nm_global_dns_config_update_checksum (const NMGlobalDnsConfig *dns, GChecksum *sum)
{
	NMGlobalDnsDomain *domain;
	GList *keys, *key;
	guint i;

	g_return_if_fail (dns);
	g_return_if_fail (dns->domains);
	g_return_if_fail (sum);

	for (i = 0; dns->searches && dns->searches[i]; i++)
		g_checksum_update (sum, (guchar *) dns->searches[i], strlen (dns->searches[i]));
	for (i = 0; dns->options && dns->options[i]; i++)
		g_checksum_update (sum, (guchar *) dns->options[i], strlen (dns->options[i]));

	keys = g_list_sort (g_hash_table_get_keys (dns->domains), (GCompareFunc) strcmp);
	for (key = keys; key; key = g_list_next (key)) {

		domain = g_hash_table_lookup (dns->domains, key->data);
		g_assert (domain != NULL);
		g_checksum_update (sum, (guchar *) domain->name, strlen (domain->name));

		for (i = 0; domain->servers && domain->servers[i]; i++)
			g_checksum_update (sum, (guchar *) domain->servers[i], strlen (domain->servers[i]));
		for (i = 0; domain->options && domain->options[i]; i++)
			g_checksum_update (sum, (guchar *) domain->options[i], strlen (domain->options[i]));
	}
	g_list_free (keys);
}

static void
global_dns_domain_free (NMGlobalDnsDomain  *domain)
{
	if (domain) {
		g_free (domain->name);
		g_strfreev (domain->servers);
		g_strfreev (domain->options);
		g_free (domain);
	}
}

void
nm_global_dns_config_free (NMGlobalDnsConfig *conf)
{
	if (conf) {
		g_strfreev (conf->searches);
		g_strfreev (conf->options);
		g_free (conf->domain_list);
		g_hash_table_unref (conf->domains);
		g_free (conf);
	}
}

NMGlobalDnsConfig *
nm_config_data_get_global_dns_config (const NMConfigData *self)
{
	g_return_val_if_fail (NM_IS_CONFIG_DATA (self), NULL);

	return NM_CONFIG_DATA_GET_PRIVATE (self)->global_dns;
}

static void
global_dns_config_update_domain_list (NMGlobalDnsConfig *dns)
{
	guint length;

	g_free (dns->domain_list);
	dns->domain_list = (char **) g_hash_table_get_keys_as_array (dns->domains, &length);
}

static NMGlobalDnsConfig *
load_global_dns (GKeyFile *keyfile, gboolean internal)
{
	NMGlobalDnsConfig *conf;
	char *group, *domain_prefix;
	gs_strfreev char **groups = NULL;
	int g, i, j, domain_prefix_len;
	gboolean default_found = FALSE;
	char **strv;

	group = internal
	        ? NM_CONFIG_KEYFILE_GROUP_INTERN_GLOBAL_DNS
	        : NM_CONFIG_KEYFILE_GROUP_GLOBAL_DNS;
	domain_prefix = internal
	                ? NM_CONFIG_KEYFILE_GROUPPREFIX_INTERN_GLOBAL_DNS_DOMAIN
	                : NM_CONFIG_KEYFILE_GROUPPREFIX_GLOBAL_DNS_DOMAIN;
	domain_prefix_len = strlen (domain_prefix);

	if (!nm_config_keyfile_has_global_dns_config (keyfile, internal))
		return NULL;

	conf = g_malloc0 (sizeof (NMGlobalDnsConfig));
	conf->domains = g_hash_table_new_full (nm_str_hash, g_str_equal,
	                                       g_free, (GDestroyNotify) global_dns_domain_free);

	strv = g_key_file_get_string_list (keyfile, group, "searches", NULL, NULL);
	if (strv)
		conf->searches = _nm_utils_strv_cleanup (strv, TRUE, TRUE, TRUE);

	strv = g_key_file_get_string_list (keyfile, group, "options", NULL, NULL);
	if (strv) {
		_nm_utils_strv_cleanup (strv, TRUE, TRUE, TRUE);
		for (i = 0, j = 0; strv[i]; i++) {
			if (_nm_utils_dns_option_validate (strv[i], NULL, NULL, TRUE, NULL))
				strv[j++] = strv[i];
			else
				g_free (strv[i]);
		}
		strv[j] = NULL;
		conf->options = strv;
	}

	groups = g_key_file_get_groups (keyfile, NULL);
	for (g = 0; groups[g]; g++) {
		char *name;
		char **servers = NULL, **options = NULL;
		NMGlobalDnsDomain *domain;

		if (   !g_str_has_prefix (groups[g], domain_prefix)
		    || !groups[g][domain_prefix_len])
			continue;

		strv = g_key_file_get_string_list (keyfile, groups[g], "servers", NULL, NULL);
		if (strv) {
			_nm_utils_strv_cleanup (strv, TRUE, TRUE, TRUE);
			for (i = 0, j = 0; strv[i]; i++) {
				if (   nm_utils_ipaddr_valid (AF_INET, strv[i])
				    || nm_utils_ipaddr_valid (AF_INET6, strv[i]))
					strv[j++] = strv[i];
				else
					g_free (strv[i]);
			}
			if (j) {
				strv[j] = NULL;
				servers = strv;
			}
			else
				g_free (strv);
		}

		if (!servers)
			continue;

		strv = g_key_file_get_string_list (keyfile, groups[g], "options", NULL, NULL);
		if (strv)
			options = _nm_utils_strv_cleanup (strv, TRUE, TRUE, TRUE);

		name = strdup (&groups[g][domain_prefix_len]);
		domain = g_malloc0 (sizeof (NMGlobalDnsDomain));
		domain->name = name;
		domain->servers = servers;
		domain->options = options;

		g_hash_table_insert (conf->domains, strdup (name), domain);

		if (!strcmp (name, "*"))
			default_found = TRUE;
	}

	if (!default_found) {
		nm_log_dbg (LOGD_CORE, "%s global DNS configuration is missing default domain, ignore it",
		            internal ? "internal" : "user");
		nm_global_dns_config_free (conf);
		return NULL;
	}

	conf->internal = internal;
	global_dns_config_update_domain_list (conf);
	return conf;
}


void
nm_global_dns_config_to_dbus (const NMGlobalDnsConfig *dns, GValue *value)
{
	GVariantBuilder conf_builder, domains_builder, domain_builder;
	NMGlobalDnsDomain *domain;
	GHashTableIter iter;

	g_variant_builder_init (&conf_builder, G_VARIANT_TYPE ("a{sv}"));
	if (!dns)
		goto out;

	if (dns->searches) {
		g_variant_builder_add (&conf_builder, "{sv}", "searches",
		                       g_variant_new_strv ((const char *const *) dns->searches, -1));
	}

	if (dns->options) {
		g_variant_builder_add (&conf_builder, "{sv}", "options",
		                       g_variant_new_strv ((const char *const *) dns->options, -1));
	}

	g_variant_builder_init (&domains_builder, G_VARIANT_TYPE ("a{sv}"));

	g_hash_table_iter_init (&iter, dns->domains);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &domain)) {

		g_variant_builder_init (&domain_builder, G_VARIANT_TYPE ("a{sv}"));

		if (domain->servers) {
			g_variant_builder_add (&domain_builder, "{sv}", "servers",
			                       g_variant_new_strv ((const char *const *) domain->servers, -1));
		}
		if (domain->options) {
			g_variant_builder_add (&domain_builder, "{sv}", "options",
			                       g_variant_new_strv ((const char *const *) domain->options, -1));
		}

		g_variant_builder_add (&domains_builder, "{sv}", domain->name,
		                       g_variant_builder_end (&domain_builder));
	}

	g_variant_builder_add (&conf_builder, "{sv}", "domains",
	                       g_variant_builder_end (&domains_builder));
out:
	g_value_take_variant (value, g_variant_builder_end (&conf_builder));
}

static NMGlobalDnsDomain *
global_dns_domain_from_dbus (char *name, GVariant *variant)
{
	NMGlobalDnsDomain *domain;
	GVariantIter iter;
	char **strv, *key;
	GVariant *val;
	int i, j;

	if (!g_variant_is_of_type (variant, G_VARIANT_TYPE ("a{sv}")))
		return NULL;

	domain = g_malloc0 (sizeof (NMGlobalDnsDomain));
	domain->name = g_strdup (name);

	g_variant_iter_init (&iter, variant);
	while (g_variant_iter_next (&iter, "{&sv}", &key, &val)) {

		if (   !g_strcmp0 (key, "servers")
		    && g_variant_is_of_type (val, G_VARIANT_TYPE ("as"))) {
			strv = g_variant_dup_strv (val, NULL);
			_nm_utils_strv_cleanup (strv, TRUE, TRUE, TRUE);
			for (i = 0, j = 0; strv && strv[i]; i++) {
				if (   nm_utils_ipaddr_valid (AF_INET, strv[i])
				    || nm_utils_ipaddr_valid (AF_INET6, strv[i]))
					strv[j++] = strv[i];
				else
					g_free (strv[i]);
			}
			if (j) {
				strv[j] = NULL;
				domain->servers = strv;
			} else
				g_free (strv);
		} else if (   !g_strcmp0 (key, "options")
		           && g_variant_is_of_type (val, G_VARIANT_TYPE ("as"))) {
			strv = g_variant_dup_strv (val, NULL);
			domain->options = _nm_utils_strv_cleanup (strv, TRUE, TRUE, TRUE);
		}

		g_variant_unref (val);
	}

	/* At least one server is required */
	if (!domain->servers) {
		global_dns_domain_free (domain);
		return NULL;
	}

	return domain;
}

NMGlobalDnsConfig *
nm_global_dns_config_from_dbus (const GValue *value, GError **error)
{
	NMGlobalDnsConfig *dns_config;
	GVariant *variant, *val;
	GVariantIter iter;
	char **strv, *key;
	int i, j;

	if (!G_VALUE_HOLDS_VARIANT (value)) {
		g_set_error (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_FAILED,
		             "invalid value type");
		return NULL;
	}

	variant = g_value_get_variant (value);
	if (!g_variant_is_of_type (variant, G_VARIANT_TYPE ("a{sv}"))) {
		g_set_error (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_FAILED,
		             "invalid variant type");
		return NULL;
	}

	dns_config = g_malloc0 (sizeof (NMGlobalDnsConfig));
	dns_config->domains = g_hash_table_new_full (nm_str_hash, g_str_equal,
	                                             g_free, (GDestroyNotify) global_dns_domain_free);

	g_variant_iter_init (&iter, variant);
	while (g_variant_iter_next (&iter, "{&sv}", &key, &val)) {

		if (   !g_strcmp0 (key, "searches")
		    && g_variant_is_of_type (val, G_VARIANT_TYPE ("as"))) {
			strv = g_variant_dup_strv (val, NULL);
			dns_config->searches = _nm_utils_strv_cleanup (strv, TRUE, TRUE, TRUE);
		} else if (   !g_strcmp0 (key, "options")
		           && g_variant_is_of_type (val, G_VARIANT_TYPE ("as"))) {
			strv = g_variant_dup_strv (val, NULL);
			_nm_utils_strv_cleanup (strv, TRUE, TRUE, TRUE);

			for (i = 0, j = 0; strv && strv[i]; i++) {
				if (_nm_utils_dns_option_validate (strv[i], NULL, NULL, TRUE, NULL))
					strv[j++] = strv[i];
				else
					g_free (strv[i]);
			}

			if (strv)
				strv[j] = NULL;

			dns_config->options = strv;
		} else if (   !g_strcmp0 (key, "domains")
		           && g_variant_is_of_type (val, G_VARIANT_TYPE ("a{sv}"))) {
			NMGlobalDnsDomain *domain;
			GVariantIter domain_iter;
			GVariant *v;
			char *k;

			g_variant_iter_init (&domain_iter, val);
			while (g_variant_iter_next (&domain_iter, "{&sv}", &k, &v)) {
				if (k) {
					domain = global_dns_domain_from_dbus (k, v);
					if (domain)
						g_hash_table_insert (dns_config->domains, strdup (k), domain);
				}
				g_variant_unref (v);
			}
		}
		g_variant_unref (val);
	}

	/* An empty value is valid and clears the internal configuration */
	if (   !nm_global_dns_config_is_empty (dns_config)
	    && !nm_global_dns_config_lookup_domain (dns_config, "*")) {
		g_set_error_literal (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_FAILED,
		                     "Global DNS configuration is missing the default domain");
		nm_global_dns_config_free (dns_config);
		return NULL;
	}

	global_dns_config_update_domain_list (dns_config);
	return dns_config;
}

static gboolean
global_dns_equal (NMGlobalDnsConfig *old, NMGlobalDnsConfig *new)
{
	NMGlobalDnsDomain *domain_old, *domain_new;
	gpointer key, value_old, value_new;
	GHashTableIter iter;

	if (old == new)
		return TRUE;

	if (!old || !new)
		return FALSE;

	if (   !_nm_utils_strv_equal (old->options, new->options)
	    || !_nm_utils_strv_equal (old->searches, new->searches))
		return FALSE;

	if ((!old->domains || !new->domains) && old->domains != new->domains)
		return FALSE;

	if (g_hash_table_size (old->domains) != g_hash_table_size (new->domains))
		return FALSE;

	g_hash_table_iter_init (&iter, old->domains);
	while (g_hash_table_iter_next (&iter, &key, &value_old)) {
		value_new = g_hash_table_lookup (new->domains, key);
		if (!value_new)
			return FALSE;

		domain_old = value_old;
		domain_new = value_new;

		if (   !_nm_utils_strv_equal (domain_old->options, domain_new->options)
		    || !_nm_utils_strv_equal (domain_old->servers, domain_new->servers))
			return FALSE;
	}

	return TRUE;
}

/*****************************************************************************/

static const MatchSectionInfo *
_match_section_infos_lookup (const MatchSectionInfo *match_section_infos,
                             GKeyFile *keyfile,
                             const char *property,
                             NMDevice *device,
                             char **out_value)
{
	if (!match_section_infos)
		return NULL;

	for (; match_section_infos->group_name; match_section_infos++) {
		char *value = NULL;
		gboolean match;

		/* FIXME: Here we use g_key_file_get_string(). This should be in sync with what keyfile-reader
		 * does.
		 *
		 * Unfortunately that is currently not possible because keyfile-reader does the two steps
		 * string_to_value(keyfile_to_string(keyfile)) in one. Optimally, keyfile library would
		 * expose both functions, and we would return here keyfile_to_string(keyfile).
		 * The caller then could convert the string to the proper value via string_to_value(value). */
		value = g_key_file_get_string (keyfile, match_section_infos->group_name, property, NULL);
		if (!value && !match_section_infos->stop_match)
			continue;

		match = TRUE;
		if (match_section_infos->match_device.has)
			match = device && nm_device_spec_match_list (device, match_section_infos->match_device.spec);

		if (match) {
			*out_value = value;
			return match_section_infos;
		}
		g_free (value);
	}
	return NULL;
}

char *
nm_config_data_get_device_config (const NMConfigData *self,
                                  const char *property,
                                  NMDevice *device,
                                  gboolean *has_match)
{
	const NMConfigDataPrivate *priv;
	const MatchSectionInfo *connection_info;
	char *value = NULL;

	g_return_val_if_fail (self, NULL);
	g_return_val_if_fail (property && *property, NULL);

	priv = NM_CONFIG_DATA_GET_PRIVATE (self);

	connection_info = _match_section_infos_lookup (&priv->device_infos[0],
	                                               priv->keyfile,
	                                               property,
	                                               device,
	                                               &value);
	NM_SET_OUT (has_match, !!connection_info);
	return value;
}

gboolean
nm_config_data_get_device_config_boolean (const NMConfigData *self,
                                          const char *property,
                                          NMDevice *device,
                                          gint val_no_match,
                                          gint val_invalid)
{
	gs_free char *value = NULL;
	gboolean has_match;

	value = nm_config_data_get_device_config (self, property, device, &has_match);
	if (!has_match)
		return val_no_match;
	return nm_config_parse_boolean (value, val_invalid);
}

char *
nm_config_data_get_connection_default (const NMConfigData *self,
                                       const char *property,
                                       NMDevice *device)
{
	const NMConfigDataPrivate *priv;
	char *value = NULL;

	g_return_val_if_fail (self, NULL);
	g_return_val_if_fail (property && *property, NULL);
	g_return_val_if_fail (strchr (property, '.'), NULL);

	priv = NM_CONFIG_DATA_GET_PRIVATE (self);

	_match_section_infos_lookup (&priv->connection_infos[0],
	                             priv->keyfile,
	                             property,
	                             device,
	                             &value);
	return value;
}

static void
_get_connection_info_init (MatchSectionInfo *connection_info, GKeyFile *keyfile, char *group)
{
	/* pass ownership of @group on... */
	connection_info->group_name = group;

	connection_info->match_device.spec = nm_config_get_match_spec (keyfile,
	                                                               group,
	                                                               "match-device",
	                                                               &connection_info->match_device.has);
	connection_info->stop_match = nm_config_keyfile_get_boolean (keyfile, group, "stop-match", FALSE);
}

static void
_match_section_infos_free (MatchSectionInfo *match_section_infos)
{
	guint i;

	if (!match_section_infos)
		return;
	for (i = 0; match_section_infos[i].group_name; i++) {
		g_free (match_section_infos[i].group_name);
		g_slist_free_full (match_section_infos[i].match_device.spec, g_free);
	}
	g_free (match_section_infos);
}

static MatchSectionInfo *
_match_section_infos_construct (GKeyFile *keyfile, const char *prefix)
{
	char **groups;
	gsize i, j, ngroups;
	char *connection_tag = NULL;
	MatchSectionInfo *match_section_infos = NULL;

	/* get the list of existing [connection.\+]/[device.\+] sections.
	 *
	 * We expect the sections in their right order, with lowest priority
	 * first. Only exception is the (literal) [connection] section, which
	 * we will always reorder to the end. */
	groups = g_key_file_get_groups (keyfile, &ngroups);
	if (!groups)
		return NULL;

	if (ngroups > 0) {
		gsize l = strlen (prefix);

		for (i = 0, j = 0; i < ngroups; i++) {
			if (g_str_has_prefix (groups[i], prefix)) {
				if (groups[i][l] == '\0')
					connection_tag = groups[i];
				else
					groups[j++] = groups[i];
			} else
				g_free (groups[i]);
		}
		ngroups = j;
	}

	if (ngroups == 0 && !connection_tag) {
		g_free (groups);
		return NULL;
	}

	match_section_infos = g_new0 (MatchSectionInfo, ngroups + 1 + (connection_tag ? 1 : 0));
	for (i = 0; i < ngroups; i++) {
		/* pass ownership of @group on... */
		_get_connection_info_init (&match_section_infos[i], keyfile, groups[ngroups - i - 1]);
	}
	if (connection_tag) {
		/* pass ownership of @connection_tag on... */
		_get_connection_info_init (&match_section_infos[i], keyfile, connection_tag);
	}
	g_free (groups);

	return match_section_infos;
}

/*****************************************************************************/

static gboolean
_slist_str_equals (GSList *a, GSList *b)
{
	while (a && b && g_strcmp0 (a->data, b->data) == 0) {
		a = a->next;
		b = b->next;
	}
	return !a && !b;
}

NMConfigChangeFlags
nm_config_data_diff (NMConfigData *old_data, NMConfigData *new_data)
{
	NMConfigChangeFlags changes = NM_CONFIG_CHANGE_NONE;
	NMConfigDataPrivate *priv_old, *priv_new;

	g_return_val_if_fail (NM_IS_CONFIG_DATA (old_data), NM_CONFIG_CHANGE_NONE);
	g_return_val_if_fail (NM_IS_CONFIG_DATA (new_data), NM_CONFIG_CHANGE_NONE);

	priv_old = NM_CONFIG_DATA_GET_PRIVATE (old_data);
	priv_new = NM_CONFIG_DATA_GET_PRIVATE (new_data);

	if (!_nm_keyfile_equals (priv_old->keyfile_user, priv_new->keyfile_user, TRUE))
		changes |= NM_CONFIG_CHANGE_VALUES | NM_CONFIG_CHANGE_VALUES_USER;

	if (!_nm_keyfile_equals (priv_old->keyfile_intern, priv_new->keyfile_intern, TRUE))
		changes |= NM_CONFIG_CHANGE_VALUES | NM_CONFIG_CHANGE_VALUES_INTERN;

	if (   g_strcmp0 (nm_config_data_get_config_main_file (old_data), nm_config_data_get_config_main_file (new_data)) != 0
	    || g_strcmp0 (nm_config_data_get_config_description (old_data), nm_config_data_get_config_description (new_data)) != 0)
		changes |= NM_CONFIG_CHANGE_CONFIG_FILES;

	if (   nm_config_data_get_connectivity_enabled (old_data) != nm_config_data_get_connectivity_enabled (new_data)
	    || nm_config_data_get_connectivity_interval (old_data) != nm_config_data_get_connectivity_interval (new_data)
	    || g_strcmp0 (nm_config_data_get_connectivity_uri (old_data), nm_config_data_get_connectivity_uri (new_data))
	    || g_strcmp0 (nm_config_data_get_connectivity_response (old_data), nm_config_data_get_connectivity_response (new_data)))
		changes |= NM_CONFIG_CHANGE_CONNECTIVITY;

	if (   !_slist_str_equals (priv_old->no_auto_default.specs, priv_new->no_auto_default.specs)
	    || !_slist_str_equals (priv_old->no_auto_default.specs_config, priv_new->no_auto_default.specs_config))
		changes |= NM_CONFIG_CHANGE_NO_AUTO_DEFAULT;

	if (g_strcmp0 (nm_config_data_get_dns_mode (old_data), nm_config_data_get_dns_mode (new_data)))
		changes |= NM_CONFIG_CHANGE_DNS_MODE;

	if (g_strcmp0 (nm_config_data_get_rc_manager (old_data), nm_config_data_get_rc_manager (new_data)))
		changes |= NM_CONFIG_CHANGE_RC_MANAGER;

	if (!global_dns_equal (priv_old->global_dns, priv_new->global_dns))
		changes |= NM_CONFIG_CHANGE_GLOBAL_DNS_CONFIG;

	nm_assert (!NM_FLAGS_ANY (changes, NM_CONFIG_CHANGE_CAUSES));

	return changes;
}

/*****************************************************************************/

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMConfigData *self = NM_CONFIG_DATA (object);

	switch (prop_id) {
	case PROP_CONFIG_MAIN_FILE:
		g_value_set_string (value, nm_config_data_get_config_main_file (self));
		break;
	case PROP_CONFIG_DESCRIPTION:
		g_value_set_string (value, nm_config_data_get_config_description (self));
		break;
	case PROP_CONNECTIVITY_ENABLED:
		g_value_set_boolean (value, nm_config_data_get_connectivity_enabled (self));
		break;
	case PROP_CONNECTIVITY_URI:
		g_value_set_string (value, nm_config_data_get_connectivity_uri (self));
		break;
	case PROP_CONNECTIVITY_INTERVAL:
		g_value_set_uint (value, nm_config_data_get_connectivity_interval (self));
		break;
	case PROP_CONNECTIVITY_RESPONSE:
		g_value_set_string (value, nm_config_data_get_connectivity_response (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object,
              guint prop_id,
              const GValue *value,
              GParamSpec *pspec)
{
	NMConfigData *self = NM_CONFIG_DATA (object);
	NMConfigDataPrivate *priv = NM_CONFIG_DATA_GET_PRIVATE (self);

	switch (prop_id) {
	case PROP_CONFIG_MAIN_FILE:
		/* construct-only */
		priv->config_main_file = g_value_dup_string (value);
		break;
	case PROP_CONFIG_DESCRIPTION:
		/* construct-only */
		priv->config_description = g_value_dup_string (value);
		break;
	case PROP_KEYFILE_USER:
		/* construct-only */
		priv->keyfile_user = g_value_dup_boxed (value);
		if (   priv->keyfile_user
		    && !_nm_keyfile_has_values (priv->keyfile_user)) {
			g_key_file_unref (priv->keyfile_user);
			priv->keyfile_user = NULL;
		}
		break;
	case PROP_KEYFILE_INTERN:
		/* construct-only */
		priv->keyfile_intern = g_value_dup_boxed (value);
		if (   priv->keyfile_intern
		    && !_nm_keyfile_has_values (priv->keyfile_intern)) {
			g_key_file_unref (priv->keyfile_intern);
			priv->keyfile_intern = NULL;
		}
		break;
	case PROP_NO_AUTO_DEFAULT:
		/* construct-only */
		{
			char **value_arr = g_value_get_boxed (value);
			guint i, j = 0;

			priv->no_auto_default.arr = g_new (char *, g_strv_length (value_arr) + 1);
			priv->no_auto_default.specs = NULL;

			for (i = 0; value_arr && value_arr[i]; i++) {
				if (   *value_arr[i]
				    && nm_utils_hwaddr_valid (value_arr[i], -1)
				    && nm_utils_strv_find_first (value_arr, i, value_arr[i]) < 0) {
					priv->no_auto_default.arr[j++] = g_strdup (value_arr[i]);
					priv->no_auto_default.specs = g_slist_prepend (priv->no_auto_default.specs, g_strdup_printf ("mac:%s", value_arr[i]));
				}
			}
			priv->no_auto_default.arr[j++] = NULL;
			priv->no_auto_default.specs = g_slist_reverse (priv->no_auto_default.specs);
		}
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_config_data_init (NMConfigData *self)
{
}

static void
constructed (GObject *object)
{
	NMConfigData *self = NM_CONFIG_DATA (object);
	NMConfigDataPrivate *priv = NM_CONFIG_DATA_GET_PRIVATE (self);
	char *str;

	priv->keyfile = _merge_keyfiles (priv->keyfile_user, priv->keyfile_intern);

	priv->connection_infos = _match_section_infos_construct (priv->keyfile, NM_CONFIG_KEYFILE_GROUPPREFIX_CONNECTION);
	priv->device_infos = _match_section_infos_construct (priv->keyfile, NM_CONFIG_KEYFILE_GROUPPREFIX_DEVICE);

	priv->connectivity.enabled = nm_config_keyfile_get_boolean (priv->keyfile, NM_CONFIG_KEYFILE_GROUP_CONNECTIVITY, "enabled", TRUE);
	priv->connectivity.uri = nm_strstrip (g_key_file_get_string (priv->keyfile, NM_CONFIG_KEYFILE_GROUP_CONNECTIVITY, "uri", NULL));
	priv->connectivity.response = g_key_file_get_string (priv->keyfile, NM_CONFIG_KEYFILE_GROUP_CONNECTIVITY, "response", NULL);

	str = nm_config_keyfile_get_value (priv->keyfile, NM_CONFIG_KEYFILE_GROUP_MAIN, NM_CONFIG_KEYFILE_KEY_MAIN_AUTOCONNECT_RETRIES_DEFAULT, NM_CONFIG_GET_VALUE_NONE);
	priv->autoconnect_retries_default = _nm_utils_ascii_str_to_int64 (str, 10, 0, G_MAXINT32, 4);
	g_free (str);

	/* On missing config value, fallback to 300. On invalid value, disable connectivity checking by setting
	 * the interval to zero. */
	str = g_key_file_get_string (priv->keyfile, NM_CONFIG_KEYFILE_GROUP_CONNECTIVITY, "interval", NULL);
	priv->connectivity.interval = _nm_utils_ascii_str_to_int64 (str, 10, 0, G_MAXUINT, NM_CONFIG_DEFAULT_CONNECTIVITY_INTERVAL);
	g_free (str);

	priv->dns_mode = nm_strstrip (g_key_file_get_string (priv->keyfile, NM_CONFIG_KEYFILE_GROUP_MAIN, "dns", NULL));
	priv->rc_manager = nm_strstrip (g_key_file_get_string (priv->keyfile, NM_CONFIG_KEYFILE_GROUP_MAIN, "rc-manager", NULL));

	priv->ignore_carrier = nm_config_get_match_spec (priv->keyfile, NM_CONFIG_KEYFILE_GROUP_MAIN, "ignore-carrier", NULL);
	priv->assume_ipv6ll_only = nm_config_get_match_spec (priv->keyfile, NM_CONFIG_KEYFILE_GROUP_MAIN, "assume-ipv6ll-only", NULL);

	priv->no_auto_default.specs_config = nm_config_get_match_spec (priv->keyfile, NM_CONFIG_KEYFILE_GROUP_MAIN, "no-auto-default", NULL);

	priv->global_dns = load_global_dns (priv->keyfile_user, FALSE);
	if (!priv->global_dns)
		priv->global_dns = load_global_dns (priv->keyfile_intern, TRUE);

	G_OBJECT_CLASS (nm_config_data_parent_class)->constructed (object);
}

NMConfigData *
nm_config_data_new (const char *config_main_file,
                    const char *config_description,
                    const char *const*no_auto_default,
                    GKeyFile *keyfile_user,
                    GKeyFile *keyfile_intern)
{
	return g_object_new (NM_TYPE_CONFIG_DATA,
	                     NM_CONFIG_DATA_CONFIG_MAIN_FILE, config_main_file,
	                     NM_CONFIG_DATA_CONFIG_DESCRIPTION, config_description,
	                     NM_CONFIG_DATA_KEYFILE_USER, keyfile_user,
	                     NM_CONFIG_DATA_KEYFILE_INTERN, keyfile_intern,
	                     NM_CONFIG_DATA_NO_AUTO_DEFAULT, no_auto_default,
	                     NULL);
}

NMConfigData *
nm_config_data_new_update_keyfile_intern (const NMConfigData *base, GKeyFile *keyfile_intern)
{
	const NMConfigDataPrivate *priv = NM_CONFIG_DATA_GET_PRIVATE (base);

	return g_object_new (NM_TYPE_CONFIG_DATA,
	                     NM_CONFIG_DATA_CONFIG_MAIN_FILE, priv->config_main_file,
	                     NM_CONFIG_DATA_CONFIG_DESCRIPTION, priv->config_description,
	                     NM_CONFIG_DATA_KEYFILE_USER, priv->keyfile_user, /* the keyfile is unchanged. It's safe to share it. */
	                     NM_CONFIG_DATA_KEYFILE_INTERN, keyfile_intern,
	                     NM_CONFIG_DATA_NO_AUTO_DEFAULT, priv->no_auto_default.arr,
	                     NULL);
}

NMConfigData *
nm_config_data_new_update_no_auto_default (const NMConfigData *base,
                                           const char *const*no_auto_default)
{
	const NMConfigDataPrivate *priv = NM_CONFIG_DATA_GET_PRIVATE (base);

	return g_object_new (NM_TYPE_CONFIG_DATA,
	                     NM_CONFIG_DATA_CONFIG_MAIN_FILE, priv->config_main_file,
	                     NM_CONFIG_DATA_CONFIG_DESCRIPTION, priv->config_description,
	                     NM_CONFIG_DATA_KEYFILE_USER, priv->keyfile_user, /* the keyfile is unchanged. It's safe to share it. */
	                     NM_CONFIG_DATA_KEYFILE_INTERN, priv->keyfile_intern,
	                     NM_CONFIG_DATA_NO_AUTO_DEFAULT, no_auto_default,
	                     NULL);
}

static void
finalize (GObject *gobject)
{
	NMConfigDataPrivate *priv = NM_CONFIG_DATA_GET_PRIVATE ((NMConfigData *) gobject);

	g_free (priv->config_main_file);
	g_free (priv->config_description);

	g_free (priv->connectivity.uri);
	g_free (priv->connectivity.response);

	g_slist_free_full (priv->no_auto_default.specs, g_free);
	g_slist_free_full (priv->no_auto_default.specs_config, g_free);
	g_strfreev (priv->no_auto_default.arr);

	g_free (priv->dns_mode);
	g_free (priv->rc_manager);

	g_slist_free_full (priv->ignore_carrier, g_free);
	g_slist_free_full (priv->assume_ipv6ll_only, g_free);

	nm_global_dns_config_free (priv->global_dns);

	_match_section_infos_free (priv->connection_infos);
	_match_section_infos_free (priv->device_infos);

	g_key_file_unref (priv->keyfile);
	if (priv->keyfile_user)
		g_key_file_unref (priv->keyfile_user);
	if (priv->keyfile_intern)
		g_key_file_unref (priv->keyfile_intern);

	G_OBJECT_CLASS (nm_config_data_parent_class)->finalize (gobject);
}

static void
nm_config_data_class_init (NMConfigDataClass *config_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (config_class);

	object_class->constructed = constructed;
	object_class->finalize = finalize;
	object_class->get_property = get_property;
	object_class->set_property = set_property;

	obj_properties[PROP_CONFIG_MAIN_FILE] =
	     g_param_spec_string (NM_CONFIG_DATA_CONFIG_MAIN_FILE, "", "",
	                          NULL,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_CONFIG_DESCRIPTION] =
	     g_param_spec_string (NM_CONFIG_DATA_CONFIG_DESCRIPTION, "", "",
	                          NULL,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_KEYFILE_USER] =
	     g_param_spec_boxed (NM_CONFIG_DATA_KEYFILE_USER, "", "",
	                         G_TYPE_KEY_FILE,
	                         G_PARAM_WRITABLE |
	                         G_PARAM_CONSTRUCT_ONLY |
	                         G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_KEYFILE_INTERN] =
	     g_param_spec_boxed (NM_CONFIG_DATA_KEYFILE_INTERN, "", "",
	                         G_TYPE_KEY_FILE,
	                         G_PARAM_WRITABLE |
	                         G_PARAM_CONSTRUCT_ONLY |
	                         G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_CONNECTIVITY_ENABLED] =
	     g_param_spec_string (NM_CONFIG_DATA_CONNECTIVITY_ENABLED, "", "",
	                          NULL,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_CONNECTIVITY_URI] =
	     g_param_spec_string (NM_CONFIG_DATA_CONNECTIVITY_URI, "", "",
	                          NULL,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_CONNECTIVITY_INTERVAL] =
	     g_param_spec_uint (NM_CONFIG_DATA_CONNECTIVITY_INTERVAL, "", "",
	                        0, G_MAXUINT, 0,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_CONNECTIVITY_RESPONSE] =
	     g_param_spec_string (NM_CONFIG_DATA_CONNECTIVITY_RESPONSE, "", "",
	                          NULL,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_NO_AUTO_DEFAULT] =
	     g_param_spec_boxed (NM_CONFIG_DATA_NO_AUTO_DEFAULT, "", "",
	                         G_TYPE_STRV,
	                         G_PARAM_WRITABLE |
	                         G_PARAM_CONSTRUCT_ONLY |
	                         G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}
