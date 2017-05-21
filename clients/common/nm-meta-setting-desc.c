/* nmcli - command-line tool to control NetworkManager
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
 * Copyright 2010 - 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-meta-setting-desc.h"

#include <stdlib.h>
#include <arpa/inet.h>

#include "nm-common-macros.h"
#include "nm-utils/nm-enum-utils.h"

#include "NetworkManager.h"
#include "nm-vpn-helpers.h"
#include "nm-client-utils.h"
#include "nm-meta-setting-access.h"

/*****************************************************************************/

static gboolean validate_int (NMSetting *setting, const char* prop, gint val, GError **error);
static gboolean validate_uint (NMSetting *setting, const char* prop, guint val, GError **error);
static gboolean validate_int64 (NMSetting *setting, const char* prop, gint64 val, GError **error);
static char *secret_flags_to_string (guint32 flags, NMMetaAccessorGetType get_type);

#define ALL_SECRET_FLAGS \
	(NM_SETTING_SECRET_FLAG_NONE | \
	 NM_SETTING_SECRET_FLAG_AGENT_OWNED | \
	 NM_SETTING_SECRET_FLAG_NOT_SAVED | \
	 NM_SETTING_SECRET_FLAG_NOT_REQUIRED)

/*****************************************************************************/

static GType
_gobject_property_get_gtype (GObject *gobject, const char *property_name)
{
	GParamSpec *param_spec;

	param_spec = g_object_class_find_property (G_OBJECT_GET_CLASS (gobject), property_name);
	if (param_spec)
		return param_spec->value_type;
	g_return_val_if_reached (G_TYPE_INVALID);
}

static GType
_gtype_property_get_gtype (GType gtype, const char *property_name)
{
	/* given @gtype, a type for a GObject, lookup the property @property_name
	 * and return its value_type. */
	if (G_TYPE_IS_CLASSED (gtype)) {
		GParamSpec *param_spec;
		nm_auto_unref_gtypeclass GTypeClass *gtypeclass = g_type_class_ref (gtype);

		if (G_IS_OBJECT_CLASS (gtypeclass)) {
			param_spec = g_object_class_find_property (G_OBJECT_CLASS (gtypeclass), property_name);
			if (param_spec)
				return param_spec->value_type;
		}
	}
	g_return_val_if_reached (G_TYPE_INVALID);
}

/*****************************************************************************/

static NMIPAddress *
_parse_ip_address (int family, const char *address, GError **error)
{
	gs_free char *ip_str = NULL;
	const int MAX_PREFIX = (family == AF_INET) ? 32 : 128;
	NMIPAddress *addr;
	char *plen;
	int prefix;
	GError *local = NULL;

	g_return_val_if_fail (address, NULL);
	g_return_val_if_fail (!error || !*error, NULL);

	ip_str = g_strstrip (g_strdup (address));

	prefix = MAX_PREFIX;

	plen = strchr (ip_str, '/');
	if (plen) {
		*plen++ = '\0';
		if ((prefix = _nm_utils_ascii_str_to_int64 (plen, 10, 1, MAX_PREFIX, -1)) == -1) {
			g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT,
			             _("invalid prefix '%s'; <1-%d> allowed"), plen, MAX_PREFIX);
			return NULL;
		}
	}

	addr = nm_ip_address_new (family, ip_str, prefix, &local);
	if (!addr) {
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT,
		             _("invalid IP address: %s"), local->message);
		g_clear_error (&local);
	}
	return addr;
}

static NMIPRoute *
_parse_ip_route (int family,
                 const char *str,
                 GError **error)
{
	const int MAX_PREFIX = (family == AF_INET) ? 32 : 128;
	char *plen = NULL;
	const char *next_hop = NULL;
	const char *canon_dest;
	int prefix;
	NMIPRoute *route = NULL;
	GError *local = NULL;
	gint64 metric = -1;
	guint i;
	gs_strfreev char **routev = NULL;
	gs_free char *str_clean = NULL;
	char *dest;
	gs_unref_hashtable GHashTable *attrs = NULL;
	GHashTable *tmp_attrs;
#define ROUTE_SYNTAX _("The valid syntax is: 'ip[/prefix] [next-hop] [metric] [attribute=val]... [,ip[/prefix] ...]'")

	nm_assert (NM_IN_SET (family, AF_INET, AF_INET6));
	nm_assert (str);
	nm_assert (!error || !*error);

	str_clean = g_strstrip (g_strdup (str));
	routev = nmc_strsplit_set (str_clean, " \t", 0);
	if (!routev || !routev[0]) {
		g_set_error (error, 1, 0,
		             "'%s' is not valid. %s",
		             str, ROUTE_SYNTAX);
		return NULL;
	}

	dest = routev[0];
	plen = strchr (dest, '/');  /* prefix delimiter */
	if (plen)
		*plen++ = '\0';
	prefix = MAX_PREFIX;
	if (plen) {
		if ((prefix = _nm_utils_ascii_str_to_int64 (plen, 10, 1, MAX_PREFIX, -1)) == -1) {
			g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT,
			             _("invalid prefix '%s'; <1-%d> allowed"),
			             plen, MAX_PREFIX);
			return NULL;
		}
	}

	for (i = 1; routev[i]; i++) {
		gint64 tmp64;

		if (nm_utils_ipaddr_valid (family, routev[i])) {
			if (metric != -1 || attrs) {
				g_set_error (error, 1, 0, _("the next hop ('%s') must be first"), routev[i]);
				return NULL;
			}
			next_hop = routev[i];
		} else if ((tmp64 = _nm_utils_ascii_str_to_int64 (routev[i], 10, 0, G_MAXUINT32, -1)) != -1) {
			if (attrs) {
				g_set_error (error, 1, 0, _("the metric ('%s') must be before attributes"), routev[i]);
				return NULL;
			}
			metric = tmp64;
		} else if (strchr (routev[i], '=')) {
			GHashTableIter iter;
			char *iter_key;
			GVariant *iter_value;

			tmp_attrs = nm_utils_parse_variant_attributes (routev[i], ' ', '=', FALSE,
			                                               nm_ip_route_get_variant_attribute_spec(),
			                                               error);
			if (!tmp_attrs) {
				g_prefix_error (error, "invalid option '%s': ", routev[i]);
				return NULL;
			}

			if (!attrs)
				attrs = g_hash_table_new (g_str_hash, g_str_equal);

			g_hash_table_iter_init (&iter, tmp_attrs);
			while (g_hash_table_iter_next (&iter, (gpointer *) &iter_key, (gpointer *) &iter_value)) {
				if (!nm_ip_route_attribute_validate (iter_key, iter_value, family, NULL, error)) {
					g_prefix_error (error, "%s: ", iter_key);
					g_hash_table_unref (tmp_attrs);
					return NULL;
				}
				g_hash_table_insert (attrs, iter_key, iter_value);
				g_hash_table_iter_steal (&iter);
			}
			g_hash_table_unref (tmp_attrs);
		} else {
			g_set_error (error, 1, 0, "%s", ROUTE_SYNTAX);
			return NULL;
		}
	}

	route = nm_ip_route_new (family, dest, prefix, next_hop, metric, &local);
	if (!route) {
		g_set_error (error, 1, 0,
		             _("invalid route: %s. %s"), local->message, ROUTE_SYNTAX);
		g_clear_error (&local);
		return NULL;
	}

	/* We don't accept default routes as NetworkManager handles it
	 * itself. But we have to check this after @route has normalized the
	 * dest string.
	 */
	canon_dest = nm_ip_route_get_dest (route);
	if (!strcmp (canon_dest, "0.0.0.0") || !strcmp (canon_dest, "::")) {
		g_set_error_literal (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT,
		                     _("default route cannot be added (NetworkManager handles it by itself)"));
		g_clear_pointer (&route, nm_ip_route_unref);
		return NULL;
	}

	if (attrs) {
		GHashTableIter iter;
		char *name;
		GVariant *variant;

		g_hash_table_iter_init (&iter, attrs);
		while (g_hash_table_iter_next (&iter, (gpointer *) &name, (gpointer *) &variant))
			nm_ip_route_set_attribute (route, name, variant);
	}

	return route;
}

/* Max priority values from libnm-core/nm-setting-vlan.c */
#define MAX_SKB_PRIO   G_MAXUINT32
#define MAX_8021P_PRIO 7  /* Max 802.1p priority */

/*
 * Parse VLAN priority mappings from the following format: 2:1,3:4,7:3
 * and verify if the priority numbers are valid
 *
 * Return: string array with split maps, or NULL on error
 * Caller is responsible for freeing the array.
 */
static char **
nmc_vlan_parse_priority_maps (const char *priority_map,
                              NMVlanPriorityMap map_type,
                              GError **error)
{
	char **mapping = NULL, **iter;
	unsigned long from, to, from_max, to_max;

	g_return_val_if_fail (priority_map != NULL, NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	if (map_type == NM_VLAN_INGRESS_MAP) {
		from_max = MAX_8021P_PRIO;
		to_max = MAX_SKB_PRIO;
	} else {
		from_max = MAX_SKB_PRIO;
		to_max = MAX_8021P_PRIO;
	}

	mapping = g_strsplit (priority_map, ",", 0);
	for (iter = mapping; iter && *iter; iter++) {
		char *left, *right;

		left = g_strstrip (*iter);
		right = strchr (left, ':');
		if (!right) {
			g_set_error (error, 1, 0, _("invalid priority map '%s'"), *iter);
			g_strfreev (mapping);
			return NULL;
		}
		*right++ = '\0';

		if (!nmc_string_to_uint (left, TRUE, 0, from_max, &from)) {
			g_set_error (error, 1, 0, _("priority '%s' is not valid (<0-%ld>)"),
			             left, from_max);
			g_strfreev (mapping);
			return NULL;
		}
		if (!nmc_string_to_uint (right, TRUE, 0, to_max, &to)) {
			g_set_error (error, 1, 0, _("priority '%s' is not valid (<0-%ld>)"),
			             right, to_max);
			g_strfreev (mapping);
			return NULL;
		}
		*(right-1) = ':'; /* Put back ':' */
	}
	return mapping;
}

/*
 * nmc_proxy_check_script:
 * @script: file name with PAC script, or raw PAC Script data
 * @out_script: raw PAC Script (with removed new-line characters)
 * @error: location to store error, or %NULL
 *
 * Check PAC Script from @script parameter and return the checked/sanitized
 * config in @out_script.
 *
 * Returns: %TRUE if the script is valid, %FALSE if it is invalid
 */
static gboolean
nmc_proxy_check_script (const char *script, char **out_script, GError **error)
{
	enum {
		_PAC_SCRIPT_TYPE_GUESS,
		_PAC_SCRIPT_TYPE_FILE,
		_PAC_SCRIPT_TYPE_JSON,
	} desired_type = _PAC_SCRIPT_TYPE_GUESS;
	const char *filename = NULL;
	size_t c_len = 0;
	gs_free char *script_clone = NULL;

	*out_script = NULL;

	if (!script || !script[0])
		return TRUE;

	if (g_str_has_prefix (script, "file://")) {
		script += NM_STRLEN ("file://");
		desired_type = _PAC_SCRIPT_TYPE_FILE;
	} else if (g_str_has_prefix (script, "js://")) {
		script += NM_STRLEN ("js://");
		desired_type = _PAC_SCRIPT_TYPE_JSON;
	}

	if (NM_IN_SET (desired_type, _PAC_SCRIPT_TYPE_FILE, _PAC_SCRIPT_TYPE_GUESS)) {
		gs_free char *contents = NULL;

		if (!g_file_get_contents (script, &contents, &c_len, NULL)) {
			if (desired_type == _PAC_SCRIPT_TYPE_FILE) {
				g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT,
				             _("cannot read pac-script from file '%s'"),
				             script);
				return FALSE;
			}
		} else {
			if (c_len != strlen (contents)) {
				g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT,
				             _("file '%s' contains non-valid utf-8"),
				             script);
				return FALSE;
			}
			filename = script;
			script = script_clone = g_steal_pointer (&contents);
		}
	}

	if (   !strstr (script, "FindProxyForURL")
	    || !g_utf8_validate (script, -1, NULL)) {
		if (filename) {
			g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT,
			             _("'%s' does not contain a valid PAC Script"), filename);
		} else {
			g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT,
			             _("Not a valid PAC Script"));
		}
		return FALSE;
	}

	*out_script = (script == script_clone)
	              ? g_steal_pointer (&script_clone)
	              : g_strdup (script);
	return TRUE;
}

/*
 * nmc_team_check_config:
 * @config: file name with team config, or raw team JSON config data
 * @out_config: raw team JSON config data
 *   The value must be freed with g_free().
 * @error: location to store error, or %NUL
 *
 * Check team config from @config parameter and return the checked
 * config in @out_config.
 *
 * Returns: %TRUE if the config is valid, %FALSE if it is invalid
 */
static gboolean
nmc_team_check_config (const char *config, char **out_config, GError **error)
{
	enum {
		_TEAM_CONFIG_TYPE_GUESS,
		_TEAM_CONFIG_TYPE_FILE,
		_TEAM_CONFIG_TYPE_JSON,
	} desired_type = _TEAM_CONFIG_TYPE_GUESS;
	const char *filename = NULL;
	size_t c_len = 0;
	gs_free char *config_clone = NULL;

	*out_config = NULL;

	if (!config || !config[0])
		return TRUE;

	if (g_str_has_prefix (config, "file://")) {
		config += NM_STRLEN ("file://");
		desired_type = _TEAM_CONFIG_TYPE_FILE;
	} else if (g_str_has_prefix (config, "json://")) {
		config += NM_STRLEN ("json://");
		desired_type = _TEAM_CONFIG_TYPE_JSON;
	}

	if (NM_IN_SET (desired_type, _TEAM_CONFIG_TYPE_FILE, _TEAM_CONFIG_TYPE_GUESS)) {
		gs_free char *contents = NULL;

		if (!g_file_get_contents (config, &contents, &c_len, NULL)) {
			if (desired_type == _TEAM_CONFIG_TYPE_FILE) {
				g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT,
				             _("cannot read team config from file '%s'"),
				             config);
				return FALSE;
			}
		} else {
			if (c_len != strlen (contents)) {
				g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT,
				             _("team config file '%s' contains non-valid utf-8"),
				             config);
				return FALSE;
			}
			filename = config;
			config = config_clone = g_steal_pointer (&contents);
		}
	}

	if (!nm_utils_is_json_object (config, NULL)) {
		if (filename) {
			g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT,
			             _("'%s' does not contain a valid team configuration"), filename);
		} else {
			g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT,
			             _("team configuration must be a JSON object"));
		}
		return FALSE;
	}

	*out_config = (config == config_clone)
	              ? g_steal_pointer (&config_clone)
	              : g_strdup (config);
	return TRUE;
}

static const char *
_get_text_hidden (NMMetaAccessorGetType get_type)
{
	if (get_type == NM_META_ACCESSOR_GET_TYPE_PRETTY)
		return _(NM_META_TEXT_HIDDEN);
	return NM_META_TEXT_HIDDEN;
}

/*****************************************************************************/

G_GNUC_PRINTF (4, 5)
static void
_env_warn_fcn (const NMMetaEnvironment *environment,
               gpointer environment_user_data,
               NMMetaEnvWarnLevel warn_level,
               const char *fmt_l10n,
               ...)
{
	va_list ap;

	if (!environment || !environment->warn_fcn)
		return;

	va_start (ap, fmt_l10n);
	environment->warn_fcn (environment,
	                       environment_user_data,
	                       warn_level,
	                       fmt_l10n,
	                       ap);
	va_end (ap);
}

/*****************************************************************************/

#define ARGS_DESCRIBE_FCN \
	const NMMetaPropertyInfo *property_info, char **out_to_free

#define ARGS_GET_FCN \
	const NMMetaPropertyInfo *property_info, const NMMetaEnvironment *environment, gpointer environment_user_data, NMSetting *setting, NMMetaAccessorGetType get_type, NMMetaAccessorGetFlags get_flags, NMMetaAccessorGetOutFlags *out_flags, gpointer *out_to_free

#define ARGS_SET_FCN \
	const NMMetaPropertyInfo *property_info, const NMMetaEnvironment *environment, gpointer environment_user_data, NMSetting *setting, const char *value, GError **error

#define ARGS_REMOVE_FCN \
	const NMMetaPropertyInfo *property_info, const NMMetaEnvironment *environment, gpointer environment_user_data, NMSetting *setting, const char *value, guint32 idx, GError **error

#define ARGS_COMPLETE_FCN \
	const NMMetaPropertyInfo *property_info, const NMMetaEnvironment *environment, gpointer environment_user_data, const NMMetaOperationContext *operation_context, const char *text, char ***out_to_free

#define ARGS_VALUES_FCN \
	const NMMetaPropertyInfo *property_info, char ***out_to_free

#define ARGS_SETTING_INIT_FCN \
	const NMMetaSettingInfoEditor *setting_info, NMSetting *setting, NMMetaAccessorSettingInitType init_type

#define RETURN_UNSUPPORTED_GET_TYPE() \
	G_STMT_START { \
		if (!NM_IN_SET (get_type, \
		                NM_META_ACCESSOR_GET_TYPE_PARSABLE, \
		                NM_META_ACCESSOR_GET_TYPE_PRETTY)) { \
			nm_assert_not_reached (); \
			return NULL; \
		} \
	} G_STMT_END;

#define RETURN_STR_TO_FREE(val) \
	G_STMT_START { \
		char *_val = (val); \
		return ((*(out_to_free)) = _val); \
	} G_STMT_END

static gconstpointer
_get_fcn_nmc_with_default (ARGS_GET_FCN)
{
	const char *s;
	char *s_full;
	GValue val = G_VALUE_INIT;

	RETURN_UNSUPPORTED_GET_TYPE ();

	if (property_info->property_typ_data->subtype.get_with_default.fcn (setting)) {
		if (get_type == NM_META_ACCESSOR_GET_TYPE_PRETTY)
			return _("(default)");
		return "";
	}

	g_value_init (&val, G_TYPE_STRING);
	g_object_get_property (G_OBJECT (setting), property_info->property_name, &val);
	s = g_value_get_string (&val);
	if (get_type == NM_META_ACCESSOR_GET_TYPE_PRETTY)
		s_full = s ? g_strdup_printf ("\"%s\"", s) : g_strdup ("");
	else
		s_full = g_strdup (s && *s ? s : " ");
	g_value_unset (&val);
	RETURN_STR_TO_FREE (s_full);
}

static gconstpointer
_get_fcn_gobject_impl (const NMMetaPropertyInfo *property_info,
                       NMSetting *setting,
                       NMMetaAccessorGetType get_type,
                       gpointer *out_to_free)
{
	char *s;
	const char *s_c;
	GType gtype_prop;
	nm_auto_unset_gvalue GValue val = G_VALUE_INIT;

	RETURN_UNSUPPORTED_GET_TYPE ();

	gtype_prop = _gobject_property_get_gtype (G_OBJECT (setting), property_info->property_name);

	if (gtype_prop == G_TYPE_BOOLEAN) {
		gboolean b;

		g_value_init (&val, gtype_prop);
		g_object_get_property (G_OBJECT (setting), property_info->property_name, &val);
		b = g_value_get_boolean (&val);
		if (get_type == NM_META_ACCESSOR_GET_TYPE_PRETTY)
			s_c = b ? _("yes") : _("no");
		else
			s_c = b ? "yes" : "no";
		return s_c;
	} else {
		g_value_init (&val, G_TYPE_STRING);
		g_object_get_property (G_OBJECT (setting), property_info->property_name, &val);
		s = g_value_dup_string (&val);
		RETURN_STR_TO_FREE (s);
	}
}

static gconstpointer
_get_fcn_gobject (ARGS_GET_FCN)
{
	return _get_fcn_gobject_impl (property_info, setting, get_type, out_to_free);
}

static gconstpointer
_get_fcn_gobject_mtu (ARGS_GET_FCN)
{
	guint32 mtu;

	RETURN_UNSUPPORTED_GET_TYPE ();

	if (   !property_info->property_typ_data
	    || !property_info->property_typ_data->subtype.mtu.get_fcn)
		return _get_fcn_gobject_impl (property_info, setting, get_type, out_to_free);

	mtu = property_info->property_typ_data->subtype.mtu.get_fcn (setting);
	if (mtu == 0) {
		if (get_type == NM_META_ACCESSOR_GET_TYPE_PRETTY)
			return _("auto");
		return "auto";
	}
	RETURN_STR_TO_FREE (g_strdup_printf ("%u", (unsigned) mtu));
}

static gconstpointer
_get_fcn_gobject_secret_flags (ARGS_GET_FCN)
{
	guint v;
	GValue val = G_VALUE_INIT;

	RETURN_UNSUPPORTED_GET_TYPE ();

	g_value_init (&val, G_TYPE_UINT);
	g_object_get_property (G_OBJECT (setting), property_info->property_name, &val);
	v = g_value_get_uint (&val);
	g_value_unset (&val);
	RETURN_STR_TO_FREE (secret_flags_to_string (v, get_type));
}

static gconstpointer
_get_fcn_gobject_enum (ARGS_GET_FCN)
{
	GType gtype = 0;
	GType gtype_prop;
	nm_auto_unref_gtypeclass GTypeClass *gtype_class = NULL;
	nm_auto_unref_gtypeclass GTypeClass *gtype_prop_class = NULL;
	gboolean has_gtype = FALSE;
	nm_auto_unset_gvalue GValue gval = G_VALUE_INIT;
	gint64 v;
	gboolean format_numeric = FALSE;
	gboolean format_numeric_hex = FALSE;
	gboolean format_numeric_hex_unknown = FALSE;
	gboolean format_text = FALSE;
	gboolean format_text_l10n = FALSE;
	gs_free char *s = NULL;
	char s_numeric[64];

	RETURN_UNSUPPORTED_GET_TYPE ();

	if (property_info->property_typ_data) {
		if (property_info->property_typ_data->subtype.gobject_enum.get_gtype) {
			gtype = property_info->property_typ_data->subtype.gobject_enum.get_gtype ();
			has_gtype = TRUE;
		}
	}

	if (   property_info->property_typ_data
	    && get_type == NM_META_ACCESSOR_GET_TYPE_PRETTY
	    && NM_FLAGS_ANY (property_info->property_typ_data->typ_flags,   NM_META_PROPERTY_TYP_FLAG_ENUM_GET_PRETTY_NUMERIC
	                                                                  | NM_META_PROPERTY_TYP_FLAG_ENUM_GET_PRETTY_NUMERIC_HEX
	                                                                  | NM_META_PROPERTY_TYP_FLAG_ENUM_GET_PRETTY_TEXT
	                                                                  | NM_META_PROPERTY_TYP_FLAG_ENUM_GET_PRETTY_TEXT_L10N)) {
		format_numeric_hex = NM_FLAGS_HAS (property_info->property_typ_data->typ_flags, NM_META_PROPERTY_TYP_FLAG_ENUM_GET_PRETTY_NUMERIC_HEX);
		format_numeric = format_numeric_hex || NM_FLAGS_HAS (property_info->property_typ_data->typ_flags, NM_META_PROPERTY_TYP_FLAG_ENUM_GET_PRETTY_NUMERIC);
		format_text_l10n = NM_FLAGS_HAS (property_info->property_typ_data->typ_flags, NM_META_PROPERTY_TYP_FLAG_ENUM_GET_PRETTY_TEXT_L10N);
		format_text = format_text_l10n || NM_FLAGS_HAS (property_info->property_typ_data->typ_flags, NM_META_PROPERTY_TYP_FLAG_ENUM_GET_PRETTY_TEXT);
	} else if (   property_info->property_typ_data
	           && get_type != NM_META_ACCESSOR_GET_TYPE_PRETTY
	           && NM_FLAGS_ANY (property_info->property_typ_data->typ_flags,   NM_META_PROPERTY_TYP_FLAG_ENUM_GET_PARSABLE_NUMERIC
	                                                                         | NM_META_PROPERTY_TYP_FLAG_ENUM_GET_PARSABLE_NUMERIC_HEX
	                                                                         | NM_META_PROPERTY_TYP_FLAG_ENUM_GET_PARSABLE_TEXT)) {
		format_numeric_hex = NM_FLAGS_HAS (property_info->property_typ_data->typ_flags, NM_META_PROPERTY_TYP_FLAG_ENUM_GET_PARSABLE_NUMERIC_HEX);
		format_numeric = format_numeric && NM_FLAGS_HAS (property_info->property_typ_data->typ_flags, NM_META_PROPERTY_TYP_FLAG_ENUM_GET_PARSABLE_NUMERIC);
		format_text = NM_FLAGS_HAS (property_info->property_typ_data->typ_flags, NM_META_PROPERTY_TYP_FLAG_ENUM_GET_PARSABLE_TEXT);
	} else if (get_type == NM_META_ACCESSOR_GET_TYPE_PRETTY) {
		/* by default, output in format "%u (%s)" (with hex for flags and l10n). */
		format_numeric = TRUE;
		format_numeric_hex_unknown = TRUE;
		format_text = TRUE;
		format_text_l10n = TRUE;
	} else {
		/* by default, output only numeric (with hex for flags). */
		format_numeric = TRUE;
		format_numeric_hex_unknown = TRUE;
	}

	nm_assert (format_text || format_numeric);

	gtype_prop = _gobject_property_get_gtype (G_OBJECT (setting), property_info->property_name);

	g_value_init (&gval, gtype_prop);

	g_object_get_property (G_OBJECT (setting), property_info->property_name, &gval);

	if (   gtype_prop == G_TYPE_INT
	    || (    G_TYPE_IS_CLASSED (gtype_prop)
	        &&  G_IS_ENUM_CLASS ((gtype_prop_class ?: (gtype_prop_class = g_type_class_ref (gtype_prop)))))) {
		if (gtype_prop == G_TYPE_INT) {
			if (!has_gtype)
				g_return_val_if_reached (NULL);
			v = g_value_get_int (&gval);
		} else
		    v = g_value_get_enum (&gval);
	} else if (   gtype_prop == G_TYPE_UINT
	           || (   G_TYPE_IS_CLASSED (gtype_prop)
	               && G_IS_FLAGS_CLASS ((gtype_prop_class ?: (gtype_prop_class = g_type_class_ref (gtype_prop)))))) {
		if (gtype_prop == G_TYPE_UINT) {
			if (!has_gtype)
				g_return_val_if_reached (NULL);
			v = g_value_get_uint (&gval);
		} else
		    v = g_value_get_flags (&gval);
	} else
		g_return_val_if_reached (NULL);

	if (!has_gtype) {
		gtype = gtype_prop;
		gtype_class = g_steal_pointer (&gtype_prop_class);
	}

	nm_assert (({
		nm_auto_unref_gtypeclass GTypeClass *t = NULL;

		(   G_TYPE_IS_CLASSED (gtype)
		 && (t = g_type_class_ref (gtype))
		 && (G_IS_ENUM_CLASS (t) || G_IS_FLAGS_CLASS (t)));
	}));

	if (format_numeric && !format_text) {
		s =    format_numeric_hex
		    || (   format_numeric_hex_unknown
		        && !G_IS_ENUM_CLASS (gtype_class ?: (gtype_class = g_type_class_ref (gtype))))
		    ? g_strdup_printf ("0x%"G_GINT64_FORMAT, v)
		    : g_strdup_printf ("%"G_GINT64_FORMAT, v);
		RETURN_STR_TO_FREE (g_steal_pointer (&s));
	}

	/* the gobject_enum.value_infos are currently ignored for the getter. They
	 * only declare additional aliases for the setter. */

	s = nm_utils_enum_to_str (gtype, (int) v);

	if (!format_numeric)
		RETURN_STR_TO_FREE (g_steal_pointer (&s));

	if (   format_numeric_hex
	    || (   format_numeric_hex_unknown
	        && !G_IS_ENUM_CLASS (gtype_class ?: (gtype_class = g_type_class_ref (gtype)))))
		nm_sprintf_buf (s_numeric, "0x%"G_GINT64_FORMAT, v);
	else
		nm_sprintf_buf (s_numeric, "%"G_GINT64_FORMAT, v);

	if (nm_streq0 (s, s_numeric))
		RETURN_STR_TO_FREE (g_steal_pointer (&s));

	if (format_text_l10n)
		RETURN_STR_TO_FREE (g_strdup_printf (_("%s (%s)"), s_numeric, s));
	else
		RETURN_STR_TO_FREE (g_strdup_printf ("%s (%s)", s_numeric, s));
}

/*****************************************************************************/

static gboolean
_set_fcn_gobject_string (ARGS_SET_FCN)
{
	if (   property_info->property_typ_data
	    && property_info->property_typ_data->values_static) {
		value = nmc_string_is_valid (value,
		                             (const char **) property_info->property_typ_data->values_static,
		                             error);
		if (!value)
			return FALSE;
	}
	g_object_set (setting, property_info->property_name, value, NULL);
	return TRUE;
}

static gboolean
_set_fcn_gobject_bool (ARGS_SET_FCN)
{
	gboolean val_bool;

	if (!nmc_string_to_bool (value, &val_bool, error))
		return FALSE;

	g_object_set (setting, property_info->property_name, val_bool, NULL);
	return TRUE;
}

static gboolean
_set_fcn_gobject_int (ARGS_SET_FCN)
{
	const gint64 INVALID = G_MININT64;
	gint64 v;

	v = _nm_utils_ascii_str_to_int64 (value, 10, G_MININT, G_MAXINT, INVALID);
	if (v == INVALID) {
		g_set_error (error, 1, 0, _("'%s' is not a valid number (or out of range)"), value);
		return FALSE;
	}

	/* Validate the number according to the property spec */
	if (!validate_int (setting, property_info->property_name, v, error))
		return FALSE;

	g_object_set (setting, property_info->property_name, (int) v, NULL);
	return TRUE;
}

static gboolean
_set_fcn_gobject_int64 (ARGS_SET_FCN)
{
	gint64 v;

	v = _nm_utils_ascii_str_to_int64 (value, 10, G_MININT64, G_MAXINT64, 0);
	if (errno) {
		g_set_error (error, 1, 0, _("'%s' is not a valid number (or out of range)"), value);
		return FALSE;
	}

	/* Validate the number according to the property spec */
	if (!validate_int64 (setting, property_info->property_name, v, error))
		return FALSE;

	g_object_set (setting, property_info->property_name, v, NULL);
	return TRUE;
}

static gboolean
_set_fcn_gobject_uint_impl (const NMMetaPropertyInfo *property_info,
                            NMSetting *setting,
                            const char *value,
                            GError **error)
{
	unsigned long val_int;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!nmc_string_to_uint (value, TRUE, 0, G_MAXUINT, &val_int)) {
		g_set_error (error, 1, 0, _("'%s' is not a valid number (or out of range)"), value);
		return FALSE;
	}

	/* Validate the number according to the property spec */
	if (!validate_uint (setting, property_info->property_name, (guint) val_int, error))
		return FALSE;

	g_object_set (setting, property_info->property_name, (guint) val_int, NULL);
	return TRUE;
}

static gboolean
_set_fcn_gobject_uint (ARGS_SET_FCN)
{
	return _set_fcn_gobject_uint_impl (property_info, setting, value, error);
}

static gboolean
_set_fcn_gobject_mtu (ARGS_SET_FCN)
{
	if (nm_streq0 (value, "auto"))
		value = "0";
	return _set_fcn_gobject_uint_impl (property_info, setting, value, error);
}

static gboolean
_set_fcn_gobject_mac (ARGS_SET_FCN)
{
	NMMetaPropertyTypeMacMode mode;
	gboolean valid;

	if (property_info->property_typ_data)
		mode = property_info->property_typ_data->subtype.mac.mode;
	else
		mode = NM_META_PROPERTY_TYPE_MAC_MODE_DEFAULT;


	if (mode == NM_META_PROPERTY_TYPE_MAC_MODE_INFINIBAND)
		valid = nm_utils_hwaddr_valid (value, INFINIBAND_ALEN);
	else {
		valid =    nm_utils_hwaddr_valid (value, ETH_ALEN)
		        || (   mode == NM_META_PROPERTY_TYPE_MAC_MODE_CLONED
		            && NM_CLONED_MAC_IS_SPECIAL (value));
	}

	if (!valid) {
		g_set_error (error, 1, 0, _("'%s' is not a valid Ethernet MAC"), value);
		return FALSE;
	}

	g_object_set (setting, property_info->property_name, value, NULL);
	return TRUE;
}

static gboolean
_set_fcn_gobject_secret_flags (ARGS_SET_FCN)
{
	char **strv = NULL, **iter;
	unsigned long flags = 0, val_int;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	strv = nmc_strsplit_set (value, " \t,", 0);
	for (iter = strv; iter && *iter; iter++) {
		if (!nmc_string_to_uint (*iter, TRUE, 0, ALL_SECRET_FLAGS, &val_int)) {
			g_set_error (error, 1, 0, _("'%s' is not a valid flag number; use <0-%d>"),
			             *iter, ALL_SECRET_FLAGS);
			g_strfreev (strv);
			return FALSE;
		}
		flags += val_int;
	}
	g_strfreev (strv);

	/* Validate the flags number */
	if (flags > ALL_SECRET_FLAGS) {
		flags = ALL_SECRET_FLAGS;
		_env_warn_fcn (environment, environment_user_data,
		               NM_META_ENV_WARN_LEVEL_WARN,
		               N_("'%s' sum is higher than all flags => all flags set"),
		               value);
	}

	g_object_set (setting, property_info->property_name, (guint) flags, NULL);
	return TRUE;
}

static gboolean
_set_fcn_gobject_enum (ARGS_SET_FCN)
{
	GType gtype = 0;
	GType gtype_prop;
	gboolean has_gtype = FALSE;
	nm_auto_unset_gvalue GValue gval = G_VALUE_INIT;
	nm_auto_unref_gtypeclass GTypeClass *gtype_class = NULL;
	int v;

	if (property_info->property_typ_data) {
		if (property_info->property_typ_data->subtype.gobject_enum.get_gtype) {
			gtype = property_info->property_typ_data->subtype.gobject_enum.get_gtype ();
			has_gtype = TRUE;
		}
	}

	gtype_prop = _gobject_property_get_gtype (G_OBJECT (setting), property_info->property_name);

	if (   gtype_prop == G_TYPE_INT
	    || gtype_prop == G_TYPE_UINT) {
		if (!has_gtype)
			g_return_val_if_reached (FALSE);
	} else if (G_TYPE_IS_CLASSED (gtype_prop)) {
		gtype_class = g_type_class_ref (gtype_prop);
		if (   !G_IS_ENUM_CLASS (gtype_class)
		    && !G_IS_FLAGS_CLASS (gtype_class))
			g_return_val_if_reached (FALSE);
	} else
		g_return_val_if_reached (FALSE);

	if (!has_gtype)
		gtype = gtype_prop;

	if (!_nm_utils_enum_from_str_full (gtype, value, &v, NULL,
	                                   property_info->property_typ_data
	                                       ? property_info->property_typ_data->subtype.gobject_enum.value_infos
	                                       : NULL))
		goto fail;

	g_value_init (&gval, gtype_prop);
	if (gtype_prop == G_TYPE_INT)
		g_value_set_int (&gval, v);
	else if (gtype_prop == G_TYPE_UINT)
		g_value_set_uint (&gval, v);
	else if (G_IS_ENUM_CLASS (gtype_class))
		g_value_set_enum (&gval, v);
	else if (G_IS_FLAGS_CLASS (gtype_class))
		g_value_set_flags (&gval, v);
	else
		g_return_val_if_reached (FALSE);

	if (!nm_g_object_set_property (G_OBJECT (setting), property_info->property_name, &gval, NULL))
		goto fail;

	return TRUE;

fail:
	if (error) {
		gs_free const char **valid_all = NULL;
		gs_free const char *valid_str = NULL;
		int min = G_MININT;
		int max = G_MAXINT;

		if (property_info->property_typ_data) {
			if (   property_info->property_typ_data->subtype.gobject_enum.min
			    || property_info->property_typ_data->subtype.gobject_enum.max) {
				min = property_info->property_typ_data->subtype.gobject_enum.min;
				max = property_info->property_typ_data->subtype.gobject_enum.max;
			}
		}
		valid_all = nm_utils_enum_get_values (gtype, min, max);
		valid_str = g_strjoinv (",", (char **) valid_all);
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT,
		             _("invalid option '%s', use one of [%s]"),
		             value,
		             valid_str);
	}
	return FALSE;
}

/*****************************************************************************/

static const char *const*
_values_fcn_gobject_enum (ARGS_VALUES_FCN)
{
	GType gtype = 0;
	gboolean has_gtype = FALSE;
	gboolean has_minmax = FALSE;
	int min = G_MININT;
	int max = G_MAXINT;
	char **v, **w;

	if (property_info->property_typ_data) {
		if (   property_info->property_typ_data->subtype.gobject_enum.min
		    || property_info->property_typ_data->subtype.gobject_enum.max) {
			min = property_info->property_typ_data->subtype.gobject_enum.min;
			max = property_info->property_typ_data->subtype.gobject_enum.max;
			has_minmax = TRUE;
		}
		if (property_info->property_typ_data->subtype.gobject_enum.get_gtype) {
			gtype = property_info->property_typ_data->subtype.gobject_enum.get_gtype ();
			has_gtype = TRUE;
		}
	}

	if (!has_gtype) {
		gtype = _gtype_property_get_gtype (property_info->setting_info->general->get_setting_gtype (),
		                                   property_info->property_name);
	}

	if (   !has_minmax
	    && G_TYPE_IS_CLASSED (gtype)) {
		nm_auto_unref_gtypeclass GTypeClass *class = NULL;

		class = g_type_class_ref (gtype);
		if (G_IS_FLAGS_CLASS (class)) {
			min = 0;
			max = (gint) G_MAXUINT;
		}
	}

	/* the gobject_enum.value_infos are currently ignored for the list of
	 * values. They only declare additional (hidden) aliases for the setter. */

	v = (char **) nm_utils_enum_get_values (gtype, min, max);
	if (v) {
		for (w = v; *w; w++)
			*w = g_strdup (*w);
	}
	return (const char *const*) (*out_to_free = v);
}

/*****************************************************************************/

static const char *const*
_complete_fcn_gobject_bool (ARGS_COMPLETE_FCN)
{
	static const char *const v[] = {
		"true",
		"false",
		"on",
		"off",
		"1",
		"0",
		"yes",
		"no",
		NULL,
	};

	if (!text || !text[0])
		return &v[6];
	return v;
}

static const char *const*
_complete_fcn_gobject_devices (ARGS_COMPLETE_FCN)
{
	NMDevice *const*devices = NULL;
	guint i, j;
	guint len = 0;
	char **ifnames;

	if (   environment
	    && environment->get_nm_devices) {
		devices = environment->get_nm_devices (environment,
		                                       environment_user_data,
		                                       &len);
	}

	if (len == 0)
		return NULL;

	ifnames = g_new (char *, len + 1);
	for (i = 0, j = 0; i < len; i++) {
		const char *ifname;

		nm_assert (NM_IS_DEVICE (devices[i]));

		ifname = nm_device_get_iface (devices[i]);
		if (ifname)
			ifnames[j++] = g_strdup (ifname);
	}
	ifnames[j++] = NULL;

	*out_to_free = ifnames;
	return (const char *const*) ifnames;
}

/*****************************************************************************/

static char *
wep_key_type_to_string (NMWepKeyType type)
{
	switch (type) {
	case NM_WEP_KEY_TYPE_KEY:
		return g_strdup_printf (_("%d (key)"), type);
	case NM_WEP_KEY_TYPE_PASSPHRASE:
		return g_strdup_printf (_("%d (passphrase)"), type);
	case NM_WEP_KEY_TYPE_UNKNOWN:
	default:
		return g_strdup_printf (_("%d (unknown)"), type);
	}
}

static char *
bytes_to_string (GBytes *bytes)
{
	const guint8 *data;
	gsize len;
	GString *cert = NULL;
	int i;

	if (!bytes)
		return NULL;
	data = g_bytes_get_data (bytes, &len);

	cert = g_string_new (NULL);
	for (i = 0; i < len; i++)
		g_string_append_printf (cert, "%02X", data[i]);

	return g_string_free (cert, FALSE);
}

static char *
vlan_flags_to_string (guint32 flags, NMMetaAccessorGetType get_type)
{
	GString *flag_str;

	if (get_type != NM_META_ACCESSOR_GET_TYPE_PRETTY)
		return g_strdup_printf ("%u", flags);

	if (flags == 0)
		return g_strdup (_("0 (NONE)"));

	flag_str = g_string_new (NULL);
	g_string_printf (flag_str, "%d (", flags);

	if (flags & NM_VLAN_FLAG_REORDER_HEADERS)
		g_string_append (flag_str, _("REORDER_HEADERS, "));
	if (flags & NM_VLAN_FLAG_GVRP)
		g_string_append (flag_str, _("GVRP, "));
	if (flags & NM_VLAN_FLAG_LOOSE_BINDING)
		g_string_append (flag_str, _("LOOSE_BINDING, "));
	if (flags & NM_VLAN_FLAG_MVRP)
		g_string_append (flag_str, _("MVRP, "));

	if (flag_str->str[flag_str->len-1] == '(')
		g_string_append (flag_str, _("unknown"));
	else
		g_string_truncate (flag_str, flag_str->len-2);  /* chop off trailing ', ' */

	g_string_append_c (flag_str, ')');

	return g_string_free (flag_str, FALSE);
}

static char *
vlan_priorities_to_string (NMSettingVlan *s_vlan, NMVlanPriorityMap map)
{
	GString *priorities;
	int i;

	priorities = g_string_new (NULL);
	for (i = 0; i < nm_setting_vlan_get_num_priorities (s_vlan, map); i++) {
		guint32 from, to;

		if (nm_setting_vlan_get_priority (s_vlan, map, i, &from, &to))
			g_string_append_printf (priorities, "%d:%d,", from, to);
	}
	if (priorities->len)
		g_string_truncate (priorities, priorities->len-1);  /* chop off trailing ',' */

	return g_string_free (priorities, FALSE);
}

static char *
ip6_privacy_to_string (NMSettingIP6ConfigPrivacy ip6_privacy, NMMetaAccessorGetType get_type)
{
	if (get_type != NM_META_ACCESSOR_GET_TYPE_PRETTY)
		return g_strdup_printf ("%d", ip6_privacy);

	switch (ip6_privacy) {
	case NM_SETTING_IP6_CONFIG_PRIVACY_DISABLED:
		return g_strdup_printf (_("%d (disabled)"), ip6_privacy);
	case NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_PUBLIC_ADDR:
		return g_strdup_printf (_("%d (enabled, prefer public IP)"), ip6_privacy);
	case NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR:
		return g_strdup_printf (_("%d (enabled, prefer temporary IP)"), ip6_privacy);
	default:
		return g_strdup_printf (_("%d (unknown)"), ip6_privacy);
	}
}

static char *
secret_flags_to_string (guint32 flags, NMMetaAccessorGetType get_type)
{
	GString *flag_str;

	if (get_type != NM_META_ACCESSOR_GET_TYPE_PRETTY)
		return g_strdup_printf ("%u", flags);

	if (flags == 0)
		return g_strdup (_("0 (none)"));

	flag_str = g_string_new (NULL);
	g_string_printf (flag_str, "%u (", flags);

	if (flags & NM_SETTING_SECRET_FLAG_AGENT_OWNED)
		g_string_append (flag_str, _("agent-owned, "));
	if (flags & NM_SETTING_SECRET_FLAG_NOT_SAVED)
		g_string_append (flag_str, _("not saved, "));
	if (flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)
		g_string_append (flag_str, _("not required, "));

	if (flag_str->str[flag_str->len-1] == '(')
		g_string_append (flag_str, _("unknown"));
	else
		g_string_truncate (flag_str, flag_str->len-2);  /* chop off trailing ', ' */

	g_string_append_c (flag_str, ')');

	return g_string_free (flag_str, FALSE);
}

static void
vpn_data_item (const char *key, const char *value, gpointer user_data)
{
	GString *ret_str = (GString *) user_data;

	if (ret_str->len != 0)
		g_string_append (ret_str, ", ");

	g_string_append_printf (ret_str, "%s = %s", key, value);
}

#define DEFINE_SETTER_STR_LIST_MULTI(def_func, s_macro, set_func) \
	static gboolean \
	def_func (NMSetting *setting, \
	          const char *prop, \
	          const char *value, \
	          const char **valid_strv, \
	          GError **error) \
	{ \
		char **strv = NULL, **iter; \
		const char *item; \
		g_return_val_if_fail (error == NULL || *error == NULL, FALSE); \
		strv = nmc_strsplit_set (value, " \t,", 0); \
		for (iter = strv; iter && *iter; iter++) { \
			if (!(item = nmc_string_is_valid (g_strstrip (*iter), valid_strv, error))) { \
				g_strfreev (strv); \
				return FALSE; \
			} \
			set_func (s_macro (setting), item); \
		} \
		g_strfreev (strv); \
		return TRUE; \
	}

#define DEFINE_SETTER_OPTIONS(def_func, s_macro, s_type, add_func, valid_func1, valid_func2) \
	static gboolean \
	def_func (ARGS_SET_FCN) \
	{ \
		char **strv = NULL, **iter; \
		const char **(*valid_func1_p) (s_type *) = valid_func1; \
		const char * (*valid_func2_p) (const char *, const char *, GError **) = valid_func2; \
		const char *opt_name, *opt_val; \
		\
		g_return_val_if_fail (error == NULL || *error == NULL, FALSE); \
		\
		strv = nmc_strsplit_set (value, ",", 0); \
		for (iter = strv; iter && *iter; iter++) { \
			char *left = g_strstrip (*iter); \
			char *right = strchr (left, '='); \
			if (!right) { \
				g_set_error (error, 1, 0, _("'%s' is not valid; use <option>=<value>"), *iter); \
				g_strfreev (strv); \
				return FALSE; \
			} \
			*right++ = '\0'; \
			\
			if (valid_func1_p) { \
				const char **valid_options = valid_func1_p (s_macro (setting)); \
				if (!(opt_name = nmc_string_is_valid (g_strstrip (left), valid_options, error))) { \
					g_strfreev (strv); \
					return FALSE; \
				} \
			} else \
				opt_name = g_strstrip (left);\
			\
			opt_val = g_strstrip (right); \
			if (valid_func2_p) { \
				if (!(opt_val = valid_func2_p ((const char *) left, (const char *) opt_val, error))) { \
					g_strfreev (strv); \
					return FALSE; \
				}\
			}\
			add_func (s_macro (setting), opt_name, opt_val); \
		} \
		g_strfreev (strv); \
		return TRUE; \
	}

#define DEFINE_REMOVER_INDEX_OR_VALUE(def_func, s_macro, num_func, rem_func_idx, rem_func_val) \
	static gboolean \
	def_func (ARGS_REMOVE_FCN) \
	{ \
		guint32 num; \
		if (value) { \
			gboolean ret; \
			char *value_stripped = g_strstrip (g_strdup (value)); \
			ret = rem_func_val (s_macro (setting), value_stripped, error); \
			g_free (value_stripped); \
			return ret; \
		} \
		num = num_func (s_macro (setting)); \
		if (num == 0) { \
			g_set_error_literal (error, 1, 0, _("no item to remove")); \
			return FALSE; \
		} \
		if (idx >= num) { \
			g_set_error (error, 1, 0, _("index '%d' is not in range <0-%d>"), idx, num - 1); \
			return FALSE; \
		} \
		rem_func_idx (s_macro (setting), idx); \
		return TRUE; \
	}

#define DEFINE_REMOVER_OPTION(def_func, s_macro, rem_func) \
	static gboolean \
	def_func (ARGS_REMOVE_FCN) \
	{ \
		gboolean success = FALSE; \
		if (value && *value) { \
			success = rem_func (s_macro (setting), value); \
			if (!success) \
				g_set_error (error, 1, 0, _("invalid option '%s'"), value); \
		} else \
			g_set_error_literal (error, 1, 0, _("missing option")); \
		return success; \
	}

#define DEFINE_ALLOWED_VAL_FUNC(def_func, valid_values) \
	static const char *const* \
	def_func (NMSetting *setting, const char *prop) \
	{ \
		return valid_values; \
	}

#define DEFINE_SETTER_MAC_BLACKLIST(def_func, s_macro, add_func) \
	static gboolean \
	def_func (ARGS_SET_FCN) \
	{ \
		guint8 buf[32]; \
		char **list = NULL, **iter; \
		GSList *macaddr_blacklist = NULL; \
		\
		g_return_val_if_fail (error == NULL || *error == NULL, FALSE); \
		\
		list = nmc_strsplit_set (value, " \t,", 0); \
		for (iter = list; iter && *iter; iter++) { \
			if (!nm_utils_hwaddr_aton (*iter, buf, ETH_ALEN)) { \
				g_set_error (error, 1, 0, _("'%s' is not a valid MAC"), *iter); \
				g_strfreev (list); \
				g_slist_free (macaddr_blacklist); \
				return FALSE; \
			} \
		} \
		\
		for (iter = list; iter && *iter; iter++) \
			add_func (s_macro (setting), *iter); \
		\
		g_strfreev (list); \
		return TRUE; \
	}


static gboolean
verify_string_list (char **strv,
                    const char *prop,
                    gboolean (*validate_func) (const char *),
                    GError **error)
{
	char **iter;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	for (iter = strv; iter && *iter; iter++) {
		if (**iter == '\0')
			continue;
		if (validate_func) {
			if (!validate_func (*iter)) {
				g_set_error (error, 1, 0, _("'%s' is not valid"),
				             *iter);
				return FALSE;
			}
		}
	}
	return TRUE;
}

static gboolean
validate_int (NMSetting *setting, const char* prop, gint val, GError **error)
{
	GParamSpec *pspec;
	GValue value = G_VALUE_INIT;
	gboolean success = TRUE;

	g_value_init (&value, G_TYPE_INT);
	g_value_set_int (&value, val);
	pspec = g_object_class_find_property (G_OBJECT_GET_CLASS (G_OBJECT (setting)), prop);
	g_assert (G_IS_PARAM_SPEC (pspec));
	if (g_param_value_validate (pspec, &value)) {
		GParamSpecInt *pspec_int = (GParamSpecInt *) pspec;
		g_set_error (error, 1, 0, _("'%d' is not valid; use <%d-%d>"),
		             val, pspec_int->minimum, pspec_int->maximum);
		success = FALSE;
	}
	g_value_unset (&value);
	return success;
}

static gboolean
validate_int64 (NMSetting *setting, const char* prop, gint64 val, GError **error)
{
	GParamSpec *pspec;
	GValue value = G_VALUE_INIT;
	gboolean success = TRUE;

	g_value_init (&value, G_TYPE_INT64);
	g_value_set_int64 (&value, val);
	pspec = g_object_class_find_property (G_OBJECT_GET_CLASS (G_OBJECT (setting)), prop);
	g_assert (G_IS_PARAM_SPEC (pspec));
	if (g_param_value_validate (pspec, &value)) {
		GParamSpecInt64 *pspec_int = (GParamSpecInt64 *) pspec;
		G_STATIC_ASSERT (sizeof (long long) >= sizeof (gint64));
		g_set_error (error, 1, 0, _("'%lld' is not valid; use <%lld-%lld>"),
		             (long long) val, (long long) pspec_int->minimum, (long long) pspec_int->maximum);
		success = FALSE;
	}
	g_value_unset (&value);
	return success;
}

static gboolean
validate_uint (NMSetting *setting, const char* prop, guint val, GError **error)
{
	GParamSpec *pspec;
	GValue value = G_VALUE_INIT;
	gboolean success = TRUE;

	g_value_init (&value, G_TYPE_UINT);
	g_value_set_uint (&value, val);
	pspec = g_object_class_find_property (G_OBJECT_GET_CLASS (G_OBJECT (setting)), prop);
	g_assert (G_IS_PARAM_SPEC (pspec));
	if (g_param_value_validate (pspec, &value)) {
		GParamSpecUInt *pspec_uint = (GParamSpecUInt *) pspec;
		g_set_error (error, 1, 0, _("'%u' is not valid; use <%u-%u>"),
		             val, pspec_uint->minimum, pspec_uint->maximum);
		success = FALSE;
	}
	g_value_unset (&value);
	return success;
}

static char *
flag_values_to_string (GFlagsValue *array, guint n)
{
	GString *str;
	guint i;

	str = g_string_new (NULL);
	for (i = 0; i < n; i++)
		g_string_append_printf (str, "%u, ", array[i].value);
	if (str->len)
		g_string_truncate (str, str->len-2);  /* chop off trailing ', ' */
	return g_string_free (str, FALSE);
}

static gboolean
validate_flags (NMSetting *setting, const char* prop, guint val, GError **error)
{
	GParamSpec *pspec;
	GValue value = G_VALUE_INIT;
	gboolean success = TRUE;

	pspec = g_object_class_find_property (G_OBJECT_GET_CLASS (G_OBJECT (setting)), prop);
	g_assert (G_IS_PARAM_SPEC (pspec));

	g_value_init (&value, pspec->value_type);
	g_value_set_flags (&value, val);

	if (g_param_value_validate (pspec, &value)) {
		GParamSpecFlags *pspec_flags = (GParamSpecFlags *) pspec;
		char *flag_values = flag_values_to_string (pspec_flags->flags_class->values,
		                                           pspec_flags->flags_class->n_values);
		g_set_error (error, 1, 0, _("'%u' flags are not valid; use combination of %s"),
		             val, flag_values);
		g_free (flag_values);
		success = FALSE;
	}
	g_value_unset (&value);
	return success;
}

static gboolean
check_and_set_string (NMSetting *setting,
                      const char *prop,
                      const char *val,
                      const char **valid_strv,
                      GError **error)
{
	const char *checked_val;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	checked_val = nmc_string_is_valid (val, valid_strv, error);
	if (!checked_val)
		return FALSE;

	g_object_set (setting, prop, checked_val, NULL);
	return TRUE;
}

static gboolean
_set_fcn_gobject_flags (ARGS_SET_FCN)
{
	unsigned long val_int;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!nmc_string_to_uint (value, TRUE, 0, G_MAXUINT, &val_int)) {
		g_set_error (error, 1, 0, _("'%s' is not a valid number (or out of range)"), value);
		return FALSE;
	}

	/* Validate the flags according to the property spec */
	if (!validate_flags (setting, property_info->property_name, (guint) val_int, error))
		return FALSE;

	g_object_set (setting, property_info->property_name, (guint) val_int, NULL);
	return TRUE;
}

static gboolean
_set_fcn_gobject_ssid (ARGS_SET_FCN)
{
	GBytes *ssid;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (strlen (value) > 32) {
		g_set_error (error, 1, 0, _("'%s' is not valid"), value);
		return FALSE;
	}

	ssid = g_bytes_new (value, strlen (value));
	g_object_set (setting, property_info->property_name, ssid, NULL);
	g_bytes_unref (ssid);
	return TRUE;
}

static gboolean
_set_fcn_gobject_ifname (ARGS_SET_FCN)
{
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!nm_utils_is_valid_iface_name (value, error))
		return FALSE;
	g_object_set (setting, property_info->property_name, value, NULL);
	return TRUE;
}

static gboolean
_set_fcn_vpn_service_type (ARGS_SET_FCN)
{
	gs_free char *service_name = NULL;

	service_name = nm_vpn_plugin_info_list_find_service_type (nm_vpn_get_plugin_infos (), value);
	g_object_set (setting, property_info->property_name, service_name ? : value, NULL);
	return TRUE;
}

static const char *const*
_complete_fcn_vpn_service_type (ARGS_COMPLETE_FCN)
{
	gsize i, j;
	char **values;

	values = nm_vpn_plugin_info_list_get_service_types (nm_vpn_get_plugin_infos (), FALSE, TRUE);
	if (!values)
		return NULL;

	if (!text || !*text) {
		/* If the prompt text is empty or contains no '.',
		 * filter out full names. */
		for (i = 0, j = 0; values[i]; i++) {
			if (strchr (values[i], '.')) {
				g_free (values[i]);
				continue;
			}

			if (i != j)
				values[j] = values[i];
			j++;
		}
		values[j++] = NULL;
	}
	return (const char *const*) (*out_to_free = values);
}

static gboolean
nmc_util_is_domain (const char *domain)
{
	//FIXME: implement
	return TRUE;
}

static gboolean
nmc_property_set_bytes (NMSetting *setting, const char *prop, const char *value, GError **error)
{
	gs_free char *val_strip = NULL;
	gs_strfreev char **strv = NULL;
	const char *delimiters = " \t,";
	char **iter;
	GBytes *bytes;
	GByteArray *array = NULL;
	gboolean success = TRUE;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	val_strip = g_strstrip (g_strdup (value));

	/* First try hex string in the format of AAbbCCDd */
	bytes = nm_utils_hexstr2bin (val_strip);
	if (bytes)
		goto done;

	/* Otherwise, consider the following format: AA b 0xCc D */
	strv = nmc_strsplit_set (val_strip, delimiters, 0);
	array = g_byte_array_sized_new (g_strv_length (strv));
	for (iter = strv; iter && *iter; iter++) {
		int v;
		guint8 v8;

		v = _nm_utils_ascii_str_to_int64 (*iter, 16, 0, 255, -1);
		if (v == -1) {
			g_set_error (error, 1, 0, _("'%s' is not a valid hex character"), *iter);
			g_byte_array_free (array, TRUE);
			success = FALSE;
			goto done;
		}
		v8 = v;
		g_byte_array_append (array, &v8, 1);
	}
	bytes = g_byte_array_free_to_bytes (array);

done:
	if (success)
		g_object_set (setting, prop, bytes, NULL);

	if (bytes)
		g_bytes_unref (bytes);

	return success;
}

/*****************************************************************************/

static gconstpointer
_get_fcn_802_1x_ca_cert (ARGS_GET_FCN)
{
	NMSetting8021x *s_8021X = NM_SETTING_802_1X (setting);
	char *ca_cert_str = NULL;

	RETURN_UNSUPPORTED_GET_TYPE ();

	switch (nm_setting_802_1x_get_ca_cert_scheme (s_8021X)) {
	case NM_SETTING_802_1X_CK_SCHEME_BLOB:
		ca_cert_str = bytes_to_string (nm_setting_802_1x_get_ca_cert_blob (s_8021X));
		break;
	case NM_SETTING_802_1X_CK_SCHEME_PATH:
		ca_cert_str = g_strdup (nm_setting_802_1x_get_ca_cert_path (s_8021X));
		break;
	case NM_SETTING_802_1X_CK_SCHEME_PKCS11:
		ca_cert_str = g_strdup (nm_setting_802_1x_get_ca_cert_uri (s_8021X));
		break;
	case NM_SETTING_802_1X_CK_SCHEME_UNKNOWN:
		break;
	}

	RETURN_STR_TO_FREE (ca_cert_str);
}

static gconstpointer
_get_fcn_802_1x_client_cert (ARGS_GET_FCN)
{
	NMSetting8021x *s_8021X = NM_SETTING_802_1X (setting);
	char *cert_str = NULL;

	RETURN_UNSUPPORTED_GET_TYPE ();

	switch (nm_setting_802_1x_get_client_cert_scheme (s_8021X)) {
	case NM_SETTING_802_1X_CK_SCHEME_BLOB:
		if (NM_FLAGS_HAS (get_flags, NM_META_ACCESSOR_GET_FLAGS_SHOW_SECRETS))
			cert_str = bytes_to_string (nm_setting_802_1x_get_client_cert_blob (s_8021X));
		else
			return _get_text_hidden (get_type);
		break;
	case NM_SETTING_802_1X_CK_SCHEME_PATH:
		cert_str = g_strdup (nm_setting_802_1x_get_client_cert_path (s_8021X));
		break;
	case NM_SETTING_802_1X_CK_SCHEME_PKCS11:
		cert_str = g_strdup (nm_setting_802_1x_get_client_cert_uri (s_8021X));
		break;
	case NM_SETTING_802_1X_CK_SCHEME_UNKNOWN:
		break;
	}

	RETURN_STR_TO_FREE (cert_str);
}

static gconstpointer
_get_fcn_802_1x_phase2_ca_cert (ARGS_GET_FCN)
{
	NMSetting8021x *s_8021X = NM_SETTING_802_1X (setting);
	char *phase2_ca_cert_str = NULL;

	RETURN_UNSUPPORTED_GET_TYPE ();

	switch (nm_setting_802_1x_get_phase2_ca_cert_scheme (s_8021X)) {
	case NM_SETTING_802_1X_CK_SCHEME_BLOB:
		phase2_ca_cert_str = bytes_to_string (nm_setting_802_1x_get_phase2_ca_cert_blob (s_8021X));
		break;
	case NM_SETTING_802_1X_CK_SCHEME_PATH:
		phase2_ca_cert_str = g_strdup (nm_setting_802_1x_get_phase2_ca_cert_path (s_8021X));
		break;
	case NM_SETTING_802_1X_CK_SCHEME_PKCS11:
		phase2_ca_cert_str = g_strdup (nm_setting_802_1x_get_phase2_ca_cert_uri (s_8021X));
		break;
	case NM_SETTING_802_1X_CK_SCHEME_UNKNOWN:
		break;
	}

	RETURN_STR_TO_FREE (phase2_ca_cert_str);
}

static gconstpointer
_get_fcn_802_1x_phase2_client_cert (ARGS_GET_FCN)
{
	NMSetting8021x *s_8021X = NM_SETTING_802_1X (setting);
	char *cert_str = NULL;

	RETURN_UNSUPPORTED_GET_TYPE ();

	switch (nm_setting_802_1x_get_phase2_client_cert_scheme (s_8021X)) {
	case NM_SETTING_802_1X_CK_SCHEME_BLOB:
		if (NM_FLAGS_HAS (get_flags, NM_META_ACCESSOR_GET_FLAGS_SHOW_SECRETS))
			cert_str = bytes_to_string (nm_setting_802_1x_get_phase2_client_cert_blob (s_8021X));
		else
			return _get_text_hidden (get_type);
		break;
	case NM_SETTING_802_1X_CK_SCHEME_PATH:
		cert_str = g_strdup (nm_setting_802_1x_get_phase2_client_cert_path (s_8021X));
		break;
	case NM_SETTING_802_1X_CK_SCHEME_PKCS11:
		cert_str = g_strdup (nm_setting_802_1x_get_phase2_client_cert_uri (s_8021X));
		break;
	case NM_SETTING_802_1X_CK_SCHEME_UNKNOWN:
		break;
	}

	RETURN_STR_TO_FREE (cert_str);
}

static gconstpointer
_get_fcn_802_1x_password_raw (ARGS_GET_FCN)
{
	NMSetting8021x *s_8021X = NM_SETTING_802_1X (setting);

	RETURN_UNSUPPORTED_GET_TYPE ();
	RETURN_STR_TO_FREE (bytes_to_string (nm_setting_802_1x_get_password_raw (s_8021X)));
}

static gconstpointer
_get_fcn_802_1x_private_key (ARGS_GET_FCN)
{
	NMSetting8021x *s_8021X = NM_SETTING_802_1X (setting);
	char *key_str = NULL;

	RETURN_UNSUPPORTED_GET_TYPE ();

	switch (nm_setting_802_1x_get_private_key_scheme (s_8021X)) {
	case NM_SETTING_802_1X_CK_SCHEME_BLOB:
		if (NM_FLAGS_HAS (get_flags, NM_META_ACCESSOR_GET_FLAGS_SHOW_SECRETS))
			key_str = bytes_to_string (nm_setting_802_1x_get_private_key_blob (s_8021X));
		else
			return _get_text_hidden (get_type);
		break;
	case NM_SETTING_802_1X_CK_SCHEME_PATH:
		key_str = g_strdup (nm_setting_802_1x_get_private_key_path (s_8021X));
		break;
	case NM_SETTING_802_1X_CK_SCHEME_PKCS11:
		key_str = g_strdup (nm_setting_802_1x_get_private_key_uri (s_8021X));
		break;
	case NM_SETTING_802_1X_CK_SCHEME_UNKNOWN:
		break;
	}

	RETURN_STR_TO_FREE (key_str);
}

static gconstpointer
_get_fcn_802_1x_phase2_private_key (ARGS_GET_FCN)
{
	NMSetting8021x *s_8021X = NM_SETTING_802_1X (setting);
	char *key_str = NULL;

	RETURN_UNSUPPORTED_GET_TYPE ();

	switch (nm_setting_802_1x_get_phase2_private_key_scheme (s_8021X)) {
	case NM_SETTING_802_1X_CK_SCHEME_BLOB:
		if (NM_FLAGS_HAS (get_flags, NM_META_ACCESSOR_GET_FLAGS_SHOW_SECRETS))
			key_str = bytes_to_string (nm_setting_802_1x_get_phase2_private_key_blob (s_8021X));
		else
			return _get_text_hidden (get_type);
		break;
	case NM_SETTING_802_1X_CK_SCHEME_PATH:
		key_str = g_strdup (nm_setting_802_1x_get_phase2_private_key_path (s_8021X));
		break;
	case NM_SETTING_802_1X_CK_SCHEME_PKCS11:
		key_str = g_strdup (nm_setting_802_1x_get_phase2_private_key_uri (s_8021X));
		break;
	case NM_SETTING_802_1X_CK_SCHEME_UNKNOWN:
		break;
	}

	RETURN_STR_TO_FREE (key_str);
}

#define DEFINE_SETTER_STR_LIST(def_func, set_func) \
	static gboolean \
	def_func (ARGS_SET_FCN) \
	{ \
		char **strv = NULL; \
		guint i = 0; \
		\
		g_return_val_if_fail (error == NULL || *error == NULL, FALSE); \
		\
		strv = nmc_strsplit_set (value, " \t,", 0); \
		while (strv && strv[i]) \
			set_func (NM_SETTING_802_1X (setting), strv[i++]); \
		g_strfreev (strv); \
		return TRUE; \
	}

#define DEFINE_SETTER_CERT(def_func, set_func) \
	static gboolean \
	def_func (ARGS_SET_FCN) \
	{ \
		char *val_strip = g_strstrip (g_strdup (value)); \
		char *p = val_strip; \
		NMSetting8021xCKScheme scheme = NM_SETTING_802_1X_CK_SCHEME_PATH; \
		gboolean success; \
		\
		if (strncmp (val_strip, NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PKCS11, NM_STRLEN (NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PKCS11)) == 0) \
			scheme = NM_SETTING_802_1X_CK_SCHEME_PKCS11; \
		else if (strncmp (val_strip, NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH, NM_STRLEN (NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH)) == 0) \
			p += NM_STRLEN (NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH); \
		\
		success = set_func (NM_SETTING_802_1X (setting), p, scheme, NULL, error); \
		g_free (val_strip); \
		return success; \
	}

#define DEFINE_SETTER_PRIV_KEY(def_func, pwd_func, set_func) \
	static gboolean \
	def_func (ARGS_SET_FCN) \
	{ \
		char **strv = NULL; \
		char *val_strip = g_strstrip (g_strdup (value)); \
		char *p = val_strip; \
		const char *path, *password; \
		gs_free char *password_free = NULL; \
		NMSetting8021xCKScheme scheme = NM_SETTING_802_1X_CK_SCHEME_PATH; \
		gboolean success; \
		\
		if (strncmp (val_strip, NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PKCS11, NM_STRLEN (NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PKCS11)) == 0) \
			scheme = NM_SETTING_802_1X_CK_SCHEME_PKCS11; \
		else if (strncmp (val_strip, NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH, NM_STRLEN (NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH)) == 0) \
			p += NM_STRLEN (NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH); \
		\
		strv = nmc_strsplit_set (p, " \t,", 2); \
		path = strv[0]; \
		if (g_strv_length (strv) == 2) \
			password = strv[1]; \
		else \
			password = password_free = g_strdup (pwd_func (NM_SETTING_802_1X (setting))); \
		success = set_func (NM_SETTING_802_1X (setting), path, password, scheme, NULL, error); \
		g_free (val_strip); \
		g_strfreev (strv); \
		return success; \
	}

DEFINE_SETTER_STR_LIST_MULTI (check_and_add_eap_method,
                              NM_SETTING_802_1X,
                              nm_setting_802_1x_add_eap_method)

static gboolean
_set_fcn_802_1x_eap (ARGS_SET_FCN)
{
	return check_and_add_eap_method (setting,
	                                 property_info->property_name,
	                                 value,
	                                 (const char **) property_info->property_typ_data->values_static,
	                                 error);
}

static gboolean
_validate_and_remove_eap_method (NMSetting8021x *setting,
                                 const char *eap,
                                 GError **error)
{
	gboolean ret;

	ret = nm_setting_802_1x_remove_eap_method_by_value (setting, eap);
	if (!ret)
		g_set_error (error, 1, 0, _("the property doesn't contain EAP method '%s'"), eap);
	return ret;
}
DEFINE_REMOVER_INDEX_OR_VALUE (_remove_fcn_802_1x_eap,
                               NM_SETTING_802_1X,
                               nm_setting_802_1x_get_num_eap_methods,
                               nm_setting_802_1x_remove_eap_method,
                               _validate_and_remove_eap_method)

DEFINE_SETTER_CERT (_set_fcn_802_1x_ca_cert, nm_setting_802_1x_set_ca_cert)

DEFINE_SETTER_STR_LIST (_set_fcn_802_1x_altsubject_matches, nm_setting_802_1x_add_altsubject_match)

static gboolean
_validate_and_remove_altsubject_match (NMSetting8021x *setting,
                                       const char *altsubject_match,
                                       GError **error)
{
	gboolean ret;

	ret = nm_setting_802_1x_remove_altsubject_match_by_value (setting, altsubject_match);
	if (!ret)
		g_set_error (error, 1, 0,
		             _("the property doesn't contain alternative subject match '%s'"),
		             altsubject_match);
	return ret;
}
DEFINE_REMOVER_INDEX_OR_VALUE (_remove_fcn_802_1x_altsubject_matches,
                               NM_SETTING_802_1X,
                               nm_setting_802_1x_get_num_altsubject_matches,
                               nm_setting_802_1x_remove_altsubject_match,
                               _validate_and_remove_altsubject_match)

DEFINE_SETTER_CERT (_set_fcn_802_1x_client_cert, nm_setting_802_1x_set_client_cert)

DEFINE_SETTER_CERT (_set_fcn_802_1x_phase2_ca_cert, nm_setting_802_1x_set_phase2_ca_cert)

DEFINE_SETTER_STR_LIST (_set_fcn_802_1x_phase2_altsubject_matches, nm_setting_802_1x_add_phase2_altsubject_match)

static gboolean
_validate_and_remove_phase2_altsubject_match (NMSetting8021x *setting,
                                              const char *phase2_altsubject_match,
                                              GError **error)
{
	gboolean ret;

	ret = nm_setting_802_1x_remove_phase2_altsubject_match_by_value (setting, phase2_altsubject_match);
	if (!ret)
		g_set_error (error, 1, 0,
		             _("the property doesn't contain \"phase2\" alternative subject match '%s'"),
		             phase2_altsubject_match);
	return ret;
}
DEFINE_REMOVER_INDEX_OR_VALUE (_remove_fcn_802_1x_phase2_altsubject_matches,
                               NM_SETTING_802_1X,
                               nm_setting_802_1x_get_num_phase2_altsubject_matches,
                               nm_setting_802_1x_remove_phase2_altsubject_match,
                               _validate_and_remove_phase2_altsubject_match)

DEFINE_SETTER_CERT (_set_fcn_802_1x_phase2_client_cert, nm_setting_802_1x_set_phase2_client_cert)

DEFINE_SETTER_PRIV_KEY (_set_fcn_802_1x_private_key,
                        nm_setting_802_1x_get_private_key_password,
                        nm_setting_802_1x_set_private_key)

DEFINE_SETTER_PRIV_KEY (_set_fcn_802_1x_phase2_private_key,
                        nm_setting_802_1x_get_phase2_private_key_password,
                        nm_setting_802_1x_set_phase2_private_key)

static gboolean
_set_fcn_802_1x_password_raw (ARGS_SET_FCN)
{
	return nmc_property_set_bytes (setting, property_info->property_name, value, error);
}

static gconstpointer
_get_fcn_bond_options (ARGS_GET_FCN)
{
	NMSettingBond *s_bond = NM_SETTING_BOND (setting);
	GString *bond_options_s;
	int i;

	RETURN_UNSUPPORTED_GET_TYPE ();

	bond_options_s = g_string_new (NULL);
	for (i = 0; i < nm_setting_bond_get_num_options (s_bond); i++) {
		const char *key, *value;
		gs_free char *tmp_value = NULL;
		char *p;

		nm_setting_bond_get_option (s_bond, i, &key, &value);

		if (nm_streq0 (key, NM_SETTING_BOND_OPTION_ARP_IP_TARGET)) {
			value = tmp_value = g_strdup (value);
			for (p = tmp_value; p && *p; p++) {
				if (*p == ',')
					*p = ' ';
			}
		}

		g_string_append_printf (bond_options_s, "%s=%s,", key, value);
	}
	g_string_truncate (bond_options_s, bond_options_s->len-1);  /* chop off trailing ',' */

	RETURN_STR_TO_FREE (g_string_free (bond_options_s, FALSE));
}

/*  example: miimon=100,mode=balance-rr, updelay=5 */
static gboolean
_validate_and_remove_bond_option (NMSettingBond *setting, const char *option)
{
	const char *opt;
	const char **valid_options;

	valid_options = nm_setting_bond_get_valid_options (setting);
	opt = nmc_string_is_valid (option, valid_options, NULL);

	if (opt)
		return nm_setting_bond_remove_option (setting, opt);
	else
		return FALSE;
}

static const char *
_validate_bond_option_value (const char *option, const char *value, GError **error)
{
	if (!g_strcmp0 (option, NM_SETTING_BOND_OPTION_MODE))
		return nmc_bond_validate_mode (value, error);

	return value;
}

static gboolean
_bond_add_option (NMSettingBond *setting,
                  const char *name,
                  const char *value)
{
	gs_free char *tmp_value = NULL;
	char *p;

	if (nm_streq0 (name, NM_SETTING_BOND_OPTION_ARP_IP_TARGET)) {
		value = tmp_value = g_strdup (value);
		for (p = tmp_value; p && *p; p++)
			if (*p == ' ')
				*p = ',';
	}

	return nm_setting_bond_add_option (setting, name, value);
}

DEFINE_SETTER_OPTIONS (_set_fcn_bond_options,
                       NM_SETTING_BOND,
                       NMSettingBond,
                       _bond_add_option,
                       nm_setting_bond_get_valid_options,
                       _validate_bond_option_value)
DEFINE_REMOVER_OPTION (_remove_fcn_bond_options,
                       NM_SETTING_BOND,
                       _validate_and_remove_bond_option)

static const char *
_describe_fcn_bond_options (ARGS_DESCRIBE_FCN)
{
	gs_free char *options_str = NULL;
	const char **valid_options;
	char *s;

	valid_options = nm_setting_bond_get_valid_options (NULL);
	options_str = g_strjoinv (", ", (char **) valid_options);

	s = g_strdup_printf (_("Enter a list of bonding options formatted as:\n"
	                       "  option = <value>, option = <value>,... \n"
	                       "Valid options are: %s\n"
	                       "'mode' can be provided as a name or a number:\n"
	                       "balance-rr    = 0\n"
	                       "active-backup = 1\n"
	                       "balance-xor   = 2\n"
	                       "broadcast     = 3\n"
	                       "802.3ad       = 4\n"
	                       "balance-tlb   = 5\n"
	                       "balance-alb   = 6\n\n"
	                       "Example: mode=2,miimon=120\n"), options_str);
	return (*out_to_free = s);
}

static const char *const*
_values_fcn_bond_options (ARGS_VALUES_FCN)
{
	return nm_setting_bond_get_valid_options (NULL);
}

static gconstpointer
_get_fcn_connection_autoconnect_retires (ARGS_GET_FCN)
{
	NMSettingConnection *s_con = NM_SETTING_CONNECTION (setting);
	gint retries;
	char *s;

	RETURN_UNSUPPORTED_GET_TYPE ();

	retries = nm_setting_connection_get_autoconnect_retries (s_con);
	if (get_type != NM_META_ACCESSOR_GET_TYPE_PRETTY)
		s = g_strdup_printf ("%d", retries);
	else {
		switch (retries) {
		case -1:
			s = g_strdup_printf (_("%d (default)"), retries);
			break;
		case 0:
			s = g_strdup_printf (_("%d (forever)"), retries);
			break;
		default:
			s = g_strdup_printf ("%d", retries);
			break;
		}
	}

	RETURN_STR_TO_FREE (s);
}

static gconstpointer
_get_fcn_connection_permissions (ARGS_GET_FCN)
{
	NMSettingConnection *s_con = NM_SETTING_CONNECTION (setting);
	GString *perm = NULL;
	const char *perm_item;
	const char *perm_type;
	int i;

	RETURN_UNSUPPORTED_GET_TYPE ();

	perm = g_string_new (NULL);
	for (i = 0; i < nm_setting_connection_get_num_permissions (s_con); i++) {
		if (nm_setting_connection_get_permission (s_con, i, &perm_type, &perm_item, NULL))
			g_string_append_printf (perm, "%s:%s,", perm_type, perm_item);
	}
	if (perm->len > 0) {
		g_string_truncate (perm, perm->len-1); /* remove trailing , */
		RETURN_STR_TO_FREE (g_string_free (perm, FALSE));
	}

	/* No value from get_permission */
	g_string_free (perm, TRUE);
	return NULL;
}

static gboolean
_set_fcn_connection_type (ARGS_SET_FCN)
{
	gs_free char *uuid = NULL;

	if (nm_setting_connection_get_uuid (NM_SETTING_CONNECTION (setting))) {
		/* Don't allow setting type unless the connection is brand new.
		 * Just because it's a bad idea and the user wouldn't probably want that.
		 * No technical reason, really.
		 * Also, using uuid to see if the connection is brand new is a bit
		 * hacky: we can not see if the type is already set, because
		 * nmc_setting_set_property() is called only after the property
		 * we're setting (type) has been removed. */
		g_set_error (error, 1, 0, _("Can not change the connection type"));
		return FALSE;
	}

	uuid = nm_utils_uuid_generate ();
	g_object_set (G_OBJECT (setting),
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NULL);

	g_object_set (G_OBJECT (setting), property_info->property_name, value, NULL);
	return TRUE;
}

static const char *const*
_complete_fcn_connection_type (ARGS_COMPLETE_FCN)
{
	guint i, j;
	char **result;
	gsize text_len;

	result = g_new (char *, _NM_META_SETTING_TYPE_NUM * 2 + 1);

	text_len = text ? strlen (text) : 0;

	for (i = 0, j = 0; i < _NM_META_SETTING_TYPE_NUM; i++) {
		const NMMetaSettingInfoEditor *setting_info = &nm_meta_setting_infos_editor[i];
		const char *v;

		v = setting_info->alias;
		if (v) {
			if (!text || strncmp (text, v, text_len) == 0)
				result[j++] = g_strdup (v);
		}
		if (!text || !*text || !v) {
			v = setting_info->general->setting_name;
			if (!text || strncmp (text, v, text_len) == 0)
				result[j++] = g_strdup (v);
		}
	}
	result[j++] = NULL;

	return (const char *const*) (*out_to_free = result);
}

/* define from libnm-core/nm-setting-connection.c */
#define PERM_USER_PREFIX  "user:"

static gboolean
permissions_valid (const char *perm)
{
	if (!perm || perm[0] == '\0')
		return FALSE;

	if (strncmp (perm, PERM_USER_PREFIX, strlen (PERM_USER_PREFIX)) == 0) {
		if (   strlen (perm) <= strlen (PERM_USER_PREFIX)
		    || strchr (perm + strlen (PERM_USER_PREFIX), ':'))
			return  FALSE;
	} else {
		if (strchr (perm, ':'))
			return  FALSE;
	}

	return TRUE;
}

static gboolean
_set_fcn_connection_permissions (ARGS_SET_FCN)
{
	char **strv = NULL;
	guint i = 0;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	strv = nmc_strsplit_set (value, " \t,", 0);
	if (!verify_string_list (strv, property_info->property_name, permissions_valid, error)) {
		g_strfreev (strv);
		return FALSE;
	}

	for (i = 0; strv && strv[i]; i++) {
		const char *user;

		if (strncmp (strv[i], PERM_USER_PREFIX, strlen (PERM_USER_PREFIX)) == 0)
			user = strv[i]+strlen (PERM_USER_PREFIX);
		else
			user = strv[i];

		nm_setting_connection_add_permission (NM_SETTING_CONNECTION (setting), "user", user, NULL);
	}

	return TRUE;
}

static gboolean
_validate_and_remove_connection_permission (NMSettingConnection *setting,
                                            const char *perm,
                                            GError **error)
{
	gboolean ret;

	ret = nm_setting_connection_remove_permission_by_value (setting, "user", perm, NULL);
	if (!ret)
		g_set_error (error, 1, 0, _("the property doesn't contain permission '%s'"), perm);
	return ret;
}
DEFINE_REMOVER_INDEX_OR_VALUE (_remove_fcn_connection_permissions,
                               NM_SETTING_CONNECTION,
                               nm_setting_connection_get_num_permissions,
                               nm_setting_connection_remove_permission,
                               _validate_and_remove_connection_permission)

static gboolean
_set_fcn_connection_master (ARGS_SET_FCN)
{
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!value)
		;
	else if (!*value)
		value = NULL;
	else if (   !nm_utils_is_valid_iface_name (value, NULL)
	         && !nm_utils_is_uuid (value)) {
		g_set_error (error, 1, 0,
		             _("'%s' is not valid master; use ifname or connection UUID"),
		             value);
		return FALSE;
	}
	g_object_set (setting, property_info->property_name, value, NULL);
	return TRUE;
}

static const char *const*
_complete_fcn_connection_master (ARGS_COMPLETE_FCN)
{
	NMRemoteConnection *const*connections = NULL;
	guint len = 0;
	guint i, j;
	char **result;
	NMSettingConnection *s_con;
	const char *expected_type = NULL;
	gsize text_len;

	if (   environment
	    && environment->get_nm_connections) {
		connections = environment->get_nm_connections (environment,
		                                               environment_user_data,
		                                               &len);
	}
	if (!len)
		return NULL;

	if (   (!text || !*text)
	    && operation_context
	    && operation_context->connection) {
		/* if we have no text yet, initially only complete for matching
		 * slave-type. */
		s_con = nm_connection_get_setting_connection (operation_context->connection);
		if (s_con)
			expected_type = nm_setting_connection_get_slave_type (s_con);
	}

	text_len = strlen (text);

	result = g_new (char *, (2 * len) + 1);
	for (i = 0, j = 0; i < len; i++) {
		const char *v;

		s_con = nm_connection_get_setting_connection (NM_CONNECTION (connections[i]));
		if (!s_con)
			continue;

		if (   expected_type
		    && !nm_streq0 (nm_setting_connection_get_connection_type (s_con),
		                   expected_type))
			continue;

		if (text && text[0]) {
			/* if we have text, also complete for the UUID. */
			v = nm_setting_connection_get_uuid (s_con);
			if (v && (!text || strncmp (text, v, text_len) == 0))
				result[j++] = g_strdup (v);
		}

		v = nm_setting_connection_get_interface_name (s_con);
		if (v && (!text || strncmp (text, v, text_len) == 0))
			result[j++] = g_strdup (v);
	}
	result[j++] = NULL;

	*out_to_free = NULL;
	return (const char *const*) result;
}

static gboolean
_set_fcn_connection_secondaries (ARGS_SET_FCN)
{
	gs_strfreev char **strv = NULL;
	char **iter;

	strv = nmc_strsplit_set (value, " \t,", 0);
	if (strv) {
		for (iter = strv; *iter; iter++) {
			if (**iter)
				nm_setting_connection_add_secondary (NM_SETTING_CONNECTION (setting), *iter);
		}
	}
	return TRUE;
}

static gboolean
_validate_and_remove_connection_secondary (NMSettingConnection *setting,
                                           const char *secondary_uuid,
                                           GError **error)
{
	gboolean ret;

	if (!nm_utils_is_uuid (secondary_uuid)) {
		g_set_error (error, 1, 0,
		             _("the value '%s' is not a valid UUID"), secondary_uuid);
		return FALSE;
	}

	ret = nm_setting_connection_remove_secondary_by_value (setting, secondary_uuid);
	if (!ret)
		g_set_error (error, 1, 0,
		             _("the property doesn't contain UUID '%s'"), secondary_uuid);
	return ret;
}
DEFINE_REMOVER_INDEX_OR_VALUE (_remove_fcn_connection_secondaries,
                               NM_SETTING_CONNECTION,
                               nm_setting_connection_get_num_secondaries,
                               nm_setting_connection_remove_secondary,
                               _validate_and_remove_connection_secondary)

static gconstpointer
_get_fcn_connection_metered (ARGS_GET_FCN)
{
	NMSettingConnection *s_conn = NM_SETTING_CONNECTION (setting);
	const char *s;

	RETURN_UNSUPPORTED_GET_TYPE ();

	switch (nm_setting_connection_get_metered (s_conn)) {
	case NM_METERED_YES:
		s = N_("yes");
		break;
	case NM_METERED_NO:
		s = N_("no");
		break;
	case NM_METERED_UNKNOWN:
	default:
		s = N_("unknown");
		break;
	}
	if (get_type == NM_META_ACCESSOR_GET_TYPE_PRETTY)
		return _(s);
	return s;
}

static gboolean
_set_fcn_connection_metered (ARGS_SET_FCN)
{
	NMMetered metered;
	NMCTriStateValue ts_val;

	if (!nmc_string_to_tristate (value, &ts_val, error))
		return FALSE;

	switch (ts_val) {
	case NMC_TRI_STATE_YES:
		metered = NM_METERED_YES;
		break;
	case NMC_TRI_STATE_NO:
		metered = NM_METERED_NO;
		break;
	case NMC_TRI_STATE_UNKNOWN:
		metered = NM_METERED_UNKNOWN;
		break;
	default:
		g_assert_not_reached();
	}

	g_object_set (setting, property_info->property_name, metered, NULL);
	return TRUE;
}

static char *
dcb_flags_to_string (NMSettingDcbFlags flags)
{
	GString *flag_str;

	if (flags == 0)
		return g_strdup (_("0 (disabled)"));

	flag_str = g_string_new (NULL);
	g_string_printf (flag_str, "%d (", flags);

	if (flags & NM_SETTING_DCB_FLAG_ENABLE)
		g_string_append (flag_str, _("enabled, "));
	if (flags & NM_SETTING_DCB_FLAG_ADVERTISE)
		g_string_append (flag_str, _("advertise, "));
	if (flags & NM_SETTING_DCB_FLAG_WILLING)
		g_string_append (flag_str, _("willing, "));

	if (flag_str->str[flag_str->len-1] == '(')
		g_string_append (flag_str, _("unknown"));
	else
		g_string_truncate (flag_str, flag_str->len-2);  /* chop off trailing ', ' */

	g_string_append_c (flag_str, ')');

	return g_string_free (flag_str, FALSE);
}

#define DEFINE_DCB_FLAGS_GETTER(func_name, property_name) \
	static gconstpointer \
	func_name (ARGS_GET_FCN) \
	{ \
		guint v; \
		GValue val = G_VALUE_INIT; \
		\
		RETURN_UNSUPPORTED_GET_TYPE (); \
		g_value_init (&val, G_TYPE_UINT); \
		g_object_get_property (G_OBJECT (setting), property_name, &val); \
		v = g_value_get_uint (&val); \
		g_value_unset (&val); \
		RETURN_STR_TO_FREE (dcb_flags_to_string (v)); \
	}

static char *
dcb_app_priority_to_string (gint priority)
{
	return (priority == -1) ? g_strdup (_("-1 (unset)")) : g_strdup_printf ("%d", priority);
}

#define DEFINE_DCB_APP_PRIORITY_GETTER(func_name, property_name) \
	static gconstpointer \
	func_name (ARGS_GET_FCN) \
	{ \
		int v; \
		GValue val = G_VALUE_INIT; \
		\
		RETURN_UNSUPPORTED_GET_TYPE (); \
		g_value_init (&val, G_TYPE_INT); \
		g_object_get_property (G_OBJECT (setting), property_name, &val); \
		v = g_value_get_int (&val); \
		g_value_unset (&val); \
		RETURN_STR_TO_FREE (dcb_app_priority_to_string (v)); \
	}

#define DEFINE_DCB_BOOL_GETTER(func_name, getter_func_name) \
	static gconstpointer \
	func_name (ARGS_GET_FCN) \
	{ \
		NMSettingDcb *s_dcb = NM_SETTING_DCB (setting); \
		GString *str; \
		guint i; \
		\
		RETURN_UNSUPPORTED_GET_TYPE (); \
		\
		str = g_string_new (NULL); \
		for (i = 0; i < 8; i++) { \
			if (getter_func_name (s_dcb,  i)) \
				g_string_append_c (str, '1'); \
			else \
				g_string_append_c (str, '0'); \
			if (i < 7) \
				g_string_append_c (str, ','); \
		} \
		\
		RETURN_STR_TO_FREE (g_string_free (str, FALSE)); \
	}

#define DEFINE_DCB_UINT_GETTER(func_name, getter_func_name) \
	static gconstpointer \
	func_name (ARGS_GET_FCN) \
	{ \
		NMSettingDcb *s_dcb = NM_SETTING_DCB (setting); \
		GString *str; \
		guint i; \
		\
		RETURN_UNSUPPORTED_GET_TYPE (); \
		\
		str = g_string_new (NULL); \
		for (i = 0; i < 8; i++) { \
			g_string_append_printf (str, "%u", getter_func_name (s_dcb, i)); \
			if (i < 7) \
				g_string_append_c (str, ','); \
		} \
		\
		RETURN_STR_TO_FREE (g_string_free (str, FALSE)); \
	}

DEFINE_DCB_FLAGS_GETTER (_get_fcn_dcb_app_fcoe_flags, NM_SETTING_DCB_APP_FCOE_FLAGS)
DEFINE_DCB_APP_PRIORITY_GETTER (_get_fcn_dcb_app_fcoe_priority, NM_SETTING_DCB_APP_FCOE_PRIORITY)
DEFINE_DCB_FLAGS_GETTER (_get_fcn_dcb_app_iscsi_flags, NM_SETTING_DCB_APP_ISCSI_FLAGS)
DEFINE_DCB_APP_PRIORITY_GETTER (_get_fcn_dcb_app_iscsi_priority, NM_SETTING_DCB_APP_ISCSI_PRIORITY)
DEFINE_DCB_FLAGS_GETTER (_get_fcn_dcb_app_fip_flags, NM_SETTING_DCB_APP_FIP_FLAGS)
DEFINE_DCB_APP_PRIORITY_GETTER (_get_fcn_dcb_app_fip_priority, NM_SETTING_DCB_APP_FIP_PRIORITY)

DEFINE_DCB_FLAGS_GETTER (_get_fcn_dcb_priority_flow_control_flags, NM_SETTING_DCB_PRIORITY_FLOW_CONTROL_FLAGS)
DEFINE_DCB_BOOL_GETTER (_get_fcn_dcb_priority_flow_control, nm_setting_dcb_get_priority_flow_control)

DEFINE_DCB_FLAGS_GETTER (_get_fcn_dcb_priority_group_flags, NM_SETTING_DCB_PRIORITY_GROUP_FLAGS)
DEFINE_DCB_UINT_GETTER (_get_fcn_dcb_priority_group_id, nm_setting_dcb_get_priority_group_id)
DEFINE_DCB_UINT_GETTER (_get_fcn_dcb_priority_group_bandwidth, nm_setting_dcb_get_priority_group_bandwidth)
DEFINE_DCB_UINT_GETTER (_get_fcn_dcb_priority_bandwidth, nm_setting_dcb_get_priority_bandwidth)
DEFINE_DCB_BOOL_GETTER (_get_fcn_dcb_priority_strict, nm_setting_dcb_get_priority_strict_bandwidth)
DEFINE_DCB_UINT_GETTER (_get_fcn_dcb_priority_traffic_class, nm_setting_dcb_get_priority_traffic_class)

#define DCB_ALL_FLAGS (NM_SETTING_DCB_FLAG_ENABLE | NM_SETTING_DCB_FLAG_ADVERTISE | NM_SETTING_DCB_FLAG_WILLING)

static gboolean
_set_fcn_dcb_flags (ARGS_SET_FCN)
{
	char **strv = NULL, **iter;
	NMSettingDcbFlags flags = NM_SETTING_DCB_FLAG_NONE;
	long int t;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	/* Check for overall hex numeric value */
	t = _nm_utils_ascii_str_to_int64 (value, 0, 0, DCB_ALL_FLAGS, -1);
	if (t != -1)
		flags = (guint) t;
	else {
		/* Check for individual flag numbers */
		strv = nmc_strsplit_set (value, " \t,", 0);
		for (iter = strv; iter && *iter; iter++) {
			t = _nm_utils_ascii_str_to_int64 (*iter, 0, 0, DCB_ALL_FLAGS, -1);

			if (   g_ascii_strcasecmp (*iter, "enable") == 0
			    || g_ascii_strcasecmp (*iter, "enabled") == 0
			    || t == NM_SETTING_DCB_FLAG_ENABLE)
				flags |= NM_SETTING_DCB_FLAG_ENABLE;
			else if (   g_ascii_strcasecmp (*iter, "advertise") == 0
				 || t == NM_SETTING_DCB_FLAG_ADVERTISE)
				flags |= NM_SETTING_DCB_FLAG_ADVERTISE;
			else if (   g_ascii_strcasecmp (*iter, "willing") == 0
				 || t == NM_SETTING_DCB_FLAG_WILLING)
				flags |= NM_SETTING_DCB_FLAG_WILLING;
			else if (   g_ascii_strcasecmp (*iter, "disable") == 0
				 || g_ascii_strcasecmp (*iter, "disabled") == 0
				 || t == 0) {
				/* pass */
			} else {
				g_set_error (error, 1, 0, _("'%s' is not a valid DCB flag"), *iter);
				return FALSE;
			}
		}
		g_strfreev (strv);
	}

	/* Validate the flags according to the property spec */
	if (!validate_flags (setting, property_info->property_name, (guint) flags, error))
		return FALSE;

	g_object_set (setting, property_info->property_name, (guint) flags, NULL);
	return TRUE;
}

static gboolean
_set_fcn_dcb_priority (ARGS_SET_FCN)
{
	const int INVALID = G_MININT;
	int v;

	v = _nm_utils_ascii_str_to_int64 (value, 10, -1, 7, INVALID);
	if (v == INVALID) {
		g_set_error (error, 1, 0, _("'%s' is not a DCB app priority"), value);
		return FALSE;
	}

	if (!validate_int (setting, property_info->property_name, v, error))
		return FALSE;

	g_object_set (setting, property_info->property_name, v, NULL);
	return TRUE;
}

static gboolean
dcb_parse_uint_array (const char *val,
                      guint max,
                      guint other,
                      guint *out_array,
                      GError **error)
{
	gs_strfreev char **items = NULL;
	char **iter;
	gsize i;

	nm_assert (out_array);

	items = g_strsplit_set (val, ",", -1);
	if (g_strv_length (items) != 8) {
		g_set_error_literal (error, 1, 0, _("must contain 8 comma-separated numbers"));
		return FALSE;
	}

	i = 0;
	for (iter = items; *iter; iter++) {
		gint64 num;

		*iter = g_strstrip (*iter);

		num = _nm_utils_ascii_str_to_int64 (*iter, 10, 0, other ? other : max, -1);

		/* If number is greater than 'max' it must equal 'other' */
		if (   num == -1
		    || (other && (num > max) && (num != other))) {
			if (other) {
				g_set_error (error, 1, 0, _("'%s' not a number between 0 and %u (inclusive) or %u"),
				             *iter, max, other);
			} else {
				g_set_error (error, 1, 0, _("'%s' not a number between 0 and %u (inclusive)"),
				             *iter, max);
			}
			return FALSE;
		}
		nm_assert (i < 8);
		out_array[i++] = (guint) num;
	}

	return TRUE;
}

static void
dcb_check_feature_enabled (const NMMetaEnvironment *environment, gpointer *environment_user_data, NMSettingDcb *s_dcb, const char *flags_prop)
{
	NMSettingDcbFlags flags = NM_SETTING_DCB_FLAG_NONE;

	g_object_get (s_dcb, flags_prop, &flags, NULL);
	if (!(flags & NM_SETTING_DCB_FLAG_ENABLE)) {
		_env_warn_fcn (environment, environment_user_data,
		               NM_META_ENV_WARN_LEVEL_WARN,
		               N_("changes will have no effect until '%s' includes 1 (enabled)"),
		               flags_prop);
	}
}

static gboolean
_set_fcn_dcb_priority_flow_control (ARGS_SET_FCN)
{
	guint i = 0;
	guint nums[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!dcb_parse_uint_array (value, 1, 0, nums, error))
		return FALSE;

	for (i = 0; i < 8; i++)
		nm_setting_dcb_set_priority_flow_control (NM_SETTING_DCB (setting), i, !!nums[i]);

	dcb_check_feature_enabled (environment, environment_user_data, NM_SETTING_DCB (setting), NM_SETTING_DCB_PRIORITY_FLOW_CONTROL_FLAGS);
	return TRUE;
}

static gboolean
_set_fcn_dcb_priority_group_id (ARGS_SET_FCN)
{
	guint i = 0;
	guint nums[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!dcb_parse_uint_array (value, 7, 15, nums, error))
		return FALSE;

	for (i = 0; i < 8; i++)
		nm_setting_dcb_set_priority_group_id (NM_SETTING_DCB (setting), i, nums[i]);

	dcb_check_feature_enabled (environment, environment_user_data, NM_SETTING_DCB (setting), NM_SETTING_DCB_PRIORITY_GROUP_FLAGS);
	return TRUE;
}

static gboolean
_set_fcn_dcb_priority_group_bandwidth (ARGS_SET_FCN)
{
	guint i = 0, sum = 0;
	guint nums[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!dcb_parse_uint_array (value, 100, 0, nums, error))
		return FALSE;

	for (i = 0; i < 8; i++)
		sum += nums[i];
	if (sum != 100) {
		g_set_error_literal (error, 1, 0, _("bandwidth percentages must total 100%%"));
		return FALSE;
	}

	for (i = 0; i < 8; i++)
		nm_setting_dcb_set_priority_group_bandwidth (NM_SETTING_DCB (setting), i, nums[i]);

	dcb_check_feature_enabled (environment, environment_user_data, NM_SETTING_DCB (setting), NM_SETTING_DCB_PRIORITY_GROUP_FLAGS);
	return TRUE;
}

static gboolean
_set_fcn_dcb_priority_bandwidth (ARGS_SET_FCN)
{
	guint i = 0;
	guint nums[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!dcb_parse_uint_array (value, 100, 0, nums, error))
		return FALSE;

	for (i = 0; i < 8; i++)
		nm_setting_dcb_set_priority_bandwidth (NM_SETTING_DCB (setting), i, nums[i]);

	dcb_check_feature_enabled (environment, environment_user_data, NM_SETTING_DCB (setting), NM_SETTING_DCB_PRIORITY_GROUP_FLAGS);
	return TRUE;
}

static gboolean
_set_fcn_dcb_priority_strict (ARGS_SET_FCN)
{
	guint i = 0;
	guint nums[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!dcb_parse_uint_array (value, 1, 0, nums, error))
		return FALSE;

	for (i = 0; i < 8; i++)
		nm_setting_dcb_set_priority_strict_bandwidth (NM_SETTING_DCB (setting), i, !!nums[i]);

	dcb_check_feature_enabled (environment, environment_user_data, NM_SETTING_DCB (setting), NM_SETTING_DCB_PRIORITY_GROUP_FLAGS);
	return TRUE;
}

static gboolean
_set_fcn_dcb_priority_traffic_class (ARGS_SET_FCN)
{
	guint i = 0;
	guint nums[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!dcb_parse_uint_array (value, 7, 0, nums, error))
		return FALSE;

	for (i = 0; i < 8; i++)
		nm_setting_dcb_set_priority_traffic_class (NM_SETTING_DCB (setting), i, nums[i]);

	dcb_check_feature_enabled (environment, environment_user_data, NM_SETTING_DCB (setting), NM_SETTING_DCB_PRIORITY_GROUP_FLAGS);
	return TRUE;
}

static gboolean
_set_fcn_gsm_sim_operator_id (ARGS_SET_FCN)
{
	const char *p = value;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (strlen (value) != 5 && strlen (value) != 6) {
		g_set_error_literal (error, 1, 0, _("SIM operator ID must be a 5 or 6 number MCCMNC code"));
		return FALSE;
	}

	while (p && *p) {
		if (!g_ascii_isdigit (*p++)) {
			g_set_error_literal (error, 1, 0, _("SIM operator ID must be a 5 or 6 number MCCMNC code"));
			return FALSE;
		}
	}
	g_object_set (G_OBJECT (setting),
	              NM_SETTING_GSM_SIM_OPERATOR_ID,
	              value,
	              NULL);
	return TRUE;
}

static gboolean
_set_fcn_infiniband_p_key (ARGS_SET_FCN)
{
	const gint64 INVALID = G_MININT64;
	gint64 p_key;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (nm_streq (value, "default"))
		p_key = -1;
	else {
		p_key = _nm_utils_ascii_str_to_int64 (value, 0, -1, G_MAXUINT16, INVALID);
		if (p_key == INVALID) {
			g_set_error (error, 1, 0, _("'%s' is not a valid IBoIP P_Key"), value);
			return FALSE;
		}
	}

	g_object_set (setting, property_info->property_name, (int) p_key, NULL);
	return TRUE;
}


static gconstpointer
_get_fcn_infiniband_p_key (ARGS_GET_FCN)
{
	NMSettingInfiniband *s_infiniband = NM_SETTING_INFINIBAND (setting);
	int p_key;

	RETURN_UNSUPPORTED_GET_TYPE ();

	p_key = nm_setting_infiniband_get_p_key (s_infiniband);
	if (p_key == -1) {
		if (get_type != NM_META_ACCESSOR_GET_TYPE_PRETTY)
			return "default";
		else
			return _("default");
	} else
		RETURN_STR_TO_FREE (g_strdup_printf ("0x%04x", p_key));
}

static gconstpointer
_get_fcn_ip_tunnel_mode (ARGS_GET_FCN)
{
	NMSettingIPTunnel *s_ip_tunnel = NM_SETTING_IP_TUNNEL (setting);
	NMIPTunnelMode mode;

	RETURN_UNSUPPORTED_GET_TYPE ();

	mode = nm_setting_ip_tunnel_get_mode (s_ip_tunnel);
	RETURN_STR_TO_FREE (nm_utils_enum_to_str (nm_ip_tunnel_mode_get_type (), mode));
}

static gboolean
_set_fcn_ip_tunnel_mode (ARGS_SET_FCN)
{
	NMIPTunnelMode mode;
	gboolean ret;

	ret = nm_utils_enum_from_str (nm_ip_tunnel_mode_get_type(), value,
	                              (int *) &mode, NULL);

	if (!ret) {
		gs_free const char **values = NULL;
		gs_free char *values_str = NULL;

		values = nm_utils_enum_get_values (nm_ip_tunnel_mode_get_type (),
		                                   NM_IP_TUNNEL_MODE_UNKNOWN + 1,
		                                   G_MAXINT);
		values_str = g_strjoinv (",", (char **) values);
		g_set_error (error, 1, 0, _("invalid mode '%s', use one of %s"),
		             value, values_str);

		return FALSE;
	}

	g_object_set (setting, property_info->property_name, mode, NULL);
	return TRUE;
}

static gconstpointer
_get_fcn_ip_config_addresses (ARGS_GET_FCN)
{
	NMSettingIPConfig *s_ip = NM_SETTING_IP_CONFIG (setting);
	GString *printable;
	guint32 num_addresses, i;
	NMIPAddress *addr;

	RETURN_UNSUPPORTED_GET_TYPE ();

	printable = g_string_new (NULL);

	num_addresses = nm_setting_ip_config_get_num_addresses (s_ip);
	for (i = 0; i < num_addresses; i++) {
		addr = nm_setting_ip_config_get_address (s_ip, i);

		if (printable->len > 0)
			g_string_append (printable, ", ");

		g_string_append_printf (printable, "%s/%u",
		                        nm_ip_address_get_address (addr),
		                        nm_ip_address_get_prefix (addr));
	}

	RETURN_STR_TO_FREE (g_string_free (printable, FALSE));
}

static gconstpointer
_get_fcn_ip_config_routes (ARGS_GET_FCN)
{
	NMSettingIPConfig *s_ip = NM_SETTING_IP_CONFIG (setting);
	GString *printable;
	guint32 num_routes, i;
	NMIPRoute *route;

	RETURN_UNSUPPORTED_GET_TYPE ();

	printable = g_string_new (NULL);

	num_routes = nm_setting_ip_config_get_num_routes (s_ip);
	for (i = 0; i < num_routes; i++) {
		gs_free char *attr_str = NULL;
		gs_strfreev char **attr_names = NULL;
		gs_unref_hashtable GHashTable *hash = g_hash_table_new (g_str_hash, g_str_equal);
		int j;

		route = nm_setting_ip_config_get_route (s_ip, i);

		attr_names = nm_ip_route_get_attribute_names (route);
		for (j = 0; attr_names && attr_names[j]; j++) {
			g_hash_table_insert (hash, attr_names[j],
			                     nm_ip_route_get_attribute (route, attr_names[j]));
		}

		attr_str = nm_utils_format_variant_attributes (hash, ' ', '=');

		if (get_type != NM_META_ACCESSOR_GET_TYPE_PRETTY) {
			if (printable->len > 0)
				g_string_append (printable, ", ");

			g_string_append_printf (printable, "%s/%u",
			                        nm_ip_route_get_dest (route),
			                        nm_ip_route_get_prefix (route));

			if (nm_ip_route_get_next_hop (route))
				g_string_append_printf (printable, " %s", nm_ip_route_get_next_hop (route));
			if (nm_ip_route_get_metric (route) != -1)
				g_string_append_printf (printable, " %u", (guint32) nm_ip_route_get_metric (route));
			if (attr_str)
				g_string_append_printf (printable, " %s", attr_str);
		} else {

			if (printable->len > 0)
				g_string_append (printable, "; ");

			g_string_append (printable, "{ ");

			g_string_append_printf (printable, "ip = %s/%u",
			                        nm_ip_route_get_dest (route),
			                        nm_ip_route_get_prefix (route));

			if (nm_ip_route_get_next_hop (route)) {
				g_string_append_printf (printable, ", nh = %s",
				                        nm_ip_route_get_next_hop (route));
			}

			if (nm_ip_route_get_metric (route) != -1)
				g_string_append_printf (printable, ", mt = %u", (guint32) nm_ip_route_get_metric (route));
			if (attr_str)
				g_string_append_printf (printable, " %s", attr_str);

			g_string_append (printable, " }");
		}
	}

	RETURN_STR_TO_FREE (g_string_free (printable, FALSE));
}

static gconstpointer
_get_fcn_ip4_config_dad_timeout (ARGS_GET_FCN)
{
	NMSettingIPConfig *s_ip = NM_SETTING_IP_CONFIG (setting);
	gint dad_timeout;

	RETURN_UNSUPPORTED_GET_TYPE ();

	dad_timeout = nm_setting_ip_config_get_dad_timeout (s_ip);
	if (get_type != NM_META_ACCESSOR_GET_TYPE_PRETTY)
		RETURN_STR_TO_FREE (g_strdup_printf ("%d", dad_timeout));

	switch (dad_timeout) {
	case -1:
		RETURN_STR_TO_FREE (g_strdup_printf (_("%d (default)"), dad_timeout));
	case 0:
		RETURN_STR_TO_FREE (g_strdup_printf (_("%d (off)"), dad_timeout));
	default:
		RETURN_STR_TO_FREE (g_strdup_printf ("%d", dad_timeout));
	}
}

static const char *ipv4_valid_methods[] = {
	NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL,
	NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
	NM_SETTING_IP4_CONFIG_METHOD_SHARED,
	NM_SETTING_IP4_CONFIG_METHOD_DISABLED,
	NULL
};

static gboolean
_set_fcn_ip4_config_method (ARGS_SET_FCN)
{
	/* Silently accept "static" and convert to "manual" */
	if (value && strlen (value) > 1 && matches (value, "static"))
		value = NM_SETTING_IP4_CONFIG_METHOD_MANUAL;

	return check_and_set_string (setting, property_info->property_name, value, ipv4_valid_methods, error);
}

static gboolean
_set_fcn_ip4_config_dns (ARGS_SET_FCN)
{
	char **strv = NULL, **iter, *addr;
	guint32 ip4_addr;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	strv = nmc_strsplit_set (value, " \t,", 0);
	for (iter = strv; iter && *iter; iter++) {
		addr = g_strstrip (*iter);
		if (inet_pton (AF_INET, addr, &ip4_addr) < 1) {
			g_set_error (error, 1, 0, _("invalid IPv4 address '%s'"), addr);
			g_strfreev (strv);
			return FALSE;
		}
		nm_setting_ip_config_add_dns (NM_SETTING_IP_CONFIG (setting), addr);
	}
	g_strfreev (strv);
	return TRUE;
}

static gboolean
_validate_and_remove_ipv4_dns (NMSettingIPConfig *setting,
                               const char *dns,
                               GError **error)
{
	guint32 ip4_addr;
	gboolean ret;

	if (inet_pton (AF_INET, dns, &ip4_addr) < 1) {
		g_set_error (error, 1, 0, _("invalid IPv4 address '%s'"), dns);
		return FALSE;
	}

	ret = nm_setting_ip_config_remove_dns_by_value (setting, dns);
	if (!ret)
		g_set_error (error, 1, 0, _("the property doesn't contain DNS server '%s'"), dns);
	return ret;
}
DEFINE_REMOVER_INDEX_OR_VALUE (_remove_fcn_ipv4_config_dns,
                               NM_SETTING_IP_CONFIG,
                               nm_setting_ip_config_get_num_dns,
                               nm_setting_ip_config_remove_dns,
                               _validate_and_remove_ipv4_dns)

static gboolean
_set_fcn_ip4_config_dns_search (ARGS_SET_FCN)
{
	char **strv = NULL;
	guint i = 0;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	strv = nmc_strsplit_set (value, " \t,", 0);
	if (!verify_string_list (strv, property_info->property_name, nmc_util_is_domain, error)) {
		g_strfreev (strv);
		return FALSE;
	}

	while (strv && strv[i])
		nm_setting_ip_config_add_dns_search (NM_SETTING_IP_CONFIG (setting), strv[i++]);
	g_strfreev (strv);

	return TRUE;
}

static gboolean
_validate_and_remove_ipv4_dns_search (NMSettingIPConfig *setting,
                                      const char *dns_search,
                                      GError **error)
{
	gboolean ret;

	ret = nm_setting_ip_config_remove_dns_search_by_value (setting, dns_search);
	if (!ret)
		g_set_error (error, 1, 0,
		             _("the property doesn't contain DNS search domain '%s'"),
		             dns_search);
	return ret;
}
DEFINE_REMOVER_INDEX_OR_VALUE (_remove_fcn_ipv4_config_dns_search,
                               NM_SETTING_IP_CONFIG,
                               nm_setting_ip_config_get_num_dns_searches,
                               nm_setting_ip_config_remove_dns_search,
                               _validate_and_remove_ipv4_dns_search)

static gboolean
_set_fcn_ip4_config_dns_options (ARGS_SET_FCN)
{
	char **strv = NULL;
	guint i = 0;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	nm_setting_ip_config_clear_dns_options (NM_SETTING_IP_CONFIG (setting), TRUE);
	strv = nmc_strsplit_set (value, " \t,", 0);
	while (strv && strv[i])
		nm_setting_ip_config_add_dns_option (NM_SETTING_IP_CONFIG (setting), strv[i++]);
	g_strfreev (strv);

	return TRUE;
}

static gboolean
_validate_and_remove_ipv4_dns_option (NMSettingIPConfig *setting,
                                      const char *dns_option,
                                      GError **error)
{
	gboolean ret;

	ret = nm_setting_ip_config_remove_dns_option_by_value (setting, dns_option);
	if (!ret)
		g_set_error (error, 1, 0,
		             _("the property doesn't contain DNS option '%s'"),
		             dns_option);
	return ret;
}
DEFINE_REMOVER_INDEX_OR_VALUE (_remove_fcn_ipv4_config_dns_options,
                               NM_SETTING_IP_CONFIG,
                               nm_setting_ip_config_get_num_dns_options,
                               nm_setting_ip_config_remove_dns_option,
                               _validate_and_remove_ipv4_dns_option)

static gboolean
_set_fcn_ip4_config_addresses (ARGS_SET_FCN)
{
	gs_strfreev char **strv = NULL;
	const char *const*iter;
	NMIPAddress *ip4addr;

	strv = nmc_strsplit_set (value, ",", 0);
	for (iter = (const char *const*) strv; *iter; iter++) {
		ip4addr = _parse_ip_address (AF_INET, *iter, error);
		if (!ip4addr)
			return FALSE;
		nm_setting_ip_config_add_address (NM_SETTING_IP_CONFIG (setting), ip4addr);
		nm_ip_address_unref (ip4addr);
	}
	return TRUE;
}

static gboolean
_validate_and_remove_ipv4_address (NMSettingIPConfig *setting,
                                   const char *address,
                                   GError **error)
{
	NMIPAddress *ip4addr;
	gboolean ret;

	ip4addr = _parse_ip_address (AF_INET, address, error);
	if (!ip4addr)
		return FALSE;

	ret = nm_setting_ip_config_remove_address_by_value (setting, ip4addr);
	if (!ret) {
		g_set_error (error, 1, 0,
		             _("the property doesn't contain IP address '%s'"), address);
	}
	nm_ip_address_unref (ip4addr);
	return ret;
}
DEFINE_REMOVER_INDEX_OR_VALUE (_remove_fcn_ipv4_config_addresses,
                               NM_SETTING_IP_CONFIG,
                               nm_setting_ip_config_get_num_addresses,
                               nm_setting_ip_config_remove_address,
                               _validate_and_remove_ipv4_address)

static gboolean
_set_fcn_ip4_config_gateway (ARGS_SET_FCN)
{
	gs_free char *addr = NULL;

	addr = g_strstrip (g_strdup (value));

	if (!nm_utils_ipaddr_valid (AF_INET, addr)) {
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT,
	                 _("invalid gateway address '%s'"), value);
		return FALSE;
	}
	g_object_set (setting, property_info->property_name, addr, NULL);
	return TRUE;
}

static gboolean
_set_fcn_ip4_config_routes (ARGS_SET_FCN)
{
	gs_strfreev char **strv = NULL;
	const char *const*iter;
	NMIPRoute *ip4route;

	strv = nmc_strsplit_set (value, ",", 0);
	for (iter = (const char *const*) strv; *iter; iter++) {
		ip4route = _parse_ip_route (AF_INET, *iter, error);
		if (!ip4route)
			return FALSE;
		nm_setting_ip_config_add_route (NM_SETTING_IP_CONFIG (setting), ip4route);
		nm_ip_route_unref (ip4route);
	}
	return TRUE;
}

static gboolean
_validate_and_remove_ipv4_route (NMSettingIPConfig *setting,
                                 const char *route,
                                 GError **error)
{
	NMIPRoute *ip4route;
	gboolean ret;

	ip4route = _parse_ip_route (AF_INET, route, error);
	if (!ip4route)
		return FALSE;

	ret = nm_setting_ip_config_remove_route_by_value (setting, ip4route);
	if (!ret)
		g_set_error (error, 1, 0, _("the property doesn't contain route '%s'"), route);
	nm_ip_route_unref (ip4route);
	return ret;
}
DEFINE_REMOVER_INDEX_OR_VALUE (_remove_fcn_ipv4_config_routes,
                               NM_SETTING_IP_CONFIG,
                               nm_setting_ip_config_get_num_routes,
                               nm_setting_ip_config_remove_route,
                               _validate_and_remove_ipv4_route)

static gconstpointer
_get_fcn_ip6_config_ip6_privacy (ARGS_GET_FCN)
{
	NMSettingIP6Config *s_ip6 = NM_SETTING_IP6_CONFIG (setting);
	RETURN_UNSUPPORTED_GET_TYPE ();
	RETURN_STR_TO_FREE (ip6_privacy_to_string (nm_setting_ip6_config_get_ip6_privacy (s_ip6), get_type));
}

static const char *ipv6_valid_methods[] = {
	NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	NM_SETTING_IP6_CONFIG_METHOD_AUTO,
	NM_SETTING_IP6_CONFIG_METHOD_DHCP,
	NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL,
	NM_SETTING_IP6_CONFIG_METHOD_MANUAL,
	NM_SETTING_IP6_CONFIG_METHOD_SHARED,
	NULL
};

static gboolean
_set_fcn_ip6_config_method (ARGS_SET_FCN)
{
	/* Silently accept "static" and convert to "manual" */
	if (value && strlen (value) > 1 && matches (value, "static"))
		value = NM_SETTING_IP6_CONFIG_METHOD_MANUAL;

	return check_and_set_string (setting, property_info->property_name, value, ipv6_valid_methods, error);
}

static gboolean
_set_fcn_ip6_config_dns (ARGS_SET_FCN)
{
	char **strv = NULL, **iter, *addr;
	struct in6_addr ip6_addr;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	strv = nmc_strsplit_set (value, " \t,", 0);
	for (iter = strv; iter && *iter; iter++) {
		addr = g_strstrip (*iter);
		if (inet_pton (AF_INET6, addr, &ip6_addr) < 1) {
			g_set_error (error, 1, 0, _("invalid IPv6 address '%s'"), addr);
			g_strfreev (strv);
			return FALSE;
		}
		nm_setting_ip_config_add_dns (NM_SETTING_IP_CONFIG (setting), addr);
	}
	g_strfreev (strv);
	return TRUE;
}

static gboolean
_validate_and_remove_ipv6_dns (NMSettingIPConfig *setting,
                               const char *dns,
                               GError **error)
{
	struct in6_addr ip6_addr;
	gboolean ret;

	if (inet_pton (AF_INET6, dns, &ip6_addr) < 1) {
		g_set_error (error, 1, 0, _("invalid IPv6 address '%s'"), dns);
		return FALSE;
	}

	ret = nm_setting_ip_config_remove_dns_by_value (setting, dns);
	if (!ret)
		g_set_error (error, 1, 0, _("the property doesn't contain DNS server '%s'"), dns);
	return ret;
}
DEFINE_REMOVER_INDEX_OR_VALUE (_remove_fcn_ipv6_config_dns,
                               NM_SETTING_IP_CONFIG,
                               nm_setting_ip_config_get_num_dns,
                               nm_setting_ip_config_remove_dns,
                               _validate_and_remove_ipv6_dns)

static gboolean
_set_fcn_ip6_config_dns_search (ARGS_SET_FCN)
{
	char **strv = NULL;
	guint i = 0;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	strv = nmc_strsplit_set (value, " \t,", 0);
	if (!verify_string_list (strv, property_info->property_name, nmc_util_is_domain, error)) {
		g_strfreev (strv);
		return FALSE;
	}

	while (strv && strv[i])
		nm_setting_ip_config_add_dns_search (NM_SETTING_IP_CONFIG (setting), strv[i++]);
	g_strfreev (strv);

	return TRUE;
}

static gboolean
_validate_and_remove_ipv6_dns_search (NMSettingIPConfig *setting,
                                      const char *dns_search,
                                      GError **error)
{
	gboolean ret;

	ret = nm_setting_ip_config_remove_dns_search_by_value (setting, dns_search);
	if (!ret)
		g_set_error (error, 1, 0,
		             _("the property doesn't contain DNS search domain '%s'"),
		             dns_search);
	return ret;
}
DEFINE_REMOVER_INDEX_OR_VALUE (_remove_fcn_ipv6_config_dns_search,
                               NM_SETTING_IP_CONFIG,
                               nm_setting_ip_config_get_num_dns_searches,
                               nm_setting_ip_config_remove_dns_search,
                               _validate_and_remove_ipv6_dns_search)

static gboolean
_set_fcn_ip6_config_dns_options (ARGS_SET_FCN)
{
	char **strv = NULL;
	guint i = 0;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	nm_setting_ip_config_clear_dns_options (NM_SETTING_IP_CONFIG (setting), TRUE);
	strv = nmc_strsplit_set (value, " \t,", 0);
	while (strv && strv[i])
		nm_setting_ip_config_add_dns_option (NM_SETTING_IP_CONFIG (setting), strv[i++]);
	g_strfreev (strv);

	return TRUE;
}

static gboolean
_validate_and_remove_ipv6_dns_option (NMSettingIPConfig *setting,
                                      const char *dns_option,
                                      GError **error)
{
	gboolean ret;

	ret = nm_setting_ip_config_remove_dns_option_by_value (setting, dns_option);
	if (!ret)
		g_set_error (error, 1, 0,
		             _("the property doesn't contain DNS option '%s'"),
		             dns_option);
	return ret;
}
DEFINE_REMOVER_INDEX_OR_VALUE (_remove_fcn_ipv6_config_dns_options,
                               NM_SETTING_IP_CONFIG,
                               nm_setting_ip_config_get_num_dns_options,
                               nm_setting_ip_config_remove_dns_option,
                               _validate_and_remove_ipv6_dns_option)

static gboolean
_set_fcn_ip6_config_addresses (ARGS_SET_FCN)
{
	gs_strfreev char **strv = NULL;
	const char *const*iter;
	NMIPAddress *ip6addr;

	strv = nmc_strsplit_set (value, ",", 0);
	for (iter = (const char *const*) strv; *iter; iter++) {
		ip6addr = _parse_ip_address (AF_INET6, *iter, error);
		if (!ip6addr)
			return FALSE;
		nm_setting_ip_config_add_address (NM_SETTING_IP_CONFIG (setting), ip6addr);
		nm_ip_address_unref (ip6addr);
	}
	return TRUE;
}

static gboolean
_validate_and_remove_ipv6_address (NMSettingIPConfig *setting,
                                   const char *address,
                                   GError **error)
{
	NMIPAddress *ip6addr;
	gboolean ret;

	ip6addr = _parse_ip_address (AF_INET6, address, error);
	if (!ip6addr)
		return FALSE;

	ret = nm_setting_ip_config_remove_address_by_value (setting, ip6addr);
	if (!ret)
		g_set_error (error, 1, 0, _("the property doesn't contain IP address '%s'"), address);
	nm_ip_address_unref (ip6addr);
	return ret;
}
DEFINE_REMOVER_INDEX_OR_VALUE (_remove_fcn_ipv6_config_addresses,
                               NM_SETTING_IP_CONFIG,
                               nm_setting_ip_config_get_num_addresses,
                               nm_setting_ip_config_remove_address,
                               _validate_and_remove_ipv6_address)

static gboolean
_set_fcn_ip6_config_gateway (ARGS_SET_FCN)
{
	gs_free char *addr = NULL;

	addr = g_strstrip (g_strdup (value));

	if (!nm_utils_ipaddr_valid (AF_INET6, addr)) {
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT,
		             _("invalid gateway address '%s'"),
		             addr);
		return FALSE;
	}

	g_object_set (setting, property_info->property_name, addr, NULL);
	return TRUE;
}

static gboolean
_set_fcn_ip6_config_routes (ARGS_SET_FCN)
{
	gs_strfreev char **strv = NULL;
	const char *const*iter;
	NMIPRoute *ip6route;

	strv = nmc_strsplit_set (value, ",", 0);
	for (iter = (const char *const*) strv; *iter; iter++) {
		ip6route = _parse_ip_route (AF_INET6, *iter, error);
		if (!ip6route)
			return FALSE;
		nm_setting_ip_config_add_route (NM_SETTING_IP_CONFIG (setting), ip6route);
		nm_ip_route_unref (ip6route);
	}
	return TRUE;
}

static gboolean
_validate_and_remove_ipv6_route (NMSettingIPConfig *setting,
                                 const char *route,
                                 GError **error)
{
	NMIPRoute *ip6route;
	gboolean ret;

	ip6route = _parse_ip_route (AF_INET6, route, error);
	if (!ip6route)
		return FALSE;

	ret = nm_setting_ip_config_remove_route_by_value (setting, ip6route);
	if (!ret)
		g_set_error (error, 1, 0, _("the property doesn't contain route '%s'"), route);
	nm_ip_route_unref (ip6route);
	return ret;
}
DEFINE_REMOVER_INDEX_OR_VALUE (_remove_fcn_ipv6_config_routes,
                               NM_SETTING_IP_CONFIG,
                               nm_setting_ip_config_get_num_routes,
                               nm_setting_ip_config_remove_route,
                               _validate_and_remove_ipv6_route)

static gboolean
_set_fcn_ip6_config_ip6_privacy (ARGS_SET_FCN)
{
	unsigned long val_int;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!nmc_string_to_uint (value, FALSE, 0, 0, &val_int)) {
		g_set_error (error, 1, 0, _("'%s' is not a number"), value);
		return FALSE;
	}

	if (   val_int != NM_SETTING_IP6_CONFIG_PRIVACY_DISABLED
	    && val_int != NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_PUBLIC_ADDR
	    && val_int != NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR) {
		g_set_error (error, 1, 0, _("'%s' is not valid; use 0, 1, or 2"), value);
		return FALSE;
	}

	g_object_set (setting, property_info->property_name, val_int, NULL);
	return TRUE;
}

static gconstpointer
_get_fcn_macsec_mode (ARGS_GET_FCN)
{
	NMSettingMacsec *s_macsec = NM_SETTING_MACSEC (setting);
	NMSettingMacsecMode mode;

	RETURN_UNSUPPORTED_GET_TYPE ();

	mode = nm_setting_macsec_get_mode (s_macsec);
	RETURN_STR_TO_FREE (nm_utils_enum_to_str (nm_setting_macsec_mode_get_type (), mode));
}

static gboolean
_set_fcn_macsec_mode (ARGS_SET_FCN)
{
	NMSettingMacsecMode mode;
	gs_free char *options = NULL;

	if (!nm_utils_enum_from_str (nm_setting_macsec_mode_get_type (), value,
	                             (int *) &mode, NULL)) {
		options = g_strjoinv (",",
		                      (char **) nm_utils_enum_get_values (nm_setting_macsec_mode_get_type (),
		                                                          G_MININT,
		                                                          G_MAXINT));
		g_set_error (error, 1, 0, _("invalid option '%s', use one of [%s]"),
		             value, options);
			return FALSE;
	}

	g_object_set (setting, property_info->property_name, mode, NULL);
	return TRUE;
}

static gconstpointer
_get_fcn_macsec_validation (ARGS_GET_FCN)
{
	NMSettingMacsec *s_macsec = NM_SETTING_MACSEC (setting);
	NMSettingMacsecValidation validation;

	RETURN_UNSUPPORTED_GET_TYPE ();

	validation = nm_setting_macsec_get_validation (s_macsec);
	RETURN_STR_TO_FREE (nm_utils_enum_to_str (nm_setting_macsec_validation_get_type (), validation));
}

static gboolean
_set_fcn_macsec_validation (ARGS_SET_FCN)
{
	NMSettingMacsecMode validation;
	gs_free char *options = NULL;

	if (!nm_utils_enum_from_str (nm_setting_macsec_validation_get_type (), value,
	                             (int *) &validation, NULL)) {
		options = g_strjoinv (",",
		                      (char **) nm_utils_enum_get_values (nm_setting_macsec_validation_get_type (),
		                                                          G_MININT,
		                                                          G_MAXINT));
		g_set_error (error, 1, 0, _("invalid option '%s', use one of [%s]"),
		             value, options);
			return FALSE;
	}

	g_object_set (setting, property_info->property_name, validation, NULL);
	return TRUE;
}

static gconstpointer
_get_fcn_olpc_mesh_ssid (ARGS_GET_FCN)
{
	NMSettingOlpcMesh *s_olpc_mesh = NM_SETTING_OLPC_MESH (setting);
	GBytes *ssid;
	char *ssid_str = NULL;

	RETURN_UNSUPPORTED_GET_TYPE ();

	ssid = nm_setting_olpc_mesh_get_ssid (s_olpc_mesh);
	if (ssid) {
		ssid_str = nm_utils_ssid_to_utf8 (g_bytes_get_data (ssid, NULL),
		                                  g_bytes_get_size (ssid));
	}

	RETURN_STR_TO_FREE (ssid_str);
}

static gboolean
_set_fcn_olpc_mesh_channel (ARGS_SET_FCN)
{
	unsigned long chan_int;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!nmc_string_to_uint (value, TRUE, 1, 13, &chan_int)) {
		g_set_error (error, 1, 0, _("'%s' is not a valid channel; use <1-13>"), value);
		return FALSE;
	}
	g_object_set (setting, property_info->property_name, chan_int, NULL);
	return TRUE;
}

static gconstpointer
_get_fcn_proxy_method (ARGS_GET_FCN)
{
	NMSettingProxy *s_proxy = NM_SETTING_PROXY (setting);
	NMSettingProxyMethod method;

	RETURN_UNSUPPORTED_GET_TYPE ();

	method = nm_setting_proxy_get_method (s_proxy);
	RETURN_STR_TO_FREE (nm_utils_enum_to_str (nm_setting_proxy_method_get_type (), method));
}

static gboolean
_set_fcn_proxy_method (ARGS_SET_FCN)
{
	int method;
	gboolean ret;

	ret = nm_utils_enum_from_str (nm_setting_proxy_method_get_type(), value,
	                              &method, NULL);

	if (!ret) {
		gs_free const char **values = NULL;
		gs_free char *values_str = NULL;

		values = nm_utils_enum_get_values (nm_setting_proxy_method_get_type (),
		                                   NM_SETTING_PROXY_METHOD_NONE,
		                                   G_MAXINT);
		values_str = g_strjoinv (",", (char **) values);
		g_set_error (error, 1, 0, _("invalid method '%s', use one of %s"),
		             value, values_str);

		return FALSE;
	}

	g_object_set (setting, property_info->property_name, method, NULL);
	return TRUE;
}

static gboolean
_set_fcn_proxy_pac_script (ARGS_SET_FCN)
{
	char *script = NULL;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!nmc_proxy_check_script (value, &script, error)) {
		return FALSE;
	}
	g_object_set (setting, property_info->property_name, script, NULL);
	g_free (script);
	return TRUE;
}

static gconstpointer
_get_fcn_serial_parity (ARGS_GET_FCN)
{
	NMSettingSerial *s_serial = NM_SETTING_SERIAL (setting);

	RETURN_UNSUPPORTED_GET_TYPE ();

	switch (nm_setting_serial_get_parity (s_serial)) {
	case NM_SETTING_SERIAL_PARITY_EVEN:
		return "even";
	case NM_SETTING_SERIAL_PARITY_ODD:
		return "odd";
	default:
	case NM_SETTING_SERIAL_PARITY_NONE:
		return "none";
	}
}

static gboolean
_set_fcn_serial_parity (ARGS_SET_FCN)
{
	NMSettingSerialParity parity;

	if (value[0] == 'E' || value[0] == 'e')
		parity = NM_SETTING_SERIAL_PARITY_EVEN;
	else if (value[0] == 'O' || value[0] == 'o')
		parity = NM_SETTING_SERIAL_PARITY_ODD;
	else if (value[0] == 'N' || value[0] == 'n')
		parity = NM_SETTING_SERIAL_PARITY_NONE;
	else {
		g_set_error (error, 1, 0, _("'%s' is not valid; use [e, o, n]"), value);
		return FALSE;
	}

	g_object_set (setting, property_info->property_name, parity, NULL);
	return TRUE;
}

static gboolean
_set_fcn_team_config (ARGS_SET_FCN)
{
	char *json = NULL;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!nmc_team_check_config (value, &json, error)) {
		return FALSE;
	}
	g_object_set (setting, property_info->property_name, json, NULL);
	g_free (json);
	return TRUE;
}

static gconstpointer
_get_fcn_vlan_flags (ARGS_GET_FCN)
{
	NMSettingVlan *s_vlan = NM_SETTING_VLAN (setting);
	RETURN_UNSUPPORTED_GET_TYPE ();
	RETURN_STR_TO_FREE (vlan_flags_to_string (nm_setting_vlan_get_flags (s_vlan), get_type));
}

static gconstpointer
_get_fcn_vlan_ingress_priority_map (ARGS_GET_FCN)
{
	NMSettingVlan *s_vlan = NM_SETTING_VLAN (setting);
	RETURN_UNSUPPORTED_GET_TYPE ();
	RETURN_STR_TO_FREE (vlan_priorities_to_string (s_vlan, NM_VLAN_INGRESS_MAP));
}

static gconstpointer
_get_fcn_vlan_egress_priority_map (ARGS_GET_FCN)
{
	NMSettingVlan *s_vlan = NM_SETTING_VLAN (setting);
	RETURN_UNSUPPORTED_GET_TYPE ();
	RETURN_STR_TO_FREE (vlan_priorities_to_string (s_vlan, NM_VLAN_EGRESS_MAP));
}

static gboolean
_set_vlan_xgress_priority_map (NMSetting *setting,
                               const char *value,
                               NMVlanPriorityMap map_type,
                               GError **error)
{
	char **prio_map, **p;

	prio_map = nmc_vlan_parse_priority_maps (value, map_type, error);
	if (!prio_map)
		return FALSE;

	for (p = prio_map; p && *p; p++)
		nm_setting_vlan_add_priority_str (NM_SETTING_VLAN (setting), map_type, *p);

	g_strfreev (prio_map);
	return TRUE;
}

static gboolean
_set_fcn_vlan_ingress_priority_map (ARGS_SET_FCN)
{
	return _set_vlan_xgress_priority_map (setting, value, NM_VLAN_INGRESS_MAP, error);
}

static gboolean
_set_fcn_vlan_egress_priority_map (ARGS_SET_FCN)
{
	return _set_vlan_xgress_priority_map (setting, value, NM_VLAN_EGRESS_MAP, error);
}

static gboolean
_remove_vlan_xgress_priority_map (const NMMetaEnvironment *environment,
                                  gpointer environment_user_data,
                                  NMSetting *setting,
                                  const NMMetaPropertyInfo *property_info,
                                  const char *value,
                                  guint32 idx,
                                  NMVlanPriorityMap map_type,
                                  GError **error)
{
	guint32 num;

	/* If value != NULL, remove by value */
	if (value) {
		gboolean ret;
		char **prio_map;
		gs_free char *v = g_strdup (value);

		prio_map = nmc_vlan_parse_priority_maps (v, map_type, error);
		if (!prio_map)
			return FALSE;
		if (prio_map[1]) {
			_env_warn_fcn (environment, environment_user_data,
			               NM_META_ENV_WARN_LEVEL_WARN,
			               N_("only one mapping at a time is supported; taking the first one (%s)"),
			               prio_map[0]);
		}
		ret = nm_setting_vlan_remove_priority_str_by_value (NM_SETTING_VLAN (setting),
		                                                    map_type,
		                                                    prio_map[0]);

		if (!ret)
			g_set_error (error, 1, 0, _("the property doesn't contain mapping '%s'"), prio_map[0]);
		g_strfreev (prio_map);
		return ret;
	}

	/* Else remove by index */
	num = nm_setting_vlan_get_num_priorities (NM_SETTING_VLAN (setting), map_type);
	if (num == 0) {
		g_set_error_literal (error, 1, 0, _("no priority to remove"));
		return FALSE;
	}
	if (idx >= num) {
		g_set_error (error, 1, 0, _("index '%d' is not in the range of <0-%d>"),
		             idx, num - 1);
		return FALSE;
	}

	nm_setting_vlan_remove_priority (NM_SETTING_VLAN (setting), map_type, idx);
	return TRUE;
}

static gboolean
_remove_fcn_vlan_ingress_priority_map (ARGS_REMOVE_FCN)
{
	return _remove_vlan_xgress_priority_map (environment,
	                                         environment_user_data,
	                                         setting,
	                                         property_info,
	                                         value,
	                                         idx,
	                                         NM_VLAN_INGRESS_MAP,
	                                         error);
}

static gboolean
_remove_fcn_vlan_egress_priority_map (ARGS_REMOVE_FCN)
{
	return _remove_vlan_xgress_priority_map (environment,
	                                         environment_user_data,
	                                         setting,
	                                         property_info,
	                                         value,
	                                         idx,
	                                         NM_VLAN_EGRESS_MAP,
	                                         error);
}

static gconstpointer
_get_fcn_vpn_data (ARGS_GET_FCN)
{
	NMSettingVpn *s_vpn = NM_SETTING_VPN (setting);
	GString *data_item_str;

	RETURN_UNSUPPORTED_GET_TYPE ();

	data_item_str = g_string_new (NULL);
	nm_setting_vpn_foreach_data_item (s_vpn, &vpn_data_item, data_item_str);

	RETURN_STR_TO_FREE (g_string_free (data_item_str, FALSE));
}

static gconstpointer
_get_fcn_vpn_secrets (ARGS_GET_FCN)
{
	NMSettingVpn *s_vpn = NM_SETTING_VPN (setting);
	GString *secret_str;

	RETURN_UNSUPPORTED_GET_TYPE ();

	secret_str = g_string_new (NULL);
	nm_setting_vpn_foreach_secret (s_vpn, &vpn_data_item, secret_str);

	RETURN_STR_TO_FREE (g_string_free (secret_str, FALSE));
}

static const char *
_validate_vpn_hash_value (const char *option, const char *value, GError **error)
{
	/* nm_setting_vpn_add_data_item() and nm_setting_vpn_add_secret() does not
	 * allow empty strings */
	if (!value || !*value) {
		g_set_error (error, 1, 0, _("'%s' cannot be empty"), option);
		return NULL;
	}
	return value;
}

DEFINE_SETTER_OPTIONS (_set_fcn_vpn_data,
                       NM_SETTING_VPN,
                       NMSettingVpn,
                       nm_setting_vpn_add_data_item,
                       NULL,
                       _validate_vpn_hash_value)
DEFINE_REMOVER_OPTION (_remove_fcn_vpn_data,
                       NM_SETTING_VPN,
                       nm_setting_vpn_remove_data_item)

DEFINE_SETTER_OPTIONS (_set_fcn_vpn_secrets,
                       NM_SETTING_VPN,
                       NMSettingVpn,
                       nm_setting_vpn_add_secret,
                       NULL,
                       _validate_vpn_hash_value)
DEFINE_REMOVER_OPTION (_remove_fcn_vpn_secrets,
                       NM_SETTING_VPN,
                       nm_setting_vpn_remove_secret)

DEFINE_SETTER_MAC_BLACKLIST (_set_fcn_wired_mac_address_blacklist,
                             NM_SETTING_WIRED,
                             nm_setting_wired_add_mac_blacklist_item)

static gboolean
_validate_and_remove_wired_mac_blacklist_item (NMSettingWired *setting,
                                              const char *mac,
                                              GError **error)
{
	gboolean ret;
	guint8 buf[32];

	if (!nm_utils_hwaddr_aton (mac, buf, ETH_ALEN)) {
		g_set_error (error, 1, 0, _("'%s' is not a valid MAC address"), mac);
                return FALSE;
	}

	ret = nm_setting_wired_remove_mac_blacklist_item_by_value (setting, mac);
	if (!ret)
		g_set_error (error, 1, 0, _("the property doesn't contain MAC address '%s'"), mac);
	return ret;
}
DEFINE_REMOVER_INDEX_OR_VALUE (_remove_fcn_wired_mac_address_blacklist,
                               NM_SETTING_WIRED,
                               nm_setting_wired_get_num_mac_blacklist_items,
                               nm_setting_wired_remove_mac_blacklist_item,
                               _validate_and_remove_wired_mac_blacklist_item)

static gboolean
_set_fcn_wired_s390_subchannels (ARGS_SET_FCN)
{
	char **strv = NULL;
	int len;

	strv = nmc_strsplit_set (value, " ,\t", 0);
	len = g_strv_length (strv);
	if (len != 2 && len != 3) {
		g_set_error (error, 1, 0, _("'%s' is not valid; 2 or 3 strings should be provided"),
		             value);
		g_strfreev (strv);
		return FALSE;
	}

	g_object_set (setting, property_info->property_name, strv, NULL);
	g_strfreev (strv);
	return TRUE;
}

static const char *
_validate_s390_option_value (const char *option, const char *value, GError **error)
{
	/*  nm_setting_wired_add_s390_option() requires value len in <1,199> interval */
	if (!value || !*value || strlen (value) >= 200) {
		g_set_error (error, 1, 0, _("'%s' string value should consist of 1 - 199 characters"), option);
		return NULL;
	}
	return value;
}
DEFINE_SETTER_OPTIONS (_set_fcn_wired_s390_options,
                       NM_SETTING_WIRED,
                       NMSettingWired,
                       nm_setting_wired_add_s390_option,
                       nm_setting_wired_get_valid_s390_options,
                       _validate_s390_option_value)
DEFINE_REMOVER_OPTION (_remove_fcn_wired_s390_options,
                       NM_SETTING_WIRED,
                       nm_setting_wired_remove_s390_option)

static const char *const*
_values_fcn__wired_s390_options (ARGS_VALUES_FCN)
{
	return nm_setting_wired_get_valid_s390_options (NULL);
}

static const char *
_describe_fcn_wired_s390_options (ARGS_DESCRIBE_FCN)
{
	gs_free char *options_str = NULL;
	const char **valid_options;
	char *s;

	valid_options = nm_setting_wired_get_valid_s390_options (NULL);

	options_str = g_strjoinv (", ", (char **) valid_options);

	s = g_strdup_printf (_("Enter a list of S/390 options formatted as:\n"
	                       "  option = <value>, option = <value>,...\n"
	                       "Valid options are: %s\n"),
	                       options_str);
	return (*out_to_free = s);
}


static gconstpointer
_get_fcn_wireless_ssid (ARGS_GET_FCN)
{
	NMSettingWireless *s_wireless = NM_SETTING_WIRELESS (setting);
	GBytes *ssid;
	char *ssid_str = NULL;

	RETURN_UNSUPPORTED_GET_TYPE ();

	ssid = nm_setting_wireless_get_ssid (s_wireless);
	if (ssid) {
		ssid_str = nm_utils_ssid_to_utf8 (g_bytes_get_data (ssid, NULL),
		                                  g_bytes_get_size (ssid));
	}

	RETURN_STR_TO_FREE (ssid_str);
}

static gboolean
_set_fcn_wireless_channel (ARGS_SET_FCN)
{
	unsigned long chan_int;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!nmc_string_to_uint (value, FALSE, 0, 0, &chan_int)) {
		g_set_error (error, 1, 0, _("'%s' is not a valid channel"), value);
		return FALSE;
	}

	if (   !nm_utils_wifi_is_channel_valid (chan_int, "a")
	    && !nm_utils_wifi_is_channel_valid (chan_int, "bg")) {
		g_set_error (error, 1, 0, _("'%ld' is not a valid channel"), chan_int);
		return FALSE;
	}

	g_object_set (setting, property_info->property_name, chan_int, NULL);
	return TRUE;
}

DEFINE_SETTER_MAC_BLACKLIST (_set_fcn_wireless_mac_address_blacklist,
                             NM_SETTING_WIRELESS,
                             nm_setting_wireless_add_mac_blacklist_item)

static gboolean
_validate_and_remove_wifi_mac_blacklist_item (NMSettingWireless *setting,
                                              const char *mac,
                                              GError **error)
{
	gboolean ret;
	guint8 buf[32];

	if (!nm_utils_hwaddr_aton (mac, buf, ETH_ALEN)) {
		g_set_error (error, 1, 0, _("'%s' is not a valid MAC address"), mac);
                return FALSE;
	}

	ret = nm_setting_wireless_remove_mac_blacklist_item_by_value (setting, mac);
	if (!ret)
		g_set_error (error, 1, 0, _("the property doesn't contain MAC address '%s'"), mac);
	return ret;
}
DEFINE_REMOVER_INDEX_OR_VALUE (_remove_fcn_wireless_mac_address_blacklist,
                               NM_SETTING_WIRELESS,
                               nm_setting_wireless_get_num_mac_blacklist_items,
                               nm_setting_wireless_remove_mac_blacklist_item,
                               _validate_and_remove_wifi_mac_blacklist_item)

static gconstpointer
_get_fcn_wireless_security_wep_key0 (ARGS_GET_FCN)
{
	NMSettingWirelessSecurity *s_wireless_sec = NM_SETTING_WIRELESS_SECURITY (setting);

	RETURN_UNSUPPORTED_GET_TYPE ();
	RETURN_STR_TO_FREE (g_strdup (nm_setting_wireless_security_get_wep_key (s_wireless_sec, 0)));
}

static gconstpointer
_get_fcn_wireless_security_wep_key1 (ARGS_GET_FCN)
{
	NMSettingWirelessSecurity *s_wireless_sec = NM_SETTING_WIRELESS_SECURITY (setting);

	RETURN_UNSUPPORTED_GET_TYPE ();
	RETURN_STR_TO_FREE (g_strdup (nm_setting_wireless_security_get_wep_key (s_wireless_sec, 1)));
}

static gconstpointer
_get_fcn_wireless_security_wep_key2 (ARGS_GET_FCN)
{
	NMSettingWirelessSecurity *s_wireless_sec = NM_SETTING_WIRELESS_SECURITY (setting);

	RETURN_UNSUPPORTED_GET_TYPE ();
	RETURN_STR_TO_FREE (g_strdup (nm_setting_wireless_security_get_wep_key (s_wireless_sec, 2)));
}

static gconstpointer
_get_fcn_wireless_security_wep_key3 (ARGS_GET_FCN)
{
	NMSettingWirelessSecurity *s_wireless_sec = NM_SETTING_WIRELESS_SECURITY (setting);

	RETURN_UNSUPPORTED_GET_TYPE ();
	RETURN_STR_TO_FREE (g_strdup (nm_setting_wireless_security_get_wep_key (s_wireless_sec, 3)));
}

static gconstpointer
_get_fcn_wireless_security_wep_key_type (ARGS_GET_FCN)
{
	RETURN_UNSUPPORTED_GET_TYPE ();
	RETURN_STR_TO_FREE (wep_key_type_to_string (nm_setting_wireless_security_get_wep_key_type (NM_SETTING_WIRELESS_SECURITY (setting))));
}

static const char *wifi_sec_valid_protos[] = { "wpa", "rsn", NULL };

DEFINE_SETTER_STR_LIST_MULTI (check_and_add_wifi_sec_proto,
                              NM_SETTING_WIRELESS_SECURITY,
                              nm_setting_wireless_security_add_proto)

static gboolean
_set_fcn_wireless_security_proto (ARGS_SET_FCN)
{
	return check_and_add_wifi_sec_proto (setting, property_info->property_name, value, wifi_sec_valid_protos, error);
}

static gboolean
_validate_and_remove_wifi_sec_proto (NMSettingWirelessSecurity *setting,
                                     const char *proto,
                                     GError **error)
{
	gboolean ret;
	const char *valid;

	valid = nmc_string_is_valid (proto, wifi_sec_valid_protos, error);
	if (!valid)
		return FALSE;

	ret = nm_setting_wireless_security_remove_proto_by_value (setting, proto);
	if (!ret)
		g_set_error (error, 1, 0,
		             _("the property doesn't contain protocol '%s'"), proto);
	return ret;
}
DEFINE_REMOVER_INDEX_OR_VALUE (_remove_fcn_wireless_security_proto,
                               NM_SETTING_WIRELESS_SECURITY,
                               nm_setting_wireless_security_get_num_protos,
                               nm_setting_wireless_security_remove_proto,
                               _validate_and_remove_wifi_sec_proto)

static const char *wifi_sec_valid_pairwises[] = { "tkip", "ccmp", NULL };

DEFINE_SETTER_STR_LIST_MULTI (check_and_add_wifi_sec_pairwise,
                              NM_SETTING_WIRELESS_SECURITY,
                              nm_setting_wireless_security_add_pairwise)

static gboolean
_set_fcn_wireless_security_pairwise (ARGS_SET_FCN)
{
	return check_and_add_wifi_sec_pairwise (setting, property_info->property_name, value, wifi_sec_valid_pairwises, error);
}

static gboolean
_validate_and_remove_wifi_sec_pairwise (NMSettingWirelessSecurity *setting,
                                        const char *pairwise,
                                        GError **error)
{
	gboolean ret;
	const char *valid;

	valid = nmc_string_is_valid (pairwise, wifi_sec_valid_pairwises, error);
	if (!valid)
		return FALSE;

	ret = nm_setting_wireless_security_remove_pairwise_by_value (setting, pairwise);
	if (!ret)
		g_set_error (error, 1, 0,
		             _("the property doesn't contain protocol '%s'"), pairwise);
	return ret;
}
DEFINE_REMOVER_INDEX_OR_VALUE (_remove_fcn_wireless_security_pairwise,
                               NM_SETTING_WIRELESS_SECURITY,
                               nm_setting_wireless_security_get_num_pairwise,
                               nm_setting_wireless_security_remove_pairwise,
                               _validate_and_remove_wifi_sec_pairwise)

static const char *wifi_sec_valid_groups[] = { "wep40", "wep104", "tkip", "ccmp", NULL };

DEFINE_SETTER_STR_LIST_MULTI (check_and_add_wifi_sec_group,
                              NM_SETTING_WIRELESS_SECURITY,
                              nm_setting_wireless_security_add_group)

static gboolean
_set_fcn_wireless_security_group (ARGS_SET_FCN)
{
	return check_and_add_wifi_sec_group (setting, property_info->property_name, value, wifi_sec_valid_groups, error);
}

static gboolean
_validate_and_remove_wifi_sec_group (NMSettingWirelessSecurity *setting,
                                     const char *group,
                                     GError **error)
{
	gboolean ret;
	const char *valid;

	valid = nmc_string_is_valid (group, wifi_sec_valid_groups, error);
	if (!valid)
		return FALSE;

	ret = nm_setting_wireless_security_remove_group_by_value (setting, group);
	if (!ret)
		g_set_error (error, 1, 0,
		             _("the property doesn't contain protocol '%s'"), group);
	return ret;
}
DEFINE_REMOVER_INDEX_OR_VALUE (_remove_fcn_wireless_security_group,
                               NM_SETTING_WIRELESS_SECURITY,
                               nm_setting_wireless_security_get_num_groups,
                               nm_setting_wireless_security_remove_group,
                               _validate_and_remove_wifi_sec_group)

static gboolean
_set_fcn_wireless_wep_key (ARGS_SET_FCN)
{
	NMWepKeyType guessed_type = NM_WEP_KEY_TYPE_UNKNOWN;
	NMWepKeyType type;
	guint32 prev_idx, idx;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	/* Get currently set type */
	type = nm_setting_wireless_security_get_wep_key_type (NM_SETTING_WIRELESS_SECURITY (setting));

	/* Guess key type */
	if (nm_utils_wep_key_valid (value, NM_WEP_KEY_TYPE_KEY))
		guessed_type = NM_WEP_KEY_TYPE_KEY;
	else if (nm_utils_wep_key_valid (value, NM_WEP_KEY_TYPE_PASSPHRASE))
		guessed_type = NM_WEP_KEY_TYPE_PASSPHRASE;

	if (guessed_type == NM_WEP_KEY_TYPE_UNKNOWN) {
		g_set_error (error, 1, 0, _("'%s' is not valid"), value);
		return FALSE;
	}

	if (type != NM_WEP_KEY_TYPE_UNKNOWN && type != guessed_type) {
		if (nm_utils_wep_key_valid (value, type))
			guessed_type = type;
		else {
			g_set_error (error, 1, 0,
			             _("'%s' not compatible with %s '%s', please change the key or set the right %s first."),
			             value, NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE, wep_key_type_to_string (type),
			             NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE);
			return FALSE;
		}
	}
	prev_idx = nm_setting_wireless_security_get_wep_tx_keyidx (NM_SETTING_WIRELESS_SECURITY (setting));
	idx = property_info->property_name[strlen (property_info->property_name) - 1] - '0';
	_env_warn_fcn (environment, environment_user_data,
	               NM_META_ENV_WARN_LEVEL_INFO,
	               N_("WEP key is guessed to be of '%s'"),
	               wep_key_type_to_string (guessed_type));
	if (idx != prev_idx) {
		_env_warn_fcn (environment, environment_user_data,
		               NM_META_ENV_WARN_LEVEL_INFO,
		               N_("WEP key index set to '%d'"),
		               idx);
	}

	g_object_set (setting, property_info->property_name, value, NULL);
	g_object_set (setting, NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE, guessed_type, NULL);
	if (idx != prev_idx)
		g_object_set (setting, NM_SETTING_WIRELESS_SECURITY_WEP_TX_KEYIDX, idx, NULL);
	return TRUE;
}

static gboolean
_set_fcn_wireless_security_wep_key_type (ARGS_SET_FCN)
{
	unsigned long  type_int;
	const char *valid_wep_types[] = { "unknown", "key", "passphrase", NULL };
	const char *type_str = NULL;
	NMWepKeyType type = NM_WEP_KEY_TYPE_UNKNOWN;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!nmc_string_to_uint (value, TRUE, 0, 2, &type_int)) {
		if (!(type_str = nmc_string_is_valid (value, valid_wep_types, NULL))) {
			g_set_error (error, 1, 0, _("'%s' not among [0 (unknown), 1 (key), 2 (passphrase)]"), value);
			return FALSE;
		}
		if (type_str == valid_wep_types[1])
			type = NM_WEP_KEY_TYPE_KEY;
		else if (type_str == valid_wep_types[2])
			type = NM_WEP_KEY_TYPE_PASSPHRASE;
	} else
		type = (NMWepKeyType) type_int;

	/* Check type compatibility with set keys */
	{
		guint i;
		const char *key;
		const char *keynames[] = {
			NM_SETTING_WIRELESS_SECURITY_WEP_KEY0,
			NM_SETTING_WIRELESS_SECURITY_WEP_KEY1,
			NM_SETTING_WIRELESS_SECURITY_WEP_KEY2,
			NM_SETTING_WIRELESS_SECURITY_WEP_KEY3,
		};

		for (i = 0; i < 4; i++) {
			key = nm_setting_wireless_security_get_wep_key (NM_SETTING_WIRELESS_SECURITY (setting), i);
			if (key && !nm_utils_wep_key_valid (key, type)) {
				_env_warn_fcn (environment, environment_user_data,
				               NM_META_ENV_WARN_LEVEL_WARN,
				               N_("'%s' is not compatible with '%s' type, please change or delete the key."),
				               keynames[i], wep_key_type_to_string (type));
			}
		}
	}

	g_object_set (setting, property_info->property_name, type, NULL);
	return TRUE;
}

static gboolean
_set_fcn_wireless_security_psk (ARGS_SET_FCN)
{
	if (!nm_utils_wpa_psk_valid (value)) {
		g_set_error (error, 1, 0, _("'%s' is not a valid PSK"), value);
		return FALSE;
	}
	g_object_set (setting, property_info->property_name, value, NULL);
	return TRUE;
}

/*****************************************************************************/

static const NMMetaPropertyInfo property_info_BOND_OPTIONS;

#define NESTED_PROPERTY_INFO_BOND(...) \
	.parent_info =                  &property_info_BOND_OPTIONS, \
	.base = { \
		.meta_type =                &nm_meta_type_nested_property_info, \
		.setting_info =             &nm_meta_setting_infos_editor[NM_META_SETTING_TYPE_BOND], \
		__VA_ARGS__ \
	}

static const NMMetaNestedPropertyInfo meta_nested_property_infos_bond[] = {
	{
		NESTED_PROPERTY_INFO_BOND (
			.property_name =            NM_SETTING_BOND_OPTIONS,
			.property_alias =           "mode",
			.prompt =                   NM_META_TEXT_PROMPT_BOND_MODE,
			.def_hint =                 "[balance-rr]",
		)
	},
	{
		NESTED_PROPERTY_INFO_BOND (
			.property_name =            NM_SETTING_BOND_OPTIONS,
			.property_alias =           "primary",
			.inf_flags =                NM_META_PROPERTY_INF_FLAG_DONT_ASK,
			.prompt =                   N_("Bonding primary interface [none]"),
		)
	},
	{
		NESTED_PROPERTY_INFO_BOND (
			.property_name =            NM_SETTING_BOND_OPTIONS,
			/* this is a virtual property, only needed during "ask" mode. */
			.prompt =                   N_("Bonding monitoring mode"),
			.def_hint =                 NM_META_TEXT_PROMPT_BOND_MON_MODE_CHOICES,
		)
	},
	{
		NESTED_PROPERTY_INFO_BOND (
			.property_name =            NM_SETTING_BOND_OPTIONS,
			.property_alias =           "miimon",
			.inf_flags =                NM_META_PROPERTY_INF_FLAG_DONT_ASK,
			.prompt =                   N_("Bonding miimon [100]"),
		)
	},
	{
		NESTED_PROPERTY_INFO_BOND (
			.property_name =            NM_SETTING_BOND_OPTIONS,
			.property_alias =           "downdelay",
			.inf_flags =                NM_META_PROPERTY_INF_FLAG_DONT_ASK,
			.prompt =                   N_("Bonding downdelay [0]"),
		)
	},
	{
		NESTED_PROPERTY_INFO_BOND (
			.property_name =            NM_SETTING_BOND_OPTIONS,
			.property_alias =           "updelay",
			.inf_flags =                NM_META_PROPERTY_INF_FLAG_DONT_ASK,
			.prompt =                   N_("Bonding updelay [0]"),
		)
	},
	{
		NESTED_PROPERTY_INFO_BOND (
			.property_name =            NM_SETTING_BOND_OPTIONS,
			.property_alias =           "arp-interval",
			.inf_flags =                NM_META_PROPERTY_INF_FLAG_DONT_ASK,
			.prompt =                   N_("Bonding arp-interval [0]"),
		)
	},
	{
		NESTED_PROPERTY_INFO_BOND (
			.property_name =            NM_SETTING_BOND_OPTIONS,
			.property_alias =           "arp-ip-target",
			.inf_flags =                NM_META_PROPERTY_INF_FLAG_DONT_ASK,
			.prompt =                   N_("Bonding arp-ip-target [none]"),
		)
	},
	{
		NESTED_PROPERTY_INFO_BOND (
			.property_name =            NM_SETTING_BOND_OPTIONS,
			.property_alias =           "lacp-rate",
			.inf_flags =                NM_META_PROPERTY_INF_FLAG_DONT_ASK,
			.prompt =                   N_("LACP rate ('slow' or 'fast') [slow]"),
		)
	},
};

const NMMetaPropertyTypDataNested nm_meta_property_typ_data_bond = {
	.nested =               meta_nested_property_infos_bond,
	.nested_len =           G_N_ELEMENTS (meta_nested_property_infos_bond),
};

/*****************************************************************************/

#define DEFINE_PROPERTY_TYPE(...) \
	(&((NMMetaPropertyType) { __VA_ARGS__ } ))

#define DEFINE_PROPERTY_TYP_DATA(...) \
	(&((NMMetaPropertyTypData) { __VA_ARGS__ } ))

#define PROPERTY_TYP_DATA_SUBTYPE(stype, ...) \
	.subtype = { \
		.stype = { __VA_ARGS__ }, \
	}

#define DEFINE_PROPERTY_TYP_DATA_SUBTYPE(stype, ...) \
	DEFINE_PROPERTY_TYP_DATA ( \
		PROPERTY_TYP_DATA_SUBTYPE (stype, __VA_ARGS__), \
	)

static const NMMetaPropertyType _pt_gobject_readonly = {
	.get_fcn =                      _get_fcn_gobject,
};

static const NMMetaPropertyType _pt_gobject_string = {
	.get_fcn =                      _get_fcn_gobject,
	.set_fcn =                      _set_fcn_gobject_string,
};

static const NMMetaPropertyType _pt_gobject_bool = {
	.get_fcn =                      _get_fcn_gobject,
	.set_fcn =                      _set_fcn_gobject_bool,
	.complete_fcn =                 _complete_fcn_gobject_bool,
};

static const NMMetaPropertyType _pt_gobject_int = {
	.get_fcn =                      _get_fcn_gobject,
	.set_fcn =                      _set_fcn_gobject_int,
};

static const NMMetaPropertyType _pt_gobject_int64 = {
	.get_fcn =                      _get_fcn_gobject,
	.set_fcn =                      _set_fcn_gobject_int64,
};

static const NMMetaPropertyType _pt_gobject_uint = {
	.get_fcn =                      _get_fcn_gobject,
	.set_fcn =                      _set_fcn_gobject_uint,
};

static const NMMetaPropertyType _pt_gobject_mtu = {
	.get_fcn =                      _get_fcn_gobject_mtu,
	.set_fcn =                      _set_fcn_gobject_mtu,
};

static const NMMetaPropertyType _pt_gobject_mac = {
	.get_fcn =                      _get_fcn_gobject,
	.set_fcn =                      _set_fcn_gobject_mac,
};

static const NMMetaPropertyType _pt_gobject_secret_flags = {
	.get_fcn =                      _get_fcn_gobject_secret_flags,
	.set_fcn =                      _set_fcn_gobject_secret_flags,
};

static const NMMetaPropertyType _pt_gobject_enum = {
	.get_fcn =                      _get_fcn_gobject_enum,
	.set_fcn =                      _set_fcn_gobject_enum,
	.values_fcn =                   _values_fcn_gobject_enum,
};

static const NMMetaPropertyType _pt_gobject_devices = {
	.get_fcn =                      _get_fcn_gobject,
	.set_fcn =                      _set_fcn_gobject_string,
	.complete_fcn =                 _complete_fcn_gobject_devices,
};

/*****************************************************************************/

#include "settings-docs.c"

/*****************************************************************************/

#define PROPERTY_INFO_INIT(name, doc, ...) \
	{ \
		.meta_type =                    &nm_meta_type_property_info, \
		.setting_info =                 &nm_meta_setting_infos_editor[_CURRENT_NM_META_SETTING_TYPE], \
		.property_name =                name, \
		.describe_doc =                 doc, \
		__VA_ARGS__ \
	}

#define PROPERTY_INFO(name, doc, ...) \
	(&((const NMMetaPropertyInfo) PROPERTY_INFO_INIT (name, doc, __VA_ARGS__)))

#define PROPERTY_INFO_WITH_DESC(name, ...) \
	PROPERTY_INFO (name, DESCRIBE_DOC_##name, ##__VA_ARGS__)

#define VALUES_STATIC(...)  (((const char *[]) { __VA_ARGS__, NULL }))

#define ENUM_VALUE_INFOS(...)  (((const NMUtilsEnumValueInfo []) { __VA_ARGS__, { 0 } }))

#define GET_FCN_WITH_DEFAULT(type, func) \
	/* macro that returns @func as const (gboolean(*)(NMSetting*)) type, but checks
	 * that the actual type is (gboolean(*)(type *)). */ \
	((gboolean (*) (NMSetting *)) ((sizeof (func == ((gboolean (*) (type *)) func))) ? func : func) )

#define MTU_GET_FCN(type, func) \
	/* macro that returns @func as const (guint32(*)(NMSetting*)) type, but checks
	 * that the actual type is (guint32(*)(type *)). */ \
	((guint32 (*) (NMSetting *)) ((sizeof (func == ((guint32 (*) (type *)) func))) ? func : func) )

#define TEAM_DESCRIBE_MESSAGE \
	N_("nmcli can accepts both direct JSON configuration data and a file name containing " \
	   "the configuration. In the latter case the file is read and the contents is put " \
	   "into this property.\n\n" \
	   "Examples: set team.config " \
	   "{ \"device\": \"team0\", \"runner\": {\"name\": \"roundrobin\"}, \"ports\": {\"eth1\": {}, \"eth2\": {}} }\n" \
	   "          set team.config /etc/my-team.conf\n")

#define _CURRENT_NM_META_SETTING_TYPE NM_META_SETTING_TYPE_802_1X
static const NMMetaPropertyInfo *const property_infos_802_1X[] = {
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_EAP,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_gobject,
			.set_fcn =                  _set_fcn_802_1x_eap,
			.remove_fcn =               _remove_fcn_802_1x_eap,
		),
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA (
			.values_static =            VALUES_STATIC ("leap", "md5", "tls", "peap", "ttls", "sim", "fast", "pwd"),
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_IDENTITY,
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_ANONYMOUS_IDENTITY,
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_PAC_FILE,
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_CA_CERT,
		.describe_message =
		    N_("Enter file path to CA certificate (optionally prefixed with file://).\n"
		       "  [file://]<file path>\n"
		       "Note that nmcli does not support specifying certificates as raw blob data.\n"
		       "Example: /home/cimrman/cacert.crt\n"),
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_802_1x_ca_cert,
			.set_fcn =                  _set_fcn_802_1x_ca_cert,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_CA_CERT_PASSWORD,
		.is_secret =                    TRUE,
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_CA_CERT_PASSWORD_FLAGS,
		.property_type =                &_pt_gobject_secret_flags,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_CA_PATH,
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_SUBJECT_MATCH,
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_ALTSUBJECT_MATCHES,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_gobject,
			.set_fcn =                  _set_fcn_802_1x_altsubject_matches,
			.remove_fcn =               _remove_fcn_802_1x_altsubject_matches,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_DOMAIN_SUFFIX_MATCH,
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_CLIENT_CERT,
		.describe_message =
		    N_("Enter file path to client certificate (optionally prefixed with file://).\n"
		       "  [file://]<file path>\n"
		       "Note that nmcli does not support specifying certificates as raw blob data.\n"
		       "Example: /home/cimrman/jara.crt\n"),
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_802_1x_client_cert,
			.set_fcn =                  _set_fcn_802_1x_client_cert,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_CLIENT_CERT_PASSWORD,
		.is_secret =                    TRUE,
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_CLIENT_CERT_PASSWORD_FLAGS,
		.property_type =                &_pt_gobject_secret_flags,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_PHASE1_PEAPVER,
		.property_type =                &_pt_gobject_string,
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA (
			.values_static =            VALUES_STATIC ("0", "1"),
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_PHASE1_PEAPLABEL,
		.property_type =                &_pt_gobject_string,
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA (
			.values_static =            VALUES_STATIC ("0", "1"),
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_PHASE1_FAST_PROVISIONING,
		.property_type =                &_pt_gobject_string,
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA (
			.values_static =            VALUES_STATIC ("0", "1", "2", "3"),
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_PHASE1_AUTH_FLAGS,
		.property_type =                &_pt_gobject_enum,
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA (
			PROPERTY_TYP_DATA_SUBTYPE (gobject_enum,
				.get_gtype =            nm_setting_802_1x_auth_flags_get_type,
			),
			.typ_flags =                NM_META_PROPERTY_TYP_FLAG_ENUM_GET_PARSABLE_TEXT,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_PHASE2_AUTH,
		.property_type =                &_pt_gobject_string,
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA (
			.values_static =            VALUES_STATIC ("pap", "chap", "mschap", "mschapv2", "gtc", "otp", "md5", "tls"),
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_PHASE2_AUTHEAP,
		.property_type =                &_pt_gobject_string,
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA (
			.values_static =            VALUES_STATIC ("md5", "mschapv2", "otp", "gtc", "tls"),
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_PHASE2_CA_CERT,
		.describe_message =
		    N_("Enter file path to CA certificate for inner authentication (optionally prefixed\n"
		       "with file://).\n"
		       "  [file://]<file path>\n"
		       "Note that nmcli does not support specifying certificates as raw blob data.\n"
		       "Example: /home/cimrman/ca-zweite-phase.crt\n"),
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_802_1x_phase2_ca_cert,
			.set_fcn =                  _set_fcn_802_1x_phase2_ca_cert,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_PHASE2_CA_CERT_PASSWORD,
		.is_secret =                    TRUE,
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_PHASE2_CA_CERT_PASSWORD_FLAGS,
		.property_type =                &_pt_gobject_secret_flags,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_PHASE2_CA_PATH,
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_PHASE2_SUBJECT_MATCH,
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_PHASE2_ALTSUBJECT_MATCHES,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_gobject,
			.set_fcn =                  _set_fcn_802_1x_phase2_altsubject_matches,
			.remove_fcn =               _remove_fcn_802_1x_phase2_altsubject_matches,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_PHASE2_DOMAIN_SUFFIX_MATCH,
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_PHASE2_CLIENT_CERT,
		.describe_message =
		    N_("Enter file path to client certificate for inner authentication (optionally prefixed\n"
		       "with file://).\n"
		       "  [file://]<file path>\n"
		       "Note that nmcli does not support specifying certificates as raw blob data.\n"
		       "Example: /home/cimrman/jara-zweite-phase.crt\n"),
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_802_1x_phase2_client_cert,
			.set_fcn =                  _set_fcn_802_1x_phase2_client_cert,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_PHASE2_CLIENT_CERT_PASSWORD,
		.is_secret =                    TRUE,
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_PHASE2_CLIENT_CERT_PASSWORD_FLAGS,
		.property_type =                &_pt_gobject_secret_flags,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_PASSWORD,
		.is_secret =                    TRUE,
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_PASSWORD_FLAGS,
		.property_type =                &_pt_gobject_secret_flags,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_PASSWORD_RAW,
		.is_secret =                    TRUE,
		.describe_message =
		    N_("Enter bytes as a list of hexadecimal values.\n"
		       "Two formats are accepted:\n"
		       "(a) a string of hexadecimal digits, where each two digits represent one byte\n"
		       "(b) space-separated list of bytes written as hexadecimal digits "
		       "(with optional 0x/0X prefix, and optional leading 0).\n\n"
		       "Examples: ab0455a6ea3a74C2\n"
		       "          ab 4 55 0xa6 ea 3a 74 C2\n"),
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_802_1x_password_raw,
			.set_fcn =                  _set_fcn_802_1x_password_raw,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_PASSWORD_RAW_FLAGS,
		.property_type =                &_pt_gobject_secret_flags,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_PRIVATE_KEY,
		.describe_message =
		    N_("Enter path to a private key and the key password (if not set yet):\n"
		       "  [file://]<file path> [<password>]\n"
		       "Note that nmcli does not support specifying private key as raw blob data.\n"
		       "Example: /home/cimrman/jara-priv-key Dardanely\n"),
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_802_1x_private_key,
			.set_fcn =                  _set_fcn_802_1x_private_key,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD,
		.is_secret =                    TRUE,
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD_FLAGS,
		.property_type =                &_pt_gobject_secret_flags,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_PHASE2_PRIVATE_KEY,
		.describe_message =
		    N_("Enter path to a private key and the key password (if not set yet):\n"
		       "  [file://]<file path> [<password>]\n"
		       "Note that nmcli does not support specifying private key as raw blob data.\n"
		       "Example: /home/cimrman/jara-priv-key Dardanely\n"),
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_802_1x_phase2_private_key,
			.set_fcn =                  _set_fcn_802_1x_phase2_private_key,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_PHASE2_PRIVATE_KEY_PASSWORD,
		.is_secret =                    TRUE,
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_PHASE2_PRIVATE_KEY_PASSWORD_FLAGS,
		.property_type =                &_pt_gobject_secret_flags,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_PIN,
		.is_secret =                    TRUE,
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_PIN_FLAGS,
		.property_type =                &_pt_gobject_secret_flags,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_SYSTEM_CA_CERTS,
		.property_type =                &_pt_gobject_bool,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_802_1X_AUTH_TIMEOUT,
		.property_type =                &_pt_gobject_int,
	),
	NULL
};

#undef  _CURRENT_NM_META_SETTING_TYPE
#define _CURRENT_NM_META_SETTING_TYPE NM_META_SETTING_TYPE_ADSL
static const NMMetaPropertyInfo *const property_infos_ADSL[] = {
	PROPERTY_INFO_WITH_DESC (NM_SETTING_ADSL_USERNAME,
		.is_cli_option =                TRUE,
		.property_alias =               "username",
		.inf_flags =                    NM_META_PROPERTY_INF_FLAG_REQD,
		.prompt =                       N_("Username"),
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_ADSL_PASSWORD,
		.is_cli_option =                TRUE,
		.property_alias =               "password",
		.prompt =                       N_("Password [none]"),
		.is_secret =                    TRUE,
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_ADSL_PASSWORD_FLAGS,
		.property_type =                &_pt_gobject_secret_flags,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_ADSL_PROTOCOL,
		.is_cli_option =                TRUE,
		.property_alias =               "protocol",
		.inf_flags =                    NM_META_PROPERTY_INF_FLAG_REQD,
		.prompt =                       NM_META_TEXT_PROMPT_ADSL_PROTO,
		.def_hint =                     NM_META_TEXT_PROMPT_ADSL_PROTO_CHOICES,
		.property_type =                &_pt_gobject_string,
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA (
			.values_static =            VALUES_STATIC (NM_SETTING_ADSL_PROTOCOL_PPPOA,
			                                           NM_SETTING_ADSL_PROTOCOL_PPPOE,
			                                           NM_SETTING_ADSL_PROTOCOL_IPOATM),
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_ADSL_ENCAPSULATION,
		.is_cli_option =                TRUE,
		.property_alias =               "encapsulation",
		.prompt =                       NM_META_TEXT_PROMPT_ADSL_ENCAP,
		.def_hint =                     NM_META_TEXT_PROMPT_ADSL_ENCAP_CHOICES,
		.property_type =                &_pt_gobject_string,
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA (
			.values_static =            VALUES_STATIC (NM_SETTING_ADSL_ENCAPSULATION_VCMUX,
			                                           NM_SETTING_ADSL_ENCAPSULATION_LLC),
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_ADSL_VPI,
		.property_type =                &_pt_gobject_uint,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_ADSL_VCI,
		.property_type =                &_pt_gobject_uint,
	),
	NULL
};

#undef  _CURRENT_NM_META_SETTING_TYPE
#define _CURRENT_NM_META_SETTING_TYPE NM_META_SETTING_TYPE_BLUETOOTH
static const NMMetaPropertyInfo *const property_infos_BLUETOOTH[] = {
	PROPERTY_INFO_WITH_DESC (NM_SETTING_BLUETOOTH_BDADDR,
		.is_cli_option =                TRUE,
		.property_alias =               "addr",
		.inf_flags =                    NM_META_PROPERTY_INF_FLAG_REQD,
		.prompt =                       N_("Bluetooth device address"),
		.property_type =                &_pt_gobject_mac,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_BLUETOOTH_TYPE,
		.is_cli_option =                TRUE,
		.property_alias =               "bt-type",
		.prompt =                       NM_META_TEXT_PROMPT_BT_TYPE,
		.def_hint =                     NM_META_TEXT_PROMPT_BT_TYPE_CHOICES,
		.property_type =                &_pt_gobject_string,
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA (
			.values_static =            VALUES_STATIC (NM_SETTING_BLUETOOTH_TYPE_DUN,
			                                           NM_SETTING_BLUETOOTH_TYPE_PANU),
		),
	),
	NULL
};

#undef  _CURRENT_NM_META_SETTING_TYPE
#define _CURRENT_NM_META_SETTING_TYPE NM_META_SETTING_TYPE_BOND
static const NMMetaPropertyInfo property_info_BOND_OPTIONS =
	PROPERTY_INFO_INIT (NM_SETTING_BOND_OPTIONS, DESCRIBE_DOC_NM_SETTING_BOND_OPTIONS,
		.property_type = DEFINE_PROPERTY_TYPE (
			.describe_fcn =             _describe_fcn_bond_options,
			.get_fcn =                  _get_fcn_bond_options,
			.set_fcn =                  _set_fcn_bond_options,
			.remove_fcn =               _remove_fcn_bond_options,
			.values_fcn =               _values_fcn_bond_options,
		),
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA (
			.nested =                   &nm_meta_property_typ_data_bond,
		),
	);

static const NMMetaPropertyInfo *const property_infos_BOND[] = {
	&property_info_BOND_OPTIONS,
	NULL
};

#undef  _CURRENT_NM_META_SETTING_TYPE
#define _CURRENT_NM_META_SETTING_TYPE NM_META_SETTING_TYPE_BRIDGE
static const NMMetaPropertyInfo *const property_infos_BRIDGE[] = {
	PROPERTY_INFO_WITH_DESC (NM_SETTING_BRIDGE_MAC_ADDRESS,
		.is_cli_option =                TRUE,
		.property_alias =               "mac",
		.prompt =                       N_("MAC [none]"),
		.property_type =                &_pt_gobject_mac,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_BRIDGE_STP,
		.is_cli_option =                TRUE,
		.property_alias =               "stp",
		.prompt =                       N_("Enable STP [no]"),
		.property_type =                &_pt_gobject_bool,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_BRIDGE_PRIORITY,
		.is_cli_option =                TRUE,
		.property_alias =               "priority",
		.prompt =                       N_("STP priority [32768]"),
		.property_type =                &_pt_gobject_uint,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_BRIDGE_FORWARD_DELAY,
		.is_cli_option =                TRUE,
		.property_alias =               "forward-delay",
		.prompt =                       N_("Forward delay [15]"),
		.property_type =                &_pt_gobject_uint,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_BRIDGE_HELLO_TIME,
		.is_cli_option =                TRUE,
		.property_alias =               "hello-time",
		.prompt =                       N_("Hello time [2]"),
		.property_type =                &_pt_gobject_uint,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_BRIDGE_MAX_AGE,
		.is_cli_option =                TRUE,
		.property_alias =               "max-age",
		.prompt =                       N_("Max age [20]"),
		.property_type =                &_pt_gobject_uint,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_BRIDGE_AGEING_TIME,
		.is_cli_option =                TRUE,
		.property_alias =               "ageing-time",
		.prompt =                       N_("MAC address ageing time [300]"),
		.property_type =                &_pt_gobject_uint,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_BRIDGE_MULTICAST_SNOOPING,
		.is_cli_option =                TRUE,
		.property_alias =               "multicast-snooping",
		.prompt =                       N_("Enable IGMP snooping [no]"),
		.property_type =                &_pt_gobject_bool,
	),
	NULL
};

#undef  _CURRENT_NM_META_SETTING_TYPE
#define _CURRENT_NM_META_SETTING_TYPE NM_META_SETTING_TYPE_BRIDGE_PORT
static const NMMetaPropertyInfo *const property_infos_BRIDGE_PORT[] = {
	PROPERTY_INFO_WITH_DESC (NM_SETTING_BRIDGE_PORT_PRIORITY,
		.is_cli_option =                TRUE,
		.property_alias =               "priority",
		.prompt =                       N_("Bridge port priority [32]"),
		.property_type =                &_pt_gobject_uint,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_BRIDGE_PORT_PATH_COST,
		.is_cli_option =                TRUE,
		.property_alias =               "path-cost",
		.prompt =                       N_("Bridge port STP path cost [100]"),
		.property_type =                &_pt_gobject_uint,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_BRIDGE_PORT_HAIRPIN_MODE,
		.is_cli_option =                TRUE,
		.property_alias =               "hairpin",
		.prompt =                       N_("Hairpin [no]"),
		.property_type =                &_pt_gobject_bool,
	),
	NULL
};

#undef  _CURRENT_NM_META_SETTING_TYPE
#define _CURRENT_NM_META_SETTING_TYPE NM_META_SETTING_TYPE_CDMA
static const NMMetaPropertyInfo *const property_infos_CDMA[] = {
	PROPERTY_INFO_WITH_DESC (NM_SETTING_CDMA_NUMBER,
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_CDMA_USERNAME,
		.is_cli_option =                TRUE,
		.property_alias =               "user",
		.prompt =                       N_("Username [none]"),
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_CDMA_PASSWORD,
		.is_cli_option =                TRUE,
		.property_alias =               "password",
		.prompt =                       N_("Password [none]"),
		.is_secret =                    TRUE,
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_CDMA_PASSWORD_FLAGS,
		.property_type =                &_pt_gobject_secret_flags,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_CDMA_MTU,
		.property_type =                &_pt_gobject_mtu,
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA_SUBTYPE (mtu,
			.get_fcn =                  MTU_GET_FCN (NMSettingCdma, nm_setting_cdma_get_mtu),
		),
	),
	NULL
};

#undef  _CURRENT_NM_META_SETTING_TYPE
#define _CURRENT_NM_META_SETTING_TYPE NM_META_SETTING_TYPE_CONNECTION
static const NMMetaPropertyInfo *const property_infos_CONNECTION[] = {
	PROPERTY_INFO_WITH_DESC (NM_SETTING_CONNECTION_ID,
		.is_cli_option =                TRUE,
		.property_alias =               "con-name",
		.inf_flags =                    NM_META_PROPERTY_INF_FLAG_DONT_ASK,
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_CONNECTION_UUID,
		.property_type =                DEFINE_PROPERTY_TYPE ( .get_fcn = _get_fcn_gobject ),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_CONNECTION_STABLE_ID,
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_CONNECTION_INTERFACE_NAME,
		.is_cli_option =                TRUE,
		.property_alias =               "ifname",
		.inf_flags =                    NM_META_PROPERTY_INF_FLAG_REQD,
		.prompt =                       NM_META_TEXT_PROMPT_IFNAME,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_gobject,
			.set_fcn =                  _set_fcn_gobject_ifname,
			.complete_fcn =             _complete_fcn_gobject_devices,
		),
	),
[_NM_META_PROPERTY_TYPE_CONNECTION_TYPE] =
	PROPERTY_INFO_WITH_DESC (NM_SETTING_CONNECTION_TYPE,
		.is_cli_option =                TRUE,
		.property_alias =               "type",
		.inf_flags =                    NM_META_PROPERTY_INF_FLAG_REQD,
		.prompt =                       NM_META_TEXT_PROMPT_CON_TYPE,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_gobject,
			.set_fcn =                  _set_fcn_connection_type,
			.complete_fcn =             _complete_fcn_connection_type,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_CONNECTION_AUTOCONNECT,
		.is_cli_option =                TRUE,
		.property_alias =               "autoconnect",
		.inf_flags =                    NM_META_PROPERTY_INF_FLAG_DONT_ASK,
		.property_type =                &_pt_gobject_bool,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY,
		.property_type =                &_pt_gobject_int,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_CONNECTION_AUTOCONNECT_RETRIES,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_connection_autoconnect_retires,
			.set_fcn =                  _set_fcn_gobject_int,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_CONNECTION_TIMESTAMP,
		.property_type =                &_pt_gobject_readonly,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_CONNECTION_READ_ONLY,
		.property_type =                &_pt_gobject_readonly,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_CONNECTION_PERMISSIONS,
		.describe_message =
		     N_("Enter a list of user permissions. This is a list of user names formatted as:\n"
		        "  [user:]<user name 1>, [user:]<user name 2>,...\n"
		        "The items can be separated by commas or spaces.\n\n"
		        "Example: alice bob charlie\n"),
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_connection_permissions,
			.set_fcn =                  _set_fcn_connection_permissions,
			.remove_fcn =               _remove_fcn_connection_permissions,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_CONNECTION_ZONE,
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_CONNECTION_MASTER,
		.is_cli_option =                TRUE,
		.property_alias =               "master",
		.inf_flags =                    NM_META_PROPERTY_INF_FLAG_DONT_ASK,
		.prompt =                       NM_META_TEXT_PROMPT_MASTER,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_gobject,
			.set_fcn =                  _set_fcn_connection_master,
			.complete_fcn =             _complete_fcn_connection_master,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_CONNECTION_SLAVE_TYPE,
		.is_cli_option =                TRUE,
		.property_alias =               "slave-type",
		.inf_flags =                    NM_META_PROPERTY_INF_FLAG_DONT_ASK,
		.property_type =                &_pt_gobject_string,
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA (
			.values_static =            VALUES_STATIC (NM_SETTING_BOND_SETTING_NAME,
			                                           NM_SETTING_BRIDGE_SETTING_NAME,
			                                           NM_SETTING_TEAM_SETTING_NAME),
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES,
		.property_type =                &_pt_gobject_enum,
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA_SUBTYPE (gobject_enum,
			.get_gtype =                nm_setting_connection_autoconnect_slaves_get_type,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_CONNECTION_SECONDARIES,
		.describe_message =
		    N_("Enter secondary connections that should be activated when this connection is\n"
		       "activated. Connections can be specified either by UUID or ID (name). nmcli\n"
		       "transparently translates names to UUIDs. Note that NetworkManager only supports\n"
		       "VPNs as secondary connections at the moment.\n"
		       "The items can be separated by commas or spaces.\n\n"
		       "Example: private-openvpn, fe6ba5d8-c2fc-4aae-b2e3-97efddd8d9a7\n"),
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_gobject,
			.set_fcn =                  _set_fcn_connection_secondaries,
			.remove_fcn =               _remove_fcn_connection_secondaries,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_CONNECTION_GATEWAY_PING_TIMEOUT,
		.property_type =                &_pt_gobject_uint,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_CONNECTION_METERED,
		.describe_message =
		    N_("Enter a value which indicates whether the connection is subject to a data\n"
		       "quota, usage costs or other limitations. Accepted options are:\n"
		       "'true','yes','on' to set the connection as metered\n"
		       "'false','no','off' to set the connection as not metered\n"
		       "'unknown' to let NetworkManager choose a value using some heuristics\n"),
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_connection_metered,
			.set_fcn =                  _set_fcn_connection_metered,
		),
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA (
			.values_static =            VALUES_STATIC ("yes", "no", "unknown"),
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_CONNECTION_LLDP,
		.property_type =                &_pt_gobject_enum,
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA (
			PROPERTY_TYP_DATA_SUBTYPE (gobject_enum,
				.get_gtype =            nm_setting_connection_lldp_get_type,
				.value_infos =          ENUM_VALUE_INFOS (
					{
						.value = NM_SETTING_CONNECTION_LLDP_ENABLE_RX,
						.nick = "enable",
					}
				),
			),
			.typ_flags =                  NM_META_PROPERTY_TYP_FLAG_ENUM_GET_PARSABLE_TEXT
			                            | NM_META_PROPERTY_TYP_FLAG_ENUM_GET_PRETTY_TEXT,
		),
	),
	NULL
};

#undef  _CURRENT_NM_META_SETTING_TYPE
#define _CURRENT_NM_META_SETTING_TYPE NM_META_SETTING_TYPE_DCB
static const NMMetaPropertyInfo *const property_infos_DCB[] = {
	PROPERTY_INFO_WITH_DESC (NM_SETTING_DCB_APP_FCOE_FLAGS,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_dcb_app_fcoe_flags,
			.set_fcn =                  _set_fcn_dcb_flags,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_DCB_APP_FCOE_PRIORITY,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_dcb_app_fcoe_priority,
			.set_fcn =                  _set_fcn_dcb_priority,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_DCB_APP_FCOE_MODE,
		.property_type =                &_pt_gobject_string,
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA (
			.values_static =            VALUES_STATIC (NM_SETTING_DCB_FCOE_MODE_FABRIC,
			                                           NM_SETTING_DCB_FCOE_MODE_VN2VN),
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_DCB_APP_ISCSI_FLAGS,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_dcb_app_iscsi_flags,
			.set_fcn =                  _set_fcn_dcb_flags,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_DCB_APP_ISCSI_PRIORITY,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_dcb_app_iscsi_priority,
			.set_fcn =                  _set_fcn_dcb_priority,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_DCB_APP_FIP_FLAGS,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_dcb_app_fip_flags,
			.set_fcn =                  _set_fcn_dcb_flags,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_DCB_APP_FIP_PRIORITY,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_dcb_app_fip_priority,
			.set_fcn =                  _set_fcn_dcb_priority,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_DCB_PRIORITY_FLOW_CONTROL_FLAGS,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_dcb_priority_flow_control_flags,
			.set_fcn =                  _set_fcn_dcb_flags,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_DCB_PRIORITY_FLOW_CONTROL,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_dcb_priority_flow_control,
			.set_fcn =                  _set_fcn_dcb_priority_flow_control,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_DCB_PRIORITY_GROUP_FLAGS,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_dcb_priority_group_flags,
			.set_fcn =                  _set_fcn_dcb_flags,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_DCB_PRIORITY_GROUP_ID,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_dcb_priority_group_id,
			.set_fcn =                  _set_fcn_dcb_priority_group_id,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_DCB_PRIORITY_GROUP_BANDWIDTH,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_dcb_priority_group_bandwidth,
			.set_fcn =                  _set_fcn_dcb_priority_group_bandwidth,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_DCB_PRIORITY_BANDWIDTH,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_dcb_priority_bandwidth,
			.set_fcn =                  _set_fcn_dcb_priority_bandwidth,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_DCB_PRIORITY_STRICT_BANDWIDTH,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_dcb_priority_strict,
			.set_fcn =                  _set_fcn_dcb_priority_strict,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_DCB_PRIORITY_TRAFFIC_CLASS,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_dcb_priority_traffic_class,
			.set_fcn =                  _set_fcn_dcb_priority_traffic_class,
		),
	),
	NULL
};

#undef  _CURRENT_NM_META_SETTING_TYPE
#define _CURRENT_NM_META_SETTING_TYPE NM_META_SETTING_TYPE_GSM
static const NMMetaPropertyInfo *const property_infos_GSM[] = {
	PROPERTY_INFO_WITH_DESC (NM_SETTING_GSM_NUMBER,
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_GSM_USERNAME,
		.is_cli_option =                TRUE,
		.property_alias =               "user",
		.prompt =                       N_("Username [none]"),
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_GSM_PASSWORD,
		.is_cli_option =                TRUE,
		.property_alias =               "password",
		.prompt =                       N_("Password [none]"),
		.is_secret =                    TRUE,
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_GSM_PASSWORD_FLAGS,
		.property_type =                &_pt_gobject_secret_flags,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_GSM_APN,
		.is_cli_option =                TRUE,
		.property_alias =               "apn",
		.inf_flags =                    NM_META_PROPERTY_INF_FLAG_REQD,
		.prompt =                       N_("APN"),
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_GSM_NETWORK_ID,
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_GSM_PIN,
		.is_secret =                    TRUE,
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_GSM_PIN_FLAGS,
		.property_type =                &_pt_gobject_secret_flags,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_GSM_HOME_ONLY,
		.property_type =                &_pt_gobject_bool,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_GSM_DEVICE_ID,
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_GSM_SIM_ID,
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_GSM_SIM_OPERATOR_ID,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_gobject,
			.set_fcn =                  _set_fcn_gsm_sim_operator_id,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_GSM_MTU,
		.property_type =                &_pt_gobject_mtu,
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA_SUBTYPE (mtu,
			.get_fcn =                  MTU_GET_FCN (NMSettingGsm, nm_setting_gsm_get_mtu),
		),
	),
	NULL
};

#undef  _CURRENT_NM_META_SETTING_TYPE
#define _CURRENT_NM_META_SETTING_TYPE NM_META_SETTING_TYPE_INFINIBAND
static const NMMetaPropertyInfo *const property_infos_INFINIBAND[] = {
	PROPERTY_INFO_WITH_DESC (NM_SETTING_INFINIBAND_MAC_ADDRESS,
		.is_cli_option =                TRUE,
		.property_alias =               "mac",
		.prompt =                       N_("MAC [none]"),
		.property_type =                &_pt_gobject_mac,
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA_SUBTYPE (mac,
			.mode =                     NM_META_PROPERTY_TYPE_MAC_MODE_INFINIBAND,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_INFINIBAND_MTU,
		.is_cli_option =                TRUE,
		.property_alias =               "mtu",
		.prompt =                       N_("MTU [auto]"),
		.property_type =                &_pt_gobject_mtu,
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA_SUBTYPE (mtu,
			.get_fcn =                  MTU_GET_FCN (NMSettingInfiniband, nm_setting_infiniband_get_mtu),
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_INFINIBAND_TRANSPORT_MODE,
		.is_cli_option =                TRUE,
		.property_alias =               "transport-mode",
		.prompt =                       NM_META_TEXT_PROMPT_IB_MODE,
		.def_hint =                     NM_META_TEXT_PROMPT_IB_MODE_CHOICES,
		.property_type =                &_pt_gobject_string,
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA (
			.values_static =            VALUES_STATIC ("datagram", "connected"),
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_INFINIBAND_P_KEY,
		.is_cli_option =                TRUE,
		.property_alias =               "p-key",
		.prompt =                       N_("P_KEY [none]"),
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_infiniband_p_key,
			.set_fcn =                  _set_fcn_infiniband_p_key,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_INFINIBAND_PARENT,
		.is_cli_option =                TRUE,
		.property_alias =               "parent",
		.prompt =                       N_("Parent interface [none]"),
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_gobject,
			.set_fcn =                  _set_fcn_gobject_ifname,
		),
	),
	NULL
};

#undef  _CURRENT_NM_META_SETTING_TYPE
#define _CURRENT_NM_META_SETTING_TYPE NM_META_SETTING_TYPE_IP4_CONFIG
static const NMMetaPropertyInfo *const property_infos_IP4_CONFIG[] = {
	PROPERTY_INFO (NM_SETTING_IP_CONFIG_METHOD, DESCRIBE_DOC_NM_SETTING_IP4_CONFIG_METHOD,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_gobject,
			.set_fcn =                  _set_fcn_ip4_config_method,
		),
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA (
			.values_static =            ipv4_valid_methods,
		),
	),
	PROPERTY_INFO (NM_SETTING_IP_CONFIG_DNS, DESCRIBE_DOC_NM_SETTING_IP4_CONFIG_DNS,
		.describe_message =
		    N_("Enter a list of IPv4 addresses of DNS servers.\n\n"
		       "Example: 8.8.8.8, 8.8.4.4\n"),
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_gobject,
			.set_fcn =                  _set_fcn_ip4_config_dns,
			.remove_fcn =               _remove_fcn_ipv4_config_dns,
		),
	),
	PROPERTY_INFO (NM_SETTING_IP_CONFIG_DNS_SEARCH, DESCRIBE_DOC_NM_SETTING_IP4_CONFIG_DNS_SEARCH,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_gobject,
			.set_fcn =                  _set_fcn_ip4_config_dns_search,
			.remove_fcn =               _remove_fcn_ipv4_config_dns_search,
		),
	),
	PROPERTY_INFO (NM_SETTING_IP_CONFIG_DNS_OPTIONS, DESCRIBE_DOC_NM_SETTING_IP4_CONFIG_DNS_OPTIONS,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_nmc_with_default,
			.set_fcn =                  _set_fcn_ip4_config_dns_options,
			.remove_fcn =               _remove_fcn_ipv4_config_dns_options,
		),
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA_SUBTYPE (get_with_default,
			.fcn =                      GET_FCN_WITH_DEFAULT (NMSettingIPConfig, nm_setting_ip_config_has_dns_options),
		),
	),
	PROPERTY_INFO (NM_SETTING_IP_CONFIG_DNS_PRIORITY, DESCRIBE_DOC_NM_SETTING_IP4_CONFIG_DNS_PRIORITY,
		.property_type =                &_pt_gobject_int,
	),
	PROPERTY_INFO (NM_SETTING_IP_CONFIG_ADDRESSES, DESCRIBE_DOC_NM_SETTING_IP4_CONFIG_ADDRESSES,
		.is_cli_option =                TRUE,
		.property_alias =               "ip4",
		.inf_flags =                    NM_META_PROPERTY_INF_FLAG_MULTI,
		.prompt =                       N_("IPv4 address (IP[/plen]) [none]"),
		.describe_message =
		    N_("Enter a list of IPv4 addresses formatted as:\n"
		       "  ip[/prefix], ip[/prefix],...\n"
		       "Missing prefix is regarded as prefix of 32.\n\n"
		       "Example: 192.168.1.5/24, 10.0.0.11/24\n"),
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_ip_config_addresses,
			.set_fcn =                  _set_fcn_ip4_config_addresses,
			.remove_fcn =               _remove_fcn_ipv4_config_addresses,
		),
	),
	PROPERTY_INFO (NM_SETTING_IP_CONFIG_GATEWAY, DESCRIBE_DOC_NM_SETTING_IP4_CONFIG_GATEWAY,
		.is_cli_option =                TRUE,
		.property_alias =               "gw4",
		.prompt =                       N_("IPv4 gateway [none]"),
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_gobject,
			.set_fcn =                  _set_fcn_ip4_config_gateway,
		),
	),
	PROPERTY_INFO (NM_SETTING_IP_CONFIG_ROUTES, DESCRIBE_DOC_NM_SETTING_IP4_CONFIG_ROUTES,
		.describe_message =
		    N_("Enter a list of IPv4 routes formatted as:\n"
		       "  ip[/prefix] [next-hop] [metric],...\n\n"
		       "Missing prefix is regarded as a prefix of 32.\n"
		       "Missing next-hop is regarded as 0.0.0.0.\n"
		       "Missing metric means default (NM/kernel will set a default value).\n\n"
		       "Examples: 192.168.2.0/24 192.168.2.1 3, 10.1.0.0/16 10.0.0.254\n"
		       "          10.1.2.0/24\n"),
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_ip_config_routes,
			.set_fcn =                  _set_fcn_ip4_config_routes,
			.remove_fcn =               _remove_fcn_ipv4_config_routes,
		),
	),
	PROPERTY_INFO (NM_SETTING_IP_CONFIG_ROUTE_METRIC, DESCRIBE_DOC_NM_SETTING_IP4_CONFIG_ROUTE_METRIC,
		.property_type =                &_pt_gobject_int64,
	),
	PROPERTY_INFO (NM_SETTING_IP_CONFIG_IGNORE_AUTO_ROUTES, DESCRIBE_DOC_NM_SETTING_IP4_CONFIG_IGNORE_AUTO_ROUTES,
		.property_type =                &_pt_gobject_bool,
	),
	PROPERTY_INFO (NM_SETTING_IP_CONFIG_IGNORE_AUTO_DNS, DESCRIBE_DOC_NM_SETTING_IP4_CONFIG_IGNORE_AUTO_DNS,
		.property_type =                &_pt_gobject_bool,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_IP4_CONFIG_DHCP_CLIENT_ID,
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO (NM_SETTING_IP_CONFIG_DHCP_TIMEOUT, DESCRIBE_DOC_NM_SETTING_IP4_CONFIG_DHCP_TIMEOUT,
		.property_type =                &_pt_gobject_int,
	),
	PROPERTY_INFO (NM_SETTING_IP_CONFIG_DHCP_SEND_HOSTNAME, DESCRIBE_DOC_NM_SETTING_IP4_CONFIG_DHCP_SEND_HOSTNAME,
		.property_type =                &_pt_gobject_bool,
	),
	PROPERTY_INFO (NM_SETTING_IP_CONFIG_DHCP_HOSTNAME, DESCRIBE_DOC_NM_SETTING_IP4_CONFIG_DHCP_HOSTNAME,
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_IP4_CONFIG_DHCP_FQDN,
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO (NM_SETTING_IP_CONFIG_NEVER_DEFAULT, DESCRIBE_DOC_NM_SETTING_IP4_CONFIG_NEVER_DEFAULT,
		.property_type =                &_pt_gobject_bool,
	),
	PROPERTY_INFO (NM_SETTING_IP_CONFIG_MAY_FAIL, DESCRIBE_DOC_NM_SETTING_IP4_CONFIG_MAY_FAIL,
		.property_type =                &_pt_gobject_bool,
	),
	PROPERTY_INFO (NM_SETTING_IP_CONFIG_DAD_TIMEOUT, DESCRIBE_DOC_NM_SETTING_IP4_CONFIG_DAD_TIMEOUT,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_ip4_config_dad_timeout,
			.set_fcn =                  _set_fcn_gobject_int,
		),
	),
	NULL
};

#undef  _CURRENT_NM_META_SETTING_TYPE
#define _CURRENT_NM_META_SETTING_TYPE NM_META_SETTING_TYPE_IP6_CONFIG
static const NMMetaPropertyInfo *const property_infos_IP6_CONFIG[] = {
	PROPERTY_INFO (NM_SETTING_IP_CONFIG_METHOD, DESCRIBE_DOC_NM_SETTING_IP6_CONFIG_METHOD,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_gobject,
			.set_fcn =                  _set_fcn_ip6_config_method,
		),
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA (
			.values_static =            ipv6_valid_methods,
		),
	),
	PROPERTY_INFO (NM_SETTING_IP_CONFIG_DNS, DESCRIBE_DOC_NM_SETTING_IP6_CONFIG_DNS,
		.describe_message =
		    N_("Enter a list of IPv6 addresses of DNS servers.  If the IPv6 "
		       "configuration method is 'auto' these DNS servers are appended "
		       "to those (if any) returned by automatic configuration.  DNS "
		       "servers cannot be used with the 'shared' or 'link-local' IPv6 "
		       "configuration methods, as there is no upstream network. In "
		       "all other IPv6 configuration methods, these DNS "
		       "servers are used as the only DNS servers for this connection.\n\n"
		       "Example: 2607:f0d0:1002:51::4, 2607:f0d0:1002:51::1\n"),
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_gobject,
			.set_fcn =                  _set_fcn_ip6_config_dns,
			.remove_fcn =               _remove_fcn_ipv6_config_dns,
		),
	),
	PROPERTY_INFO (NM_SETTING_IP_CONFIG_DNS_SEARCH, DESCRIBE_DOC_NM_SETTING_IP6_CONFIG_DNS_SEARCH,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_gobject,
			.set_fcn =                  _set_fcn_ip6_config_dns_search,
			.remove_fcn =               _remove_fcn_ipv6_config_dns_search,
		),
	),
	PROPERTY_INFO (NM_SETTING_IP_CONFIG_DNS_OPTIONS, DESCRIBE_DOC_NM_SETTING_IP6_CONFIG_DNS_OPTIONS,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_nmc_with_default,
			.set_fcn =                  _set_fcn_ip6_config_dns_options,
			.remove_fcn =               _remove_fcn_ipv6_config_dns_options,
		),
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA_SUBTYPE (get_with_default,
			.fcn =     GET_FCN_WITH_DEFAULT (NMSettingIPConfig, nm_setting_ip_config_has_dns_options),
		),
	),
	PROPERTY_INFO (NM_SETTING_IP_CONFIG_DNS_PRIORITY, DESCRIBE_DOC_NM_SETTING_IP6_CONFIG_DNS_PRIORITY,
		.property_type =                &_pt_gobject_int,
	),
	PROPERTY_INFO (NM_SETTING_IP_CONFIG_ADDRESSES, DESCRIBE_DOC_NM_SETTING_IP6_CONFIG_ADDRESSES,
		.is_cli_option =                TRUE,
		.property_alias =               "ip6",
		.inf_flags =                    NM_META_PROPERTY_INF_FLAG_MULTI,
		.prompt =                       N_("IPv6 address (IP[/plen]) [none]"),
		.describe_message =
		    N_("Enter a list of IPv6 addresses formatted as:\n"
		       "  ip[/prefix], ip[/prefix],...\n"
		       "Missing prefix is regarded as prefix of 128.\n\n"
		       "Example: 2607:f0d0:1002:51::4/64, 1050:0:0:0:5:600:300c:326b\n"),
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_ip_config_addresses,
			.set_fcn =                  _set_fcn_ip6_config_addresses,
			.remove_fcn =               _remove_fcn_ipv6_config_addresses,
		),
	),
	PROPERTY_INFO (NM_SETTING_IP_CONFIG_GATEWAY, DESCRIBE_DOC_NM_SETTING_IP6_CONFIG_GATEWAY,
		.is_cli_option =                TRUE,
		.property_alias =               "gw6",
		.prompt =                       N_("IPv6 gateway [none]"),
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_gobject,
			.set_fcn =                  _set_fcn_ip6_config_gateway,
		),
	),
	PROPERTY_INFO (NM_SETTING_IP_CONFIG_ROUTES, DESCRIBE_DOC_NM_SETTING_IP6_CONFIG_ROUTES,
		.describe_message =
		    N_("Enter a list of IPv6 routes formatted as:\n"
		       "  ip[/prefix] [next-hop] [metric],...\n\n"
		       "Missing prefix is regarded as a prefix of 128.\n"
		       "Missing next-hop is regarded as \"::\".\n"
		       "Missing metric means default (NM/kernel will set a default value).\n\n"
		       "Examples: 2001:db8:beef:2::/64 2001:db8:beef::2, 2001:db8:beef:3::/64 2001:db8:beef::3 2\n"
		       "          abbe::/64 55\n"),
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_ip_config_routes,
			.set_fcn =                  _set_fcn_ip6_config_routes,
			.remove_fcn =               _remove_fcn_ipv6_config_routes,
		),
	),
	PROPERTY_INFO (NM_SETTING_IP_CONFIG_ROUTE_METRIC, DESCRIBE_DOC_NM_SETTING_IP6_CONFIG_ROUTE_METRIC,
		.property_type =                &_pt_gobject_int64,
	),
	PROPERTY_INFO (NM_SETTING_IP_CONFIG_IGNORE_AUTO_ROUTES, DESCRIBE_DOC_NM_SETTING_IP6_CONFIG_IGNORE_AUTO_ROUTES,
		.property_type =                &_pt_gobject_bool,
	),
	PROPERTY_INFO (NM_SETTING_IP_CONFIG_IGNORE_AUTO_DNS, DESCRIBE_DOC_NM_SETTING_IP6_CONFIG_IGNORE_AUTO_DNS,
		.property_type =                &_pt_gobject_bool,
	),
	PROPERTY_INFO (NM_SETTING_IP_CONFIG_NEVER_DEFAULT, DESCRIBE_DOC_NM_SETTING_IP6_CONFIG_NEVER_DEFAULT,
		.property_type =                &_pt_gobject_bool,
	),
	PROPERTY_INFO (NM_SETTING_IP_CONFIG_MAY_FAIL, DESCRIBE_DOC_NM_SETTING_IP6_CONFIG_MAY_FAIL,
		.property_type =                &_pt_gobject_bool,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_IP6_CONFIG_IP6_PRIVACY,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_ip6_config_ip6_privacy,
			.set_fcn =                  _set_fcn_ip6_config_ip6_privacy,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE,
		.property_type =                &_pt_gobject_enum,
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA (
			PROPERTY_TYP_DATA_SUBTYPE (gobject_enum,
				.get_gtype =            nm_setting_ip6_config_addr_gen_mode_get_type,
			),
			.typ_flags =                  NM_META_PROPERTY_TYP_FLAG_ENUM_GET_PARSABLE_TEXT
			                            | NM_META_PROPERTY_TYP_FLAG_ENUM_GET_PRETTY_TEXT,
		),
	),
	PROPERTY_INFO (NM_SETTING_IP_CONFIG_DHCP_SEND_HOSTNAME, DESCRIBE_DOC_NM_SETTING_IP6_CONFIG_DHCP_SEND_HOSTNAME,
		.property_type =                &_pt_gobject_bool,
	),
	PROPERTY_INFO (NM_SETTING_IP_CONFIG_DHCP_HOSTNAME, DESCRIBE_DOC_NM_SETTING_IP6_CONFIG_DHCP_HOSTNAME,
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_IP6_CONFIG_TOKEN,
		.property_type =                &_pt_gobject_string,
	),
	NULL
};

#undef  _CURRENT_NM_META_SETTING_TYPE
#define _CURRENT_NM_META_SETTING_TYPE NM_META_SETTING_TYPE_IP_TUNNEL
static const NMMetaPropertyInfo *const property_infos_IP_TUNNEL[] = {
	PROPERTY_INFO_WITH_DESC (NM_SETTING_IP_TUNNEL_MODE,
		.is_cli_option =                TRUE,
		.property_alias =               "mode",
		.inf_flags =                    NM_META_PROPERTY_INF_FLAG_REQD,
		.prompt =                       NM_META_TEXT_PROMPT_IP_TUNNEL_MODE,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_ip_tunnel_mode,
			.set_fcn =                  _set_fcn_ip_tunnel_mode,
			.values_fcn =               _values_fcn_gobject_enum,
		),
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA_SUBTYPE (gobject_enum,
			.get_gtype =        nm_ip_tunnel_mode_get_type,
			.min =              NM_IP_TUNNEL_MODE_UNKNOWN + 1,
			.max =              G_MAXINT,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_IP_TUNNEL_PARENT,
		.is_cli_option =                TRUE,
		.property_alias =               "dev",
		.prompt =                       N_("Parent device [none]"),
		.property_type =                &_pt_gobject_devices,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_IP_TUNNEL_LOCAL,
		.is_cli_option =                TRUE,
		.property_alias =               "local",
		.prompt =                       N_("Local endpoint [none]"),
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_IP_TUNNEL_REMOTE,
		.is_cli_option =                TRUE,
		.property_alias =               "remote",
		.inf_flags =                    NM_META_PROPERTY_INF_FLAG_REQD,
		.prompt =                       N_("Remote"),
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_IP_TUNNEL_TTL,
		.property_type =                &_pt_gobject_uint,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_IP_TUNNEL_TOS,
		.property_type =                &_pt_gobject_uint,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_IP_TUNNEL_PATH_MTU_DISCOVERY,
		.property_type =                &_pt_gobject_bool,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_IP_TUNNEL_INPUT_KEY,
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_IP_TUNNEL_OUTPUT_KEY,
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_IP_TUNNEL_ENCAPSULATION_LIMIT,
		.property_type =                &_pt_gobject_uint,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_IP_TUNNEL_FLOW_LABEL,
		.property_type =                &_pt_gobject_uint,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_IP_TUNNEL_MTU,
		.property_type =                &_pt_gobject_mtu,
	),
	NULL
};

#undef  _CURRENT_NM_META_SETTING_TYPE
#define _CURRENT_NM_META_SETTING_TYPE NM_META_SETTING_TYPE_MACSEC
static const NMMetaPropertyInfo *const property_infos_MACSEC[] = {
	PROPERTY_INFO_WITH_DESC (NM_SETTING_MACSEC_PARENT,
		.is_cli_option =                TRUE,
		.property_alias =               "dev",
		.inf_flags =                    NM_META_PROPERTY_INF_FLAG_REQD,
		.prompt =                       N_("MACsec parent device or connection UUID"),
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_MACSEC_MODE,
		.is_cli_option =                TRUE,
		.property_alias =               "mode",
		.inf_flags =                    NM_META_PROPERTY_INF_FLAG_REQD,
		.prompt =                       NM_META_TEXT_PROMPT_MACSEC_MODE,
		.def_hint =                     NM_META_TEXT_PROMPT_MACSEC_MODE_CHOICES,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_macsec_mode,
			.set_fcn =                  _set_fcn_macsec_mode,
			.values_fcn =               _values_fcn_gobject_enum,
		),
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA_SUBTYPE (gobject_enum,
			.get_gtype =                nm_setting_macsec_mode_get_type,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_MACSEC_ENCRYPT,
		.is_cli_option =                TRUE,
		.property_alias =               "encrypt",
		.prompt =                       N_("Enable encryption [yes]"),
		.property_type =                &_pt_gobject_bool,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_MACSEC_MKA_CAK,
		.is_cli_option =                TRUE,
		.property_alias =               "cak",
		.prompt =                       N_("MKA CAK"),
		.is_secret =                    TRUE,
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_MACSEC_MKA_CAK_FLAGS,
		.property_type =                &_pt_gobject_secret_flags,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_MACSEC_MKA_CKN,
		.is_cli_option =                TRUE,
		.property_alias =               "ckn",
		.prompt =                       N_("MKA_CKN"),
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_MACSEC_PORT,
		.is_cli_option =                TRUE,
		.property_alias =               "port",
		.prompt =                       N_("SCI port [1]"),
		.property_type =                &_pt_gobject_int,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_MACSEC_VALIDATION,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_macsec_validation,
			.set_fcn =                  _set_fcn_macsec_validation,
			.values_fcn =               _values_fcn_gobject_enum,
		),
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA_SUBTYPE (gobject_enum,
			.get_gtype =                nm_setting_macsec_validation_get_type,
		),
	),
	NULL
};

#undef  _CURRENT_NM_META_SETTING_TYPE
#define _CURRENT_NM_META_SETTING_TYPE NM_META_SETTING_TYPE_MACVLAN
static const NMMetaPropertyInfo *const property_infos_MACVLAN[] = {
	PROPERTY_INFO_WITH_DESC (NM_SETTING_MACVLAN_PARENT,
		.is_cli_option =                TRUE,
		.property_alias =               "dev",
		.inf_flags =                    NM_META_PROPERTY_INF_FLAG_REQD,
		.prompt =                       N_("MACVLAN parent device or connection UUID"),
		.property_type =                &_pt_gobject_devices,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_MACVLAN_MODE,
		.is_cli_option =                TRUE,
		.property_alias =               "mode",
		.inf_flags =                    NM_META_PROPERTY_INF_FLAG_REQD,
		.prompt =                       NM_META_TEXT_PROMPT_MACVLAN_MODE,
		.property_type =                &_pt_gobject_enum,
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA_SUBTYPE (gobject_enum,
			.get_gtype =                nm_setting_macvlan_mode_get_type,
			.min =                      NM_SETTING_MACVLAN_MODE_UNKNOWN + 1,
			.max =                      G_MAXINT,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_MACVLAN_PROMISCUOUS,
		.property_type =                &_pt_gobject_bool,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_MACVLAN_TAP,
		.is_cli_option =                TRUE,
		.property_alias =               "tap",
		.prompt =                       N_("Tap [no]"),
		.property_type =                &_pt_gobject_bool,
	),
	NULL
};

#undef  _CURRENT_NM_META_SETTING_TYPE
#define _CURRENT_NM_META_SETTING_TYPE NM_META_SETTING_TYPE_OLPC_MESH
static const NMMetaPropertyInfo *const property_infos_OLPC_MESH[] = {
	PROPERTY_INFO_WITH_DESC (NM_SETTING_OLPC_MESH_SSID,
		.is_cli_option =                TRUE,
		.property_alias =               "ssid",
		.inf_flags =                    NM_META_PROPERTY_INF_FLAG_REQD,
		.prompt =                       N_("SSID"),
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_olpc_mesh_ssid,
			.set_fcn =                  _set_fcn_gobject_ssid,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_OLPC_MESH_CHANNEL,
		.is_cli_option =                TRUE,
		.property_alias =               "channel",
		.prompt =                       N_("OLPC Mesh channel [1]"),
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_gobject,
			.set_fcn =                  _set_fcn_olpc_mesh_channel,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_OLPC_MESH_DHCP_ANYCAST_ADDRESS,
		.is_cli_option =                TRUE,
		.property_alias =               "dhcp-anycast",
		.prompt =                       N_("DHCP anycast MAC address [none]"),
		.property_type =                &_pt_gobject_mac,
	),
	NULL
};

#undef  _CURRENT_NM_META_SETTING_TYPE
#define _CURRENT_NM_META_SETTING_TYPE NM_META_SETTING_TYPE_PPPOE
static const NMMetaPropertyInfo *const property_infos_PPPOE[] = {
	PROPERTY_INFO_WITH_DESC (NM_SETTING_PPPOE_SERVICE,
		.is_cli_option =                TRUE,
		.property_alias =               "service",
		.prompt =                       N_("Service [none]"),
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_PPPOE_USERNAME,
		.is_cli_option =                TRUE,
		.property_alias =               "username",
		.inf_flags =                    NM_META_PROPERTY_INF_FLAG_REQD,
		.prompt =                       N_("PPPoE username"),
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_PPPOE_PASSWORD,
		.is_cli_option =                TRUE,
		.property_alias =               "password",
		.prompt =                       N_("Password [none]"),
		.is_secret =                    TRUE,
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_PPPOE_PASSWORD_FLAGS,
		.property_type =                &_pt_gobject_secret_flags,
	),
	NULL
};

#undef  _CURRENT_NM_META_SETTING_TYPE
#define _CURRENT_NM_META_SETTING_TYPE NM_META_SETTING_TYPE_PPP
static const NMMetaPropertyInfo *const property_infos_PPP[] = {
	PROPERTY_INFO_WITH_DESC (NM_SETTING_PPP_NOAUTH,
		.property_type =                &_pt_gobject_bool,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_PPP_REFUSE_EAP,
		.property_type =                &_pt_gobject_bool,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_PPP_REFUSE_PAP,
		.property_type =                &_pt_gobject_bool,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_PPP_REFUSE_CHAP,
		.property_type =                &_pt_gobject_bool,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_PPP_REFUSE_MSCHAP,
		.property_type =                &_pt_gobject_bool,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_PPP_REFUSE_MSCHAPV2,
		.property_type =                &_pt_gobject_bool,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_PPP_NOBSDCOMP,
		.property_type =                &_pt_gobject_bool,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_PPP_NODEFLATE,
		.property_type =                &_pt_gobject_bool,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_PPP_NO_VJ_COMP,
		.property_type =                &_pt_gobject_bool,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_PPP_REQUIRE_MPPE,
		.property_type =                &_pt_gobject_bool,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_PPP_REQUIRE_MPPE_128,
		.property_type =                &_pt_gobject_bool,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_PPP_MPPE_STATEFUL,
		.property_type =                &_pt_gobject_bool,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_PPP_CRTSCTS,
		.property_type =                &_pt_gobject_bool,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_PPP_BAUD,
		.property_type =                &_pt_gobject_uint,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_PPP_MRU,
		.property_type =                &_pt_gobject_uint,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_PPP_MTU,
		.property_type =                &_pt_gobject_mtu,
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA_SUBTYPE (mtu,
			.get_fcn =                  MTU_GET_FCN (NMSettingPpp, nm_setting_ppp_get_mtu),
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_PPP_LCP_ECHO_FAILURE,
		.property_type =                &_pt_gobject_uint,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_PPP_LCP_ECHO_INTERVAL,
		.property_type =                &_pt_gobject_uint,
	),
	NULL
};

#undef  _CURRENT_NM_META_SETTING_TYPE
#define _CURRENT_NM_META_SETTING_TYPE NM_META_SETTING_TYPE_PROXY
static const NMMetaPropertyInfo *const property_infos_PROXY[] = {
	PROPERTY_INFO_WITH_DESC (NM_SETTING_PROXY_METHOD,
		.is_cli_option =                TRUE,
		.property_alias =               "method",
		.prompt =                       NM_META_TEXT_PROMPT_PROXY_METHOD,
		.def_hint =                     NM_META_TEXT_PROMPT_PROXY_METHOD_CHOICES,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_proxy_method,
			.set_fcn =                  _set_fcn_proxy_method,
			.values_fcn =               _values_fcn_gobject_enum,
		),
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA_SUBTYPE (gobject_enum,
			.get_gtype =                nm_setting_proxy_method_get_type,
			.min =                      NM_SETTING_PROXY_METHOD_NONE,
			.max =                      G_MAXINT,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_PROXY_BROWSER_ONLY,
		.is_cli_option =                TRUE,
		.property_alias =               "browser-only",
		.prompt =                       N_("Browser only [no]"),
		.property_type =                &_pt_gobject_bool
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_PROXY_PAC_URL,
		.is_cli_option =                TRUE,
		.property_alias =               "pac-url",
		.prompt =                       N_("PAC URL"),
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_PROXY_PAC_SCRIPT,
		.is_cli_option =                TRUE,
		.property_alias =               "pac-script",
		.prompt =                       N_("PAC script"),
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_gobject,
			.set_fcn =                  _set_fcn_proxy_pac_script,
		),
	),
	NULL
};

#undef  _CURRENT_NM_META_SETTING_TYPE
#define _CURRENT_NM_META_SETTING_TYPE NM_META_SETTING_TYPE_TEAM
static const NMMetaPropertyInfo *const property_infos_TEAM[] = {
	PROPERTY_INFO_WITH_DESC (NM_SETTING_TEAM_CONFIG,
		.is_cli_option =                TRUE,
		.property_alias =               "config",
		.prompt =                       N_("Team JSON configuration [none]"),
		.describe_message =             TEAM_DESCRIBE_MESSAGE,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_gobject,
			.set_fcn =                  _set_fcn_team_config,
		),
	),
	NULL
};

#undef  _CURRENT_NM_META_SETTING_TYPE
#define _CURRENT_NM_META_SETTING_TYPE NM_META_SETTING_TYPE_TEAM_PORT
static const NMMetaPropertyInfo *const property_infos_TEAM_PORT[] = {
	PROPERTY_INFO_WITH_DESC (NM_SETTING_TEAM_PORT_CONFIG,
		.is_cli_option =                TRUE,
		.property_alias =               "config",
		.prompt =                       N_("Team JSON configuration [none]"),
		.describe_message =             TEAM_DESCRIBE_MESSAGE,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_gobject,
			.set_fcn =                  _set_fcn_team_config,
		),
	),
	NULL
};

#undef  _CURRENT_NM_META_SETTING_TYPE
#define _CURRENT_NM_META_SETTING_TYPE NM_META_SETTING_TYPE_SERIAL
static const NMMetaPropertyInfo *const property_infos_SERIAL[] = {
	PROPERTY_INFO_WITH_DESC (NM_SETTING_SERIAL_BAUD,
		.property_type =                &_pt_gobject_uint,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_SERIAL_BITS,
		.property_type =                &_pt_gobject_uint,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_SERIAL_PARITY,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_serial_parity,
			.set_fcn =                  _set_fcn_serial_parity,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_SERIAL_STOPBITS,
		.property_type =                &_pt_gobject_uint,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_SERIAL_SEND_DELAY,
		.property_type =                &_pt_gobject_uint,
	),
	NULL
};

#undef  _CURRENT_NM_META_SETTING_TYPE
#define _CURRENT_NM_META_SETTING_TYPE NM_META_SETTING_TYPE_TUN
static const NMMetaPropertyInfo *const property_infos_TUN[] = {
	PROPERTY_INFO_WITH_DESC (NM_SETTING_TUN_MODE,
		.is_cli_option =                TRUE,
		.property_alias =               "mode",
		.prompt =                       NM_META_TEXT_PROMPT_TUN_MODE,
		.def_hint =                     NM_META_TEXT_PROMPT_TUN_MODE_CHOICES,
		.property_type =                &_pt_gobject_enum,
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA_SUBTYPE (gobject_enum,
			.get_gtype =                nm_setting_tun_mode_get_type,
			.min =                      NM_SETTING_TUN_MODE_UNKNOWN + 1,
			.max =                      G_MAXINT,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_TUN_OWNER,
		.is_cli_option =                TRUE,
		.property_alias =               "owner",
		.prompt =                       N_("User ID [none]"),
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_TUN_GROUP,
		.is_cli_option =                TRUE,
		.property_alias =               "group",
		.prompt =                       N_("Group ID [none]"),
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_TUN_PI,
		.is_cli_option =                TRUE,
		.property_alias =               "pi",
		.prompt =                       N_("Enable PI [no]"),
		.property_type =                &_pt_gobject_bool,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_TUN_VNET_HDR,
		.is_cli_option =                TRUE,
		.property_alias =               "vnet-hdr",
		.prompt =                       N_("Enable VNET header [no]"),
		.property_type =                &_pt_gobject_bool,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_TUN_MULTI_QUEUE,
		.is_cli_option =                TRUE,
		.property_alias =               "multi-queue",
		.prompt =                       N_("Enable multi queue [no]"),
		.property_type =                &_pt_gobject_bool,
	),
	NULL
};

#undef  _CURRENT_NM_META_SETTING_TYPE
#define _CURRENT_NM_META_SETTING_TYPE NM_META_SETTING_TYPE_VLAN
static const NMMetaPropertyInfo *const property_infos_VLAN[] = {
	PROPERTY_INFO_WITH_DESC (NM_SETTING_VLAN_PARENT,
		.is_cli_option =                TRUE,
		.property_alias =               "dev",
		.inf_flags =                    NM_META_PROPERTY_INF_FLAG_REQD,
		.prompt =                       N_("VLAN parent device or connection UUID"),
		.property_type =                &_pt_gobject_devices,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_VLAN_ID,
		.is_cli_option =                TRUE,
		.property_alias =               "id",
		.inf_flags =                    NM_META_PROPERTY_INF_FLAG_REQD,
		.prompt =                       N_("VLAN ID (<0-4094>)"),
		.property_type =                &_pt_gobject_uint,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_VLAN_FLAGS,
		.is_cli_option =                TRUE,
		.property_alias =               "flags",
		.prompt =                       N_("VLAN flags (<0-7>) [none]"),
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_vlan_flags,
			.set_fcn =                  _set_fcn_gobject_flags,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_VLAN_INGRESS_PRIORITY_MAP,
		.is_cli_option =                TRUE,
		.property_alias =               "ingress",
		.prompt =                       N_("Ingress priority maps [none]"),
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_vlan_ingress_priority_map,
			.set_fcn =                  _set_fcn_vlan_ingress_priority_map,
			.remove_fcn =               _remove_fcn_vlan_ingress_priority_map,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_VLAN_EGRESS_PRIORITY_MAP,
		.is_cli_option =                TRUE,
		.property_alias =               "egress",
		.prompt =                       N_("Egress priority maps [none]"),
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_vlan_egress_priority_map,
			.set_fcn =                  _set_fcn_vlan_egress_priority_map,
			.remove_fcn =               _remove_fcn_vlan_egress_priority_map,
		),
	),
	NULL
};

#undef  _CURRENT_NM_META_SETTING_TYPE
#define _CURRENT_NM_META_SETTING_TYPE NM_META_SETTING_TYPE_VPN
static const NMMetaPropertyInfo *const property_infos_VPN[] = {
[_NM_META_PROPERTY_TYPE_VPN_SERVICE_TYPE] =
	PROPERTY_INFO_WITH_DESC (NM_SETTING_VPN_SERVICE_TYPE,
		.is_cli_option =                TRUE,
		.property_alias =               "vpn-type",
		.inf_flags =                    NM_META_PROPERTY_INF_FLAG_REQD,
		.prompt =                       NM_META_TEXT_PROMPT_VPN_TYPE,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_gobject,
			.set_fcn =                  _set_fcn_vpn_service_type,
			.complete_fcn =             _complete_fcn_vpn_service_type,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_VPN_USER_NAME,
		.is_cli_option =                TRUE,
		.property_alias =               "user",
		.prompt =                       N_("Username [none]"),
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_VPN_DATA,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_vpn_data,
			.set_fcn =                  _set_fcn_vpn_data,
			.remove_fcn =               _remove_fcn_vpn_data,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_VPN_SECRETS,
		.is_secret =                    TRUE,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_vpn_secrets,
			.set_fcn =                  _set_fcn_vpn_secrets,
			.remove_fcn =               _remove_fcn_vpn_secrets,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_VPN_PERSISTENT,
		.property_type =                &_pt_gobject_bool,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_VPN_TIMEOUT,
		.property_type =                &_pt_gobject_uint,
	),
	NULL
};

#undef  _CURRENT_NM_META_SETTING_TYPE
#define _CURRENT_NM_META_SETTING_TYPE NM_META_SETTING_TYPE_VXLAN
static const NMMetaPropertyInfo *const property_infos_VXLAN[] = {
	PROPERTY_INFO_WITH_DESC (NM_SETTING_VXLAN_PARENT,
		.is_cli_option =                TRUE,
		.property_alias =               "dev",
		.prompt =                       N_("Parent device [none]"),
		.property_type =                &_pt_gobject_devices,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_VXLAN_ID,
		.is_cli_option =                TRUE,
		.property_alias =               "id",
		.inf_flags =                    NM_META_PROPERTY_INF_FLAG_REQD,
		.prompt =                       N_("VXLAN ID"),
		.property_type =                &_pt_gobject_uint,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_VXLAN_LOCAL,
		.is_cli_option =                TRUE,
		.property_alias =               "local",
		.prompt =                       N_("Local address [none]"),
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_VXLAN_REMOTE,
		.is_cli_option =                TRUE,
		.property_alias =               "remote",
		.inf_flags =                    NM_META_PROPERTY_INF_FLAG_REQD,
		.prompt =                       N_("Remote"),
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_VXLAN_SOURCE_PORT_MIN,
		.is_cli_option =                TRUE,
		.property_alias =               "source-port-min",
		.prompt =                       N_("Minimum source port [0]"),
		.property_type =                &_pt_gobject_uint,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_VXLAN_SOURCE_PORT_MAX,
		.is_cli_option =                TRUE,
		.property_alias =               "source-port-max",
		.prompt =                       N_("Maximum source port [0]"),
		.property_type =                &_pt_gobject_uint,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_VXLAN_DESTINATION_PORT,
		.is_cli_option =                TRUE,
		.property_alias =               "destination-port",
		.prompt =                       N_("Destination port [8472]"),
		.property_type =                &_pt_gobject_uint,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_VXLAN_TOS,
		.property_type =                &_pt_gobject_uint,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_VXLAN_TTL,
		.property_type =                &_pt_gobject_uint,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_VXLAN_AGEING,
		.property_type =                &_pt_gobject_uint,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_VXLAN_LIMIT,
		.property_type =                &_pt_gobject_uint,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_VXLAN_LEARNING,
		.property_type =                &_pt_gobject_bool,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_VXLAN_PROXY,
		.property_type =                &_pt_gobject_bool,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_VXLAN_RSC,
		.property_type =                &_pt_gobject_bool,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_VXLAN_L2_MISS,
		.property_type =                &_pt_gobject_bool,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_VXLAN_L3_MISS,
		.property_type =                &_pt_gobject_bool,
	),
	NULL
};

#undef  _CURRENT_NM_META_SETTING_TYPE
#define _CURRENT_NM_META_SETTING_TYPE NM_META_SETTING_TYPE_WIMAX
static const NMMetaPropertyInfo *const property_infos_WIMAX[] = {
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIMAX_MAC_ADDRESS,
		.is_cli_option =                TRUE,
		.property_alias =               "mac",
		.prompt =                       N_("MAC [none]"),
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIMAX_NETWORK_NAME,
		.is_cli_option =                TRUE,
		.property_alias =               "nsp",
		.inf_flags =                    NM_META_PROPERTY_INF_FLAG_REQD,
		.prompt =                       N_("WiMAX NSP name"),
		.property_type =                &_pt_gobject_mac,
	),
	NULL
};

#undef  _CURRENT_NM_META_SETTING_TYPE
#define _CURRENT_NM_META_SETTING_TYPE NM_META_SETTING_TYPE_WIRED
static const NMMetaPropertyInfo *const property_infos_WIRED[] = {
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRED_PORT,
		/* Do not allow setting 'port' for now. It is not implemented in
		 * NM core, nor in ifcfg-rh plugin. Enable this when it gets done.
		 * wired_valid_ports[] = { "tp", "aui", "bnc", "mii", NULL };
		 */
		.property_type =                &_pt_gobject_readonly,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRED_SPEED,
		.property_type =                &_pt_gobject_uint,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRED_DUPLEX,
		.property_type =                &_pt_gobject_string,
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA (
			.values_static =            VALUES_STATIC ("half", "full"),
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRED_AUTO_NEGOTIATE,
		.property_type =                &_pt_gobject_bool,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRED_MAC_ADDRESS,
		.is_cli_option =                TRUE,
		.property_alias =               "mac",
		.prompt =                       N_("MAC [none]"),
		.property_type =                &_pt_gobject_mac,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRED_CLONED_MAC_ADDRESS,
		.is_cli_option =                TRUE,
		.property_alias =               "cloned-mac",
		.prompt =                       N_("Cloned MAC [none]"),
		.property_type =                &_pt_gobject_mac,
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA_SUBTYPE (mac,
			.mode =                     NM_META_PROPERTY_TYPE_MAC_MODE_CLONED,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRED_GENERATE_MAC_ADDRESS_MASK,
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRED_MAC_ADDRESS_BLACKLIST,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_gobject,
			.set_fcn =                  _set_fcn_wired_mac_address_blacklist,
			.remove_fcn =               _remove_fcn_wired_mac_address_blacklist,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRED_MTU,
		.is_cli_option =                TRUE,
		.property_alias =               "mtu",
		.prompt =                       N_("MTU [auto]"),
		.property_type =                &_pt_gobject_mtu,
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA_SUBTYPE (mtu,
			.get_fcn =                  MTU_GET_FCN (NMSettingWired, nm_setting_wired_get_mtu),
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRED_S390_SUBCHANNELS,
		.describe_message =
		    N_("Enter a list of subchannels (comma or space separated).\n\n"
		       "Example: 0.0.0e20 0.0.0e21 0.0.0e22\n"),
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_gobject,
			.set_fcn =                  _set_fcn_wired_s390_subchannels,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRED_S390_NETTYPE,
		.property_type =                &_pt_gobject_string,
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA (
			.values_static =            VALUES_STATIC ("qeth", "lcs", "ctc"),
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRED_S390_OPTIONS,
		.property_type = DEFINE_PROPERTY_TYPE (
			.describe_fcn =             _describe_fcn_wired_s390_options,
			.get_fcn =                  _get_fcn_gobject,
			.set_fcn =                  _set_fcn_wired_s390_options,
			.remove_fcn =               _remove_fcn_wired_s390_options,
			.values_fcn =               _values_fcn__wired_s390_options,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRED_WAKE_ON_LAN,
		.property_type =                &_pt_gobject_enum,
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA (
			PROPERTY_TYP_DATA_SUBTYPE (gobject_enum,
				.get_gtype =            nm_setting_wired_wake_on_lan_get_type,
				.value_infos =          ENUM_VALUE_INFOS (
					{
						.value = NM_SETTING_WIRED_WAKE_ON_LAN_NONE,
						.nick = "none",
					},
					{
						.value = NM_SETTING_WIRED_WAKE_ON_LAN_NONE,
						.nick = "disable",
					},
					{
						.value = NM_SETTING_WIRED_WAKE_ON_LAN_NONE,
						.nick = "disabled",
					}
				),
			),
			.typ_flags =                  NM_META_PROPERTY_TYP_FLAG_ENUM_GET_PARSABLE_TEXT
			                            | NM_META_PROPERTY_TYP_FLAG_ENUM_GET_PRETTY_TEXT,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRED_WAKE_ON_LAN_PASSWORD,
		.property_type =                &_pt_gobject_mac,
	),
	NULL
};

#undef  _CURRENT_NM_META_SETTING_TYPE
#define _CURRENT_NM_META_SETTING_TYPE NM_META_SETTING_TYPE_WIRELESS
static const NMMetaPropertyInfo *const property_infos_WIRELESS[] = {
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRELESS_SSID,
		.is_cli_option =                TRUE,
		.property_alias =               "ssid",
		.inf_flags =                    NM_META_PROPERTY_INF_FLAG_REQD,
		.prompt =                       N_("SSID"),
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_wireless_ssid,
			.set_fcn =                  _set_fcn_gobject_ssid,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRELESS_MODE,
		.is_cli_option =                TRUE,
		.property_alias =               "mode",
		.prompt =                       NM_META_TEXT_PROMPT_WIFI_MODE,
		.def_hint =                     NM_META_TEXT_PROMPT_WIFI_MODE_CHOICES,
		.property_type =                &_pt_gobject_string,
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA (
			.values_static =            VALUES_STATIC (NM_SETTING_WIRELESS_MODE_INFRA,
			                                           NM_SETTING_WIRELESS_MODE_ADHOC,
			                                           NM_SETTING_WIRELESS_MODE_AP),
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRELESS_BAND,
		.property_type =                &_pt_gobject_string,
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA (
			.values_static =            VALUES_STATIC ("a", "bg"),
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRELESS_CHANNEL,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_gobject,
			.set_fcn =                  _set_fcn_wireless_channel,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRELESS_BSSID,
		.property_type =                &_pt_gobject_mac,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRELESS_RATE,
		/* Do not allow setting 'rate'. It is not implemented in NM core. */
		.property_type =                &_pt_gobject_readonly,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRELESS_TX_POWER,
		/* Do not allow setting 'tx-power'. It is not implemented in NM core. */
		.property_type =                &_pt_gobject_readonly,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRELESS_MAC_ADDRESS,
		.property_type =                &_pt_gobject_mac,
		.is_cli_option =                TRUE,
		.property_alias =               "mac",
		.prompt =                       N_("MAC [none]"),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS,
		.is_cli_option =                TRUE,
		.property_alias =               "cloned-mac",
		.prompt =                       N_("Cloned MAC [none]"),
		.property_type =                &_pt_gobject_mac,
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA_SUBTYPE (mac,
			.mode =                     NM_META_PROPERTY_TYPE_MAC_MODE_CLONED,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRELESS_GENERATE_MAC_ADDRESS_MASK,
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRELESS_MAC_ADDRESS_BLACKLIST,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_gobject,
			.set_fcn =                  _set_fcn_wireless_mac_address_blacklist,
			.remove_fcn =               _remove_fcn_wireless_mac_address_blacklist,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRELESS_MAC_ADDRESS_RANDOMIZATION,
		.property_type =                &_pt_gobject_enum,
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA (
			PROPERTY_TYP_DATA_SUBTYPE (gobject_enum,
				.get_gtype =            nm_setting_mac_randomization_get_type,
			),
			.typ_flags =                  NM_META_PROPERTY_TYP_FLAG_ENUM_GET_PARSABLE_TEXT
			                            | NM_META_PROPERTY_TYP_FLAG_ENUM_GET_PRETTY_TEXT,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRELESS_MTU,
		.is_cli_option =                TRUE,
		.property_alias =               "mtu",
		.prompt =                       N_("MTU [auto]"),
		.property_type =                &_pt_gobject_mtu,
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA_SUBTYPE (mtu,
			.get_fcn =                  MTU_GET_FCN (NMSettingWireless, nm_setting_wireless_get_mtu),
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRELESS_SEEN_BSSIDS,
		.property_type =                &_pt_gobject_readonly,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRELESS_HIDDEN,
		.property_type =                &_pt_gobject_bool,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRELESS_POWERSAVE,
		.property_type =                &_pt_gobject_enum,
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA (
			PROPERTY_TYP_DATA_SUBTYPE (gobject_enum,
				.get_gtype =            nm_setting_wireless_powersave_get_type,
			),
			.typ_flags =                NM_META_PROPERTY_TYP_FLAG_ENUM_GET_PARSABLE_TEXT,
		),
	),
	NULL
};

#undef  _CURRENT_NM_META_SETTING_TYPE
#define _CURRENT_NM_META_SETTING_TYPE NM_META_SETTING_TYPE_WIRELESS_SECURITY
static const NMMetaPropertyInfo *const property_infos_WIRELESS_SECURITY[] = {
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRELESS_SECURITY_KEY_MGMT,
		.property_type =                &_pt_gobject_string,
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA (
			.values_static =            VALUES_STATIC ("none", "ieee8021x", "wpa-none", "wpa-psk", "wpa-eap"),
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRELESS_SECURITY_WEP_TX_KEYIDX,
		.property_type =                &_pt_gobject_uint,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRELESS_SECURITY_AUTH_ALG,
		.property_type =                &_pt_gobject_string,
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA (
			.values_static =            VALUES_STATIC ("open", "shared", "leap"),
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRELESS_SECURITY_PROTO,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_gobject,
			.set_fcn =                  _set_fcn_wireless_security_proto,
			.remove_fcn =               _remove_fcn_wireless_security_proto,
		),
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA (
			.values_static =            wifi_sec_valid_protos,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRELESS_SECURITY_PAIRWISE,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_gobject,
			.set_fcn =                  _set_fcn_wireless_security_pairwise,
			.remove_fcn =               _remove_fcn_wireless_security_pairwise,
		),
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA (
			.values_static =            wifi_sec_valid_pairwises,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRELESS_SECURITY_GROUP,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_gobject,
			.set_fcn =                  _set_fcn_wireless_security_group,
			.remove_fcn =               _remove_fcn_wireless_security_group,
		),
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA (
			.values_static =            wifi_sec_valid_groups,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRELESS_SECURITY_PMF,
		.property_type =                &_pt_gobject_enum,
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA (
			PROPERTY_TYP_DATA_SUBTYPE (gobject_enum,
				.get_gtype =            nm_setting_wireless_security_pmf_get_type,
			),
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME,
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRELESS_SECURITY_WEP_KEY0,
		.is_secret =                    TRUE,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_wireless_security_wep_key0,
			.set_fcn =                  _set_fcn_wireless_wep_key,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRELESS_SECURITY_WEP_KEY1,
		.is_secret =                    TRUE,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_wireless_security_wep_key1,
			.set_fcn =                  _set_fcn_wireless_wep_key,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRELESS_SECURITY_WEP_KEY2,
		.is_secret =                    TRUE,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_wireless_security_wep_key2,
			.set_fcn =                  _set_fcn_wireless_wep_key,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRELESS_SECURITY_WEP_KEY3,
		.is_secret =                    TRUE,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_wireless_security_wep_key3,
			.set_fcn =                  _set_fcn_wireless_wep_key,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRELESS_SECURITY_WEP_KEY_FLAGS,
		.property_type =                &_pt_gobject_secret_flags,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE,
		.describe_message =
		    N_("Enter the type of WEP keys. The accepted values are: "
		       "0 or unknown, 1 or key, and 2 or passphrase.\n"),
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_wireless_security_wep_key_type,
			.set_fcn =                  _set_fcn_wireless_security_wep_key_type,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRELESS_SECURITY_PSK,
		.is_secret =                    TRUE,
		.property_type = DEFINE_PROPERTY_TYPE (
			.get_fcn =                  _get_fcn_gobject,
			.set_fcn =                  _set_fcn_wireless_security_psk,
		),
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRELESS_SECURITY_PSK_FLAGS,
		.property_type =                &_pt_gobject_secret_flags,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD,
		.is_secret =                    TRUE,
		.property_type =                &_pt_gobject_string,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD_FLAGS,
		.property_type =                &_pt_gobject_secret_flags,
	),
	PROPERTY_INFO_WITH_DESC (NM_SETTING_WIRELESS_SECURITY_WPS_METHOD,
		.property_type =                &_pt_gobject_enum,
		.property_typ_data = DEFINE_PROPERTY_TYP_DATA (
			PROPERTY_TYP_DATA_SUBTYPE (gobject_enum,
				.get_gtype =            nm_setting_wireless_security_wps_method_get_type,
			),
		),
	),
	NULL
};

/*****************************************************************************/

static void
_setting_init_fcn_adsl (ARGS_SETTING_INIT_FCN)
{
	if (init_type == NM_META_ACCESSOR_SETTING_INIT_TYPE_CLI) {
		/* Initialize a protocol */
		g_object_set (NM_SETTING_ADSL (setting),
		              NM_SETTING_ADSL_PROTOCOL, NM_SETTING_ADSL_PROTOCOL_PPPOE,
		              NULL);
	}
}

static void
_setting_init_fcn_bluetooth (ARGS_SETTING_INIT_FCN)
{
	if (init_type == NM_META_ACCESSOR_SETTING_INIT_TYPE_CLI) {
		g_object_set (NM_SETTING_BLUETOOTH (setting),
		              NM_SETTING_BLUETOOTH_TYPE, NM_SETTING_BLUETOOTH_TYPE_PANU,
		              NULL);
	}
}

static void
_setting_init_fcn_cdma (ARGS_SETTING_INIT_FCN)
{
	if (init_type == NM_META_ACCESSOR_SETTING_INIT_TYPE_CLI) {
		/* Initialize 'number' so that 'cdma' is valid */
		g_object_set (NM_SETTING_CDMA (setting),
		              NM_SETTING_CDMA_NUMBER, "#777",
		              NULL);
	}
}

static void
_setting_init_fcn_gsm (ARGS_SETTING_INIT_FCN)
{
	if (init_type == NM_META_ACCESSOR_SETTING_INIT_TYPE_CLI) {
		/* Initialize 'number' so that 'gsm' is valid */
		g_object_set (NM_SETTING_GSM (setting),
		              NM_SETTING_GSM_NUMBER, "*99#",
		              NULL);
	}
}

static void
_setting_init_fcn_infiniband (ARGS_SETTING_INIT_FCN)
{
	if (init_type == NM_META_ACCESSOR_SETTING_INIT_TYPE_CLI) {
		/* Initialize 'transport-mode' so that 'infiniband' is valid */
		g_object_set (NM_SETTING_INFINIBAND (setting),
		              NM_SETTING_INFINIBAND_TRANSPORT_MODE, "datagram",
		              NULL);
	}
}

static void
_setting_init_fcn_ip4_config (ARGS_SETTING_INIT_FCN)
{
	if (init_type == NM_META_ACCESSOR_SETTING_INIT_TYPE_CLI) {
		g_object_set (NM_SETTING_IP_CONFIG (setting),
		              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
		              NULL);
	}
}

static void
_setting_init_fcn_ip6_config (ARGS_SETTING_INIT_FCN)
{
	if (init_type == NM_META_ACCESSOR_SETTING_INIT_TYPE_CLI) {
		g_object_set (NM_SETTING_IP_CONFIG (setting),
		              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO,
		              NULL);
	}
}

static void
_setting_init_fcn_olpc_mesh (ARGS_SETTING_INIT_FCN)
{
	if (init_type == NM_META_ACCESSOR_SETTING_INIT_TYPE_CLI) {
		g_object_set (NM_SETTING_OLPC_MESH (setting),
		              NM_SETTING_OLPC_MESH_CHANNEL, 1,
		              NULL);
	}
}

static void
_setting_init_fcn_proxy (ARGS_SETTING_INIT_FCN)
{
	if (init_type == NM_META_ACCESSOR_SETTING_INIT_TYPE_CLI) {
		g_object_set (NM_SETTING_PROXY (setting),
		              NM_SETTING_PROXY_METHOD, (int) NM_SETTING_PROXY_METHOD_NONE,
		              NULL);
	}
}

static void
_setting_init_fcn_tun (ARGS_SETTING_INIT_FCN)
{
	if (init_type == NM_META_ACCESSOR_SETTING_INIT_TYPE_CLI) {
		g_object_set (NM_SETTING_TUN (setting),
		              NM_SETTING_TUN_MODE, NM_SETTING_TUN_MODE_TUN,
		              NULL);
	}
}

static void
_setting_init_fcn_vlan (ARGS_SETTING_INIT_FCN)
{
	if (init_type == NM_META_ACCESSOR_SETTING_INIT_TYPE_CLI) {
		g_object_set (setting,
		              NM_SETTING_VLAN_ID, 1,
		              NULL);
	}
}

static void
_setting_init_fcn_wireless (ARGS_SETTING_INIT_FCN)
{
	if (init_type == NM_META_ACCESSOR_SETTING_INIT_TYPE_CLI) {
		/* For Wi-Fi set mode to "infrastructure". Even though mode == NULL
		 * is regarded as "infrastructure", explicit value makes no doubts.
		 */
		g_object_set (NM_SETTING_WIRELESS (setting),
		              NM_SETTING_WIRELESS_MODE, NM_SETTING_WIRELESS_MODE_INFRA,
		              NULL);
	}
}

/*****************************************************************************/

#define SETTING_PRETTY_NAME_802_1X              N_("802-1x settings")
#define SETTING_PRETTY_NAME_ADSL                N_("ADSL connection")
#define SETTING_PRETTY_NAME_BLUETOOTH           N_("bluetooth connection")
#define SETTING_PRETTY_NAME_BOND                N_("Bond device")
#define SETTING_PRETTY_NAME_BRIDGE              N_("Bridge device")
#define SETTING_PRETTY_NAME_BRIDGE_PORT         N_("Bridge port")
#define SETTING_PRETTY_NAME_CDMA                N_("CDMA mobile broadband connection")
#define SETTING_PRETTY_NAME_CONNECTION          N_("General settings")
#define SETTING_PRETTY_NAME_DCB                 N_("DCB settings")
#define SETTING_PRETTY_NAME_DUMMY               N_("Dummy settings")
#define SETTING_PRETTY_NAME_GENERIC             N_("Generic settings")
#define SETTING_PRETTY_NAME_GSM                 N_("GSM mobile broadband connection")
#define SETTING_PRETTY_NAME_INFINIBAND          N_("InfiniBand connection")
#define SETTING_PRETTY_NAME_IP4_CONFIG          N_("IPv4 protocol")
#define SETTING_PRETTY_NAME_IP6_CONFIG          N_("IPv6 protocol")
#define SETTING_PRETTY_NAME_IP_TUNNEL           N_("IP-tunnel settings")
#define SETTING_PRETTY_NAME_MACSEC              N_("MACsec connection")
#define SETTING_PRETTY_NAME_MACVLAN             N_("macvlan connection")
#define SETTING_PRETTY_NAME_OLPC_MESH           N_("OLPC Mesh connection")
#define SETTING_PRETTY_NAME_PPP                 N_("PPP settings")
#define SETTING_PRETTY_NAME_PPPOE               N_("PPPoE")
#define SETTING_PRETTY_NAME_PROXY               N_("Proxy")
#define SETTING_PRETTY_NAME_SERIAL              N_("Serial settings")
#define SETTING_PRETTY_NAME_TEAM                N_("Team device")
#define SETTING_PRETTY_NAME_TEAM_PORT           N_("Team port")
#define SETTING_PRETTY_NAME_TUN                 N_("Tun device")
#define SETTING_PRETTY_NAME_USER                N_("User settings")
#define SETTING_PRETTY_NAME_VLAN                N_("VLAN connection")
#define SETTING_PRETTY_NAME_VPN                 N_("VPN connection")
#define SETTING_PRETTY_NAME_VXLAN               N_("VXLAN connection")
#define SETTING_PRETTY_NAME_WIMAX               N_("WiMAX connection")
#define SETTING_PRETTY_NAME_WIRED               N_("Wired Ethernet")
#define SETTING_PRETTY_NAME_WIRELESS            N_("Wi-Fi connection")
#define SETTING_PRETTY_NAME_WIRELESS_SECURITY   N_("Wi-Fi security settings")

#define NM_META_SETTING_VALID_PARTS(...) \
	((const NMMetaSettingValidPartItem *const[]) { __VA_ARGS__  NULL })

#define NM_META_SETTING_VALID_PART_ITEM(type, mand) \
	(&((const NMMetaSettingValidPartItem) { \
		.setting_info =                     &nm_meta_setting_infos_editor[NM_META_SETTING_TYPE_##type], \
		.mandatory =                        mand, \
	}))

const NMMetaSettingInfoEditor nm_meta_setting_infos_editor[] = {
#define SETTING_INFO_EMPTY(type, ...) \
	[NM_META_SETTING_TYPE_##type] = { \
		.meta_type =                        &nm_meta_type_setting_info_editor, \
		.general =                          &nm_meta_setting_infos[NM_META_SETTING_TYPE_##type], \
		.pretty_name =                      SETTING_PRETTY_NAME_##type, \
		__VA_ARGS__ \
	}
#define SETTING_INFO(type, ...) \
	[NM_META_SETTING_TYPE_##type] = { \
		.meta_type =                        &nm_meta_type_setting_info_editor, \
		.general =                          &nm_meta_setting_infos[NM_META_SETTING_TYPE_##type], \
		.properties =                       property_infos_##type, \
		.properties_num =                   G_N_ELEMENTS (property_infos_##type) - 1, \
		.pretty_name =                      SETTING_PRETTY_NAME_##type, \
		__VA_ARGS__ \
	}
	SETTING_INFO (802_1X),
	SETTING_INFO (ADSL,
		.valid_parts = NM_META_SETTING_VALID_PARTS (
			NM_META_SETTING_VALID_PART_ITEM (CONNECTION,            TRUE),
			NM_META_SETTING_VALID_PART_ITEM (ADSL,                  TRUE),
		),
		.setting_init_fcn =             _setting_init_fcn_adsl,
	),
	SETTING_INFO (BLUETOOTH,
		.valid_parts = NM_META_SETTING_VALID_PARTS (
			NM_META_SETTING_VALID_PART_ITEM (CONNECTION,            TRUE),
			NM_META_SETTING_VALID_PART_ITEM (BLUETOOTH,             TRUE),
		),
		.setting_init_fcn =             _setting_init_fcn_bluetooth,
	),
	SETTING_INFO (BOND,
		.valid_parts = NM_META_SETTING_VALID_PARTS (
			NM_META_SETTING_VALID_PART_ITEM (CONNECTION,            TRUE),
			NM_META_SETTING_VALID_PART_ITEM (BOND,                  TRUE),
			NM_META_SETTING_VALID_PART_ITEM (WIRED,                 FALSE),
		),
	),
	SETTING_INFO (BRIDGE,
		.valid_parts = NM_META_SETTING_VALID_PARTS (
			NM_META_SETTING_VALID_PART_ITEM (CONNECTION,            TRUE),
			NM_META_SETTING_VALID_PART_ITEM (BRIDGE,                TRUE),
			NM_META_SETTING_VALID_PART_ITEM (WIRED,                 FALSE),
		),
	),
	SETTING_INFO (BRIDGE_PORT),
	SETTING_INFO (CDMA,
		.valid_parts = NM_META_SETTING_VALID_PARTS (
			NM_META_SETTING_VALID_PART_ITEM (CONNECTION,            TRUE),
			NM_META_SETTING_VALID_PART_ITEM (CDMA,                  TRUE),
			NM_META_SETTING_VALID_PART_ITEM (SERIAL,                FALSE),
			NM_META_SETTING_VALID_PART_ITEM (PPP,                   FALSE),
		),
		.setting_init_fcn =             _setting_init_fcn_cdma,
	),
	SETTING_INFO (CONNECTION),
	SETTING_INFO (DCB),
	SETTING_INFO_EMPTY (DUMMY,
		.valid_parts = NM_META_SETTING_VALID_PARTS (
			NM_META_SETTING_VALID_PART_ITEM (CONNECTION,            TRUE),
			NM_META_SETTING_VALID_PART_ITEM (DUMMY,                 TRUE),
			NM_META_SETTING_VALID_PART_ITEM (WIRED,                 FALSE),
		),
	),
	SETTING_INFO_EMPTY (GENERIC,
		.valid_parts = NM_META_SETTING_VALID_PARTS (
			NM_META_SETTING_VALID_PART_ITEM (CONNECTION,            TRUE),
			NM_META_SETTING_VALID_PART_ITEM (GENERIC,               TRUE),
		),
	),
	SETTING_INFO (GSM,
		.valid_parts = NM_META_SETTING_VALID_PARTS (
			NM_META_SETTING_VALID_PART_ITEM (CONNECTION,            TRUE),
			NM_META_SETTING_VALID_PART_ITEM (GSM,                   TRUE),
			NM_META_SETTING_VALID_PART_ITEM (SERIAL,                FALSE),
			NM_META_SETTING_VALID_PART_ITEM (PPP,                   FALSE),
		),
		.setting_init_fcn =             _setting_init_fcn_gsm,
	),
	SETTING_INFO (INFINIBAND,
		.valid_parts = NM_META_SETTING_VALID_PARTS (
			NM_META_SETTING_VALID_PART_ITEM (CONNECTION,            TRUE),
			NM_META_SETTING_VALID_PART_ITEM (INFINIBAND,            TRUE),
		),
		.setting_init_fcn =             _setting_init_fcn_infiniband,
	),
	SETTING_INFO (IP4_CONFIG,
		.setting_init_fcn =             _setting_init_fcn_ip4_config,
	),
	SETTING_INFO (IP6_CONFIG,
		.setting_init_fcn =             _setting_init_fcn_ip6_config,
	),
	SETTING_INFO (IP_TUNNEL,
		.valid_parts = NM_META_SETTING_VALID_PARTS (
			NM_META_SETTING_VALID_PART_ITEM (CONNECTION,            TRUE),
			NM_META_SETTING_VALID_PART_ITEM (IP_TUNNEL,             TRUE),
		),
	),
	SETTING_INFO (MACSEC,
		.valid_parts = NM_META_SETTING_VALID_PARTS (
			NM_META_SETTING_VALID_PART_ITEM (CONNECTION,            TRUE),
			NM_META_SETTING_VALID_PART_ITEM (MACSEC,                TRUE),
			NM_META_SETTING_VALID_PART_ITEM (WIRED,                 FALSE),
			NM_META_SETTING_VALID_PART_ITEM (802_1X,                FALSE),
		),
	),
	SETTING_INFO (MACVLAN,
		.valid_parts = NM_META_SETTING_VALID_PARTS (
			NM_META_SETTING_VALID_PART_ITEM (CONNECTION,            TRUE),
			NM_META_SETTING_VALID_PART_ITEM (MACVLAN,               TRUE),
			NM_META_SETTING_VALID_PART_ITEM (WIRED,                 FALSE),
		),
	),
	SETTING_INFO (OLPC_MESH,
		.alias =                            "olpc-mesh",
		.valid_parts = NM_META_SETTING_VALID_PARTS (
			NM_META_SETTING_VALID_PART_ITEM (CONNECTION,            TRUE),
			NM_META_SETTING_VALID_PART_ITEM (OLPC_MESH,             TRUE),
		),
		.setting_init_fcn =             _setting_init_fcn_olpc_mesh,
	),
	SETTING_INFO (PPPOE,
		/* PPPoE is a base connection type from historical reasons.
		 * See libnm-core/nm-setting.c:_nm_setting_is_base_type()
		 */
		.valid_parts = NM_META_SETTING_VALID_PARTS (
			NM_META_SETTING_VALID_PART_ITEM (CONNECTION,            TRUE),
			NM_META_SETTING_VALID_PART_ITEM (PPPOE,                 TRUE),
			NM_META_SETTING_VALID_PART_ITEM (WIRED,                 TRUE),
			NM_META_SETTING_VALID_PART_ITEM (PPP,                   FALSE),
			NM_META_SETTING_VALID_PART_ITEM (802_1X,                FALSE),
		),
	),
	SETTING_INFO (PPP),
	SETTING_INFO (PROXY,
		.setting_init_fcn =             _setting_init_fcn_proxy,
	),
	SETTING_INFO (SERIAL),
	SETTING_INFO (TEAM,
		.valid_parts = NM_META_SETTING_VALID_PARTS (
			NM_META_SETTING_VALID_PART_ITEM (CONNECTION,            TRUE),
			NM_META_SETTING_VALID_PART_ITEM (TEAM,                  TRUE),
			NM_META_SETTING_VALID_PART_ITEM (WIRED,                 FALSE),
		),
	),
	SETTING_INFO (TEAM_PORT),
	SETTING_INFO (TUN,
		.valid_parts = NM_META_SETTING_VALID_PARTS (
			NM_META_SETTING_VALID_PART_ITEM (CONNECTION,            TRUE),
			NM_META_SETTING_VALID_PART_ITEM (TUN,                   TRUE),
			NM_META_SETTING_VALID_PART_ITEM (WIRED,                 FALSE),
		),
		.setting_init_fcn =             _setting_init_fcn_tun,
	),
	SETTING_INFO_EMPTY (USER),
	SETTING_INFO (VLAN,
		.valid_parts = NM_META_SETTING_VALID_PARTS (
			NM_META_SETTING_VALID_PART_ITEM (CONNECTION,            TRUE),
			NM_META_SETTING_VALID_PART_ITEM (VLAN,                  TRUE),
			NM_META_SETTING_VALID_PART_ITEM (WIRED,                 FALSE),
		),
		.setting_init_fcn =             _setting_init_fcn_vlan,
	),
	SETTING_INFO (VPN,
		.valid_parts = NM_META_SETTING_VALID_PARTS (
			NM_META_SETTING_VALID_PART_ITEM (CONNECTION,            TRUE),
			NM_META_SETTING_VALID_PART_ITEM (VPN,                   TRUE),
		),
	),
	SETTING_INFO (VXLAN,
		.valid_parts = NM_META_SETTING_VALID_PARTS (
			NM_META_SETTING_VALID_PART_ITEM (CONNECTION,            TRUE),
			NM_META_SETTING_VALID_PART_ITEM (VXLAN,                 TRUE),
			NM_META_SETTING_VALID_PART_ITEM (WIRED,                 FALSE),
		),
	),
	SETTING_INFO (WIMAX,
		.valid_parts = NM_META_SETTING_VALID_PARTS (
			NM_META_SETTING_VALID_PART_ITEM (CONNECTION,            TRUE),
			NM_META_SETTING_VALID_PART_ITEM (WIMAX,                 TRUE),
		),
	),
	SETTING_INFO (WIRED,
		.alias =                            "ethernet",
		.valid_parts = NM_META_SETTING_VALID_PARTS (
			NM_META_SETTING_VALID_PART_ITEM (CONNECTION,            TRUE),
			NM_META_SETTING_VALID_PART_ITEM (WIRED,                 TRUE),
			NM_META_SETTING_VALID_PART_ITEM (802_1X,                FALSE),
			NM_META_SETTING_VALID_PART_ITEM (DCB,                   FALSE),
		),
	),
	SETTING_INFO (WIRELESS,
		.alias =                            "wifi",
		.valid_parts = NM_META_SETTING_VALID_PARTS (
			NM_META_SETTING_VALID_PART_ITEM (CONNECTION,            TRUE),
			NM_META_SETTING_VALID_PART_ITEM (WIRELESS,              TRUE),
			NM_META_SETTING_VALID_PART_ITEM (WIRELESS_SECURITY,     FALSE),
			NM_META_SETTING_VALID_PART_ITEM (802_1X,                FALSE),
		),
		.setting_init_fcn =             _setting_init_fcn_wireless,
	),
	SETTING_INFO (WIRELESS_SECURITY,
		.alias =                            "wifi-sec",
	),
};

/*****************************************************************************/

const NMMetaSettingValidPartItem *const nm_meta_setting_info_valid_parts_default[] = {
	NM_META_SETTING_VALID_PART_ITEM (CONNECTION, TRUE),
	NULL
};

/*****************************************************************************/

static const NMMetaSettingValidPartItem *const valid_settings_noslave[] = {
	NM_META_SETTING_VALID_PART_ITEM (IP4_CONFIG, FALSE),
	NM_META_SETTING_VALID_PART_ITEM (IP6_CONFIG, FALSE),
	NM_META_SETTING_VALID_PART_ITEM (PROXY,      FALSE),
	NULL,
};

static const NMMetaSettingValidPartItem *const valid_settings_slave_bridge[] = {
	NM_META_SETTING_VALID_PART_ITEM (BRIDGE_PORT, TRUE),
	NULL,
};

static const NMMetaSettingValidPartItem *const valid_settings_slave_team[] = {
	NM_META_SETTING_VALID_PART_ITEM (TEAM_PORT, TRUE),
	NULL,
};

const NMMetaSettingValidPartItem *const*
nm_meta_setting_info_valid_parts_for_slave_type (const char *slave_type, const char **out_slave_name)
{
	if (!slave_type) {
		NM_SET_OUT (out_slave_name, NULL);
		return valid_settings_noslave;
	}
	if (nm_streq (slave_type, NM_SETTING_BOND_SETTING_NAME)) {
		NM_SET_OUT (out_slave_name, "bond-slave");
		return NM_PTRARRAY_EMPTY (const NMMetaSettingValidPartItem *);
	}
	if (nm_streq (slave_type, NM_SETTING_BRIDGE_SETTING_NAME)) {
		NM_SET_OUT (out_slave_name, "bridge-slave");
		return valid_settings_slave_bridge;
	}
	if (nm_streq (slave_type, NM_SETTING_TEAM_SETTING_NAME)) {
		NM_SET_OUT (out_slave_name, "team-slave");
		return valid_settings_slave_team;
	}
	return NULL;
}

/*****************************************************************************/

static const char *
_meta_type_setting_info_editor_get_name (const NMMetaAbstractInfo *abstract_info, gboolean for_header)
{
	if (for_header)
		return N_("name");
	return ((const NMMetaSettingInfoEditor *) abstract_info)->general->setting_name;
}

static const char *
_meta_type_property_info_get_name (const NMMetaAbstractInfo *abstract_info, gboolean for_header)
{
	return ((const NMMetaPropertyInfo *) abstract_info)->property_name;
}

static gconstpointer
_meta_type_setting_info_editor_get_fcn (const NMMetaAbstractInfo *abstract_info,
                                        const NMMetaEnvironment *environment,
                                        gpointer environment_user_data,
                                        gpointer target,
                                        NMMetaAccessorGetType get_type,
                                        NMMetaAccessorGetFlags get_flags,
                                        NMMetaAccessorGetOutFlags *out_flags,
                                        gpointer *out_to_free)
{
	const NMMetaSettingInfoEditor *info = (const NMMetaSettingInfoEditor *) abstract_info;

	nm_assert (!out_to_free || !*out_to_free);
	nm_assert (out_flags && !*out_flags);

	if (!NM_IN_SET (get_type,
	                NM_META_ACCESSOR_GET_TYPE_PARSABLE,
	                NM_META_ACCESSOR_GET_TYPE_PRETTY))
		return NULL;

	nm_assert (out_to_free);

	return info->general->setting_name;
}

static gconstpointer
_meta_type_property_info_get_fcn (const NMMetaAbstractInfo *abstract_info,
                                  const NMMetaEnvironment *environment,
                                  gpointer environment_user_data,
                                  gpointer target,
                                  NMMetaAccessorGetType get_type,
                                  NMMetaAccessorGetFlags get_flags,
                                  NMMetaAccessorGetOutFlags *out_flags,
                                  gpointer *out_to_free)
{
	const NMMetaPropertyInfo *info = (const NMMetaPropertyInfo *) abstract_info;

	nm_assert (!out_to_free || !*out_to_free);
	nm_assert (out_flags && !*out_flags);

	if (!NM_IN_SET (get_type,
	                NM_META_ACCESSOR_GET_TYPE_PARSABLE,
	                NM_META_ACCESSOR_GET_TYPE_PRETTY))
		return NULL;

	nm_assert (out_to_free);

	if (   info->is_secret
	    && !NM_FLAGS_HAS (get_flags, NM_META_ACCESSOR_GET_FLAGS_SHOW_SECRETS))
		return _get_text_hidden (get_type);

	return info->property_type->get_fcn (info,
	                                     environment,
	                                     environment_user_data,
	                                     target,
	                                     get_type,
	                                     get_flags,
	                                     out_flags,
	                                     out_to_free);

}

static const NMMetaAbstractInfo *const*
_meta_type_setting_info_editor_get_nested (const NMMetaAbstractInfo *abstract_info,
                                           guint *out_len,
                                           gpointer *out_to_free)
{
	const NMMetaSettingInfoEditor *info;

	info = (const NMMetaSettingInfoEditor *) abstract_info;

	NM_SET_OUT (out_len, info->properties_num);
	*out_to_free = NULL;
	return (const NMMetaAbstractInfo *const*) info->properties;
}

static const NMMetaAbstractInfo *const*
_meta_type_property_info_get_nested (const NMMetaAbstractInfo *abstract_info,
                                     guint *out_len,
                                     gpointer *out_to_free)
{
	NM_SET_OUT (out_len, 0);
	*out_to_free = NULL;
	return NULL;
}

static const char *const*
_meta_type_property_info_complete_fcn (const NMMetaAbstractInfo *abstract_info,
                                       const NMMetaEnvironment *environment,
                                       gpointer environment_user_data,
                                       const NMMetaOperationContext *operation_context,
                                       const char *text,
                                       char ***out_to_free)
{
	const NMMetaPropertyInfo *info = (const NMMetaPropertyInfo *) abstract_info;

	nm_assert (out_to_free && !*out_to_free);

	if (info->property_type->complete_fcn) {
		return info->property_type->complete_fcn (info,
		                                          environment,
		                                          environment_user_data,
		                                          operation_context,
		                                          text,
		                                          out_to_free);
	}

	if (info->property_type->values_fcn) {
		return info->property_type->values_fcn (info,
		                                        out_to_free);
	}

	if (   info->property_typ_data
	    && info->property_typ_data->values_static)
		return info->property_typ_data->values_static;

	return NULL;
}

const NMMetaType nm_meta_type_setting_info_editor = {
	.type_name =         "setting_info_editor",
	.get_name =          _meta_type_setting_info_editor_get_name,
	.get_nested =        _meta_type_setting_info_editor_get_nested,
	.get_fcn =           _meta_type_setting_info_editor_get_fcn,
};

const NMMetaType nm_meta_type_property_info = {
	.type_name =        "property_info",
	.get_name =         _meta_type_property_info_get_name,
	.get_nested =       _meta_type_property_info_get_nested,
	.get_fcn =          _meta_type_property_info_get_fcn,
	.complete_fcn =     _meta_type_property_info_complete_fcn,
};

const NMMetaType nm_meta_type_nested_property_info = {
	.type_name =        "nested_property_info",
};
