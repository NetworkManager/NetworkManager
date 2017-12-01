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
 * Copyright 2010 - 2015 Red Hat, Inc.
 */

#include "nm-default.h"

#include "settings.h"

#include <stdlib.h>
#include <arpa/inet.h>

#include "nm-common-macros.h"

#include "nm-client-utils.h"
#include "nm-vpn-helpers.h"
#include "nm-meta-setting-access.h"

#include "utils.h"
#include "common.h"

/*****************************************************************************/

static gboolean
get_answer (const char *prop, const char *value)
{
	char *tmp_str;
	char *question;
	gboolean answer = FALSE;

	if (value)
		question = g_strdup_printf (_("Do you also want to set '%s' to '%s'? [yes]: "), prop, value);
	else
		question = g_strdup_printf (_("Do you also want to clear '%s'? [yes]: "), prop);
	tmp_str = nmc_get_user_input (question);
	if (!tmp_str || matches (tmp_str, "yes"))
		answer = TRUE;
	g_free (tmp_str);
	g_free (question);
	return answer;
}

static void ipv4_method_changed_cb (GObject *object, GParamSpec *pspec, gpointer user_data);
static void ipv6_method_changed_cb (GObject *object, GParamSpec *pspec, gpointer user_data);

static void
ipv4_addresses_changed_cb (GObject *object, GParamSpec *pspec, gpointer user_data)
{
	static gboolean answered = FALSE;
	static gboolean answer = FALSE;

	g_signal_handlers_block_by_func (object, G_CALLBACK (ipv4_method_changed_cb), NULL);

	/* If we have some IP addresses set method to 'manual'.
	 * Else if the method was 'manual', change it back to 'auto'.
	 */
	if (nm_setting_ip_config_get_num_addresses (NM_SETTING_IP_CONFIG (object))) {
		if (g_strcmp0 (nm_setting_ip_config_get_method (NM_SETTING_IP_CONFIG (object)), NM_SETTING_IP4_CONFIG_METHOD_MANUAL)) {
			if (!answered) {
				answered = TRUE;
				answer = get_answer ("ipv4.method", "manual");
			}
			if (answer)
				g_object_set (object, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL, NULL);
		}
	} else {
		answered = FALSE;
		if (!g_strcmp0 (nm_setting_ip_config_get_method (NM_SETTING_IP_CONFIG (object)), NM_SETTING_IP4_CONFIG_METHOD_MANUAL))
			g_object_set (object, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);
	}

	g_signal_handlers_unblock_by_func (object, G_CALLBACK (ipv4_method_changed_cb), NULL);
}

static void
ipv4_method_changed_cb (GObject *object, GParamSpec *pspec, gpointer user_data)
{
	static GValue value = G_VALUE_INIT;
	static gboolean answered = FALSE;
	static gboolean answer = FALSE;

	g_signal_handlers_block_by_func (object, G_CALLBACK (ipv4_addresses_changed_cb), NULL);

	/* If method != manual, remove addresses (save them for restoring them later when method becomes 'manual' */
	if (g_strcmp0 (nm_setting_ip_config_get_method (NM_SETTING_IP_CONFIG (object)), NM_SETTING_IP4_CONFIG_METHOD_MANUAL)) {
		if (nm_setting_ip_config_get_num_addresses (NM_SETTING_IP_CONFIG (object))) {
			if (!answered) {
				answered = TRUE;
				answer = get_answer ("ipv4.addresses", NULL);
			}
			if (answer) {
				if (G_IS_VALUE (&value))
					g_value_unset (&value);
				nmc_property_get_gvalue (NM_SETTING (object), NM_SETTING_IP_CONFIG_ADDRESSES, &value);
				g_object_set (object, NM_SETTING_IP_CONFIG_ADDRESSES, NULL, NULL);
			}
		}
	} else {
		answered = FALSE;
		if (G_IS_VALUE (&value)) {
			nmc_property_set_gvalue (NM_SETTING (object), NM_SETTING_IP_CONFIG_ADDRESSES, &value);
			g_value_unset (&value);
		}
	}

	g_signal_handlers_unblock_by_func (object, G_CALLBACK (ipv4_addresses_changed_cb), NULL);
}

static void
ipv6_addresses_changed_cb (GObject *object, GParamSpec *pspec, gpointer user_data)
{
	static gboolean answered = FALSE;
	static gboolean answer = FALSE;

	g_signal_handlers_block_by_func (object, G_CALLBACK (ipv6_method_changed_cb), NULL);

	/* If we have some IP addresses set method to 'manual'.
	 * Else if the method was 'manual', change it back to 'auto'.
	 */
	if (nm_setting_ip_config_get_num_addresses (NM_SETTING_IP_CONFIG (object))) {
		if (g_strcmp0 (nm_setting_ip_config_get_method (NM_SETTING_IP_CONFIG (object)), NM_SETTING_IP6_CONFIG_METHOD_MANUAL)) {
			if (!answered) {
				answered = TRUE;
				answer = get_answer ("ipv6.method", "manual");
			}
			if (answer)
				g_object_set (object, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_MANUAL, NULL);
		}
	} else {
		answered = FALSE;
		if (!g_strcmp0 (nm_setting_ip_config_get_method (NM_SETTING_IP_CONFIG (object)), NM_SETTING_IP6_CONFIG_METHOD_MANUAL))
			g_object_set (object, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO, NULL);
	}

	g_signal_handlers_unblock_by_func (object, G_CALLBACK (ipv6_method_changed_cb), NULL);
}

static void
ipv6_method_changed_cb (GObject *object, GParamSpec *pspec, gpointer user_data)
{
	static GValue value = G_VALUE_INIT;
	static gboolean answered = FALSE;
	static gboolean answer = FALSE;

	g_signal_handlers_block_by_func (object, G_CALLBACK (ipv6_addresses_changed_cb), NULL);

	/* If method != manual, remove addresses (save them for restoring them later when method becomes 'manual' */
	if (g_strcmp0 (nm_setting_ip_config_get_method (NM_SETTING_IP_CONFIG (object)), NM_SETTING_IP6_CONFIG_METHOD_MANUAL)) {
		if (nm_setting_ip_config_get_num_addresses (NM_SETTING_IP_CONFIG (object))) {
			if (!answered) {
				answered = TRUE;
				answer = get_answer ("ipv6.addresses", NULL);
			}
			if (answer) {
				if (G_IS_VALUE (&value))
					g_value_unset (&value);
				nmc_property_get_gvalue (NM_SETTING (object), NM_SETTING_IP_CONFIG_ADDRESSES, &value);
				g_object_set (object, NM_SETTING_IP_CONFIG_ADDRESSES, NULL, NULL);
			}
		}
	} else {
		answered = FALSE;
		if (G_IS_VALUE (&value)) {
			nmc_property_set_gvalue (NM_SETTING (object), NM_SETTING_IP_CONFIG_ADDRESSES, &value);
			g_value_unset (&value);
		}
	}

	g_signal_handlers_unblock_by_func (object, G_CALLBACK (ipv6_addresses_changed_cb), NULL);
}

static void
proxy_method_changed_cb (GObject *object, GParamSpec *pspec, gpointer user_data)
{
	NMSettingProxyMethod method;

	method = nm_setting_proxy_get_method (NM_SETTING_PROXY (object));

	if (method == NM_SETTING_PROXY_METHOD_NONE) {
		g_object_set (object,
		              NM_SETTING_PROXY_PAC_URL, NULL,
		              NM_SETTING_PROXY_PAC_SCRIPT, NULL,
		              NULL);
	}
}

static void
wireless_band_channel_changed_cb (GObject *object, GParamSpec *pspec, gpointer user_data)
{
	const char *value = NULL, *mode;
	char str[16];
	NMSettingWireless *s_wireless = NM_SETTING_WIRELESS (object);

	if (strcmp (g_param_spec_get_name (pspec), NM_SETTING_WIRELESS_BAND) == 0) {
		value = nm_setting_wireless_get_band (s_wireless);
		if (!value)
			return;
	} else {
		guint32 channel = nm_setting_wireless_get_channel (s_wireless);

		if (channel == 0)
			return;

		g_snprintf (str, sizeof (str), "%d", nm_setting_wireless_get_channel (s_wireless));
		value = str;
	}

	mode = nm_setting_wireless_get_mode (NM_SETTING_WIRELESS (object));
	if (!mode || !*mode || strcmp (mode, NM_SETTING_WIRELESS_MODE_INFRA) == 0) {
		g_print (_("Warning: %s.%s set to '%s', but it might be ignored in infrastructure mode\n"),
		         nm_setting_get_name (NM_SETTING (s_wireless)), g_param_spec_get_name (pspec),
		         value);
	}
}

static void
connection_master_changed_cb (GObject *object, GParamSpec *pspec, gpointer user_data)
{
	NMSettingConnection *s_con = NM_SETTING_CONNECTION (object);
	NMConnection *connection = NM_CONNECTION (user_data);
	NMSetting *s_ipv4, *s_ipv6;
	const char *value, *tmp_str;

	value = nm_setting_connection_get_master (s_con);
	if (value) {
		s_ipv4 = nm_connection_get_setting_by_name (connection, NM_SETTING_IP4_CONFIG_SETTING_NAME);
		s_ipv6 = nm_connection_get_setting_by_name (connection, NM_SETTING_IP6_CONFIG_SETTING_NAME);
		if (s_ipv4 || s_ipv6) {
			g_print (_("Warning: setting %s.%s requires removing ipv4 and ipv6 settings\n"),
			         nm_setting_get_name (NM_SETTING (s_con)), g_param_spec_get_name (pspec));
			tmp_str = nmc_get_user_input (_("Do you want to remove them? [yes] "));
			if (!tmp_str || matches (tmp_str, "yes")) {
				if (s_ipv4)
					nm_connection_remove_setting (connection, G_OBJECT_TYPE (s_ipv4));
				if (s_ipv6)
					nm_connection_remove_setting (connection, G_OBJECT_TYPE (s_ipv6));
			}
		}
	}
}

void
nmc_setting_ip4_connect_handlers (NMSettingIPConfig *setting)
{
	g_return_if_fail (NM_IS_SETTING_IP4_CONFIG (setting));

	g_signal_connect (setting, "notify::" NM_SETTING_IP_CONFIG_ADDRESSES,
	                  G_CALLBACK (ipv4_addresses_changed_cb), NULL);
	g_signal_connect (setting, "notify::" NM_SETTING_IP_CONFIG_METHOD,
	                  G_CALLBACK (ipv4_method_changed_cb), NULL);
}

void
nmc_setting_ip6_connect_handlers (NMSettingIPConfig *setting)
{
	g_return_if_fail (NM_IS_SETTING_IP6_CONFIG (setting));

	g_signal_connect (setting, "notify::" NM_SETTING_IP_CONFIG_ADDRESSES,
	                  G_CALLBACK (ipv6_addresses_changed_cb), NULL);
	g_signal_connect (setting, "notify::" NM_SETTING_IP_CONFIG_METHOD,
	                  G_CALLBACK (ipv6_method_changed_cb), NULL);
}

void
nmc_setting_proxy_connect_handlers (NMSettingProxy *setting)
{
	g_return_if_fail (NM_IS_SETTING_PROXY (setting));

	g_signal_connect (setting, "notify::" NM_SETTING_PROXY_METHOD,
	                  G_CALLBACK (proxy_method_changed_cb), NULL);
}

void
nmc_setting_wireless_connect_handlers (NMSettingWireless *setting)
{
	g_return_if_fail (NM_IS_SETTING_WIRELESS (setting));

	g_signal_connect (setting, "notify::" NM_SETTING_WIRELESS_BAND,
	                  G_CALLBACK (wireless_band_channel_changed_cb), NULL);
	g_signal_connect (setting, "notify::" NM_SETTING_WIRELESS_CHANNEL,
	                  G_CALLBACK (wireless_band_channel_changed_cb), NULL);
}

void
nmc_setting_connection_connect_handlers (NMSettingConnection *setting, NMConnection *connection)
{
	g_return_if_fail (NM_IS_SETTING_CONNECTION (setting));

	g_signal_connect (setting, "notify::" NM_SETTING_CONNECTION_MASTER,
	                  G_CALLBACK (connection_master_changed_cb), connection);
}

/*****************************************************************************/

static gboolean
_set_fcn_precheck_connection_secondaries (const char *value,
                                          char **value_coerced,
                                          GError **error)
{
	const GPtrArray *connections;
	NMConnection *con;
	gs_strfreev char **strv = NULL;
	char **iter;
	gboolean modified;

	strv = nmc_strsplit_set (value, " \t,", 0);
	if (!strv)
		return TRUE;

	connections = nm_client_get_connections (nm_cli.client);

	for (iter = strv; *iter; iter++) {
		if (nm_utils_is_uuid (*iter)) {
			con = nmc_find_connection (connections, "uuid", *iter, NULL, FALSE);
			if (!con){
				g_print (_("Warning: %s is not an UUID of any existing connection profile\n"),
				         *iter);
			} else {
				/* Currenly NM only supports VPN connections as secondaries */
				if (!nm_connection_is_type (con, NM_SETTING_VPN_SETTING_NAME)) {
					g_set_error (error, 1, 0, _("'%s' is not a VPN connection profile"), *iter);
					return FALSE;
				}
			}
		} else {
			con = nmc_find_connection (connections, "id", *iter, NULL, FALSE);
			if (!con) {
				g_set_error (error, 1, 0, _("'%s' is not a name of any exiting profile"), *iter);
				return FALSE;
			}

			/* Currenly NM only supports VPN connections as secondaries */
			if (!nm_connection_is_type (con, NM_SETTING_VPN_SETTING_NAME)) {
				g_set_error (error, 1, 0, _("'%s' is not a VPN connection profile"), *iter);
				return FALSE;
			}

			/* translate id to uuid */
			g_free (*iter);
			*iter = g_strdup (nm_connection_get_uuid (con));
			modified = TRUE;
		}
	}

	if (modified)
		*value_coerced = g_strjoinv (" ", strv);

	return TRUE;
}

/*****************************************************************************/

static void
_env_warn_fcn_handle (const NMMetaEnvironment *environment,
                      gpointer environment_user_data,
                      NMMetaEnvWarnLevel warn_level,
                      const char *fmt_l10n, /* the untranslated format string, but it is marked for translation using N_(). */
                      va_list ap)
{
	NmCli *nmc = environment_user_data;
	gs_free char *m = NULL;

	if (nmc->complete)
		return;

	NM_PRAGMA_WARNING_DISABLE("-Wformat-nonliteral")
	m = g_strdup_vprintf (_(fmt_l10n), ap);
	NM_PRAGMA_WARNING_REENABLE

	switch (warn_level) {
	case NM_META_ENV_WARN_LEVEL_WARN:
		g_print (_("Warning: %s\n"), m);
		return;
	case NM_META_ENV_WARN_LEVEL_INFO:
		g_print (_("Info: %s\n"), m);
		return;
	}
	g_print (_("Error: %s\n"), m);
}

static NMDevice *const*
_env_get_nm_devices (const NMMetaEnvironment *environment,
                     gpointer environment_user_data,
                     guint *out_len)
{
	NmCli *nmc = environment_user_data;
	const GPtrArray *devices;

	nm_assert (nmc);

	/* the returned list is *not* NULL terminated. Need to
	 * provide and honor the out_len argument. */
	nm_assert (out_len);

	devices = nm_client_get_devices (nmc->client);
	if (!devices) {
		*out_len = 0;
		return NULL;
	}

	*out_len = devices->len;
	return (NMDevice *const*) devices->pdata;
}

static NMRemoteConnection *const*
_env_get_nm_connections (const NMMetaEnvironment *environment,
                         gpointer environment_user_data,
                         guint *out_len)
{
	NmCli *nmc = environment_user_data;
	const GPtrArray *values;

	nm_assert (nmc);

	/* the returned list is *not* NULL terminated. Need to
	 * provide and honor the out_len argument. */
	nm_assert (out_len);

	values = nm_client_get_connections (nmc->client);
	if (!values) {
		*out_len = 0;
		return NULL;
	}

	*out_len = values->len;
	return (NMRemoteConnection *const*) values->pdata;
}

/*****************************************************************************/

const NMMetaEnvironment *const nmc_meta_environment = &((NMMetaEnvironment) {
	.warn_fcn = _env_warn_fcn_handle,
	.get_nm_devices = _env_get_nm_devices,
	.get_nm_connections = _env_get_nm_connections,
});

NmCli *const nmc_meta_environment_arg = &nm_cli;

static char *
get_property_val (NMSetting *setting, const char *prop, NMMetaAccessorGetType get_type, gboolean show_secrets, GError **error)
{
	const NMMetaPropertyInfo *property_info;

	g_return_val_if_fail (NM_IS_SETTING (setting), NULL);
	g_return_val_if_fail (!error || !*error, NULL);
	g_return_val_if_fail (NM_IN_SET (get_type, NM_META_ACCESSOR_GET_TYPE_PARSABLE, NM_META_ACCESSOR_GET_TYPE_PRETTY), NULL);

	if ((property_info = nm_meta_property_info_find_by_setting (setting, prop))) {
		if (property_info->property_type->get_fcn) {
			NMMetaAccessorGetOutFlags out_flags = NM_META_ACCESSOR_GET_OUT_FLAGS_NONE;
			char *to_free = NULL;
			const char *value;

			value = property_info->property_type->get_fcn (property_info,
			                                               nmc_meta_environment,
			                                               nmc_meta_environment_arg,
			                                               setting,
			                                               get_type,
			                                               show_secrets ? NM_META_ACCESSOR_GET_FLAGS_SHOW_SECRETS : 0,
			                                               &out_flags,
			                                               (gpointer *) &to_free);
			nm_assert (!out_flags);
			return to_free ?: g_strdup (value);
		}
	}

	g_set_error_literal (error, 1, 0, _("don't know how to get the property value"));
	return NULL;
}

/*
 * Generic function for getting property value.
 *
 * Gets property value as a string by calling specialized functions.
 *
 * Returns: current property value. The caller must free the returned string.
 */
char *
nmc_setting_get_property (NMSetting *setting, const char *prop, GError **error)
{
	return get_property_val (setting, prop, NM_META_ACCESSOR_GET_TYPE_PRETTY, TRUE, error);
}

/*
 * Similar to nmc_setting_get_property(), but returns the property in a string
 * format that can be parsed via nmc_setting_set_property().
 */
char *
nmc_setting_get_property_parsable (NMSetting *setting, const char *prop, GError **error)
{
	return get_property_val (setting, prop, NM_META_ACCESSOR_GET_TYPE_PARSABLE, TRUE, error);
}

static gboolean
_set_fcn_call (const NMMetaPropertyInfo *property_info,
               NMSetting *setting,
               const char *value,
               GError **error)
{
	return property_info->property_type->set_fcn (property_info,
	                                              nmc_meta_environment,
	                                              nmc_meta_environment_arg,
	                                              setting,
	                                              value,
	                                              error);
}

/*
 * Generic function for setting property value.
 *
 * Sets property=value in setting by calling specialized functions.
 * If value is NULL then default property value is set.
 *
 * Returns: TRUE on success; FALSE on failure and sets error
 */
gboolean
nmc_setting_set_property (NMSetting *setting, const char *prop, const char *value, GError **error)
{
	const NMMetaPropertyInfo *property_info;

	g_return_val_if_fail (NM_IS_SETTING (setting), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if ((property_info = nm_meta_property_info_find_by_setting (setting, prop))) {

		if (!value) {
			/* No value argument sets default value */
			nmc_property_set_default_value (setting, prop);
			return TRUE;
		}

		if (property_info->property_type->set_fcn) {
			switch (property_info->setting_info->general->meta_type) {
			case NM_META_SETTING_TYPE_CONNECTION:
				if (nm_streq (property_info->property_name, NM_SETTING_CONNECTION_SECONDARIES)) {
					gs_free char *value_coerced = NULL;

					if (!_set_fcn_precheck_connection_secondaries (value, &value_coerced, error))
						return FALSE;

					return _set_fcn_call (property_info,
					                      setting,
					                      value_coerced ?: value,
					                      error);
				}
				break;
			default:
				break;
			}
			return _set_fcn_call (property_info,
			                      setting,
			                      value,
			                      error);
		}
	}

	g_set_error_literal (error, 1, 0, _("the property can't be changed"));
	return FALSE;
}

void
nmc_property_set_default_value (NMSetting *setting, const char *prop)
{
	GValue value = G_VALUE_INIT;
	GParamSpec *param_spec;

	param_spec = g_object_class_find_property (G_OBJECT_GET_CLASS (G_OBJECT (setting)), prop);
	if (param_spec) {
		g_value_init (&value, G_PARAM_SPEC_VALUE_TYPE (param_spec));
		g_param_value_set_default (param_spec, &value);
		g_object_set_property (G_OBJECT (setting), prop, &value);
	}
}

/*
 * Generic function for reseting (single value) properties.
 *
 * The function resets the property value to the default one. It respects
 * nmcli restrictions for changing properties. So if 'set_func' is NULL,
 * reseting the value is denied.
 *
 * Returns: TRUE on success; FALSE on failure and sets error
 */
gboolean
nmc_setting_reset_property (NMSetting *setting, const char *prop, GError **error)
{
	const NMMetaPropertyInfo *property_info;

	g_return_val_if_fail (NM_IS_SETTING (setting), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if ((property_info = nm_meta_property_info_find_by_setting (setting, prop))) {
		if (property_info->property_type->set_fcn) {
			nmc_property_set_default_value (setting, prop);
			return TRUE;
		}
	}

	g_set_error_literal (error, 1, 0, _("the property can't be changed"));
	return FALSE;
}

/*
 * Generic function for removing items for collection-type properties.
 *
 * If 'option' is not NULL, it tries to remove it, otherwise 'idx' is used.
 * For single-value properties (not having specialized remove function) this
 * function does nothing and just returns TRUE.
 *
 * Returns: TRUE on success; FALSE on failure and sets error
 */
gboolean
nmc_setting_remove_property_option (NMSetting *setting,
                                    const char *prop,
                                    const char *option,
                                    guint32 idx,
                                    GError **error)
{
	const NMMetaPropertyInfo *property_info;

	g_return_val_if_fail (NM_IS_SETTING (setting), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if ((property_info = nm_meta_property_info_find_by_setting (setting, prop))) {
		if (property_info->property_type->remove_fcn) {
			return property_info->property_type->remove_fcn (property_info,
			                                                 nmc_meta_environment,
			                                                 nmc_meta_environment_arg,
			                                                 setting,
			                                                 option,
			                                                 idx,
			                                                 error);
		}
	}

	return TRUE;
}

/*
 * Get valid property names for a setting.
 *
 * Returns: string array with the properties or NULL on failure.
 *          The returned value should be freed with g_strfreev()
 */
char **
nmc_setting_get_valid_properties (NMSetting *setting)
{
	char **valid_props = NULL;
	GParamSpec **props, **iter;
	guint num;
	int i;

	/* Iterate through properties */
	i = 0;
	props = g_object_class_list_properties (G_OBJECT_GET_CLASS (G_OBJECT (setting)), &num);
	valid_props = g_malloc0 (sizeof (char*) * (num + 1));
	for (iter = props; iter && *iter; iter++) {
		const char *key_name = g_param_spec_get_name (*iter);

		/* Add all properties except for "name" that is non-editable */
		if (g_strcmp0 (key_name, "name") != 0)
			valid_props[i++] = g_strdup (key_name);
	}
	valid_props[i] = NULL;
	g_free (props);

	return valid_props;
}

const char *const*
nmc_setting_get_property_allowed_values (NMSetting *setting, const char *prop, char ***out_to_free)
{
	const NMMetaPropertyInfo *property_info;

	g_return_val_if_fail (NM_IS_SETTING (setting), FALSE);
	g_return_val_if_fail (out_to_free, FALSE);

	*out_to_free = NULL;

	if ((property_info = nm_meta_property_info_find_by_setting (setting, prop))) {
		if (property_info->property_type->values_fcn) {
			return property_info->property_type->values_fcn (property_info,
			                                                 out_to_free);
		} else if (property_info->property_typ_data && property_info->property_typ_data->values_static)
			return property_info->property_typ_data->values_static;
	}

	return NULL;
}

/*
 * Create a description string for a property.
 *
 * It returns a description got from property documentation, concatenated with
 * nmcli specific description (if it exists).
 *
 * Returns: property description or NULL on failure. The caller must free the string.
 */
char *
nmc_setting_get_property_desc (NMSetting *setting, const char *prop)
{
	gs_free char *desc_to_free = NULL;
	const char *setting_desc = NULL;
	const char *setting_desc_title = "";
	const char *nmcli_desc = NULL;
	const char *nmcli_desc_title = "";
	const char *nmcli_nl = "";
	const NMMetaPropertyInfo *property_info;
	const char *desc = NULL;

	g_return_val_if_fail (NM_IS_SETTING (setting), FALSE);

	property_info = nm_meta_property_info_find_by_setting (setting, prop);
	if (!property_info)
		return NULL;

	if (property_info->describe_doc) {
		setting_desc = _(property_info->describe_doc);
		setting_desc_title = _("[NM property description]");
	}

	if (property_info->property_type->describe_fcn) {
		desc = property_info->property_type->describe_fcn (property_info, &desc_to_free);
	} else
		desc = _(property_info->describe_message);

	if (desc) {
		nmcli_desc = desc;
		nmcli_desc_title = _("[nmcli specific description]");
		nmcli_nl = "\n";
	}

	return g_strdup_printf ("%s\n%s\n%s%s%s%s",
	                        setting_desc_title,
	                        setting_desc ? setting_desc : "",
	                        nmcli_nl, nmcli_desc_title, nmcli_nl,
	                        nmcli_desc ? nmcli_desc : "");
}

/*
 * Gets setting:prop property value and returns it in 'value'.
 * Caller is responsible for freeing the GValue resources using g_value_unset()
 */
gboolean
nmc_property_get_gvalue (NMSetting *setting, const char *prop, GValue *value)
{
	GParamSpec *param_spec;

	param_spec = g_object_class_find_property (G_OBJECT_GET_CLASS (G_OBJECT (setting)), prop);
	if (param_spec) {
		memset (value, 0, sizeof (GValue));
		g_value_init (value, G_PARAM_SPEC_VALUE_TYPE (param_spec));
		g_object_get_property (G_OBJECT (setting), prop, value);
		return TRUE;
	}
	return FALSE;
}

/*
 * Sets setting:prop property value from 'value'.
 */
gboolean
nmc_property_set_gvalue (NMSetting *setting, const char *prop, GValue *value)
{
	GParamSpec *param_spec;

	param_spec = g_object_class_find_property (G_OBJECT_GET_CLASS (G_OBJECT (setting)), prop);
	if (param_spec && G_VALUE_TYPE (value) == G_PARAM_SPEC_VALUE_TYPE (param_spec)) {
		g_object_set_property (G_OBJECT (setting), prop, value);
		return TRUE;
	}
	return FALSE;
}

/*****************************************************************************/

gboolean
setting_details (const NmcConfig *nmc_config, NMSetting *setting, const char *one_prop)
{
	const NMMetaSettingInfoEditor *setting_info;
	gs_free_error GError *error = NULL;
	gs_free char *fields_str = NULL;

	g_return_val_if_fail (NM_IS_SETTING (setting), FALSE);

	setting_info = nm_meta_setting_info_editor_find_by_setting (setting);
	if (!setting_info)
		return FALSE;

	if (one_prop) {
		/* hack around setting-details being called for one setting. Must prefix the
		 * property name with the setting name. Later we should remove setting_details()
		 * and merge it into the caller. */
		fields_str = g_strdup_printf ("%s.%s", nm_setting_get_name (setting), one_prop);
	}

	if (!nmc_print (nmc_config,
	                (gpointer[]) { setting, NULL },
	                NULL,
	                (const NMMetaAbstractInfo *const[]) { (const NMMetaAbstractInfo *) setting_info, NULL },
	                fields_str,
	                &error))
		return FALSE;

	return TRUE;
}
