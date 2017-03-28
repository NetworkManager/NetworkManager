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
#include "utils.h"
#include "common.h"
#include "nm-vpn-helpers.h"

/*****************************************************************************/

static const NMMetaSettingInfoEditor *
_meta_find_setting_info_by_name (const char *setting_name)
{
	const NMMetaSettingInfo *meta_setting_info;
	const NMMetaSettingInfoEditor *setting_info;

	g_return_val_if_fail (setting_name, NULL);

	meta_setting_info = nm_meta_setting_infos_by_name (setting_name);

	if (!meta_setting_info)
		return NULL;

	g_return_val_if_fail (nm_streq0 (meta_setting_info->setting_name, setting_name), NULL);

	if (meta_setting_info->meta_type >= G_N_ELEMENTS (nm_meta_setting_infos_editor))
		return NULL;

	setting_info = &nm_meta_setting_infos_editor[meta_setting_info->meta_type];

	g_return_val_if_fail (setting_info->general == meta_setting_info, NULL);

	return setting_info;
}

static const NMMetaSettingInfoEditor *
_meta_find_setting_info_by_gtype (GType gtype)
{
	const NMMetaSettingInfo *meta_setting_info;
	const NMMetaSettingInfoEditor *setting_info;

	meta_setting_info = nm_meta_setting_infos_by_gtype (gtype);

	if (!meta_setting_info)
		return NULL;

	g_return_val_if_fail (meta_setting_info->get_setting_gtype, NULL);
	g_return_val_if_fail (meta_setting_info->get_setting_gtype () == gtype, NULL);

	if (meta_setting_info->meta_type >= G_N_ELEMENTS (nm_meta_setting_infos_editor))
		return NULL;

	setting_info = &nm_meta_setting_infos_editor[meta_setting_info->meta_type];

	g_return_val_if_fail (setting_info->general == meta_setting_info, NULL);

	return setting_info;
}

static const NMMetaSettingInfoEditor *
_meta_find_setting_info_by_setting (NMSetting *setting)
{
	const NMMetaSettingInfoEditor *setting_info;

	g_return_val_if_fail (NM_IS_SETTING (setting), NULL);

	setting_info = _meta_find_setting_info_by_gtype (G_OBJECT_TYPE (setting));

	if (!setting_info)
		return NULL;

	g_return_val_if_fail (setting_info == _meta_find_setting_info_by_name (nm_setting_get_name (setting)), NULL);

	return setting_info;
}

static const NMMetaPropertyInfo *
_meta_setting_info_find_property_info (const NMMetaSettingInfoEditor *setting_info, const char *property_name)
{
	guint i;

	g_return_val_if_fail (setting_info, NULL);
	g_return_val_if_fail (property_name, NULL);

	for (i = 0; i < setting_info->properties_num; i++) {
		if (nm_streq (setting_info->properties[i].property_name, property_name))
			return &setting_info->properties[i];
	}

	return NULL;
}

static const NMMetaPropertyInfo *
_meta_find_property_info_by_name (const char *setting_name, const char *property_name, const NMMetaSettingInfoEditor **out_setting_info)
{
	const NMMetaSettingInfoEditor *setting_info;

	setting_info = _meta_find_setting_info_by_name (setting_name);

	NM_SET_OUT (out_setting_info, setting_info);
	if (!setting_info)
		return NULL;
	return _meta_setting_info_find_property_info (setting_info, property_name);
}

static const NMMetaPropertyInfo *
_meta_find_property_info_by_setting (NMSetting *setting, const char *property_name, const NMMetaSettingInfoEditor **out_setting_info)
{
	const NMMetaSettingInfoEditor *setting_info;
	const NMMetaPropertyInfo *property_info;

	setting_info = _meta_find_setting_info_by_setting (setting);

	NM_SET_OUT (out_setting_info, setting_info);
	if (!setting_info)
		return NULL;
	property_info = _meta_setting_info_find_property_info (setting_info, property_name);

	nm_assert (property_info == _meta_find_property_info_by_name (nm_setting_get_name (setting), property_name, NULL));

	return property_info;
}

/*****************************************************************************/

static const NmcOutputField *
_get_nmc_output_fields (const NMMetaSettingInfoEditor *setting_info)
{
	static NmcOutputField *fields[_NM_META_SETTING_TYPE_NUM + 1] = { };
	NmcOutputField **field;
	guint i;

	g_return_val_if_fail (setting_info, NULL);
	g_return_val_if_fail (setting_info->general->meta_type < _NM_META_SETTING_TYPE_NUM, NULL);

	field = &fields[setting_info->general->meta_type];

	if (G_UNLIKELY (!*field)) {
		*field = g_new0 (NmcOutputField, setting_info->properties_num + 1);
		for (i = 0; i < setting_info->properties_num; i++) {
			NmcOutputField *f = &(*field)[i];

			f->name = setting_info->properties[i].property_name;
			f->name_l10n = setting_info->properties[i].property_name;
		}
	}

	return *field;
}

/*****************************************************************************/

NMSetting *
nmc_setting_new_for_name (const char *name)
{
	GType stype;
	NMSetting *setting = NULL;

	if (name) {
		stype = nm_setting_lookup_type (name);
		if (stype != G_TYPE_INVALID) {
			setting = g_object_new (stype, NULL);
			g_warn_if_fail (NM_IS_SETTING (setting));
		}
	}
	return setting;
}

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

/*
 * Customize some properties of the setting so that the setting has sensible
 * values.
 */
void
nmc_setting_custom_init (NMSetting *setting)
{
	g_return_if_fail (NM_IS_SETTING (setting));

	if (NM_IS_SETTING_VLAN (setting)) {
		/* Set sensible initial VLAN values */
		g_object_set (NM_SETTING_VLAN (setting),
		              NM_SETTING_VLAN_ID, 1,
		              NULL);
	} else if (NM_IS_SETTING_INFINIBAND (setting)) {
		/* Initialize 'transport-mode' so that 'infiniband' is valid */
		g_object_set (NM_SETTING_INFINIBAND (setting),
		              NM_SETTING_INFINIBAND_TRANSPORT_MODE, "datagram",
		              NULL);
	} else if (NM_IS_SETTING_CDMA (setting)) {
		/* Initialize 'number' so that 'cdma' is valid */
		g_object_set (NM_SETTING_CDMA (setting),
		              NM_SETTING_CDMA_NUMBER, "#777",
		              NULL);
	} else if (NM_IS_SETTING_GSM (setting)) {
		/* Initialize 'number' so that 'gsm' is valid */
		g_object_set (NM_SETTING_GSM (setting),
		              NM_SETTING_GSM_NUMBER, "*99#",
		              NULL);
	} else if (NM_IS_SETTING_OLPC_MESH (setting)) {
		g_object_set (NM_SETTING_OLPC_MESH (setting),
		              NM_SETTING_OLPC_MESH_CHANNEL, 1,
		              NULL);
	} else if (NM_IS_SETTING_WIRELESS (setting)) {
		/* For Wi-Fi set mode to "infrastructure". Even though mode == NULL
		 * is regarded as "infrastructure", explicit value makes no doubts.
		 */
		g_object_set (NM_SETTING_WIRELESS (setting),
		              NM_SETTING_WIRELESS_MODE, NM_SETTING_WIRELESS_MODE_INFRA,
		              NULL);
	} else if (NM_IS_SETTING_ADSL (setting)) {
		/* Initialize a protocol */
		g_object_set (NM_SETTING_ADSL (setting),
		              NM_SETTING_ADSL_PROTOCOL, NM_SETTING_ADSL_PROTOCOL_PPPOE,
		              NULL);
	} else if (NM_IS_SETTING_IP4_CONFIG (setting)) {
		g_object_set (NM_SETTING_IP_CONFIG (setting),
		              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
		              NULL);
	} else if (NM_IS_SETTING_IP6_CONFIG (setting)) {
		g_object_set (NM_SETTING_IP_CONFIG (setting),
		              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO,
		              NULL);
	} else if (NM_IS_SETTING_PROXY (setting)) {
		g_object_set (NM_SETTING_PROXY (setting),
		              NM_SETTING_PROXY_METHOD, (int) NM_SETTING_PROXY_METHOD_NONE,
		              NULL);
	} else if (NM_IS_SETTING_TUN (setting)) {
		g_object_set (NM_SETTING_TUN (setting),
		              NM_SETTING_TUN_MODE, NM_SETTING_TUN_MODE_TUN,
		              NULL);
	} else if (NM_IS_SETTING_BLUETOOTH (setting)) {
		g_object_set (NM_SETTING_BLUETOOTH (setting),
		              NM_SETTING_BLUETOOTH_TYPE, NM_SETTING_BLUETOOTH_TYPE_PANU,
		              NULL);
	}
}

/*****************************************************************************/

static char *
get_property_val (NMSetting *setting, const char *prop, NMMetaAccessorGetType get_type, gboolean show_secrets, GError **error)
{
	const NMMetaSettingInfoEditor *setting_info;
	const NMMetaPropertyInfo *property_info;

	g_return_val_if_fail (NM_IS_SETTING (setting), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if ((property_info = _meta_find_property_info_by_setting (setting, prop, &setting_info))) {
		if (property_info->is_name) {
			/* Traditionally, the "name" property was not handled here.
			 * For the moment, skip it from get_property_val(). */
		} else if (property_info->property_type->get_fcn) {
			return property_info->property_type->get_fcn (setting_info,
			                                              property_info,
			                                              setting,
			                                              get_type,
			                                              show_secrets);
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
	const NMMetaSettingInfoEditor *setting_info;
	const NMMetaPropertyInfo *property_info;

	g_return_val_if_fail (NM_IS_SETTING (setting), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if ((property_info = _meta_find_property_info_by_setting (setting, prop, &setting_info))) {

		if (!value) {
			/* No value argument sets default value */
			nmc_property_set_default_value (setting, prop);
			return TRUE;
		}

		if (property_info->is_name) {
			/* Traditionally, the "name" property was not handled here.
			 * For the moment, skip it from get_property_val(). */
		} else if (property_info->property_type->set_fcn) {
			return property_info->property_type->set_fcn (setting_info,
			                                              property_info,
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
	const NMMetaSettingInfoEditor *setting_info;
	const NMMetaPropertyInfo *property_info;

	g_return_val_if_fail (NM_IS_SETTING (setting), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if ((property_info = _meta_find_property_info_by_setting (setting, prop, &setting_info))) {
		if (property_info->is_name) {
			/* Traditionally, the "name" property was not handled here.
			 * For the moment, skip it from get_property_val(). */
		} else if (property_info->property_type->set_fcn) {
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
	const NMMetaSettingInfoEditor *setting_info;
	const NMMetaPropertyInfo *property_info;

	g_return_val_if_fail (NM_IS_SETTING (setting), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if ((property_info = _meta_find_property_info_by_setting (setting, prop, &setting_info))) {
		if (property_info->is_name) {
			/* Traditionally, the "name" property was not handled here.
			 * For the moment, skip it from get_property_val(). */
		} else if (property_info->property_type->remove_fcn) {
			return property_info->property_type->remove_fcn (setting_info,
			                                                 property_info,
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

	const NMMetaSettingInfoEditor *setting_info;
	const NMMetaPropertyInfo *property_info;

	g_return_val_if_fail (NM_IS_SETTING (setting), FALSE);
	g_return_val_if_fail (out_to_free, FALSE);

	*out_to_free = NULL;

	if ((property_info = _meta_find_property_info_by_setting (setting, prop, &setting_info))) {
		if (property_info->is_name) {
			/* Traditionally, the "name" property was not handled here.
			 * For the moment, skip it from get_property_val(). */
		} else if (property_info->property_type->values_fcn) {
			return property_info->property_type->values_fcn (setting_info,
			                                                 property_info,
			                                                 out_to_free);
		} else if (property_info->property_typ_data && property_info->property_typ_data->values_static)
			return property_info->property_typ_data->values_static;
	}

	return NULL;
}

#include "settings-docs.c"

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
	const NMMetaSettingInfoEditor *setting_info;
	const NMMetaPropertyInfo *property_info;

	g_return_val_if_fail (NM_IS_SETTING (setting), FALSE);

	setting_desc = nmc_setting_get_property_doc (setting, prop);
	if (setting_desc)
		setting_desc_title = _("[NM property description]");

	if ((property_info = _meta_find_property_info_by_setting (setting, prop, &setting_info))) {
		const char *desc = NULL;

		if (property_info->is_name) {
			/* Traditionally, the "name" property was not handled here.
			 * For the moment, skip it from get_property_val(). */
		} else if (property_info->property_type->describe_fcn) {
			desc = property_info->property_type->describe_fcn (setting_info, property_info, &desc_to_free);
		} else
			desc = property_info->describe_message;

		if (desc) {
			nmcli_desc = _(desc);
			nmcli_desc_title = _("[nmcli specific description]");
			nmcli_nl = "\n";
		}
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

static char *
_all_properties (const NMMetaSettingInfoEditor *setting_info)
{
	GString *str;
	guint i;

	str = g_string_sized_new (250);
	for (i = 0; i < setting_info->properties_num; i++) {
		if (str->len)
			g_string_append_c (str, ',');
		g_string_append (str, setting_info->properties[i].property_name);
	}
	return g_string_free (str, FALSE);
}

gboolean
setting_details (NMSetting *setting, NmCli *nmc, const char *one_prop, gboolean show_secrets)
{
	const NMMetaSettingInfo *meta_setting_info;
	const NMMetaSettingInfoEditor *setting_info;
	gs_free NmcOutputField *tmpl = NULL;
	NmcOutputField *arr;
	guint i;
	size_t tmpl_len;
	gs_free char *s_all = NULL;
	NMMetaAccessorGetType type = NM_META_ACCESSOR_GET_TYPE_PRETTY;

	g_return_val_if_fail (NM_IS_SETTING (setting), FALSE);

	meta_setting_info = nm_meta_setting_infos_by_gtype (G_OBJECT_TYPE (setting));
	g_return_val_if_fail (meta_setting_info, FALSE);

	setting_info = &nm_meta_setting_infos_editor[meta_setting_info->meta_type];
	g_return_val_if_fail (setting_info, FALSE);

	g_return_val_if_fail (G_TYPE_CHECK_INSTANCE_TYPE (setting, setting_info->general->get_setting_gtype ()), FALSE);

	if (nmc->print_output == NMC_PRINT_TERSE)
		type = NM_META_ACCESSOR_GET_TYPE_PARSABLE;

	tmpl_len = sizeof (NmcOutputField) * (setting_info->properties_num + 1);
	tmpl = g_memdup (_get_nmc_output_fields (setting_info), tmpl_len);

	nmc->print_fields.indices = parse_output_fields (one_prop ?: (s_all = _all_properties (setting_info)),
	                                                 tmpl, FALSE, NULL, NULL);
	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
	g_ptr_array_add (nmc->output_data, arr);

	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_SECTION_PREFIX);
	for (i = 0; i < setting_info->properties_num; i++) {
		const NMMetaPropertyInfo *property_info = &setting_info->properties[i];

		if (!property_info->is_secret || show_secrets) {
			set_val_str (arr, i, property_info->property_type->get_fcn (setting_info,
			                                                            property_info,
			                                                            setting,
			                                                            type,
			                                                            show_secrets));
		} else
			set_val_str (arr, i, g_strdup (_(NM_META_TEXT_HIDDEN)));
	}

	g_ptr_array_add (nmc->output_data, arr);

	print_data (nmc);  /* Print all data */

	return TRUE;
}
