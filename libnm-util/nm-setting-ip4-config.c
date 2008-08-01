/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/*
 * Dan Williams <dcbw@redhat.com>
 * Tambet Ingo <tambet@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2007 - 2008 Red Hat, Inc.
 * (C) Copyright 2007 - 2008 Novell, Inc.
 */

#include <string.h>

#include <dbus/dbus-glib.h>
#include "nm-setting-ip4-config.h"
#include "nm-param-spec-specialized.h"
#include "nm-utils.h"
#include "nm-dbus-glib-types.h"

GQuark
nm_setting_ip4_config_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-setting-ip4-config-error-quark");
	return quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
nm_setting_ip4_config_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Unknown error. */
			ENUM_ENTRY (NM_SETTING_IP4_CONFIG_ERROR_UNKNOWN, "UnknownError"),
			/* The specified property was invalid. */
			ENUM_ENTRY (NM_SETTING_IP4_CONFIG_ERROR_INVALID_PROPERTY, "InvalidProperty"),
			/* The specified property was missing and is required. */
			ENUM_ENTRY (NM_SETTING_IP4_CONFIG_ERROR_MISSING_PROPERTY, "MissingProperty"),
			/* The specified property was not allowed in combination with the current 'method' */
			ENUM_ENTRY (NM_SETTING_IP4_CONFIG_ERROR_NOT_ALLOWED_FOR_METHOD, "NotAllowedForMethod"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("NMSettingIP4ConfigError", values);
	}
	return etype;
}


G_DEFINE_TYPE (NMSettingIP4Config, nm_setting_ip4_config, NM_TYPE_SETTING)

enum {
	PROP_0,
	PROP_METHOD,
	PROP_DNS,
	PROP_DNS_SEARCH,
	PROP_ADDRESSES,
	PROP_ROUTES,
	PROP_IGNORE_DHCP_DNS,
	PROP_DHCP_CLIENT_ID,
	PROP_DHCP_HOSTNAME,

	LAST_PROP
};

NMSetting *
nm_setting_ip4_config_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_IP4_CONFIG, NULL);
}

static gboolean
verify (NMSetting *setting, GSList *all_settings, GError **error)
{
	NMSettingIP4Config *self = NM_SETTING_IP4_CONFIG (setting);
	GSList *iter;
	int i;

	if (!self->method) {
		g_set_error (error,
		             NM_SETTING_IP4_CONFIG_ERROR,
		             NM_SETTING_IP4_CONFIG_ERROR_MISSING_PROPERTY,
		             NM_SETTING_IP4_CONFIG_METHOD);
		return FALSE;
	}

	if (!strcmp (self->method, NM_SETTING_IP4_CONFIG_METHOD_MANUAL)) {
		if (!self->addresses) {
			g_set_error (error,
			             NM_SETTING_IP4_CONFIG_ERROR,
			             NM_SETTING_IP4_CONFIG_ERROR_MISSING_PROPERTY,
			             NM_SETTING_IP4_CONFIG_ADDRESSES);
			return FALSE;
		}
	} else if (   !strcmp (self->method, NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL)
	           || !strcmp (self->method, NM_SETTING_IP4_CONFIG_METHOD_SHARED)) {
		if (self->dns && self->dns->len) {
			g_set_error (error,
			             NM_SETTING_IP4_CONFIG_ERROR,
			             NM_SETTING_IP4_CONFIG_ERROR_NOT_ALLOWED_FOR_METHOD,
			             NM_SETTING_IP4_CONFIG_DNS);
			return FALSE;
		}

		if (g_slist_length (self->dns_search)) {
			g_set_error (error,
			             NM_SETTING_IP4_CONFIG_ERROR,
			             NM_SETTING_IP4_CONFIG_ERROR_NOT_ALLOWED_FOR_METHOD,
			             NM_SETTING_IP4_CONFIG_DNS_SEARCH);
			return FALSE;
		}

		if (g_slist_length (self->addresses)) {
			g_set_error (error,
			             NM_SETTING_IP4_CONFIG_ERROR,
			             NM_SETTING_IP4_CONFIG_ERROR_NOT_ALLOWED_FOR_METHOD,
			             NM_SETTING_IP4_CONFIG_ADDRESSES);
			return FALSE;
		}
	} else if (!strcmp (self->method, NM_SETTING_IP4_CONFIG_METHOD_AUTO)) {
		/* nothing to do */
	} else {
		g_set_error (error,
		             NM_SETTING_IP4_CONFIG_ERROR,
		             NM_SETTING_IP4_CONFIG_ERROR_INVALID_PROPERTY,
		             NM_SETTING_IP4_CONFIG_METHOD);
		return FALSE;
	}

	if (self->dhcp_client_id && !strlen (self->dhcp_client_id)) {
		g_set_error (error,
		             NM_SETTING_IP4_CONFIG_ERROR,
		             NM_SETTING_IP4_CONFIG_ERROR_INVALID_PROPERTY,
		             NM_SETTING_IP4_CONFIG_DHCP_CLIENT_ID);
		return FALSE;
	}

	if (self->dhcp_hostname && !strlen (self->dhcp_hostname)) {
		g_set_error (error,
		             NM_SETTING_IP4_CONFIG_ERROR,
		             NM_SETTING_IP4_CONFIG_ERROR_INVALID_PROPERTY,
		             NM_SETTING_IP4_CONFIG_DHCP_HOSTNAME);
		return FALSE;
	}

	/* Validate addresses */
	for (iter = self->addresses, i = 0; iter; iter = g_slist_next (iter), i++) {
		NMSettingIP4Address *addr = (NMSettingIP4Address *) iter->data;

		if (!addr->address) {
			g_set_error (error,
			             NM_SETTING_IP4_CONFIG_ERROR,
			             NM_SETTING_IP4_CONFIG_ERROR_INVALID_PROPERTY,
			             NM_SETTING_IP4_CONFIG_ADDRESSES);
			return FALSE;
		}

		if (!addr->prefix || addr->prefix > 32) {
			g_set_error (error,
			             NM_SETTING_IP4_CONFIG_ERROR,
			             NM_SETTING_IP4_CONFIG_ERROR_INVALID_PROPERTY,
			             NM_SETTING_IP4_CONFIG_ADDRESSES);
			return FALSE;
		}
	}

	/* Validate routes */
	for (iter = self->routes, i = 0; iter; iter = g_slist_next (iter), i++) {
		NMSettingIP4Address *addr = (NMSettingIP4Address *) iter->data;

		if (!addr->address) {
			g_set_error (error,
			             NM_SETTING_IP4_CONFIG_ERROR,
			             NM_SETTING_IP4_CONFIG_ERROR_INVALID_PROPERTY,
			             NM_SETTING_IP4_CONFIG_ROUTES);
			return FALSE;
		}

		if (!addr->prefix || addr->prefix > 32) {
			g_set_error (error,
			             NM_SETTING_IP4_CONFIG_ERROR,
			             NM_SETTING_IP4_CONFIG_ERROR_INVALID_PROPERTY,
			             NM_SETTING_IP4_CONFIG_ROUTES);
			return FALSE;
		}
	}

	return TRUE;
}


static void
nm_setting_ip4_config_init (NMSettingIP4Config *setting)
{
	((NMSetting *) setting)->name = g_strdup (NM_SETTING_IP4_CONFIG_SETTING_NAME);
}

static void
finalize (GObject *object)
{
	NMSettingIP4Config *self = NM_SETTING_IP4_CONFIG (object);

	g_free (self->method);

	if (self->dns)
		g_array_free (self->dns, TRUE);

	nm_utils_slist_free (self->dns_search, g_free);
	nm_utils_slist_free (self->addresses, g_free);
	nm_utils_slist_free (self->routes, g_free);

	G_OBJECT_CLASS (nm_setting_ip4_config_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	NMSettingIP4Config *setting = NM_SETTING_IP4_CONFIG (object);

	switch (prop_id) {
	case PROP_METHOD:
		g_free (setting->method);
		setting->method = g_value_dup_string (value);
		break;
	case PROP_DNS:
		if (setting->dns)
			g_array_free (setting->dns, TRUE);
		setting->dns = g_value_dup_boxed (value);
		break;
	case PROP_DNS_SEARCH:
		nm_utils_slist_free (setting->dns_search, g_free);
		setting->dns_search = g_value_dup_boxed (value);
		break;
	case PROP_ADDRESSES:
		nm_utils_slist_free (setting->addresses, g_free);
		setting->addresses = nm_utils_ip4_addresses_from_gvalue (value);
		break;
	case PROP_ROUTES:
		nm_utils_slist_free (setting->routes, g_free);
		setting->routes = nm_utils_ip4_addresses_from_gvalue (value);
		break;
	case PROP_IGNORE_DHCP_DNS:
		setting->ignore_dhcp_dns = g_value_get_boolean (value);
		break;
	case PROP_DHCP_CLIENT_ID:
		g_free (setting->dhcp_client_id);
		setting->dhcp_client_id = g_value_dup_string (value);
		break;
	case PROP_DHCP_HOSTNAME:
		g_free (setting->dhcp_hostname);
		setting->dhcp_hostname = g_value_dup_string (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
		    GValue *value, GParamSpec *pspec)
{
	NMSettingIP4Config *setting = NM_SETTING_IP4_CONFIG (object);

	switch (prop_id) {
	case PROP_METHOD:
		g_value_set_string (value, setting->method);
		break;
	case PROP_DNS:
		g_value_set_boxed (value, setting->dns);
		break;
	case PROP_DNS_SEARCH:
		g_value_set_boxed (value, setting->dns_search);
		break;
	case PROP_ADDRESSES:
		nm_utils_ip4_addresses_to_gvalue (setting->addresses, value);
		break;
	case PROP_ROUTES:
		nm_utils_ip4_addresses_to_gvalue (setting->routes, value);
		break;
	case PROP_IGNORE_DHCP_DNS:
		g_value_set_boolean (value, setting->ignore_dhcp_dns);
		break;
	case PROP_DHCP_CLIENT_ID:
		g_value_set_string (value, setting->dhcp_client_id);
		break;
	case PROP_DHCP_HOSTNAME:
		g_value_set_string (value, setting->dhcp_hostname);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_setting_ip4_config_class_init (NMSettingIP4ConfigClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;
	parent_class->verify       = verify;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_METHOD,
		 g_param_spec_string (NM_SETTING_IP4_CONFIG_METHOD,
						      "Method",
						      "IP configuration method",
						      NULL,
						      G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_DNS,
		 nm_param_spec_specialized (NM_SETTING_IP4_CONFIG_DNS,
							   "DNS",
							   "List of DNS servers",
							   DBUS_TYPE_G_UINT_ARRAY,
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_DNS_SEARCH,
		 nm_param_spec_specialized (NM_SETTING_IP4_CONFIG_DNS_SEARCH,
							   "DNS search",
							   "List of DNS search domains",
							   DBUS_TYPE_G_LIST_OF_STRING,
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_ADDRESSES,
		 nm_param_spec_specialized (NM_SETTING_IP4_CONFIG_ADDRESSES,
							   "Addresses",
							   "List of NMSettingIP4Addresses",
							   DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UINT,
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_ROUTES,
		 nm_param_spec_specialized (NM_SETTING_IP4_CONFIG_ROUTES,
							   "Routes",
							   "List of NMSettingIP4Addresses",
							   DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UINT,
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_IGNORE_DHCP_DNS,
		 g_param_spec_boolean (NM_SETTING_IP4_CONFIG_IGNORE_DHCP_DNS,
						   "Ignore DHCP DNS",
						   "Ignore DHCP DNS",
						   FALSE,
						   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_DHCP_CLIENT_ID,
		 g_param_spec_string (NM_SETTING_IP4_CONFIG_DHCP_CLIENT_ID,
						   "DHCP Client ID",
						   "DHCP Client ID",
						   NULL,
						   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_DHCP_HOSTNAME,
		 g_param_spec_string (NM_SETTING_IP4_CONFIG_DHCP_HOSTNAME,
						   "DHCP Hostname",
						   "DHCP Hostname",
						   NULL,
						   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));
}

