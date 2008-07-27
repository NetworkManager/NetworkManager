/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/*
 * Dan Williams <dcbw@redhat.com>
 * David Cantrell <dcantrel@redhat.com>
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
 */

#include <string.h>

#include <dbus/dbus-glib.h>
#include "nm-setting-ip6-config.h"
#include "nm-param-spec-specialized.h"
#include "nm-utils.h"
#include "nm-dbus-glib-types.h"

GQuark
nm_setting_ip6_config_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-setting-ip6-config-error-quark");
	return quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
nm_setting_ip6_config_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Unknown error. */
			ENUM_ENTRY (NM_SETTING_IP6_CONFIG_ERROR_UNKNOWN, "UnknownError"),
			/* The specified property was invalid. */
			ENUM_ENTRY (NM_SETTING_IP6_CONFIG_ERROR_INVALID_PROPERTY, "InvalidProperty"),
			/* The specified property was missing and is required. */
			ENUM_ENTRY (NM_SETTING_IP6_CONFIG_ERROR_MISSING_PROPERTY, "MissingProperty"),
			/* The specified property was not allowed in combination with the current 'method' */
			ENUM_ENTRY (NM_SETTING_IP6_CONFIG_ERROR_NOT_ALLOWED_FOR_METHOD, "NotAllowedForMethod"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("NMSettingIP6ConfigError", values);
	}
	return etype;
}


G_DEFINE_TYPE (NMSettingIP6Config, nm_setting_ip6_config, NM_TYPE_SETTING)

enum {
	PROP_0,
	PROP_METHOD,
	PROP_DNS,
	PROP_DNS_SEARCH,
	PROP_ADDRESSES,
	PROP_ROUTES,
	PROP_IGNORE_DHCPV6_DNS,
	PROP_DISABLE_RA,
	PROP_DHCPV6_MODE,

	LAST_PROP
};

NMSetting *
nm_setting_ip6_config_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_IP6_CONFIG, NULL);
}

static gboolean
verify (NMSetting *setting, GSList *all_settings, GError **error)
{
	NMSettingIP6Config *self = NM_SETTING_IP6_CONFIG (setting);

	if (!self->method) {
		g_set_error (error,
		             NM_SETTING_IP6_CONFIG_ERROR,
		             NM_SETTING_IP6_CONFIG_ERROR_MISSING_PROPERTY,
		             NM_SETTING_IP6_CONFIG_METHOD);
		return FALSE;
	}

	if (!strcmp (self->method, NM_SETTING_IP6_CONFIG_METHOD_MANUAL)) {
		if (!self->addresses) {
			g_set_error (error,
			             NM_SETTING_IP6_CONFIG_ERROR,
			             NM_SETTING_IP6_CONFIG_ERROR_MISSING_PROPERTY,
			             NM_SETTING_IP6_CONFIG_ADDRESSES);
			return FALSE;
		}
	} else if (   !strcmp (self->method, NM_SETTING_IP6_CONFIG_METHOD_AUTO)
	           || !strcmp (self->method, NM_SETTING_IP6_CONFIG_METHOD_SHARED)) {
		if (!self->ignore_dhcpv6_dns) {
			if (self->dns && g_slist_length (self->dns)) {
				g_set_error (error,
				             NM_SETTING_IP6_CONFIG_ERROR,
				             NM_SETTING_IP6_CONFIG_ERROR_NOT_ALLOWED_FOR_METHOD,
				             NM_SETTING_IP6_CONFIG_DNS);
				return FALSE;
			}

			if (g_slist_length (self->dns_search)) {
				g_set_error (error,
				             NM_SETTING_IP6_CONFIG_ERROR,
				             NM_SETTING_IP6_CONFIG_ERROR_NOT_ALLOWED_FOR_METHOD,
				             NM_SETTING_IP6_CONFIG_DNS_SEARCH);
				return FALSE;
			}
		}

		if (g_slist_length (self->addresses)) {
			g_set_error (error,
			             NM_SETTING_IP6_CONFIG_ERROR,
			             NM_SETTING_IP6_CONFIG_ERROR_NOT_ALLOWED_FOR_METHOD,
			             NM_SETTING_IP6_CONFIG_ADDRESSES);
			return FALSE;
		}

		/* if router advertisement autoconf is disabled, dhcpv6 mode must
		 * be SOMETHING as long as the user has selected the auto method
		 */
		if (self->disable_ra && (self->dhcpv6_mode == NULL)) {
			g_set_error (error,
			             NM_SETTING_IP6_CONFIG_ERROR,
			             NM_SETTING_IP6_CONFIG_ERROR_INVALID_PROPERTY,
			             NM_SETTING_IP6_CONFIG_DHCPV6_MODE);
			return FALSE;
		}
	} else {
		g_set_error (error,
		             NM_SETTING_IP6_CONFIG_ERROR,
		             NM_SETTING_IP6_CONFIG_ERROR_INVALID_PROPERTY,
		             NM_SETTING_IP6_CONFIG_METHOD);
		return FALSE;
	}

	return TRUE;
}


static void
nm_setting_ip6_config_init (NMSettingIP6Config *setting)
{
	((NMSetting *) setting)->name = g_strdup (NM_SETTING_IP6_CONFIG_SETTING_NAME);
}

static void
finalize (GObject *object)
{
	NMSettingIP6Config *self = NM_SETTING_IP6_CONFIG (object);

	g_free (self->method);

	if (self->dns)
		g_slist_free (self->dns);

	nm_utils_slist_free (self->dns_search, g_free);
	nm_utils_slist_free (self->addresses, g_free);
	nm_utils_slist_free (self->routes, g_free);

	G_OBJECT_CLASS (nm_setting_ip6_config_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	NMSettingIP6Config *setting = NM_SETTING_IP6_CONFIG (object);

	switch (prop_id) {
	case PROP_METHOD:
		g_free (setting->method);
		setting->method = g_value_dup_string (value);
		break;
	case PROP_DNS:
		nm_utils_slist_free (setting->dns, g_free);
		setting->dns = nm_utils_ip6_dns_from_gvalue (value);
		break;
	case PROP_DNS_SEARCH:
		nm_utils_slist_free (setting->dns_search, g_free);
		setting->dns_search = g_value_dup_boxed (value);
		break;
	case PROP_ADDRESSES:
		nm_utils_slist_free (setting->addresses, g_free);
		setting->addresses = nm_utils_ip6_addresses_from_gvalue (value);
		break;
	case PROP_ROUTES:
		nm_utils_slist_free (setting->routes, g_free);
		setting->routes = nm_utils_ip6_addresses_from_gvalue (value);
		break;
	case PROP_IGNORE_DHCPV6_DNS:
		setting->ignore_dhcpv6_dns = g_value_get_boolean (value);
		break;
	case PROP_DISABLE_RA:
		setting->disable_ra = g_value_get_boolean (value);
		break;
	case PROP_DHCPV6_MODE:
		g_free (setting->dhcpv6_mode);
		setting->dhcpv6_mode = g_value_dup_string (value);
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
	NMSettingIP6Config *setting = NM_SETTING_IP6_CONFIG (object);

	switch (prop_id) {
	case PROP_METHOD:
		g_value_set_string (value, setting->method);
		break;
	case PROP_DNS:
		nm_utils_ip6_dns_to_gvalue (setting->dns, value);
		break;
	case PROP_DNS_SEARCH:
		g_value_set_boxed (value, setting->dns_search);
		break;
	case PROP_ADDRESSES:
		nm_utils_ip6_addresses_to_gvalue (setting->addresses, value);
		break;
	case PROP_ROUTES:
		nm_utils_ip6_addresses_to_gvalue (setting->routes, value);
		break;
	case PROP_IGNORE_DHCPV6_DNS:
		g_value_set_boolean (value, setting->ignore_dhcpv6_dns);
		break;
	case PROP_DISABLE_RA:
		g_value_set_boolean (value, setting->disable_ra);
		break;
	case PROP_DHCPV6_MODE:
		g_value_set_string (value, setting->dhcpv6_mode);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_setting_ip6_config_class_init (NMSettingIP6ConfigClass *setting_class)
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
		 g_param_spec_string (NM_SETTING_IP6_CONFIG_METHOD,
						      "Method",
						      "IP configuration method",
						      NULL,
						      G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_DNS,
		 nm_param_spec_specialized (NM_SETTING_IP6_CONFIG_DNS,
							   "DNS",
							   "List of DNS servers",
							   DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UCHAR,
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_DNS_SEARCH,
		 nm_param_spec_specialized (NM_SETTING_IP6_CONFIG_DNS_SEARCH,
							   "DNS search",
							   "List of DNS search domains",
							   DBUS_TYPE_G_LIST_OF_STRING,
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_ADDRESSES,
		 nm_param_spec_specialized (NM_SETTING_IP6_CONFIG_ADDRESSES,
							   "Addresses",
							   "List of NMSettingIP6Addresses",
							   DBUS_TYPE_G_ARRAY_OF_IP6_ADDRESS,
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_ROUTES,
		 nm_param_spec_specialized (NM_SETTING_IP6_CONFIG_ROUTES,
							   "Routes",
							   "List of NMSettingIP6Addresses",
							   DBUS_TYPE_G_ARRAY_OF_IP6_ADDRESS,
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_IGNORE_DHCPV6_DNS,
		 g_param_spec_boolean (NM_SETTING_IP6_CONFIG_IGNORE_DHCPV6_DNS,
						   "Ignore DHCPv6 DNS",
						   "Ignore DHCPv6 DNS",
						   FALSE,
						   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_DISABLE_RA,
		 g_param_spec_boolean (NM_SETTING_IP6_CONFIG_DISABLE_RA,
						   "Ignore Router Advertisements",
						   "Ignore Router Advertisements",
						   FALSE,
						   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_DHCPV6_MODE,
		 g_param_spec_string (NM_SETTING_IP6_CONFIG_DHCPV6_MODE,
						   "DHCPv6 Client Mode",
						   "DHCPv6 Client Mode",
						   NULL,
						   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));
}
