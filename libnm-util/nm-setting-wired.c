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

#include <net/ethernet.h>
#include <dbus/dbus-glib.h>
#include "nm-setting-wired.h"
#include "nm-param-spec-specialized.h"
#include "nm-utils.h"

GQuark
nm_setting_wired_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-setting-wired-error-quark");
	return quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
nm_setting_wired_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Unknown error. */
			ENUM_ENTRY (NM_SETTING_WIRED_ERROR_UNKNOWN, "UnknownError"),
			/* The specified property was invalid. */
			ENUM_ENTRY (NM_SETTING_WIRED_ERROR_INVALID_PROPERTY, "InvalidProperty"),
			/* The specified property was missing and is required. */
			ENUM_ENTRY (NM_SETTING_WIRED_ERROR_MISSING_PROPERTY, "MissingProperty"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("NMSettingWiredError", values);
	}
	return etype;
}


G_DEFINE_TYPE (NMSettingWired, nm_setting_wired, NM_TYPE_SETTING)

enum {
	PROP_0,
	PROP_PORT,
	PROP_SPEED,
	PROP_DUPLEX,
	PROP_AUTO_NEGOTIATE,
	PROP_MAC_ADDRESS,
	PROP_MTU,

	LAST_PROP
};

NMSetting *
nm_setting_wired_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_WIRED, NULL);
}

static gboolean
verify (NMSetting *setting, GSList *all_settings, GError **error)
{
	NMSettingWired *self = NM_SETTING_WIRED (setting);
	const char *valid_ports[] = { "tp", "aui", "bnc", "mii", NULL };
	const char *valid_duplex[] = { "half", "full", NULL };

	if (self->port && !nm_utils_string_in_list (self->port, valid_ports)) {
		g_set_error (error,
		             NM_SETTING_WIRED_ERROR,
		             NM_SETTING_WIRED_ERROR_INVALID_PROPERTY,
		             NM_SETTING_WIRED_PORT);
		return FALSE;
	}

	if (self->duplex && !nm_utils_string_in_list (self->duplex, valid_duplex)) {
		g_set_error (error,
		             NM_SETTING_WIRED_ERROR,
		             NM_SETTING_WIRED_ERROR_INVALID_PROPERTY,
		             NM_SETTING_WIRED_DUPLEX);
		return FALSE;
	}

	if (self->mac_address && self->mac_address->len != ETH_ALEN) {
		g_set_error (error,
		             NM_SETTING_WIRED_ERROR,
		             NM_SETTING_WIRED_ERROR_INVALID_PROPERTY,
		             NM_SETTING_WIRED_MAC_ADDRESS);
		return FALSE;
	}

	return TRUE;
}

static void
nm_setting_wired_init (NMSettingWired *setting)
{
	((NMSetting *) setting)->name = g_strdup (NM_SETTING_WIRED_SETTING_NAME);
}

static void
finalize (GObject *object)
{
	NMSettingWired *self = NM_SETTING_WIRED (object);

	g_free (self->port);
	g_free (self->duplex);

	if (self->mac_address)
		g_byte_array_free (self->mac_address, TRUE);

	G_OBJECT_CLASS (nm_setting_wired_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	NMSettingWired *setting = NM_SETTING_WIRED (object);

	switch (prop_id) {
	case PROP_PORT:
		g_free (setting->port);
		setting->port = g_value_dup_string (value);
		break;
	case PROP_SPEED:
		setting->speed = g_value_get_uint (value);
		break;
	case PROP_DUPLEX:
		g_free (setting->duplex);
		setting->duplex = g_value_dup_string (value);
		break;
	case PROP_AUTO_NEGOTIATE:
		setting->auto_negotiate = g_value_get_boolean (value);
		break;
	case PROP_MAC_ADDRESS:
		if (setting->mac_address)
			g_byte_array_free (setting->mac_address, TRUE);
		setting->mac_address = g_value_dup_boxed (value);
		break;
	case PROP_MTU:
		setting->mtu = g_value_get_uint (value);
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
	NMSettingWired *setting = NM_SETTING_WIRED (object);

	switch (prop_id) {
	case PROP_PORT:
		g_value_set_string (value, setting->port);
		break;
	case PROP_SPEED:
		g_value_set_uint (value, setting->speed);
		break;
	case PROP_DUPLEX:
		g_value_set_string (value, setting->duplex);
		break;
	case PROP_AUTO_NEGOTIATE:
		g_value_set_boolean (value, setting->auto_negotiate);
		break;
	case PROP_MAC_ADDRESS:
		g_value_set_boxed (value, setting->mac_address);
		break;
	case PROP_MTU:
		g_value_set_uint (value, setting->mtu);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_setting_wired_class_init (NMSettingWiredClass *setting_class)
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
		(object_class, PROP_PORT,
		 g_param_spec_string (NM_SETTING_WIRED_PORT,
						  "Port",
						  "Port type",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_SPEED,
		 g_param_spec_uint (NM_SETTING_WIRED_SPEED,
						"Speed",
						"Speed",
						0, G_MAXUINT32, 0,
						G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | G_PARAM_CONSTRUCT));

	g_object_class_install_property
		(object_class, PROP_DUPLEX,
		 g_param_spec_string (NM_SETTING_WIRED_DUPLEX,
						  "Duplex",
						  "Duplex",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_AUTO_NEGOTIATE,
		 g_param_spec_boolean (NM_SETTING_WIRED_AUTO_NEGOTIATE,
						   "AutoNegotiate",
						   "Auto negotiate",
						   TRUE,
						   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | G_PARAM_CONSTRUCT));

	g_object_class_install_property
		(object_class, PROP_MAC_ADDRESS,
		 nm_param_spec_specialized (NM_SETTING_WIRED_MAC_ADDRESS,
							   "MAC Address",
							   "Harware address",
							   DBUS_TYPE_G_UCHAR_ARRAY,
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_MTU,
		 g_param_spec_uint (NM_SETTING_WIRED_MTU,
						"MTU",
						"MTU",
						0, G_MAXUINT32, 0,
						G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_FUZZY_IGNORE));
}

