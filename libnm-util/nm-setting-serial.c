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

#include "nm-setting-serial.h"
#include "nm-setting-ppp.h"

GQuark
nm_setting_serial_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-setting-serial-error-quark");
	return quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
nm_setting_serial_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Unknown error. */
			ENUM_ENTRY (NM_SETTING_SERIAL_ERROR_UNKNOWN, "UnknownError"),
			/* The specified property was invalid. */
			ENUM_ENTRY (NM_SETTING_SERIAL_ERROR_INVALID_PROPERTY, "InvalidProperty"),
			/* The specified property was missing and is required. */
			ENUM_ENTRY (NM_SETTING_SERIAL_ERROR_MISSING_PROPERTY, "MissingProperty"),
			/* The required PPP setting is missing */
			ENUM_ENTRY (NM_SETTING_SERIAL_ERROR_MISSING_PPP_SETTING, "MissingPPPSetting"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("NMSettingSerialError", values);
	}
	return etype;
}


G_DEFINE_TYPE (NMSettingSerial, nm_setting_serial, NM_TYPE_SETTING)

enum {
	PROP_0,
	PROP_BAUD,
	PROP_BITS,
	PROP_PARITY,
	PROP_STOPBITS,
	PROP_SEND_DELAY,

	LAST_PROP
};

NMSetting *
nm_setting_serial_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_SERIAL, NULL);
}

static gint
find_setting_by_name (gconstpointer a, gconstpointer b)
{
	NMSetting *setting = NM_SETTING (a);
	const char *str = (const char *) b;

	return strcmp (nm_setting_get_name (setting), str);
}

static gboolean
verify (NMSetting *setting, GSList *all_settings, GError **error)
{
	/* Serial connections require a PPP setting */
	if (all_settings && 
	    !g_slist_find_custom (all_settings, NM_SETTING_PPP_SETTING_NAME, find_setting_by_name)) {
		g_set_error (error,
		             NM_SETTING_SERIAL_ERROR,
		             NM_SETTING_SERIAL_ERROR_MISSING_PPP_SETTING,
		             NULL);
		return FALSE;
	}

	return TRUE;
}

static void
nm_setting_serial_init (NMSettingSerial *setting)
{
	((NMSetting *) setting)->name = g_strdup (NM_SETTING_SERIAL_SETTING_NAME);
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	NMSettingSerial *setting = NM_SETTING_SERIAL (object);

	switch (prop_id) {
	case PROP_BAUD:
		setting->baud = g_value_get_uint (value);
		break;
	case PROP_BITS:
		setting->bits = g_value_get_uint (value);
		break;
	case PROP_PARITY:
		setting->parity = g_value_get_char (value);
		break;
	case PROP_STOPBITS:
		setting->stopbits = g_value_get_uint (value);
		break;
	case PROP_SEND_DELAY:
		setting->send_delay = g_value_get_uint64 (value);
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
	NMSettingSerial *setting = NM_SETTING_SERIAL (object);

	switch (prop_id) {
	case PROP_BAUD:
		g_value_set_uint (value, setting->baud);
		break;
	case PROP_BITS:
		g_value_set_uint (value, setting->bits);
		break;
	case PROP_PARITY:
		g_value_set_char (value, setting->parity);
		break;
	case PROP_STOPBITS:
		g_value_set_uint (value, setting->stopbits);
		break;
	case PROP_SEND_DELAY:
		g_value_set_uint64 (value, setting->send_delay);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_setting_serial_class_init (NMSettingSerialClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	parent_class->verify       = verify;

	/* Properties */

	g_object_class_install_property
		(object_class, PROP_BAUD,
		 g_param_spec_uint (NM_SETTING_SERIAL_BAUD,
						"Baud",
						"Baud rate",
						0, G_MAXUINT, 57600,
						G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_BITS,
		 g_param_spec_uint (NM_SETTING_SERIAL_BITS,
						"Bits",
						"Bits",
						5, 8, 8,
						G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_PARITY,
		 g_param_spec_char (NM_SETTING_SERIAL_PARITY,
						"Parity",
						"Parity",
						'E', 'o', 'n',
						G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_STOPBITS,
		 g_param_spec_uint (NM_SETTING_SERIAL_STOPBITS,
						"Stopbits",
						"Stopbits",
						1, 2, 1,
						G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_SEND_DELAY,
		 g_param_spec_uint64 (NM_SETTING_SERIAL_SEND_DELAY,
						  "SendDelay",
						  "Send delay",
						  0, G_MAXUINT64, 0,
						  G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE));
}
