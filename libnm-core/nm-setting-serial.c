/*
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
 * Copyright 2007 - 2018 Red Hat, Inc.
 * Copyright 2007 - 2008 Novell, Inc.
 */

#include "nm-default.h"

#include "nm-setting-serial.h"

#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-serial
 * @short_description: Describes connection properties for devices that use
 * serial communications
 *
 * The #NMSettingSerial object is a #NMSetting subclass that describes
 * properties necessary for connections that may use serial communications,
 * such as mobile broadband or analog telephone connections.
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_BAUD,
	PROP_BITS,
	PROP_PARITY,
	PROP_STOPBITS,
	PROP_SEND_DELAY,
);

typedef struct {
	guint baud;
	guint bits;
	char parity;
	guint stopbits;
	guint64 send_delay;
} NMSettingSerialPrivate;

G_DEFINE_TYPE (NMSettingSerial, nm_setting_serial, NM_TYPE_SETTING)

#define NM_SETTING_SERIAL_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_SERIAL, NMSettingSerialPrivate))

/*****************************************************************************/

/**
 * nm_setting_serial_get_baud:
 * @setting: the #NMSettingSerial
 *
 * Returns: the #NMSettingSerial:baud property of the setting
 **/
guint
nm_setting_serial_get_baud (NMSettingSerial *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_SERIAL (setting), 0);

	return NM_SETTING_SERIAL_GET_PRIVATE (setting)->baud;
}

/**
 * nm_setting_serial_get_bits:
 * @setting: the #NMSettingSerial
 *
 * Returns: the #NMSettingSerial:bits property of the setting
 **/
guint
nm_setting_serial_get_bits (NMSettingSerial *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_SERIAL (setting), 0);

	return NM_SETTING_SERIAL_GET_PRIVATE (setting)->bits;
}

/**
 * nm_setting_serial_get_parity:
 * @setting: the #NMSettingSerial
 *
 * Returns: the #NMSettingSerial:parity property of the setting
 **/
NMSettingSerialParity
nm_setting_serial_get_parity (NMSettingSerial *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_SERIAL (setting), 0);

	return NM_SETTING_SERIAL_GET_PRIVATE (setting)->parity;
}

/**
 * nm_setting_serial_get_stopbits:
 * @setting: the #NMSettingSerial
 *
 * Returns: the #NMSettingSerial:stopbits property of the setting
 **/
guint
nm_setting_serial_get_stopbits (NMSettingSerial *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_SERIAL (setting), 0);

	return NM_SETTING_SERIAL_GET_PRIVATE (setting)->stopbits;
}

/**
 * nm_setting_serial_get_send_delay:
 * @setting: the #NMSettingSerial
 *
 * Returns: the #NMSettingSerial:send-delay property of the setting
 **/
guint64
nm_setting_serial_get_send_delay (NMSettingSerial *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_SERIAL (setting), 0);

	return NM_SETTING_SERIAL_GET_PRIVATE (setting)->send_delay;
}

static GVariant *
parity_to_dbus (const GValue *from)
{
	switch (g_value_get_enum (from)) {
	case NM_SETTING_SERIAL_PARITY_EVEN:
		return g_variant_new_byte ('E');
	case NM_SETTING_SERIAL_PARITY_ODD:
		return g_variant_new_byte ('o');
	case NM_SETTING_SERIAL_PARITY_NONE:
	default:
		return g_variant_new_byte ('n');
	}
}

static void
parity_from_dbus (GVariant *from, GValue *to)
{
	switch (g_variant_get_byte (from)) {
	case 'E':
		g_value_set_enum (to, NM_SETTING_SERIAL_PARITY_EVEN);
		break;
	case 'o':
		g_value_set_enum (to, NM_SETTING_SERIAL_PARITY_ODD);
		break;
	case 'n':
	default:
		g_value_set_enum (to, NM_SETTING_SERIAL_PARITY_NONE);
		break;
	}
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettingSerial *setting = NM_SETTING_SERIAL (object);

	switch (prop_id) {
	case PROP_BAUD:
		g_value_set_uint (value, nm_setting_serial_get_baud (setting));
		break;
	case PROP_BITS:
		g_value_set_uint (value, nm_setting_serial_get_bits (setting));
		break;
	case PROP_PARITY:
		g_value_set_enum (value, nm_setting_serial_get_parity (setting));
		break;
	case PROP_STOPBITS:
		g_value_set_uint (value, nm_setting_serial_get_stopbits (setting));
		break;
	case PROP_SEND_DELAY:
		g_value_set_uint64 (value, nm_setting_serial_get_send_delay (setting));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSettingSerialPrivate *priv = NM_SETTING_SERIAL_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_BAUD:
		priv->baud = g_value_get_uint (value);
		break;
	case PROP_BITS:
		priv->bits = g_value_get_uint (value);
		break;
	case PROP_PARITY:
		priv->parity = g_value_get_enum (value);
		break;
	case PROP_STOPBITS:
		priv->stopbits = g_value_get_uint (value);
		break;
	case PROP_SEND_DELAY:
		priv->send_delay = g_value_get_uint64 (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_setting_serial_init (NMSettingSerial *setting)
{
}

/**
 * nm_setting_serial_new:
 *
 * Creates a new #NMSettingSerial object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingSerial object
 **/
NMSetting *
nm_setting_serial_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_SERIAL, NULL);
}

static void
nm_setting_serial_class_init (NMSettingSerialClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMSettingClass *setting_class = NM_SETTING_CLASS (klass);
	GArray *properties_override = _nm_sett_info_property_override_create_array ();

	g_type_class_add_private (klass, sizeof (NMSettingSerialPrivate));

	object_class->get_property = get_property;
	object_class->set_property = set_property;

	/**
	 * NMSettingSerial:baud:
	 *
	 * Speed to use for communication over the serial port.  Note that this
	 * value usually has no effect for mobile broadband modems as they generally
	 * ignore speed settings and use the highest available speed.
	 **/
	obj_properties[PROP_BAUD] =
	    g_param_spec_uint (NM_SETTING_SERIAL_BAUD, "", "",
	                       0, G_MAXUINT, 57600,
	                       G_PARAM_READWRITE |
	                       G_PARAM_CONSTRUCT |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingSerial:bits:
	 *
	 * Byte-width of the serial communication. The 8 in "8n1" for example.
	 **/
	obj_properties[PROP_BITS] =
	    g_param_spec_uint (NM_SETTING_SERIAL_BITS, "", "",
	                       5, 8, 8,
	                       G_PARAM_READWRITE |
	                       G_PARAM_CONSTRUCT |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingSerial:parity:
	 *
	 * Parity setting of the serial port.
	 **/
	/* ---keyfile---
	 * property: parity
	 * format: 'e', 'o', or 'n'
	 * description: The connection parity; even, odd, or none. Note that older
	 *   versions of NetworkManager stored this as an integer: 69 ('E') for even,
	 *   111 ('o') for odd, or 110 ('n') for none.
	 * example: parity=n
	 * ---end---
	 * ---dbus---
	 * property: parity
	 * format: byte
	 * description: The connection parity: 69 (ASCII 'E') for even parity,
	 *   111 (ASCII 'o') for odd, 110 (ASCII 'n') for none.
	 * ---end---
	 */
	obj_properties[PROP_PARITY] =
	    g_param_spec_enum (NM_SETTING_SERIAL_PARITY, "", "",
	                       NM_TYPE_SETTING_SERIAL_PARITY,
	                       NM_SETTING_SERIAL_PARITY_NONE,
	                       G_PARAM_READWRITE |
	                       G_PARAM_CONSTRUCT |
	                       G_PARAM_STATIC_STRINGS);

	_properties_override_add_transform (properties_override,
	                                    obj_properties[PROP_PARITY],
	                                    G_VARIANT_TYPE_BYTE,
	                                    parity_to_dbus,
	                                    parity_from_dbus);

	/**
	 * NMSettingSerial:stopbits:
	 *
	 * Number of stop bits for communication on the serial port.  Either 1 or 2.
	 * The 1 in "8n1" for example.
	 **/
	obj_properties[PROP_STOPBITS] =
	    g_param_spec_uint (NM_SETTING_SERIAL_STOPBITS, "", "",
	                       1, 2, 1,
	                       G_PARAM_READWRITE |
	                       G_PARAM_CONSTRUCT |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingSerial:send-delay:
	 *
	 * Time to delay between each byte sent to the modem, in microseconds.
	 **/
	obj_properties[PROP_SEND_DELAY] =
	    g_param_spec_uint64 (NM_SETTING_SERIAL_SEND_DELAY, "", "",
	                         0, G_MAXUINT64, 0,
	                         G_PARAM_READWRITE |
	                         G_PARAM_CONSTRUCT |
	                         G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	_nm_setting_class_commit_full (setting_class, NM_META_SETTING_TYPE_SERIAL,
	                               NULL, properties_override);
}
