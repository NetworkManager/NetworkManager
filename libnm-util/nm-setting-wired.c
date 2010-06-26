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
 * (C) Copyright 2007 - 2010 Red Hat, Inc.
 * (C) Copyright 2007 - 2008 Novell, Inc.
 */

#include <string.h>
#include <net/ethernet.h>
#include <dbus/dbus-glib.h>
#include "nm-setting-wired.h"
#include "nm-param-spec-specialized.h"
#include "nm-utils.h"
#include "nm-utils-private.h"
#include "nm-dbus-glib-types.h"

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

#define NM_SETTING_WIRED_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_WIRED, NMSettingWiredPrivate))

typedef struct {
	char *port;
	guint32 speed;
	char *duplex;
	gboolean auto_negotiate;
	GByteArray *device_mac_address;
	GByteArray *cloned_mac_address;
	guint32 mtu;
	GPtrArray *s390_subchannels;
	char *s390_port_name;
	guint32 s390_port_number;
	guint32 s390_qeth_layer;
	char *s390_nettype;
} NMSettingWiredPrivate;

enum {
	PROP_0,
	PROP_PORT,
	PROP_SPEED,
	PROP_DUPLEX,
	PROP_AUTO_NEGOTIATE,
	PROP_MAC_ADDRESS,
	PROP_CLONED_MAC_ADDRESS,
	PROP_MTU,
	PROP_S390_SUBCHANNELS,
	PROP_S390_PORT_NAME,
	PROP_S390_PORT_NUMBER,
	PROP_S390_QETH_LAYER,
	PROP_S390_NETTYPE,

	LAST_PROP
};

NMSetting *
nm_setting_wired_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_WIRED, NULL);
}

const char *
nm_setting_wired_get_port (NMSettingWired *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), NULL);

	return NM_SETTING_WIRED_GET_PRIVATE (setting)->port;
}

guint32
nm_setting_wired_get_speed (NMSettingWired *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), 0);

	return NM_SETTING_WIRED_GET_PRIVATE (setting)->speed;
}

const char *
nm_setting_wired_get_duplex (NMSettingWired *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), NULL);

	return NM_SETTING_WIRED_GET_PRIVATE (setting)->duplex;
}

gboolean
nm_setting_wired_get_auto_negotiate (NMSettingWired *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), FALSE);

	return NM_SETTING_WIRED_GET_PRIVATE (setting)->auto_negotiate;
}

const GByteArray *
nm_setting_wired_get_mac_address (NMSettingWired *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), NULL);

	return NM_SETTING_WIRED_GET_PRIVATE (setting)->device_mac_address;
}

const GByteArray *
nm_setting_wired_get_cloned_mac_address (NMSettingWired *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), NULL);

	return NM_SETTING_WIRED_GET_PRIVATE (setting)->cloned_mac_address;
}

guint32
nm_setting_wired_get_mtu (NMSettingWired *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), 0);

	return NM_SETTING_WIRED_GET_PRIVATE (setting)->mtu;
}

const GPtrArray *
nm_setting_wired_get_s390_subchannels (NMSettingWired *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), NULL);

	return NM_SETTING_WIRED_GET_PRIVATE (setting)->s390_subchannels;
}

const char *
nm_setting_wired_get_s390_port_name (NMSettingWired *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), NULL);

	return NM_SETTING_WIRED_GET_PRIVATE (setting)->s390_port_name;
}

guint32
nm_setting_wired_get_s390_port_number (NMSettingWired *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), 0);

	return NM_SETTING_WIRED_GET_PRIVATE (setting)->s390_port_number;
}

guint32
nm_setting_wired_get_s390_qeth_layer (NMSettingWired *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), 2);

	return NM_SETTING_WIRED_GET_PRIVATE (setting)->s390_qeth_layer;
}

const char *
nm_setting_wired_get_s390_nettype (NMSettingWired *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), NULL);

	return NM_SETTING_WIRED_GET_PRIVATE (setting)->s390_nettype;
}

static gboolean
verify (NMSetting *setting, GSList *all_settings, GError **error)
{
	NMSettingWiredPrivate *priv = NM_SETTING_WIRED_GET_PRIVATE (setting);
	const char *valid_ports[] = { "tp", "aui", "bnc", "mii", NULL };
	const char *valid_duplex[] = { "half", "full", NULL };

	if (priv->port && !_nm_utils_string_in_list (priv->port, valid_ports)) {
		g_set_error (error,
		             NM_SETTING_WIRED_ERROR,
		             NM_SETTING_WIRED_ERROR_INVALID_PROPERTY,
		             NM_SETTING_WIRED_PORT);
		return FALSE;
	}

	if (priv->duplex && !_nm_utils_string_in_list (priv->duplex, valid_duplex)) {
		g_set_error (error,
		             NM_SETTING_WIRED_ERROR,
		             NM_SETTING_WIRED_ERROR_INVALID_PROPERTY,
		             NM_SETTING_WIRED_DUPLEX);
		return FALSE;
	}

	if (priv->device_mac_address && priv->device_mac_address->len != ETH_ALEN) {
		g_set_error (error,
		             NM_SETTING_WIRED_ERROR,
		             NM_SETTING_WIRED_ERROR_INVALID_PROPERTY,
		             NM_SETTING_WIRED_MAC_ADDRESS);
		return FALSE;
	}

	if (priv->s390_subchannels && priv->s390_subchannels->len != 3) {
		g_set_error (error,
		             NM_SETTING_WIRED_ERROR,
		             NM_SETTING_WIRED_ERROR_INVALID_PROPERTY,
		             NM_SETTING_WIRED_S390_SUBCHANNELS);
		return FALSE;
	}

	if (priv->s390_nettype) {
		if (   strcmp (priv->s390_nettype, "qeth")
		    && strcmp (priv->s390_nettype, "lcs")
		    && strcmp (priv->s390_nettype, "ctc")) {
			g_set_error (error,
				         NM_SETTING_WIRED_ERROR,
				         NM_SETTING_WIRED_ERROR_INVALID_PROPERTY,
				         NM_SETTING_WIRED_S390_NETTYPE);
			return FALSE;
		}
	}

	if (priv->s390_port_name && strlen (priv->s390_port_name) > 8) {
		g_set_error (error,
			         NM_SETTING_WIRED_ERROR,
			         NM_SETTING_WIRED_ERROR_INVALID_PROPERTY,
			         NM_SETTING_WIRED_S390_PORT_NAME);
		return FALSE;
	}

	if (priv->cloned_mac_address && priv->cloned_mac_address->len != ETH_ALEN) {
		g_set_error (error,
		             NM_SETTING_WIRED_ERROR,
		             NM_SETTING_WIRED_ERROR_INVALID_PROPERTY,
		             NM_SETTING_WIRED_CLONED_MAC_ADDRESS);
		return FALSE;
	}

	return TRUE;
}

static void
nm_setting_wired_init (NMSettingWired *setting)
{
	g_object_set (setting, NM_SETTING_NAME, NM_SETTING_WIRED_SETTING_NAME, NULL);
}

static void
finalize (GObject *object)
{
	NMSettingWiredPrivate *priv = NM_SETTING_WIRED_GET_PRIVATE (object);

	g_free (priv->port);
	g_free (priv->duplex);
	g_free (priv->s390_port_name);
	g_free (priv->s390_nettype);

	if (priv->device_mac_address)
		g_byte_array_free (priv->device_mac_address, TRUE);

	if (priv->cloned_mac_address)
		g_byte_array_free (priv->cloned_mac_address, TRUE);

	G_OBJECT_CLASS (nm_setting_wired_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	NMSettingWiredPrivate *priv = NM_SETTING_WIRED_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_PORT:
		g_free (priv->port);
		priv->port = g_value_dup_string (value);
		break;
	case PROP_SPEED:
		priv->speed = g_value_get_uint (value);
		break;
	case PROP_DUPLEX:
		g_free (priv->duplex);
		priv->duplex = g_value_dup_string (value);
		break;
	case PROP_AUTO_NEGOTIATE:
		priv->auto_negotiate = g_value_get_boolean (value);
		break;
	case PROP_MAC_ADDRESS:
		if (priv->device_mac_address)
			g_byte_array_free (priv->device_mac_address, TRUE);
		priv->device_mac_address = g_value_dup_boxed (value);
		break;
	case PROP_CLONED_MAC_ADDRESS:
		if (priv->cloned_mac_address)
			g_byte_array_free (priv->cloned_mac_address, TRUE);
		priv->cloned_mac_address = g_value_dup_boxed (value);
		break;
	case PROP_MTU:
		priv->mtu = g_value_get_uint (value);
		break;
	case PROP_S390_SUBCHANNELS:
		if (priv->s390_subchannels) {
			g_ptr_array_foreach (priv->s390_subchannels, (GFunc) g_free, NULL);
			g_ptr_array_free (priv->s390_subchannels, TRUE);
		}
		priv->s390_subchannels = g_value_dup_boxed (value);
		break;
	case PROP_S390_PORT_NAME:
		g_free (priv->s390_port_name);
		priv->s390_port_name = g_value_dup_string (value);
		break;
	case PROP_S390_PORT_NUMBER:
		priv->s390_port_number = g_value_get_uint (value);
		break;
	case PROP_S390_QETH_LAYER:
		priv->s390_qeth_layer = g_value_get_uint (value);
		break;
	case PROP_S390_NETTYPE:
		g_free (priv->s390_nettype);
		priv->s390_nettype = g_value_dup_string (value);
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
		g_value_set_string (value, nm_setting_wired_get_port (setting));
		break;
	case PROP_SPEED:
		g_value_set_uint (value, nm_setting_wired_get_speed (setting));
		break;
	case PROP_DUPLEX:
		g_value_set_string (value, nm_setting_wired_get_duplex (setting));
		break;
	case PROP_AUTO_NEGOTIATE:
		g_value_set_boolean (value, nm_setting_wired_get_auto_negotiate (setting));
		break;
	case PROP_MAC_ADDRESS:
		g_value_set_boxed (value, nm_setting_wired_get_mac_address (setting));
		break;
	case PROP_CLONED_MAC_ADDRESS:
		g_value_set_boxed (value, nm_setting_wired_get_cloned_mac_address (setting));
		break;
	case PROP_MTU:
		g_value_set_uint (value, nm_setting_wired_get_mtu (setting));
		break;
	case PROP_S390_SUBCHANNELS:
		g_value_set_boxed (value, nm_setting_wired_get_s390_subchannels (setting));
		break;
	case PROP_S390_PORT_NAME:
		g_value_set_string (value, nm_setting_wired_get_s390_port_name (setting));
		break;
	case PROP_S390_PORT_NUMBER:
		g_value_set_uint (value, nm_setting_wired_get_s390_port_number (setting));
		break;
	case PROP_S390_QETH_LAYER:
		g_value_set_uint (value, nm_setting_wired_get_s390_qeth_layer (setting));
		break;
	case PROP_S390_NETTYPE:
		g_value_set_string (value, nm_setting_wired_get_s390_nettype (setting));
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

	g_type_class_add_private (setting_class, sizeof (NMSettingWiredPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;
	parent_class->verify       = verify;

	/* Properties */
	/**
	 * NMSettingWired:port:
	 *
	 * Specific port type to use if multiple the device supports multiple
	 * attachment methods.  One of 'tp' (Twisted Pair), 'aui' (Attachment Unit
	 * Interface), 'bnc' (Thin Ethernet) or 'mii' (Media Independent Interface.
	 * If the device supports only one port type, this setting is ignored.
	 **/
	g_object_class_install_property
		(object_class, PROP_PORT,
		 g_param_spec_string (NM_SETTING_WIRED_PORT,
						  "Port",
						  "Specific port type to use if multiple the device "
						  "supports multiple attachment methods.  One of "
						  "'tp' (Twisted Pair), 'aui' (Attachment Unit Interface), "
						  "'bnc' (Thin Ethernet) or 'mii' (Media Independent "
						  "Interface.  If the device supports only one port "
						  "type, this setting is ignored.",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingWired:speed:
	 *
	 * If non-zero, request that the device use only the specified speed. 
	 * In Mbit/s, ie 100 == 100Mbit/s.
	 **/
	g_object_class_install_property
		(object_class, PROP_SPEED,
		 g_param_spec_uint (NM_SETTING_WIRED_SPEED,
						"Speed",
						"If non-zero, request that the device use only the "
						"specified speed.  In Mbit/s, ie 100 == 100Mbit/s.",
						0, G_MAXUINT32, 0,
						G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingWired:duplex:
	 *
	 * If specified, request that the device only use the specified duplex mode.
	 * Either 'half' or 'full'.
	 **/
	g_object_class_install_property
		(object_class, PROP_DUPLEX,
		 g_param_spec_string (NM_SETTING_WIRED_DUPLEX,
						  "Duplex",
						  "If specified, request that the device only use the "
						  "specified duplex mode.  Either 'half' or 'full'.",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingEthernet:auto-negotiate:
	 *
	 * If TRUE, allow auto-negotiation of port speed and duplex mode.  If FALSE,
	 * do not allow auto-negotiation, in which case the 'speed' and 'duplex'
	 * properties should be set.
	 **/
	g_object_class_install_property
		(object_class, PROP_AUTO_NEGOTIATE,
		 g_param_spec_boolean (NM_SETTING_WIRED_AUTO_NEGOTIATE,
						   "AutoNegotiate",
						   "If TRUE, allow auto-negotiation of port speed and "
						   "duplex mode.  If FALSE, do not allow auto-negotiation,"
						   "in which case the 'speed' and 'duplex' properties "
						   "should be set.",
						   TRUE,
						   G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingWired:mac-address:
	 *
	 * If specified, this connection will only apply to the ethernet device
	 * whose permanent MAC address matches. This property does not change the MAC address
	 * of the device (i.e. MAC spoofing).
	 **/
	g_object_class_install_property
		(object_class, PROP_MAC_ADDRESS,
		 _nm_param_spec_specialized (NM_SETTING_WIRED_MAC_ADDRESS,
							   "Device MAC Address",
							   "If specified, this connection will only apply to "
							   "the ethernet device whose permanent MAC address matches.  "
							   "This property does not change the MAC address "
							   "of the device (i.e. MAC spoofing).",
							   DBUS_TYPE_G_UCHAR_ARRAY,
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingWired:cloned-mac-address:
	 *
	 * If specified, request that the device use this MAC address instead of its
	 * permanent MAC address.  This is known as MAC cloning or spoofing.
	 **/
	g_object_class_install_property
		(object_class, PROP_CLONED_MAC_ADDRESS,
		 _nm_param_spec_specialized (NM_SETTING_WIRED_CLONED_MAC_ADDRESS,
	                                     "Cloned MAC Address",
	                                     "If specified, request that the device use "
	                                     "this MAC address instead of its permanent MAC address.  "
	                                     "This is known as MAC cloning or spoofing.",
	                                     DBUS_TYPE_G_UCHAR_ARRAY,
	                                     G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingWired:mtu:
	 *
	 * If non-zero, only transmit packets of the specified size or smaller,
	 * breaking larger packets up into multiple Ethernet frames.
	 **/
	g_object_class_install_property
		(object_class, PROP_MTU,
		 g_param_spec_uint (NM_SETTING_WIRED_MTU,
						"MTU",
						"If non-zero, only transmit packets of the specified "
						"size or smaller, breaking larger packets up into "
						"multiple Ethernet frames.",
						0, G_MAXUINT32, 0,
						G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_FUZZY_IGNORE));

	/**
	 * NMSettingWired:s390-subchannels:
	 *
	 * Identifies specific subchannels that this network device uses for
	 * communcation with z/VM or s390 host.  Like #NMSettingWired:mac-address
	 * for non-z/VM devices, this property can be used to ensure this connection
	 * only applies to the network device that uses these subchannels.  The
	 * list should contain exactly 3 strings, and each string may only only be
	 * composed of hexadecimal characters and the period (.) character.
	 **/
	g_object_class_install_property
		(object_class, PROP_S390_SUBCHANNELS,
		 _nm_param_spec_specialized (NM_SETTING_WIRED_S390_SUBCHANNELS,
		                       "z/VM Subchannels",
		                       "Identifies specific subchannels that this "
		                       "network device uses for communcation with z/VM "
		                       "or s390 host.  Like the 'mac-address' property "
		                       "for non-z/VM devices, this property can be used "
		                       "to ensure this connection only applies to the "
		                       "network device that uses these subchannels. The "
		                       "list should contain exactly 3 strings, and each "
		                       "string may only only be composed of hexadecimal "
		                       "characters and the period (.) character.",
		                       DBUS_TYPE_G_ARRAY_OF_STRING,
		                       G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingWired:s390-port-name:
	 *
	 * s390 device port name, if required by your configuration.
	 **/
	g_object_class_install_property
		(object_class, PROP_S390_PORT_NAME,
		 g_param_spec_string (NM_SETTING_WIRED_S390_PORT_NAME,
						  "s390 Port Name",
						  "s390 device port name, if required by your configuration.",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingWired:s390-port-number:
	 *
	 * s390 device port number, if required by your configuration.  For 'qeth'
	 * devices, this is the "relative port number".
	 **/
	g_object_class_install_property
		(object_class, PROP_S390_PORT_NUMBER,
		 g_param_spec_uint (NM_SETTING_WIRED_S390_PORT_NUMBER,
						  "s390 Port Number",
		                  "s390 device port number, if required by your "
		                  "configuration.  For 'qeth' devices, this is the "
		                  "'relative port number'.",
						  0, 100, 0,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingWired:s390-qeth-layer:
	 *
	 * s390 'qeth' device layer, either '2' or '3'.
	 **/
	g_object_class_install_property
		(object_class, PROP_S390_QETH_LAYER,
		 g_param_spec_uint (NM_SETTING_WIRED_S390_QETH_LAYER,
						  "s390 'qeth' layer",
		                  "s390 'qeth' device layer, either '2' or '3'.",
						  2, 3, 2,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingWired:s390-nettype:
	 *
	 * s390 network device type; one of 'qeth', 'lcs', or 'ctc', representing
	 * the different types of virtual network devices available on s390 systems.
	 **/
	g_object_class_install_property
		(object_class, PROP_S390_NETTYPE,
		 g_param_spec_string (NM_SETTING_WIRED_S390_NETTYPE,
						  "s390 Net Type",
						  "s390 network device type; one of 'qeth', 'lcs', or "
						  "'ctc', representing the different types of virtual "
						  "network devices available on s390 systems.",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));
}

