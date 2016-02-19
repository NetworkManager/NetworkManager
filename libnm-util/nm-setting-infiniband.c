/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

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
 * Copyright 2011 - 2013 Red Hat, Inc.
 */

#include "nm-default.h"

#include <stdlib.h>
#include <dbus/dbus-glib.h>
#include <linux/if_infiniband.h>

#include "nm-setting-infiniband.h"
#include "nm-param-spec-specialized.h"
#include "nm-utils.h"
#include "nm-utils-private.h"
#include "nm-setting-private.h"
#include "nm-setting-connection.h"

/**
 * SECTION:nm-setting-infiniband
 * @short_description: Describes connection properties for IP-over-InfiniBand networks
 * @include: nm-setting-infiniband.h
 *
 * The #NMSettingInfiniband object is a #NMSetting subclass that describes properties
 * necessary for connection to IP-over-InfiniBand networks.
 **/

/**
 * nm_setting_infiniband_error_quark:
 *
 * Registers an error quark for #NMSettingInfiniband if necessary.
 *
 * Returns: the error quark used for #NMSettingInfiniband errors.
 **/
GQuark
nm_setting_infiniband_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-setting-infiniband-error-quark");
	return quark;
}

G_DEFINE_TYPE_WITH_CODE (NMSettingInfiniband, nm_setting_infiniband, NM_TYPE_SETTING,
                         _nm_register_setting (NM_SETTING_INFINIBAND_SETTING_NAME,
                                               g_define_type_id,
                                               1,
                                               NM_SETTING_INFINIBAND_ERROR))
NM_SETTING_REGISTER_TYPE (NM_TYPE_SETTING_INFINIBAND)

#define NM_SETTING_INFINIBAND_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_INFINIBAND, NMSettingInfinibandPrivate))

typedef struct {
	GByteArray *mac_address;
	char *transport_mode;
	guint32 mtu;
	int p_key;
	char *parent, *virtual_iface_name;
} NMSettingInfinibandPrivate;

enum {
	PROP_0,
	PROP_MAC_ADDRESS,
	PROP_MTU,
	PROP_TRANSPORT_MODE,
	PROP_P_KEY,
	PROP_PARENT,

	LAST_PROP
};

/**
 * nm_setting_infiniband_new:
 *
 * Creates a new #NMSettingInfiniband object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingInfiniband object
 **/
NMSetting *
nm_setting_infiniband_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_INFINIBAND, NULL);
}

/**
 * nm_setting_infiniband_get_mac_address:
 * @setting: the #NMSettingInfiniband
 *
 * Returns: the #NMSettingInfiniband:mac-address property of the setting
 **/
const GByteArray *
nm_setting_infiniband_get_mac_address (NMSettingInfiniband *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_INFINIBAND (setting), NULL);

	return NM_SETTING_INFINIBAND_GET_PRIVATE (setting)->mac_address;
}

/**
 * nm_setting_infiniband_get_mtu:
 * @setting: the #NMSettingInfiniband
 *
 * Returns: the #NMSettingInfiniband:mtu property of the setting
 **/
guint32
nm_setting_infiniband_get_mtu (NMSettingInfiniband *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_INFINIBAND (setting), 0);

	return NM_SETTING_INFINIBAND_GET_PRIVATE (setting)->mtu;
}

/**
 * nm_setting_infiniband_get_transport_mode:
 * @setting: the #NMSettingInfiniband
 *
 * Returns the transport mode for this device. Either 'datagram' or
 * 'connected'.
 *
 * Returns: the IPoIB transport mode
 **/
const char *
nm_setting_infiniband_get_transport_mode (NMSettingInfiniband *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_INFINIBAND (setting), NULL);

	return NM_SETTING_INFINIBAND_GET_PRIVATE (setting)->transport_mode;
}

/**
 * nm_setting_infiniband_get_p_key:
 * @setting: the #NMSettingInfiniband
 *
 * Returns the P_Key to use for this device. A value of -1 means to
 * use the default P_Key (aka "the P_Key at index 0"). Otherwise it is
 * a 16-bit unsigned integer.
 *
 * Returns: the IPoIB P_Key
 **/
int
nm_setting_infiniband_get_p_key (NMSettingInfiniband *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_INFINIBAND (setting), -1);

	return NM_SETTING_INFINIBAND_GET_PRIVATE (setting)->p_key;
}

/**
 * nm_setting_infiniband_get_parent:
 * @setting: the #NMSettingInfiniband
 *
 * Returns the parent interface name for this device, if set.
 *
 * Returns: the parent interface name
 **/
const char *
nm_setting_infiniband_get_parent (NMSettingInfiniband *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_INFINIBAND (setting), NULL);

	return NM_SETTING_INFINIBAND_GET_PRIVATE (setting)->parent;
}

static const char *
get_virtual_iface_name (NMSetting *setting)
{
	NMSettingInfinibandPrivate *priv = NM_SETTING_INFINIBAND_GET_PRIVATE (setting);

	if (priv->p_key == -1 || !priv->parent)
		return NULL;

	if (!priv->virtual_iface_name)
		priv->virtual_iface_name = g_strdup_printf ("%s.%04x", priv->parent, priv->p_key);

	return NM_SETTING_INFINIBAND_GET_PRIVATE (setting)->virtual_iface_name;
}

static gboolean
verify (NMSetting *setting, GSList *all_settings, GError **error)
{
	NMSettingConnection *s_con;
	NMSettingInfinibandPrivate *priv = NM_SETTING_INFINIBAND_GET_PRIVATE (setting);

	if (priv->mac_address && priv->mac_address->len != INFINIBAND_ALEN) {
		g_set_error_literal (error,
		                     NM_SETTING_INFINIBAND_ERROR,
		                     NM_SETTING_INFINIBAND_ERROR_INVALID_PROPERTY,
		                     _("property is invalid"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_INFINIBAND_SETTING_NAME, NM_SETTING_INFINIBAND_MAC_ADDRESS);
		return FALSE;
	}

	/* FIXME: verify() should not modify the setting, but return NORMALIZABLE success. */
	if (!g_strcmp0 (priv->transport_mode, "datagram")) {
		if (priv->mtu > 2044)
			priv->mtu = 2044;
	} else if (!g_strcmp0 (priv->transport_mode, "connected")) {
		if (priv->mtu > 65520)
			priv->mtu = 65520;
	} else {
		g_set_error_literal (error,
		                     NM_SETTING_INFINIBAND_ERROR,
		                     NM_SETTING_INFINIBAND_ERROR_INVALID_PROPERTY,
		                     _("property is invalid"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_INFINIBAND_SETTING_NAME, NM_SETTING_INFINIBAND_TRANSPORT_MODE);
		return FALSE;
	}

	if (priv->parent) {
		if (!nm_utils_iface_valid_name (priv->parent)) {
			g_set_error_literal (error,
			                     NM_SETTING_INFINIBAND_ERROR,
			                     NM_SETTING_INFINIBAND_ERROR_INVALID_PROPERTY,
			                     _("not a valid interface name"));
			g_prefix_error (error, "%s: ", NM_SETTING_INFINIBAND_PARENT);
			return FALSE;
		}
		if (priv->p_key == -1) {
			g_set_error_literal (error,
			                     NM_SETTING_INFINIBAND_ERROR,
			                     NM_SETTING_INFINIBAND_ERROR_INVALID_PROPERTY,
			                     _("Must specify a P_Key if specifying parent"));
			g_prefix_error (error, "%s: ", NM_SETTING_INFINIBAND_PARENT);
		}
	}

	if (priv->p_key != -1) {
		if (!priv->mac_address && !priv->parent) {
			g_set_error_literal (error,
			                     NM_SETTING_INFINIBAND_ERROR,
			                     NM_SETTING_INFINIBAND_ERROR_MISSING_PROPERTY,
			                     _("InfiniBand P_Key connection did not specify parent interface name"));
			g_prefix_error (error, "%s: ", NM_SETTING_INFINIBAND_PARENT);
			return FALSE;
		}
	}

	s_con = NM_SETTING_CONNECTION (nm_setting_find_in_list (all_settings, NM_SETTING_CONNECTION_SETTING_NAME));
	if (s_con) {
		const char *interface_name = nm_setting_connection_get_interface_name (s_con);

		if (!interface_name)
			;
		else if (!nm_utils_iface_valid_name (interface_name)) {
			/* report the error for NMSettingConnection:interface-name, because
			 * it's that property that is invalid -- although we currently verify()
			 * NMSettingInfiniband.
			 **/
			g_set_error (error,
			             NM_SETTING_CONNECTION_ERROR,
			             NM_SETTING_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("'%s' is not a valid interface name"),
			             interface_name);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_CONNECTION_SETTING_NAME, NM_SETTING_CONNECTION_INTERFACE_NAME);
			return FALSE;
		} else {
			if (priv->p_key != -1) {
				if (!priv->virtual_iface_name)
					priv->virtual_iface_name = g_strdup_printf ("%s.%04x", priv->parent, priv->p_key);

				if (strcmp (interface_name, priv->virtual_iface_name) != 0) {
					/* We don't support renaming software infiniband devices. Later we might, but
					 * for now just reject such connections.
					 **/
					g_set_error (error,
					             NM_SETTING_CONNECTION_ERROR,
					             NM_SETTING_CONNECTION_ERROR_INVALID_PROPERTY,
					             _("interface name of software infiniband device must be '%s' or unset (instead it is '%s')"),
					             priv->virtual_iface_name, interface_name);
					g_prefix_error (error, "%s.%s: ", NM_SETTING_CONNECTION_SETTING_NAME, NM_SETTING_CONNECTION_INTERFACE_NAME);
					return FALSE;
				}
			}
		}
	}

	return TRUE;
}

static void
nm_setting_infiniband_init (NMSettingInfiniband *setting)
{
}

static void
finalize (GObject *object)
{
	NMSettingInfinibandPrivate *priv = NM_SETTING_INFINIBAND_GET_PRIVATE (object);

	g_free (priv->transport_mode);
	if (priv->mac_address)
		g_byte_array_free (priv->mac_address, TRUE);
	g_free (priv->parent);
	g_free (priv->virtual_iface_name);

	G_OBJECT_CLASS (nm_setting_infiniband_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSettingInfinibandPrivate *priv = NM_SETTING_INFINIBAND_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_MAC_ADDRESS:
		if (priv->mac_address)
			g_byte_array_free (priv->mac_address, TRUE);
		priv->mac_address = g_value_dup_boxed (value);
		break;
	case PROP_MTU:
		priv->mtu = g_value_get_uint (value);
		break;
	case PROP_TRANSPORT_MODE:
		g_free (priv->transport_mode);
		priv->transport_mode = g_value_dup_string (value);
		break;
	case PROP_P_KEY:
		priv->p_key = g_value_get_int (value);
		g_clear_pointer (&priv->virtual_iface_name, g_free);
		break;
	case PROP_PARENT:
		g_free (priv->parent);
		priv->parent = g_value_dup_string (value);
		g_clear_pointer (&priv->virtual_iface_name, g_free);
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
	NMSettingInfiniband *setting = NM_SETTING_INFINIBAND (object);

	switch (prop_id) {
	case PROP_MAC_ADDRESS:
		g_value_set_boxed (value, nm_setting_infiniband_get_mac_address (setting));
		break;
	case PROP_MTU:
		g_value_set_uint (value, nm_setting_infiniband_get_mtu (setting));
		break;
	case PROP_TRANSPORT_MODE:
		g_value_set_string (value, nm_setting_infiniband_get_transport_mode (setting));
		break;
	case PROP_P_KEY:
		g_value_set_int (value, nm_setting_infiniband_get_p_key (setting));
		break;
	case PROP_PARENT:
		g_value_set_string (value, nm_setting_infiniband_get_parent (setting));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_setting_infiniband_class_init (NMSettingInfinibandClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	g_type_class_add_private (setting_class, sizeof (NMSettingInfinibandPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;

	parent_class->verify                 = verify;
	parent_class->get_virtual_iface_name = get_virtual_iface_name;

	/* Properties */
	/**
	 * NMSettingInfiniband:mac-address:
	 *
	 * If specified, this connection will only apply to the IPoIB device whose
	 * permanent MAC address matches. This property does not change the MAC
	 * address of the device (i.e. MAC spoofing).
	 **/
	g_object_class_install_property
		(object_class, PROP_MAC_ADDRESS,
		 _nm_param_spec_specialized (NM_SETTING_INFINIBAND_MAC_ADDRESS, "", "",
		                             DBUS_TYPE_G_UCHAR_ARRAY,
		                             G_PARAM_READWRITE |
		                             NM_SETTING_PARAM_INFERRABLE |
		                             G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingInfiniband:mtu:
	 *
	 * If non-zero, only transmit packets of the specified size or smaller,
	 * breaking larger packets up into multiple frames.
	 **/
	g_object_class_install_property
		(object_class, PROP_MTU,
		 g_param_spec_uint (NM_SETTING_INFINIBAND_MTU, "", "",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READWRITE |
		                    G_PARAM_CONSTRUCT |
		                    NM_SETTING_PARAM_FUZZY_IGNORE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingInfiniband:transport-mode:
	 *
	 * The IP-over-InfiniBand transport mode. Either "datagram" or
	 * "connected".
	 **/
	g_object_class_install_property
		(object_class, PROP_TRANSPORT_MODE,
		 g_param_spec_string (NM_SETTING_INFINIBAND_TRANSPORT_MODE, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_CONSTRUCT |
		                      NM_SETTING_PARAM_INFERRABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingInfiniband:p-key:
	 *
	 * The InfiniBand P_Key to use for this device. A value of -1 means to use
	 * the default P_Key (aka "the P_Key at index 0").  Otherwise it is a 16-bit
	 * unsigned integer, whose high bit is set if it is a "full membership"
	 * P_Key.
	 **/
	g_object_class_install_property
		(object_class, PROP_P_KEY,
		 g_param_spec_int (NM_SETTING_INFINIBAND_P_KEY, "", "",
		                   -1, 0xFFFF, -1,
		                   G_PARAM_READWRITE |
		                   G_PARAM_CONSTRUCT |
		                   NM_SETTING_PARAM_INFERRABLE |
		                   G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingInfiniband:parent:
	 *
	 * The interface name of the parent device of this device. Normally %NULL,
	 * but if the #NMSettingInfiniband:p_key property is set, then you must
	 * specify the base device by setting either this property or
	 * #NMSettingInfiniband:mac-address.
	 **/
	g_object_class_install_property
		(object_class, PROP_PARENT,
		 g_param_spec_string (NM_SETTING_INFINIBAND_PARENT, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_CONSTRUCT |
		                      NM_SETTING_PARAM_INFERRABLE |
		                      G_PARAM_STATIC_STRINGS));

}
