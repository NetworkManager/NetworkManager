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
 * Copyright 2011 Red Hat, Inc.
 */

#include <dbus/dbus-glib.h>
#include <linux/if_infiniband.h>

#include "nm-setting-infiniband.h"
#include "nm-param-spec-specialized.h"
#include "nm-utils-private.h"
#include "nm-setting-private.h"

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
} NMSettingInfinibandPrivate;

enum {
	PROP_0,
	PROP_MAC_ADDRESS,
	PROP_MTU,
	PROP_TRANSPORT_MODE,

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


static gboolean
verify (NMSetting *setting, GSList *all_settings, GError **error)
{
	NMSettingInfinibandPrivate *priv = NM_SETTING_INFINIBAND_GET_PRIVATE (setting);

	if (priv->mac_address && priv->mac_address->len != INFINIBAND_ALEN) {
		g_set_error (error,
		             NM_SETTING_INFINIBAND_ERROR,
		             NM_SETTING_INFINIBAND_ERROR_INVALID_PROPERTY,
		             NM_SETTING_INFINIBAND_MAC_ADDRESS);
		return FALSE;
	}

	if (!g_strcmp0 (priv->transport_mode, "datagram")) {
		if (priv->mtu > 2044)
			priv->mtu = 2044;
	} else if (!g_strcmp0 (priv->transport_mode, "connected")) {
		if (priv->mtu > 65520)
			priv->mtu = 65520;
	} else {
		g_set_error (error,
		             NM_SETTING_INFINIBAND_ERROR,
		             NM_SETTING_INFINIBAND_ERROR_INVALID_PROPERTY,
		             NM_SETTING_INFINIBAND_TRANSPORT_MODE);
		return FALSE;
	}

	return TRUE;
}

static void
nm_setting_infiniband_init (NMSettingInfiniband *setting)
{
	g_object_set (setting, NM_SETTING_NAME, NM_SETTING_INFINIBAND_SETTING_NAME, NULL);
}

static void
finalize (GObject *object)
{
	NMSettingInfinibandPrivate *priv = NM_SETTING_INFINIBAND_GET_PRIVATE (object);

	g_free (priv->transport_mode);
	if (priv->mac_address)
		g_byte_array_free (priv->mac_address, TRUE);

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
	parent_class->verify       = verify;

	/* Properties */
	/**
	 * NMSettingInfiniband:mac-address:
	 *
	 * If specified, this connection will only apply to the IPoIB
	 * device whose permanent MAC address matches. This property does
	 * not change the MAC address of the device (i.e. MAC spoofing).
	 **/
	g_object_class_install_property
		(object_class, PROP_MAC_ADDRESS,
		 _nm_param_spec_specialized (NM_SETTING_INFINIBAND_MAC_ADDRESS,
		                             "Device MAC Address",
		                             "If specified, this connection will only apply to "
		                             "the IPoIB device whose permanent MAC address matches.  "
		                             "This property does not change the MAC address "
		                             "of the device (i.e. MAC spoofing).",
		                             DBUS_TYPE_G_UCHAR_ARRAY,
		                             G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingInfiniband:mtu:
	 *
	 * If non-zero, only transmit packets of the specified size or smaller,
	 * breaking larger packets up into multiple frames.
	 **/
	g_object_class_install_property
		(object_class, PROP_MTU,
		 g_param_spec_uint (NM_SETTING_INFINIBAND_MTU,
		                    "MTU",
		                    "If non-zero, only transmit packets of the specified "
		                    "size or smaller, breaking larger packets up into "
		                    "multiple frames.",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_FUZZY_IGNORE));

	/**
	 * NMSettingInfiniband:transport-mode:
	 *
	 * The IP-over-InfiniBand transport mode. Either 'datagram' or
	 * 'connected'.
	 **/
	g_object_class_install_property
		(object_class, PROP_TRANSPORT_MODE,
		 g_param_spec_string (NM_SETTING_INFINIBAND_TRANSPORT_MODE,
							  "Transport Mode",
							  "The IPoIB transport mode. Either 'datagram' or 'connected'.",
							  NULL,
							  G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE));
}

