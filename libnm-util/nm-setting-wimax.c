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
 * Copyright 2009 Novell, Inc.
 */

#include "nm-default.h"

#include <string.h>
#include <net/ethernet.h>
#include <dbus/dbus-glib.h>

#include "nm-setting-wimax.h"
#include "nm-param-spec-specialized.h"
#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-wimax
 * @short_description: Describes 802.16e Mobile WiMAX connection properties
 * @include: nm-setting-wimax.h
 *
 * The #NMSettingWimax object is a #NMSetting subclass that describes properties
 * necessary for connection to 802.16e Mobile WiMAX networks.
 *
 * NetworkManager no longer supports WiMAX; while this API remains available for
 * backward-compatibility reasons, it serves no real purpose, since WiMAX
 * connections cannot be activated.
 **/

/**
 * nm_setting_wimax_error_quark:
 *
 * Registers an error quark for #NMSettingWimax if necessary.
 *
 * Returns: the error quark used for #NMSettingWimax errors.
 *
 * Deprecated: 1.2: WiMAX is no longer supported.
 **/
GQuark
nm_setting_wimax_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-setting-wimax-error-quark");
	return quark;
}

G_DEFINE_TYPE_WITH_CODE (NMSettingWimax, nm_setting_wimax, NM_TYPE_SETTING,
                         _nm_register_setting (NM_SETTING_WIMAX_SETTING_NAME,
                                               g_define_type_id,
                                               1,
                                               NM_SETTING_WIMAX_ERROR))
NM_SETTING_REGISTER_TYPE (NM_TYPE_SETTING_WIMAX)

#define NM_SETTING_WIMAX_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_WIMAX, NMSettingWimaxPrivate))

typedef struct {
	char *network_name;
	GByteArray *mac_address;
} NMSettingWimaxPrivate;

enum {
	PROP_0,
	PROP_NETWORK_NAME,
	PROP_MAC_ADDRESS,

	LAST_PROP
};

/**
 * nm_setting_wimax_new:
 *
 * Creates a new #NMSettingWimax object with default values.
 *
 * Returns: the new empty #NMSettingWimax object
 *
 * Deprecated: 1.2: WiMAX is no longer supported.
 **/
NMSetting *
nm_setting_wimax_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_WIMAX, NULL);
}

/**
 * nm_setting_wimax_get_network_name:
 * @setting: the #NMSettingWimax
 *
 * Returns the WiMAX NSP name (ex "Sprint" or "CLEAR") which identifies the
 * specific WiMAX network this setting describes a connection to.
 *
 * Returns: the WiMAX NSP name
 *
 * Deprecated: 1.2: WiMAX is no longer supported.
 **/
const char *
nm_setting_wimax_get_network_name (NMSettingWimax *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIMAX (setting), NULL);

	return NM_SETTING_WIMAX_GET_PRIVATE (setting)->network_name;
}

/**
 * nm_setting_wimax_get_mac_address:
 * @setting: the #NMSettingWimax
 *
 * Returns the MAC address of a WiMAX device which this connection is locked
 * to.
 *
 * Returns: the MAC address
 *
 * Deprecated: 1.2: WiMAX is no longer supported.
 **/
const GByteArray *
nm_setting_wimax_get_mac_address (NMSettingWimax *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIMAX (setting), NULL);

	return NM_SETTING_WIMAX_GET_PRIVATE (setting)->mac_address;
}

static gboolean
verify (NMSetting *setting, GSList *all_settings, GError **error)
{
	NMSettingWimaxPrivate *priv = NM_SETTING_WIMAX_GET_PRIVATE (setting);

	if (!priv->network_name) {
		g_set_error_literal (error,
		                     NM_SETTING_WIMAX_ERROR,
		                     NM_SETTING_WIMAX_ERROR_MISSING_PROPERTY,
		                     _("property is missing"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIMAX_SETTING_NAME, NM_SETTING_WIMAX_NETWORK_NAME);
		return FALSE;
	}

	if (!strlen (priv->network_name)) {
		g_set_error_literal (error,
		                     NM_SETTING_WIMAX_ERROR,
		                     NM_SETTING_WIMAX_ERROR_INVALID_PROPERTY,
		                     _("property is empty"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIMAX_SETTING_NAME, NM_SETTING_WIMAX_NETWORK_NAME);
		return FALSE;
	}

	if (priv->mac_address && priv->mac_address->len != ETH_ALEN) {
		g_set_error_literal (error,
		                     NM_SETTING_WIMAX_ERROR,
		                     NM_SETTING_WIMAX_ERROR_INVALID_PROPERTY,
		                     _("property is invalid"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIMAX_SETTING_NAME, NM_SETTING_WIMAX_MAC_ADDRESS);
		return FALSE;
	}

	return TRUE;
}

static void
nm_setting_wimax_init (NMSettingWimax *setting)
{
}

static void
finalize (GObject *object)
{
	NMSettingWimaxPrivate *priv = NM_SETTING_WIMAX_GET_PRIVATE (object);

	g_free (priv->network_name);
	if (priv->mac_address)
		g_byte_array_free (priv->mac_address, TRUE);

	G_OBJECT_CLASS (nm_setting_wimax_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSettingWimaxPrivate *priv = NM_SETTING_WIMAX_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_NETWORK_NAME:
		g_free (priv->network_name);
		priv->network_name = g_value_dup_string (value);
		break;
	case PROP_MAC_ADDRESS:
		if (priv->mac_address)
			g_byte_array_free (priv->mac_address, TRUE);
		priv->mac_address = g_value_dup_boxed (value);
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
	NMSettingWimax *setting = NM_SETTING_WIMAX (object);

	switch (prop_id) {
	case PROP_NETWORK_NAME:
		g_value_set_string (value, nm_setting_wimax_get_network_name (setting));
		break;
	case PROP_MAC_ADDRESS:
		g_value_set_boxed (value, nm_setting_wimax_get_mac_address (setting));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_setting_wimax_class_init (NMSettingWimaxClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	g_type_class_add_private (setting_class, sizeof (NMSettingWimaxPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;
	parent_class->verify       = verify;

	/* Properties */
	/**
	 * NMSettingWimax:network-name:
	 *
	 * Network Service Provider (NSP) name of the WiMAX network this connection
	 * should use.
	 *
	 * Deprecated: 1.2: WiMAX is no longer supported.
	 **/
	g_object_class_install_property
		(object_class, PROP_NETWORK_NAME,
		 g_param_spec_string (NM_SETTING_WIMAX_NETWORK_NAME, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingWimax:mac-address:
	 *
	 * If specified, this connection will only apply to the WiMAX device whose
	 * MAC address matches. This property does not change the MAC address of the
	 * device (known as MAC spoofing).
	 *
	 * Deprecated: 1.2: WiMAX is no longer supported.
	 **/
	g_object_class_install_property
		(object_class, PROP_MAC_ADDRESS,
		 _nm_param_spec_specialized (NM_SETTING_WIMAX_MAC_ADDRESS, "", "",
		                             DBUS_TYPE_G_UCHAR_ARRAY,
		                             G_PARAM_READWRITE |
		                             G_PARAM_STATIC_STRINGS));
}
