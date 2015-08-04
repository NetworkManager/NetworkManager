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

#include "config.h"

#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#include "nm-setting-bridge.h"
#include "nm-connection-private.h"
#include "nm-utils.h"
#include "nm-utils-private.h"

/**
 * SECTION:nm-setting-bridge
 * @short_description: Describes connection properties for bridges
 *
 * The #NMSettingBridge object is a #NMSetting subclass that describes properties
 * necessary for bridging connections.
 **/

G_DEFINE_TYPE_WITH_CODE (NMSettingBridge, nm_setting_bridge, NM_TYPE_SETTING,
                         _nm_register_setting (BRIDGE, 1))
NM_SETTING_REGISTER_TYPE (NM_TYPE_SETTING_BRIDGE)

#define NM_SETTING_BRIDGE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_BRIDGE, NMSettingBridgePrivate))

typedef struct {
	char *   mac_address;
	gboolean stp;
	guint16  priority;
	guint16  forward_delay;
	guint16  hello_time;
	guint16  max_age;
	guint32  ageing_time;
	gboolean multicast_snooping;
} NMSettingBridgePrivate;

enum {
	PROP_0,
	PROP_MAC_ADDRESS,
	PROP_STP,
	PROP_PRIORITY,
	PROP_FORWARD_DELAY,
	PROP_HELLO_TIME,
	PROP_MAX_AGE,
	PROP_AGEING_TIME,
	PROP_MULTICAST_SNOOPING,
	LAST_PROP
};

/**
 * nm_setting_bridge_new:
 *
 * Creates a new #NMSettingBridge object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingBridge object
 **/
NMSetting *
nm_setting_bridge_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_BRIDGE, NULL);
}

/**
 * nm_setting_bridge_get_mac_address:
 * @setting: the #NMSettingBridge
 *
 * Returns: the #NMSettingBridge:mac-address property of the setting
 **/
const char *
nm_setting_bridge_get_mac_address (NMSettingBridge *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BRIDGE (setting), NULL);

	return NM_SETTING_BRIDGE_GET_PRIVATE (setting)->mac_address;
}

/**
 * nm_setting_bridge_get_stp:
 * @setting: the #NMSettingBridge
 *
 * Returns: the #NMSettingBridge:stp property of the setting
 **/
gboolean
nm_setting_bridge_get_stp (NMSettingBridge *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BRIDGE (setting), FALSE);

	return NM_SETTING_BRIDGE_GET_PRIVATE (setting)->stp;
}

/**
 * nm_setting_bridge_get_priority:
 * @setting: the #NMSettingBridge
 *
 * Returns: the #NMSettingBridge:priority property of the setting
 **/
guint16
nm_setting_bridge_get_priority (NMSettingBridge *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BRIDGE (setting), 0);

	return NM_SETTING_BRIDGE_GET_PRIVATE (setting)->priority;
}

/**
 * nm_setting_bridge_get_forward_delay:
 * @setting: the #NMSettingBridge
 *
 * Returns: the #NMSettingBridge:forward-delay property of the setting
 **/
guint16
nm_setting_bridge_get_forward_delay (NMSettingBridge *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BRIDGE (setting), 0);

	return NM_SETTING_BRIDGE_GET_PRIVATE (setting)->forward_delay;
}

/**
 * nm_setting_bridge_get_hello_time:
 * @setting: the #NMSettingBridge
 *
 * Returns: the #NMSettingBridge:hello-time property of the setting
 **/
guint16
nm_setting_bridge_get_hello_time (NMSettingBridge *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BRIDGE (setting), 0);

	return NM_SETTING_BRIDGE_GET_PRIVATE (setting)->hello_time;
}

/**
 * nm_setting_bridge_get_max_age:
 * @setting: the #NMSettingBridge
 *
 * Returns: the #NMSettingBridge:max-age property of the setting
 **/
guint16
nm_setting_bridge_get_max_age (NMSettingBridge *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BRIDGE (setting), 0);

	return NM_SETTING_BRIDGE_GET_PRIVATE (setting)->max_age;
}

/**
 * nm_setting_bridge_get_ageing_time:
 * @setting: the #NMSettingBridge
 *
 * Returns: the #NMSettingBridge:ageing-time property of the setting
 **/
guint
nm_setting_bridge_get_ageing_time (NMSettingBridge *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BRIDGE (setting), 0);

	return NM_SETTING_BRIDGE_GET_PRIVATE (setting)->ageing_time;
}

/**
 * nm_setting_bridge_get_multicast_snooping:
 * @setting: the #NMSettingBridge
 *
 * Returns: the #NMSettingBridge:multicast-snooping property of the setting
 *
 * Since: 1.2
 **/
gboolean
nm_setting_bridge_get_multicast_snooping (NMSettingBridge *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BRIDGE (setting), FALSE);

	return NM_SETTING_BRIDGE_GET_PRIVATE (setting)->multicast_snooping;
}

/* IEEE 802.1D-1998 timer values */
#define BR_MIN_HELLO_TIME    1
#define BR_MAX_HELLO_TIME    10

#define BR_MIN_FORWARD_DELAY 2
#define BR_MAX_FORWARD_DELAY 30

#define BR_MIN_MAX_AGE       6
#define BR_MAX_MAX_AGE       40

/* IEEE 802.1D-1998 Table 7.4 */
#define BR_MIN_AGEING_TIME   0
#define BR_MAX_AGEING_TIME   1000000

static inline gboolean
check_range (guint32 val,
             guint32 min,
             guint32 max,
             gboolean zero,
             const char *prop,
             GError **error)
{
	if (zero && val == 0)
		return TRUE;

	if (val < min || val > max) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("value '%d' is out of range <%d-%d>"),
		             val, min, max);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_BRIDGE_SETTING_NAME, prop);
		return FALSE;
	}
	return TRUE;
}

static gboolean
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSettingBridgePrivate *priv = NM_SETTING_BRIDGE_GET_PRIVATE (setting);

	if (priv->mac_address && !nm_utils_hwaddr_valid (priv->mac_address, ETH_ALEN)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("is not a valid MAC address"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_BRIDGE_SETTING_NAME, NM_SETTING_BRIDGE_MAC_ADDRESS);
		return FALSE;
	}

	if (!check_range (priv->forward_delay,
	                  BR_MIN_FORWARD_DELAY,
	                  BR_MAX_FORWARD_DELAY,
	                  !priv->stp,
	                  NM_SETTING_BRIDGE_FORWARD_DELAY,
	                  error))
		return FALSE;

	if (!check_range (priv->hello_time,
	                  BR_MIN_HELLO_TIME,
	                  BR_MAX_HELLO_TIME,
	                  !priv->stp,
	                  NM_SETTING_BRIDGE_HELLO_TIME,
	                  error))
		return FALSE;

	if (!check_range (priv->max_age,
	                  BR_MIN_MAX_AGE,
	                  BR_MAX_MAX_AGE,
	                  !priv->stp,
	                  NM_SETTING_BRIDGE_MAX_AGE,
	                  error))
		return FALSE;

	if (!check_range (priv->ageing_time,
	                  BR_MIN_AGEING_TIME,
	                  BR_MAX_AGEING_TIME,
	                  !priv->stp,
	                  NM_SETTING_BRIDGE_AGEING_TIME,
	                  error))
		return FALSE;

	return _nm_connection_verify_required_interface_name (connection, error);
}

static void
nm_setting_bridge_init (NMSettingBridge *setting)
{
}

static void
finalize (GObject *object)
{
	NMSettingBridgePrivate *priv = NM_SETTING_BRIDGE_GET_PRIVATE (object);

	g_free (priv->mac_address);

	G_OBJECT_CLASS (nm_setting_bridge_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSettingBridgePrivate *priv = NM_SETTING_BRIDGE_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_MAC_ADDRESS:
		g_free (priv->mac_address);
		priv->mac_address = _nm_utils_hwaddr_canonical_or_invalid (g_value_get_string (value),
		                                                           ETH_ALEN);
		break;
	case PROP_STP:
		priv->stp = g_value_get_boolean (value);
		break;
	case PROP_PRIORITY:
		priv->priority = (guint16) g_value_get_uint (value);
		break;
	case PROP_FORWARD_DELAY:
		priv->forward_delay = (guint16) g_value_get_uint (value);
		break;
	case PROP_HELLO_TIME:
		priv->hello_time = (guint16) g_value_get_uint (value);
		break;
	case PROP_MAX_AGE:
		priv->max_age = (guint16) g_value_get_uint (value);
		break;
	case PROP_AGEING_TIME:
		priv->ageing_time = g_value_get_uint (value);
		break;
	case PROP_MULTICAST_SNOOPING:
		priv->multicast_snooping = g_value_get_boolean (value);
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
	NMSettingBridgePrivate *priv = NM_SETTING_BRIDGE_GET_PRIVATE (object);
	NMSettingBridge *setting = NM_SETTING_BRIDGE (object);

	switch (prop_id) {
	case PROP_MAC_ADDRESS:
		g_value_set_string (value, nm_setting_bridge_get_mac_address (setting));
		break;
	case PROP_STP:
		g_value_set_boolean (value, priv->stp);
		break;
	case PROP_PRIORITY:
		g_value_set_uint (value, priv->priority);
		break;
	case PROP_FORWARD_DELAY:
		g_value_set_uint (value, priv->forward_delay);
		break;
	case PROP_HELLO_TIME:
		g_value_set_uint (value, priv->hello_time);
		break;
	case PROP_MAX_AGE:
		g_value_set_uint (value, priv->max_age);
		break;
	case PROP_AGEING_TIME:
		g_value_set_uint (value, priv->ageing_time);
		break;
	case PROP_MULTICAST_SNOOPING:
		g_value_set_boolean (value, priv->multicast_snooping);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_setting_bridge_class_init (NMSettingBridgeClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	g_type_class_add_private (setting_class, sizeof (NMSettingBridgePrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;
	parent_class->verify       = verify;

	/* Properties */
	/**
	 * NMSettingBridge:mac-address:
	 *
	 * If specified, the MAC address of bridge. When creating a new bridge, this
	 * MAC address will be set. When matching an existing (outside
	 * NetworkManager created) bridge, this MAC address must match.
	 **/
	/* ---keyfile---
	 * property: mac-address
	 * format: ususal hex-digits-and-colons notation
	 * description: MAC address in traditional hex-digits-and-colons notation,
	 *   or semicolon separated list of 6 decimal bytes (obsolete)
	 * example: mac-address=00:22:68:12:79:A2
	 *  mac-address=0;34;104;18;121;162;
	 * ---end---
	 * ---ifcfg-rh---
	 * property: mac-address
	 * variable: MACADDR(+)
	 * description: MAC address of the bridge. Note that this requires a recent
	 *   kernel support, originally introduced in 3.15 upstream kernel)
	 *   MACADDR for bridges is an NM extension.
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_MAC_ADDRESS,
		 g_param_spec_string (NM_SETTING_BRIDGE_MAC_ADDRESS, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      NM_SETTING_PARAM_INFERRABLE |
		                      G_PARAM_STATIC_STRINGS));
	_nm_setting_class_transform_property (parent_class, NM_SETTING_BRIDGE_MAC_ADDRESS,
	                                      G_VARIANT_TYPE_BYTESTRING,
	                                      _nm_utils_hwaddr_to_dbus,
	                                      _nm_utils_hwaddr_from_dbus);

	/**
	 * NMSettingBridge:stp:
	 *
	 * Controls whether Spanning Tree Protocol (STP) is enabled for this bridge.
	 **/
	/* ---ifcfg-rh---
	 * property: stp
	 * variable: STP
	 * default: no
	 * description: Span tree protocol participation.
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_STP,
		 g_param_spec_boolean (NM_SETTING_BRIDGE_STP, "", "",
		                       TRUE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT |
		                       NM_SETTING_PARAM_INFERRABLE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingBridge:priority:
	 *
	 * Sets the Spanning Tree Protocol (STP) priority for this bridge.  Lower
	 * values are "better"; the lowest priority bridge will be elected the root
	 * bridge.
	 **/
	/* ---ifcfg-rh---
	 * property: priority
	 * variable: BRIDGING_OPTS: priority=
	 * values: 0 - 32768
	 * default: 32768
	 * description: STP priority.
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_PRIORITY,
		 g_param_spec_uint (NM_SETTING_BRIDGE_PRIORITY, "", "",
		                    0, G_MAXUINT16, 0x8000,
		                    G_PARAM_READWRITE |
		                    G_PARAM_CONSTRUCT |
		                    NM_SETTING_PARAM_INFERRABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingBridge:forward-delay:
	 *
	 * The Spanning Tree Protocol (STP) forwarding delay, in seconds.
	 **/
	/* ---ifcfg-rh---
	 * property: forward-delay
	 * variable: DELAY
	 * values: 2 - 30
	 * default: 15
	 * description: STP forwarding delay.
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_FORWARD_DELAY,
		 g_param_spec_uint (NM_SETTING_BRIDGE_FORWARD_DELAY, "", "",
		                    0, BR_MAX_FORWARD_DELAY, 15,
		                    G_PARAM_READWRITE |
		                    G_PARAM_CONSTRUCT |
		                    NM_SETTING_PARAM_INFERRABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingBridge:hello-time:
	 *
	 * The Spanning Tree Protocol (STP) hello time, in seconds.
	 **/
	/* ---ifcfg-rh---
	 * property: hello-time
	 * variable: BRIDGING_OPTS: hello_time=
	 * values: 1 - 10
	 * default: 2
	 * description: STP hello time.
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_HELLO_TIME,
		 g_param_spec_uint (NM_SETTING_BRIDGE_HELLO_TIME, "", "",
		                    0, BR_MAX_HELLO_TIME, 2,
		                    G_PARAM_READWRITE |
		                    G_PARAM_CONSTRUCT |
		                    NM_SETTING_PARAM_INFERRABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingBridge:max-age:
	 *
	 * The Spanning Tree Protocol (STP) maximum message age, in seconds.
	 **/
	/* ---ifcfg-rh---
	 * property: max-age
	 * variable: BRIDGING_OPTS: max_age=
	 * values: 6 - 40
	 * default: 20
	 * description: STP maximum message age.
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_MAX_AGE,
		 g_param_spec_uint (NM_SETTING_BRIDGE_MAX_AGE, "", "",
		                    0, BR_MAX_MAX_AGE, 20,
		                    G_PARAM_READWRITE |
		                    G_PARAM_CONSTRUCT |
		                    NM_SETTING_PARAM_INFERRABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingBridge:ageing-time:
	 *
	 * The Ethernet MAC address aging time, in seconds.
	 **/
	/* ---ifcfg-rh---
	 * property: ageing-time
	 * variable: BRIDGING_OPTS: ageing_time=
	 * values: 0 - 1000000
	 * default: 300
	 * description: Ethernet MAC ageing time.
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_AGEING_TIME,
		 g_param_spec_uint (NM_SETTING_BRIDGE_AGEING_TIME, "", "",
		                    0, BR_MAX_AGEING_TIME, 300,
		                    G_PARAM_READWRITE |
		                    G_PARAM_CONSTRUCT |
		                    NM_SETTING_PARAM_INFERRABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingBridge:multicast-snooping:
	 *
	 * Controls whether IGMP snooping is enabled for this bridge.
	 * Note that if snooping was automatically disabled due to hash collisions,
	 * the system may refuse to enable the feature until the collisions are
	 * resolved.
	 *
	 * Since: 1.2
	 **/
	/* ---ifcfg-rh---
	 * property: multicast-snooping
	 * variable: BRIDGING_OPTS: multicast_snooping=
	 * values: 0 or 1
	 * default: 1
	 * description: IGMP snooping support.
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_MULTICAST_SNOOPING,
		 g_param_spec_boolean (NM_SETTING_BRIDGE_MULTICAST_SNOOPING, "", "",
		                       TRUE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT |
		                       NM_SETTING_PARAM_INFERRABLE |
		                       G_PARAM_STATIC_STRINGS));

	/* ---dbus---
	 * property: interface-name
	 * format: string
	 * description: Deprecated in favor of connection.interface-name, but can
	 *   be used for backward-compatibility with older daemons, to set the
	 *   bridge's interface name.
	 * ---end---
	 */
	_nm_setting_class_add_dbus_only_property (parent_class, "interface-name",
	                                          G_VARIANT_TYPE_STRING,
	                                          _nm_setting_get_deprecated_virtual_interface_name,
	                                          NULL);
}
