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
 * Copyright 2015 Red Hat, Inc.
 */

#include "nm-default.h"

#include <stdlib.h>
#include <string.h>

#include "nm-setting-tun.h"
#include "nm-utils.h"
#include "nm-setting-connection.h"
#include "nm-setting-private.h"
#include "nm-connection-private.h"

/**
 * SECTION:nm-setting-tun
 * @short_description: Describes connection properties for TUN/TAP interfaces
 *
 * The #NMSettingTun object is a #NMSetting subclass that describes properties
 * necessary for connection to TUN/TAP interfaces.
 **/

G_DEFINE_TYPE_WITH_CODE (NMSettingTun, nm_setting_tun, NM_TYPE_SETTING,
                         _nm_register_setting (TUN, 1))
NM_SETTING_REGISTER_TYPE (NM_TYPE_SETTING_TUN)

#define NM_SETTING_TUN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_TUN, NMSettingTunPrivate))

typedef struct {
	NMSettingTunMode mode;
	char *owner;
	char *group;
	gboolean pi;
	gboolean vnet_hdr;
	gboolean multi_queue;
} NMSettingTunPrivate;

enum {
	PROP_0,
	PROP_MODE,
	PROP_OWNER,
	PROP_GROUP,
	PROP_PI,
	PROP_VNET_HDR,
	PROP_MULTI_QUEUE,
	LAST_PROP
};

/**
 * nm_setting_tun_new:
 *
 * Creates a new #NMSettingTun object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingTun object
 *
 * Since: 1.2
 **/
NMSetting *
nm_setting_tun_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_TUN, NULL);
}

/**
 * nm_setting_tun_get_mode:
 * @setting: the #NMSettingTun
 *
 * Returns: the #NMSettingTun:mode property of the setting
 *
 * Since: 1.2
 **/
NMSettingTunMode
nm_setting_tun_get_mode (NMSettingTun *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TUN (setting), NM_SETTING_TUN_MODE_TUN);
	return NM_SETTING_TUN_GET_PRIVATE (setting)->mode;
}

/**
 * nm_setting_tun_get_owner:
 * @setting: the #NMSettingTun
 *
 * Returns: the #NMSettingTun:owner property of the setting
 *
 * Since: 1.2
 **/
const char *
nm_setting_tun_get_owner (NMSettingTun *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TUN (setting), NULL);
	return NM_SETTING_TUN_GET_PRIVATE (setting)->owner;
}

/**
 * nm_setting_tun_get_group:
 * @setting: the #NMSettingTun
 *
 * Returns: the #NMSettingTun:group property of the setting
 *
 * Since: 1.2
 **/
const char *
nm_setting_tun_get_group (NMSettingTun *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TUN (setting), NULL);
	return NM_SETTING_TUN_GET_PRIVATE (setting)->group;
}

/**
 * nm_setting_tun_get_pi:
 * @setting: the #NMSettingTun
 *
 * Returns: the #NMSettingTun:pi property of the setting
 *
 * Since: 1.2
 **/
gboolean
nm_setting_tun_get_pi (NMSettingTun *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TUN (setting), FALSE);
	return NM_SETTING_TUN_GET_PRIVATE (setting)->pi;
}

/**
 * nm_setting_tun_get_vnet_hdr:
 * @setting: the #NMSettingTun
 *
 * Returns: the #NMSettingTun:vnet_hdr property of the setting
 *
 * Since: 1.2
 **/
gboolean
nm_setting_tun_get_vnet_hdr (NMSettingTun *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TUN (setting), FALSE);
	return NM_SETTING_TUN_GET_PRIVATE (setting)->vnet_hdr;
}

/**
 * nm_setting_tun_get_multi_queue:
 * @setting: the #NMSettingTun
 *
 * Returns: the #NMSettingTun:multi-queue property of the setting
 *
 * Since: 1.2
 **/
gboolean
nm_setting_tun_get_multi_queue (NMSettingTun *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TUN (setting), FALSE);
	return NM_SETTING_TUN_GET_PRIVATE (setting)->multi_queue;
}

static void
nm_setting_tun_init (NMSettingTun *setting)
{
}

static gboolean
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSettingTunPrivate *priv = NM_SETTING_TUN_GET_PRIVATE (setting);

	if (   priv->mode != NM_SETTING_TUN_MODE_TUN
	    && priv->mode != NM_SETTING_TUN_MODE_TAP) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("'%u': invalid mode"), (unsigned int) priv->mode);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_TUN_SETTING_NAME, NM_SETTING_TUN_MODE);
		return FALSE;
	}

	if (priv->owner) {
		if (_nm_utils_ascii_str_to_int64 (priv->owner, 10, 0, G_MAXINT32, -1) == -1) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("'%s': invalid user ID"), priv->owner);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_TUN_SETTING_NAME, NM_SETTING_TUN_OWNER);
			return FALSE;
		}
	}

	if (priv->group) {
		if (_nm_utils_ascii_str_to_int64 (priv->group, 10, 0, G_MAXINT32, -1) == -1) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("'%s': invalid group ID"), priv->group);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_TUN_SETTING_NAME, NM_SETTING_TUN_GROUP);
			return FALSE;
		}
	}

	return TRUE;
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSettingTun *setting = NM_SETTING_TUN (object);
	NMSettingTunPrivate *priv = NM_SETTING_TUN_GET_PRIVATE (setting);

	switch (prop_id) {
	case PROP_MODE:
		priv->mode = g_value_get_uint (value);
		break;
	case PROP_OWNER:
		g_free (priv->owner);
		priv->owner = g_value_dup_string (value);
		break;
	case PROP_GROUP:
		g_free (priv->group);
		priv->group = g_value_dup_string (value);
		break;
	case PROP_PI:
		priv->pi = g_value_get_boolean (value);
		break;
	case PROP_VNET_HDR:
		priv->vnet_hdr = g_value_get_boolean (value);
		break;
	case PROP_MULTI_QUEUE:
		priv->multi_queue = g_value_get_boolean (value);
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
	NMSettingTun *setting = NM_SETTING_TUN (object);
	NMSettingTunPrivate *priv = NM_SETTING_TUN_GET_PRIVATE (setting);

	switch (prop_id) {
	case PROP_MODE:
		g_value_set_uint (value, priv->mode);
		break;
	case PROP_OWNER:
		g_value_set_string (value, priv->owner);
		break;
	case PROP_GROUP:
		g_value_set_string (value, priv->group);
		break;
	case PROP_PI:
		g_value_set_boolean (value, priv->pi);
		break;
	case PROP_VNET_HDR:
		g_value_set_boolean (value, priv->vnet_hdr);
		break;
	case PROP_MULTI_QUEUE:
		g_value_set_boolean (value, priv->multi_queue);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
finalize (GObject *object)
{
	NMSettingTun *setting = NM_SETTING_TUN (object);
	NMSettingTunPrivate *priv = NM_SETTING_TUN_GET_PRIVATE (setting);

	g_free (priv->owner);
	g_free (priv->group);

	G_OBJECT_CLASS (nm_setting_tun_parent_class)->finalize (object);
}

static void
nm_setting_tun_class_init (NMSettingTunClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	g_type_class_add_private (setting_class, sizeof (NMSettingTunPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;
	parent_class->verify       = verify;

	/* Properties */
	/**
	 * NMSettingTun:mode:
	 *
	 * The operating mode of the virtual device. Allowed values are
	 * %NM_SETTING_TUN_MODE_TUN to create a layer 3 device and
	 * %NM_SETTING_TUN_MODE_TAP to create an Ethernet-like layer 2
	 * one.
	 *
	 * Since: 1.2
	 */
	g_object_class_install_property
		(object_class, PROP_MODE,
		 g_param_spec_uint (NM_SETTING_TUN_MODE, "", "",
		                    0, G_MAXUINT, NM_SETTING_TUN_MODE_TUN,
		                    G_PARAM_READWRITE |
		                    G_PARAM_CONSTRUCT |
		                    NM_SETTING_PARAM_INFERRABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingTun:owner:
	 *
	 * The user ID which will own the device. If set to %NULL everyone
	 * will be able to use the device.
	 *
	 * Since: 1.2
	 */
	g_object_class_install_property
		(object_class, PROP_OWNER,
		 g_param_spec_string (NM_SETTING_TUN_OWNER, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      NM_SETTING_PARAM_INFERRABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingTun:group:
	 *
	 * The group ID which will own the device. If set to %NULL everyone
	 * will be able to use the device.
	 *
	 * Since: 1.2
	 */
	g_object_class_install_property
		(object_class, PROP_GROUP,
		 g_param_spec_string (NM_SETTING_TUN_GROUP, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      NM_SETTING_PARAM_INFERRABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingTun:pi:
	 *
	 * If %TRUE the interface will prepend a 4 byte header describing the
	 * physical interface to the packets.
	 *
	 * Since: 1.2
	 */
	g_object_class_install_property
		(object_class, PROP_PI,
		 g_param_spec_boolean (NM_SETTING_TUN_PI, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       NM_SETTING_PARAM_INFERRABLE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingTun:vnet-hdr:
	 *
	 * If %TRUE the IFF_VNET_HDR the tunnel packets will include a virtio
	 * network header.
	 *
	 * Since: 1.2
	 */
	g_object_class_install_property
		(object_class, PROP_VNET_HDR,
		 g_param_spec_boolean (NM_SETTING_TUN_VNET_HDR, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       NM_SETTING_PARAM_INFERRABLE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingTun:multi-queue:
	 *
	 * If the property is set to %TRUE, the interface will support
	 * multiple file descriptors (queues) to parallelize packet
	 * sending or receiving. Otherwise, the interface will only
	 * support a single queue.
	 *
	 * Since: 1.2
	 */
	g_object_class_install_property
		(object_class, PROP_MULTI_QUEUE,
		 g_param_spec_boolean (NM_SETTING_TUN_MULTI_QUEUE, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       NM_SETTING_PARAM_INFERRABLE |
		                       G_PARAM_STATIC_STRINGS));
}
