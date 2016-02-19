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
 * Copyright 2012 - 2013 Red Hat, Inc.
 */

#include "nm-default.h"

#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <dbus/dbus-glib.h>

#include "nm-setting-bridge-port.h"
#include "nm-utils.h"
#include "nm-utils-private.h"
#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-bridge-port
 * @short_description: Describes connection properties for bridge ports
 * @include: nm-setting-bridge-port.h
 *
 * The #NMSettingBridgePort object is a #NMSetting subclass that describes
 * optional properties that apply to bridge ports.
 *
 * Since: 0.9.8
 **/

/**
 * nm_setting_bridge_port_error_quark:
 *
 * Registers an error quark for #NMSettingBridgePort if necessary.
 *
 * Returns: the error quark used for #NMSettingBridgePort errors.
 *
 * Since: 0.9.8
 **/
GQuark
nm_setting_bridge_port_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-setting-bridge-port-error-quark");
	return quark;
}

G_DEFINE_TYPE_WITH_CODE (NMSettingBridgePort, nm_setting_bridge_port, NM_TYPE_SETTING,
                         _nm_register_setting (NM_SETTING_BRIDGE_PORT_SETTING_NAME,
                                               g_define_type_id,
                                               3,
                                               NM_SETTING_BRIDGE_PORT_ERROR))
NM_SETTING_REGISTER_TYPE (NM_TYPE_SETTING_BRIDGE_PORT)

#define NM_SETTING_BRIDGE_PORT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_BRIDGE_PORT, NMSettingBridgePortPrivate))

typedef struct {
	guint16 priority;
	guint16 path_cost;
	gboolean hairpin_mode;
} NMSettingBridgePortPrivate;

enum {
	PROP_0,
	PROP_PRIORITY,
	PROP_PATH_COST,
	PROP_HAIRPIN_MODE,
	LAST_PROP
};

/**************************************************************************/

/**
 * nm_setting_bridge_port_get_priority:
 * @setting: the #NMSettingBridgePort
 *
 * Returns: the #NMSettingBridgePort:priority property of the setting
 *
 * Since: 0.9.8
 **/
guint16
nm_setting_bridge_port_get_priority (NMSettingBridgePort *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BRIDGE_PORT (setting), 0);

	return NM_SETTING_BRIDGE_PORT_GET_PRIVATE (setting)->priority;
}

/**
 * nm_setting_bridge_port_get_path_cost:
 * @setting: the #NMSettingBridgePort
 *
 * Returns: the #NMSettingBridgePort:path-cost property of the setting
 *
 * Since: 0.9.8
 **/
guint16
nm_setting_bridge_port_get_path_cost (NMSettingBridgePort *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BRIDGE_PORT (setting), 0);

	return NM_SETTING_BRIDGE_PORT_GET_PRIVATE (setting)->path_cost;
}

/**
 * nm_setting_bridge_port_get_hairpin_mode:
 * @setting: the #NMSettingBridgePort
 *
 * Returns: the #NMSettingBridgePort:hairpin-mode property of the setting
 *
 * Since: 0.9.8
 **/
gboolean
nm_setting_bridge_port_get_hairpin_mode (NMSettingBridgePort *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BRIDGE_PORT (setting), FALSE);

	return NM_SETTING_BRIDGE_PORT_GET_PRIVATE (setting)->hairpin_mode;
}

/**************************************************************************/

#define BR_MAX_PORT_PRIORITY 63
#define BR_DEF_PRIORITY      32

#define BR_MIN_PATH_COST     1
#define BR_MAX_PATH_COST     65535

static gboolean
verify (NMSetting *setting, GSList *all_settings, GError **error)
{
	NMSettingBridgePortPrivate *priv = NM_SETTING_BRIDGE_PORT_GET_PRIVATE (setting);

	if (priv->priority > BR_MAX_PORT_PRIORITY) {
		g_set_error (error,
		             NM_SETTING_BRIDGE_PORT_ERROR,
		             NM_SETTING_BRIDGE_PORT_ERROR_INVALID_PROPERTY,
		             _("'%d' is not a valid value for the property (should be <= %d)"),
		             priv->priority, BR_MAX_PORT_PRIORITY);
		g_prefix_error (error, "%s.%s: ",
		                NM_SETTING_BRIDGE_PORT_SETTING_NAME,
		                NM_SETTING_BRIDGE_PORT_PRIORITY);
		return FALSE;
	}

	if (priv->path_cost > BR_MAX_PATH_COST) {
		g_set_error (error,
		             NM_SETTING_BRIDGE_PORT_ERROR,
		             NM_SETTING_BRIDGE_PORT_ERROR_INVALID_PROPERTY,
		             _("'%d' is not a valid value for the property (should be <= %d)"),
		             priv->path_cost, BR_MAX_PATH_COST);
		g_prefix_error (error, "%s.%s: ",
		                NM_SETTING_BRIDGE_PORT_SETTING_NAME,
		                NM_SETTING_BRIDGE_PORT_PATH_COST);
		return FALSE;
	}

	return TRUE;
}

/**************************************************************************/

/**
 * nm_setting_bridge_port_new:
 *
 * Creates a new #NMSettingBridgePort object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingBridgePort object
 *
 * Since: 0.9.8
 **/
NMSetting *
nm_setting_bridge_port_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_BRIDGE_PORT, NULL);
}

static void
nm_setting_bridge_port_init (NMSettingBridgePort *setting)
{
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSettingBridgePortPrivate *priv = NM_SETTING_BRIDGE_PORT_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_PRIORITY:
		priv->priority = (guint16) (g_value_get_uint (value) & 0xFFFF);
		break;
	case PROP_PATH_COST:
		priv->path_cost = (guint16) (g_value_get_uint (value) & 0xFFFF);
		break;
	case PROP_HAIRPIN_MODE:
		priv->hairpin_mode = g_value_get_boolean (value);
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
	NMSettingBridgePortPrivate *priv = NM_SETTING_BRIDGE_PORT_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_PRIORITY:
		g_value_set_uint (value, priv->priority);
		break;
	case PROP_PATH_COST:
		g_value_set_uint (value, priv->path_cost);
		break;
	case PROP_HAIRPIN_MODE:
		g_value_set_boolean (value, priv->hairpin_mode);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_setting_bridge_port_class_init (NMSettingBridgePortClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	g_type_class_add_private (setting_class, sizeof (NMSettingBridgePortPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	parent_class->verify       = verify;

	/* Properties */
	/**
	 * NMSettingBridgePort:priority:
	 *
	 * The Spanning Tree Protocol (STP) priority of this bridge port.
	 *
	 * Since: 0.9.8
	 **/
	g_object_class_install_property
		(object_class, PROP_PRIORITY,
		 g_param_spec_uint (NM_SETTING_BRIDGE_PORT_PRIORITY, "", "",
		                    0, BR_MAX_PORT_PRIORITY, BR_DEF_PRIORITY,
		                    G_PARAM_READWRITE |
		                    G_PARAM_CONSTRUCT |
		                    NM_SETTING_PARAM_INFERRABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingBridgePort:path-cost:
	 *
	 * The Spanning Tree Protocol (STP) port cost for destinations via this
	 * port.
	 *
	 * Since: 0.9.8
	 **/
	g_object_class_install_property
		(object_class, PROP_PATH_COST,
		 g_param_spec_uint (NM_SETTING_BRIDGE_PORT_PATH_COST, "", "",
		                    0, BR_MAX_PATH_COST, 100,
		                    G_PARAM_READWRITE |
		                    G_PARAM_CONSTRUCT |
		                    NM_SETTING_PARAM_INFERRABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingBridgePort:hairpin-mode:
	 *
	 * Enables or disabled "hairpin mode" for the port, which allows frames to
	 * be sent back out through the port the frame was received on.
	 *
	 * Since: 0.9.8
	 **/
	g_object_class_install_property
		(object_class, PROP_HAIRPIN_MODE,
		 g_param_spec_boolean (NM_SETTING_BRIDGE_PORT_HAIRPIN_MODE, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       NM_SETTING_PARAM_INFERRABLE |
		                       G_PARAM_STATIC_STRINGS));
}
