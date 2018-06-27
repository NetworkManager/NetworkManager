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
 * Copyright 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-setting-ovs-port.h"

#include "nm-connection-private.h"
#include "nm-setting-connection.h"
#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-ovs-port
 * @short_description: Describes connection properties for Open vSwitch ports.
 *
 * The #NMSettingOvsPort object is a #NMSetting subclass that describes properties
 * necessary for Open vSwitch ports.
 **/

enum {
	PROP_0,
	PROP_VLAN_MODE,
	PROP_TAG,
	PROP_LACP,
	PROP_BOND_MODE,
	PROP_BOND_UPDELAY,
	PROP_BOND_DOWNDELAY,
	LAST_PROP
};

/**
 * NMSettingOvsPort:
 *
 * OvsPort Link Settings
 */
struct _NMSettingOvsPort {
	NMSetting parent;

	char *vlan_mode;
	guint tag;
	char *lacp;
	char *bond_mode;
	guint bond_updelay;
	guint bond_downdelay;
};

struct _NMSettingOvsPortClass {
	NMSettingClass parent;
};

G_DEFINE_TYPE_WITH_CODE (NMSettingOvsPort, nm_setting_ovs_port, NM_TYPE_SETTING,
                         _nm_register_setting (OVS_PORT, NM_SETTING_PRIORITY_HW_BASE))
NM_SETTING_REGISTER_TYPE (NM_TYPE_SETTING_OVS_PORT)

/*****************************************************************************/

/**
 * nm_setting_ovs_port_get_vlan_mode:
 * @self: the #NMSettingOvsPort
 *
 * Returns: the #NMSettingOvsPort:vlan-mode property of the setting
 *
 * Since: 1.10
 **/
const char *
nm_setting_ovs_port_get_vlan_mode (NMSettingOvsPort *self)
{
	g_return_val_if_fail (NM_IS_SETTING_OVS_PORT (self), NULL);

	return self->vlan_mode;
}

/**
 * nm_setting_ovs_port_get_tag:
 * @self: the #NMSettingOvsPort
 *
 * Returns: the #NMSettingOvsPort:tag property of the setting
 *
 * Since: 1.10
 **/
guint
nm_setting_ovs_port_get_tag (NMSettingOvsPort *self)
{
	g_return_val_if_fail (NM_IS_SETTING_OVS_PORT (self), 0);

	return self->tag;
}

/**
 * nm_setting_ovs_port_get_lacp:
 * @self: the #NMSettingOvsPort
 *
 * Returns: the #NMSettingOvsPort:lacp property of the setting
 *
 * Since: 1.10
 **/
const char *
nm_setting_ovs_port_get_lacp (NMSettingOvsPort *self)
{
	g_return_val_if_fail (NM_IS_SETTING_OVS_PORT (self), NULL);

	return self->lacp;
}

/**
 * nm_setting_ovs_port_get_bond_mode:
 * @self: the #NMSettingOvsPort
 *
 * Returns: the #NMSettingOvsPort:bond-mode property of the setting
 *
 * Since: 1.10
 **/
const char *
nm_setting_ovs_port_get_bond_mode (NMSettingOvsPort *self)
{
	g_return_val_if_fail (NM_IS_SETTING_OVS_PORT (self), NULL);

	return self->bond_mode;
}

/**
 * nm_setting_ovs_port_get_bond_updelay:
 * @self: the #NMSettingOvsPort
 *
 * Returns: the #NMSettingOvsPort:bond-updelay property of the setting
 *
 * Since: 1.10
 **/
guint
nm_setting_ovs_port_get_bond_updelay (NMSettingOvsPort *self)
{
	g_return_val_if_fail (NM_IS_SETTING_OVS_PORT (self), 0);

	return self->bond_updelay;
}

/**
 * nm_setting_ovs_port_get_bond_downdelay:
 * @self: the #NMSettingOvsPort
 *
 * Returns: the #NMSettingOvsPort:bond-downdelay property of the setting
 *
 * Since: 1.10
 **/
guint
nm_setting_ovs_port_get_bond_downdelay (NMSettingOvsPort *self)
{
	g_return_val_if_fail (NM_IS_SETTING_OVS_PORT (self), 0);

	return self->bond_downdelay;
}

/*****************************************************************************/

static int
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSettingOvsPort *self = NM_SETTING_OVS_PORT (setting);

	if (!_nm_connection_verify_required_interface_name (connection, error))
		return FALSE;

	if (connection) {
		NMSettingConnection *s_con;
		const char *slave_type;

		s_con = nm_connection_get_setting_connection (connection);
		if (!s_con) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_MISSING_SETTING,
			             _("missing setting"));
			g_prefix_error (error, "%s: ", NM_SETTING_CONNECTION_SETTING_NAME);
			return FALSE;
		}

		if (!nm_setting_connection_get_master (s_con)) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("A connection with a '%s' setting must have a master."),
			             NM_SETTING_OVS_PORT_SETTING_NAME);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_CONNECTION_SETTING_NAME, NM_SETTING_CONNECTION_MASTER);
			return FALSE;
		}

		slave_type = nm_setting_connection_get_slave_type (s_con);
		if (   slave_type
		    && strcmp (slave_type, NM_SETTING_OVS_BRIDGE_SETTING_NAME)) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("A connection with a '%s' setting must have the slave-type set to '%s'. Instead it is '%s'"),
			             NM_SETTING_OVS_PORT_SETTING_NAME,
			             NM_SETTING_OVS_BRIDGE_SETTING_NAME,
			             slave_type);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_CONNECTION_SETTING_NAME, NM_SETTING_CONNECTION_SLAVE_TYPE);
			return FALSE;
		}
	}

	if (!NM_IN_STRSET (self->vlan_mode, "access", "native-tagged", "native-untagged", "trunk", NULL)) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("'%s' is not allowed in vlan_mode"),
		             self->vlan_mode);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_OVS_PORT_SETTING_NAME, NM_SETTING_OVS_PORT_VLAN_MODE);
		return FALSE;
	}

	if (self->tag >= 4095) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("the tag id must be in range 0-4094 but is %u"),
		             self->tag);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_OVS_PORT_SETTING_NAME, NM_SETTING_OVS_PORT_TAG);
		return FALSE;
	}

	if (!NM_IN_STRSET (self->lacp, "active", "off", "passive", NULL)) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("'%s' is not allowed in lacp"),
		             self->lacp);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_OVS_PORT_SETTING_NAME, NM_SETTING_OVS_PORT_LACP);
		return FALSE;
	}

	if (!NM_IN_STRSET (self->bond_mode, "active-backup", "balance-slb", "balance-tcp", NULL)) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("'%s' is not allowed in bond_mode"),
		             self->bond_mode);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_OVS_PORT_SETTING_NAME, NM_SETTING_OVS_PORT_BOND_MODE);
		return FALSE;
	}

	return TRUE;
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettingOvsPort *self = NM_SETTING_OVS_PORT (object);

	switch (prop_id) {
	case PROP_VLAN_MODE:
		g_value_set_string (value, self->vlan_mode);
		break;
	case PROP_TAG:
		g_value_set_uint (value, self->tag);
		break;
	case PROP_LACP:
		g_value_set_string (value, self->lacp);
		break;
	case PROP_BOND_MODE:
		g_value_set_string (value, self->bond_mode);
		break;
	case PROP_BOND_UPDELAY:
		g_value_set_uint (value, self->bond_updelay);
		break;
	case PROP_BOND_DOWNDELAY:
		g_value_set_uint (value, self->bond_downdelay);
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
	NMSettingOvsPort *self = NM_SETTING_OVS_PORT (object);

	switch (prop_id) {
	case PROP_VLAN_MODE:
		g_free (self->vlan_mode);
		self->vlan_mode = g_value_dup_string (value);
		break;
	case PROP_TAG:
		self->tag = g_value_get_uint (value);
		break;
	case PROP_LACP:
		g_free (self->lacp);
		self->lacp = g_value_dup_string (value);
		break;
	case PROP_BOND_MODE:
		g_free (self->bond_mode);
		self->bond_mode = g_value_dup_string (value);
		break;
	case PROP_BOND_UPDELAY:
		self->bond_updelay = g_value_get_uint (value);
		break;
	case PROP_BOND_DOWNDELAY:
		self->bond_downdelay = g_value_get_uint (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_setting_ovs_port_init (NMSettingOvsPort *self)
{
}

/**
 * nm_setting_ovs_port_new:
 *
 * Creates a new #NMSettingOvsPort object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingOvsPort object
 *
 * Since: 1.10
 **/
NMSetting *
nm_setting_ovs_port_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_OVS_PORT, NULL);
}

static void
finalize (GObject *object)
{
	NMSettingOvsPort *self = NM_SETTING_OVS_PORT (object);

	g_free (self->vlan_mode);
	g_free (self->lacp);
	g_free (self->bond_mode);

	G_OBJECT_CLASS (nm_setting_ovs_port_parent_class)->finalize (object);
}

static void
nm_setting_ovs_port_class_init (NMSettingOvsPortClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize = finalize;
	parent_class->verify = verify;

	/**
	 * NMSettingOvsPort:vlan-mode:
	 *
	 * The VLAN mode. One of "access", "native-tagged", "native-untagged",
	 * "trunk" or unset.
	 *
	 * Since: 1.10
	 **/
	g_object_class_install_property
	        (object_class, PROP_VLAN_MODE,
	         g_param_spec_string (NM_SETTING_OVS_PORT_VLAN_MODE, "", "",
	                              NULL,
	                              G_PARAM_READWRITE |
	                              G_PARAM_CONSTRUCT |
	                              NM_SETTING_PARAM_INFERRABLE |
	                              G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingOvsPort:tag:
	 *
	 * The VLAN tag in the range 0-4095.
	 *
	 * Since: 1.10
	 **/
	g_object_class_install_property
	        (object_class, PROP_TAG,
	         g_param_spec_uint (NM_SETTING_OVS_PORT_TAG, "", "",
	                            0, 4095, 0,
	                            G_PARAM_READWRITE |
	                            G_PARAM_CONSTRUCT |
	                            NM_SETTING_PARAM_INFERRABLE |
	                            G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingOvsPort:lacp:
	 *
	 * LACP mode. One of "active", "off", or "passive".
	 *
	 * Since: 1.10
	 **/
	g_object_class_install_property
	        (object_class, PROP_LACP,
	         g_param_spec_string (NM_SETTING_OVS_PORT_LACP, "", "",
	                              NULL,
	                              G_PARAM_READWRITE |
	                              G_PARAM_CONSTRUCT |
	                              NM_SETTING_PARAM_INFERRABLE |
	                              G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingOvsPort:bond-mode:
	 *
	 * Bonding mode. One of "active-backup", "balance-slb", or "balance-tcp".
	 *
	 * Since: 1.10
	 **/
	g_object_class_install_property
	        (object_class, PROP_BOND_MODE,
	         g_param_spec_string (NM_SETTING_OVS_PORT_BOND_MODE, "", "",
	                              NULL,
	                              G_PARAM_READWRITE |
	                              G_PARAM_CONSTRUCT |
	                              NM_SETTING_PARAM_INFERRABLE |
	                              G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingOvsPort:bond-updelay:
	 *
	 * The time port must be active before it starts forwarding traffic.
	 *
	 * Since: 1.10
	 **/
	g_object_class_install_property
	        (object_class, PROP_BOND_UPDELAY,
	         g_param_spec_uint (NM_SETTING_OVS_PORT_BOND_UPDELAY, "", "",
	                            0, G_MAXUINT, 0,
	                            G_PARAM_READWRITE |
	                            G_PARAM_CONSTRUCT |
	                            NM_SETTING_PARAM_INFERRABLE |
	                            G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingOvsPort:bond-downdelay:
	 *
	 * The time port must be inactive in order to be considered down.
	 *
	 * Since: 1.10
	 **/
	g_object_class_install_property
	        (object_class, PROP_BOND_DOWNDELAY,
	         g_param_spec_uint (NM_SETTING_OVS_PORT_BOND_DOWNDELAY, "", "",
	                            0, G_MAXUINT, 0,
	                            G_PARAM_READWRITE |
	                            G_PARAM_CONSTRUCT |
	                            NM_SETTING_PARAM_INFERRABLE |
	                            G_PARAM_STATIC_STRINGS));
}
