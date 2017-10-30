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

#include "nm-setting-ovs-bridge.h"

#include "nm-connection-private.h"
#include "nm-setting-connection.h"
#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-ovs-bridge
 * @short_description: Describes connection properties for OpenVSwitch bridges.
 *
 * The #NMSettingOvsBridge object is a #NMSetting subclass that describes properties
 * necessary for OpenVSwitch bridges.
 **/

enum {
	PROP_0,
	PROP_FAIL_MODE,
	PROP_MCAST_SNOOPING_ENABLE,
	PROP_RSTP_ENABLE,
	PROP_STP_ENABLE,
	LAST_PROP
};

/**
 * NMSettingOvsBridge:
 *
 * OvsBridge Link Settings
 */
struct _NMSettingOvsBridge {
	NMSetting parent;

	char *fail_mode;
	gboolean mcast_snooping_enable;
	gboolean rstp_enable;
	gboolean stp_enable;
};

struct _NMSettingOvsBridgeClass {
	NMSettingClass parent;
};

G_DEFINE_TYPE_WITH_CODE (NMSettingOvsBridge, nm_setting_ovs_bridge, NM_TYPE_SETTING,
                         _nm_register_setting (OVS_BRIDGE, NM_SETTING_PRIORITY_HW_BASE))
NM_SETTING_REGISTER_TYPE (NM_TYPE_SETTING_OVS_BRIDGE)

/*****************************************************************************/

/**
 * nm_setting_ovs_bridge_get_fail_mode:
 * @self: the #NMSettingOvsBridge
 *
 * Returns: the #NMSettingOvsBridge:fail_mode property of the setting
 *
 * Since: 1.10
 **/
const char *
nm_setting_ovs_bridge_get_fail_mode (NMSettingOvsBridge *self)
{
	g_return_val_if_fail (NM_IS_SETTING_OVS_BRIDGE (self), NULL);

	return self->fail_mode;
}

/**
 * nm_setting_ovs_bridge_get_mcast_snooping_enable:
 * @self: the #NMSettingOvsBridge
 *
 * Returns: the #NMSettingOvsBridge:mcast_snooping_enable property of the setting
 *
 * Since: 1.10
 **/
gboolean
nm_setting_ovs_bridge_get_mcast_snooping_enable (NMSettingOvsBridge *self)
{
	g_return_val_if_fail (NM_IS_SETTING_OVS_BRIDGE (self), FALSE);

	return self->mcast_snooping_enable;
}

/**
 * nm_setting_ovs_bridge_get_rstp_enable:
 * @self: the #NMSettingOvsBridge
 *
 * Returns: the #NMSettingOvsBridge:rstp_enable property of the setting
 *
 * Since: 1.10
 **/
gboolean
nm_setting_ovs_bridge_get_rstp_enable (NMSettingOvsBridge *self)
{
	g_return_val_if_fail (NM_IS_SETTING_OVS_BRIDGE (self), FALSE);

	return self->rstp_enable;
}

/**
 * nm_setting_ovs_bridge_get_stp_enable:
 * @self: the #NMSettingOvsBridge
 *
 * Returns: the #NMSettingOvsBridge:stp_enable property of the setting
 *
 * Since: 1.10
 **/
gboolean
nm_setting_ovs_bridge_get_stp_enable (NMSettingOvsBridge *self)
{
	g_return_val_if_fail (NM_IS_SETTING_OVS_BRIDGE (self), FALSE);

	return self->stp_enable;
}

/*****************************************************************************/

static int
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSettingOvsBridge *self = NM_SETTING_OVS_BRIDGE (setting);

	if (!_nm_connection_verify_required_interface_name (connection, error))
		return FALSE;

	if (connection) {
		NMSettingConnection *s_con;

		s_con = nm_connection_get_setting_connection (connection);
		if (!s_con) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_MISSING_SETTING,
			             _("missing setting"));
			g_prefix_error (error, "%s: ", NM_SETTING_CONNECTION_SETTING_NAME);
			return FALSE;
		}

		if (nm_setting_connection_get_master (s_con)) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("A connection with a '%s' setting must not have a master."),
			             NM_SETTING_OVS_BRIDGE_SETTING_NAME);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_CONNECTION_SETTING_NAME, NM_SETTING_CONNECTION_MASTER);
			return FALSE;
		}
	}

	if (!NM_IN_STRSET (self->fail_mode, "secure", "standalone", NULL)) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("'%s' is not allowed in fail_mode"),
		             self->fail_mode);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_OVS_BRIDGE_SETTING_NAME, NM_SETTING_OVS_BRIDGE_FAIL_MODE);
		return FALSE;
	}

	return TRUE;
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettingOvsBridge *self = NM_SETTING_OVS_BRIDGE (object);

	switch (prop_id) {
	case PROP_FAIL_MODE:
		g_value_set_string (value, self->fail_mode);
		break;
	case PROP_MCAST_SNOOPING_ENABLE:
		g_value_set_boolean (value, self->mcast_snooping_enable);
		break;
	case PROP_RSTP_ENABLE:
		g_value_set_boolean (value, self->rstp_enable);
		break;
	case PROP_STP_ENABLE:
		g_value_set_boolean (value, self->stp_enable);
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
	NMSettingOvsBridge *self = NM_SETTING_OVS_BRIDGE (object);

	switch (prop_id) {
	case PROP_FAIL_MODE:
		g_free (self->fail_mode);
		self->fail_mode = g_value_dup_string (value);
		break;
	case PROP_MCAST_SNOOPING_ENABLE:
		self->mcast_snooping_enable = g_value_get_boolean (value);
		break;
	case PROP_RSTP_ENABLE:
		self->rstp_enable = g_value_get_boolean (value);
		break;
	case PROP_STP_ENABLE:
		self->stp_enable = g_value_get_boolean (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_setting_ovs_bridge_init (NMSettingOvsBridge *self)
{
}

/**
 * nm_setting_ovs_bridge_new:
 *
 * Creates a new #NMSettingOvsBridge object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingOvsBridge object
 *
 * Since: 1.10
 **/
NMSetting *
nm_setting_ovs_bridge_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_OVS_BRIDGE, NULL);
}

static void
finalize (GObject *object)
{
	NMSettingOvsBridge *self = NM_SETTING_OVS_BRIDGE (object);

	g_free (self->fail_mode);

	G_OBJECT_CLASS (nm_setting_ovs_bridge_parent_class)->finalize (object);
}

static void
nm_setting_ovs_bridge_class_init (NMSettingOvsBridgeClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize = finalize;
	parent_class->verify = verify;

	/**
	 * NMSettingOvsBridge:fail-mode:
	 *
	 * The bridge failure mode. One of "secure", "standalone" or empty.
	 *
	 * Since: 1.10
	 **/
	g_object_class_install_property
	        (object_class, PROP_FAIL_MODE,
	         g_param_spec_string (NM_SETTING_OVS_BRIDGE_FAIL_MODE, "", "",
	                              NULL,
	                              G_PARAM_READWRITE |
	                              G_PARAM_CONSTRUCT |
	                              NM_SETTING_PARAM_INFERRABLE |
	                              G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingOvsBridge:mcast-snooping-enable:
	 *
	 * Enable or disable multicast snooping.
	 *
	 * Since: 1.10
	 **/
	g_object_class_install_property
	        (object_class, PROP_MCAST_SNOOPING_ENABLE,
	         g_param_spec_boolean (NM_SETTING_OVS_BRIDGE_MCAST_SNOOPING_ENABLE, "", "",
	                               FALSE,
	                               G_PARAM_READWRITE |
	                               G_PARAM_CONSTRUCT |
	                               G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingOvsBridge:rstp-enable:
	 *
	 * Enable or disable RSTP.
	 *
	 * Since: 1.10
	 **/
	g_object_class_install_property
	        (object_class, PROP_RSTP_ENABLE,
	         g_param_spec_boolean (NM_SETTING_OVS_BRIDGE_RSTP_ENABLE, "", "",
	                               FALSE,
	                               G_PARAM_READWRITE |
	                               G_PARAM_CONSTRUCT |
	                               G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingOvsBridge:stp-enable:
	 *
	 * Enable or disable STP.
	 *
	 * Since: 1.10
	 **/
	g_object_class_install_property
	        (object_class, PROP_STP_ENABLE,
	         g_param_spec_boolean (NM_SETTING_OVS_BRIDGE_STP_ENABLE, "", "",
	                               FALSE,
	                               G_PARAM_READWRITE |
	                               G_PARAM_CONSTRUCT |
	                               G_PARAM_STATIC_STRINGS));
}
