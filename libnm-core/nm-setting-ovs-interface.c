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

#include "nm-setting-ovs-interface.h"

#include "nm-connection-private.h"
#include "nm-setting-connection.h"
#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-ovs-interface
 * @short_description: Describes connection properties for OpenVSwitch interfaces.
 *
 * The #NMSettingOvsInterface object is a #NMSetting subclass that describes properties
 * necessary for OpenVSwitch interfaces.
 **/

enum {
	PROP_0,
	PROP_TYPE,
	LAST_PROP
};

/**
 * NMSettingOvsInterface:
 *
 * OpenVSwitch Interface Settings
 */
struct _NMSettingOvsInterface {
	NMSetting parent;

	char *type;
};

struct _NMSettingOvsInterfaceClass {
	NMSettingClass parent;
};

G_DEFINE_TYPE_WITH_CODE (NMSettingOvsInterface, nm_setting_ovs_interface, NM_TYPE_SETTING,
                         _nm_register_setting (OVS_INTERFACE, NM_SETTING_PRIORITY_HW_BASE))
NM_SETTING_REGISTER_TYPE (NM_TYPE_SETTING_OVS_INTERFACE)

/*****************************************************************************/

/**
 * nm_setting_ovs_interface_get_interface_type:
 * @self: the #NMSettingOvsInterface
 *
 * Returns: the #NMSettingOvsInterface:type property of the setting
 *
 * Since: 1.10
 **/
const char *
nm_setting_ovs_interface_get_interface_type (NMSettingOvsInterface *self)
{
	g_return_val_if_fail (NM_IS_SETTING_OVS_INTERFACE (self), NULL);

	return self->type;
}

/*****************************************************************************/

static int
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSettingOvsInterface *self = NM_SETTING_OVS_INTERFACE (setting);

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

		if (!nm_setting_connection_get_master (s_con)) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("A connection with a '%s' setting must have a master."),
			             NM_SETTING_OVS_INTERFACE_SETTING_NAME);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_CONNECTION_SETTING_NAME, NM_SETTING_CONNECTION_MASTER);
			return FALSE;
		}
	}

	if (!NM_IN_STRSET (self->type, "internal", "system", "patch", "", NULL)) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("'%s' is not a valid interface type"),
		             self->type);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_OVS_INTERFACE_SETTING_NAME, NM_SETTING_OVS_INTERFACE_TYPE);
		return FALSE;
	}

	if (connection) {
		if (   g_strcmp0 (self->type, "patch") == 0
		    && !nm_connection_get_setting_ovs_patch (connection)) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("A connection of 'patch' interface type needs a '%s' setting."),
			             NM_SETTING_OVS_PATCH_SETTING_NAME);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_OVS_INTERFACE_SETTING_NAME, NM_SETTING_OVS_INTERFACE_TYPE);
			return FALSE;
		}
	}

	return TRUE;
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettingOvsInterface *self = NM_SETTING_OVS_INTERFACE (object);

	switch (prop_id) {
	case PROP_TYPE:
		g_value_set_string (value, self->type);
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
	NMSettingOvsInterface *self = NM_SETTING_OVS_INTERFACE (object);

	switch (prop_id) {
	case PROP_TYPE:
		g_free (self->type);
		self->type = g_value_dup_string (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_setting_ovs_interface_init (NMSettingOvsInterface *self)
{
}

/**
 * nm_setting_ovs_interface_new:
 *
 * Creates a new #NMSettingOvsInterface object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingOvsInterface object
 *
 * Since: 1.10
 **/
NMSetting *
nm_setting_ovs_interface_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_OVS_INTERFACE, NULL);
}

static void
finalize (GObject *object)
{
	NMSettingOvsInterface *self = NM_SETTING_OVS_INTERFACE (object);

	g_free (self->type);

	G_OBJECT_CLASS (nm_setting_ovs_interface_parent_class)->finalize (object);
}

static void
nm_setting_ovs_interface_class_init (NMSettingOvsInterfaceClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize = finalize;
	parent_class->verify = verify;

	/**
	 * NMSettingOvsInterface:type:
	 *
	 * The interface type. Either "internal", or empty.
	 *
	 * Since: 1.10
	 **/
	g_object_class_install_property
	        (object_class, PROP_TYPE,
	         g_param_spec_string (NM_SETTING_OVS_INTERFACE_TYPE, "", "",
	                              NULL,
	                              G_PARAM_READWRITE |
	                              G_PARAM_CONSTRUCT |
	                              NM_SETTING_PARAM_INFERRABLE |
	                              G_PARAM_STATIC_STRINGS));
}
