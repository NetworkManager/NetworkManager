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
 * Copyright 2019 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-setting-contrail-vrouter.h"

#include "nm-connection-private.h"
#include "nm-setting-connection.h"
#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-contrail-vrouter
 * @short_description: Describes connection properties for Contrail vrouter.
 *
 * The #NMSettingContrailVrouter object is a #NMSetting subclass that describes properties
 * necessary for Contrail vrouter.
 **/

enum {
	PROP_0,
	PROP_PHYSDEV,
	LAST_PROP
};

/**
 * NMSettingContrailVrouter:
 *
 * Contrail vrouter Settings
 */
struct _NMSettingContrailVrouter {
	NMSetting parent;

	char *physdev;
};

struct _NMSettingContrailVrouterClass {
	NMSettingClass parent;
};

G_DEFINE_TYPE (NMSettingContrailVrouter, nm_setting_contrail_vrouter, NM_TYPE_SETTING)

/*****************************************************************************/

/**
 * nm_setting_ovs_interface_get_physdev:
 * @self: the #NMSettingContrailVrouter
 *
 * Returns: the #NMSettingContrailVrouter:physdev property of the setting
 *
 * Since: 1.14
 **/
const char *
nm_setting_contrail_vrouter_get_physdev (NMSettingContrailVrouter *self)
{
	g_return_val_if_fail (NM_IS_SETTING_CONTRAIL_VROUTER (self), NULL);

	return self->physdev;
}

/*****************************************************************************/

static int
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSettingContrailVrouter *self = NM_SETTING_CONTRAIL_VROUTER (setting);

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
	}
	return TRUE;
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettingContrailVrouter *self = NM_SETTING_CONTRAIL_VROUTER (object);

	switch (prop_id) {
	case PROP_PHYSDEV:
		g_value_set_string (value, self->physdev);
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
	NMSettingContrailVrouter *self = NM_SETTING_CONTRAIL_VROUTER (object);

	switch (prop_id) {
	case PROP_PHYSDEV:
		g_free (self->physdev);
		self->physdev = g_value_dup_string (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_setting_contrail_vrouter_init (NMSettingContrailVrouter *self)
{
}

/**
 * nm_setting_contrail_vrouter_new:
 *
 * Creates a new #NMSettingContrailVrouter object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingContrailVrouter object
 *
 * Since: 1.14
 **/
NMSetting *
nm_setting_contrail_vrouter_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_CONTRAIL_VROUTER, NULL);
}

static void
finalize (GObject *object)
{
	NMSettingContrailVrouter *self = NM_SETTING_CONTRAIL_VROUTER (object);

	g_free (self->physdev);

	G_OBJECT_CLASS (nm_setting_contrail_vrouter_parent_class)->finalize (object);
}

static void
nm_setting_contrail_vrouter_class_init (NMSettingContrailVrouterClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMSettingClass *setting_class = NM_SETTING_CLASS (klass);

	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;

	setting_class->verify = verify;

	/**
	 * NMSettingContrailVrouter:physdev:
	 *
	 * The physical device name.
	 *
	 * Since: 1.14
	 **/
	g_object_class_install_property
	        (object_class, PROP_PHYSDEV,
	         g_param_spec_string (NM_SETTING_CONTRAIL_VROUTER_PHYSDEV, "", "",
	                              NULL,
	                              G_PARAM_READWRITE |
	                              G_PARAM_CONSTRUCT |
	                              NM_SETTING_PARAM_INFERRABLE |
	                              G_PARAM_STATIC_STRINGS));

	_nm_setting_class_commit (setting_class, NM_META_SETTING_TYPE_CONTRAIL_VROUTER);
}
