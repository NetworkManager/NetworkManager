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
 * Copyright 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-setting-6lowpan.h"

#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-6lowpan
 * @short_description: Describes connection properties for 6LoWPAN interfaces
 *
 * The #NMSetting6Lowpan object is a #NMSetting subclass that describes properties
 * necessary for connection to 6LoWPAN interfaces.
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_PARENT,
);

typedef struct {
	char *parent;
} NMSetting6LowpanPrivate;

/**
 * NMSetting6Lowpan:
 *
 * 6LoWPAN Settings
 */
struct _NMSetting6Lowpan {
	NMSetting parent;
};

struct _NMSetting6LowpanClass {
	NMSettingClass parent;
};

G_DEFINE_TYPE (NMSetting6Lowpan, nm_setting_6lowpan, NM_TYPE_SETTING)

#define NM_SETTING_6LOWPAN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_6LOWPAN, NMSetting6LowpanPrivate))

/*****************************************************************************/

/**
 * nm_setting_6lowpan_get_parent:
 * @setting: the #NMSetting6Lowpan
 *
 * Returns: the #NMSetting6Lowpan:parent property of the setting
 *
 * Since: 1.14
 **/
const char *
nm_setting_6lowpan_get_parent (NMSetting6Lowpan *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_6LOWPAN (setting), NULL);
	return NM_SETTING_6LOWPAN_GET_PRIVATE (setting)->parent;
}

/*********************************************************************/

static gboolean
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSetting6LowpanPrivate *priv = NM_SETTING_6LOWPAN_GET_PRIVATE (setting);
	NMSettingConnection *s_con = NULL;

	if (connection)
		s_con = nm_connection_get_setting_connection (connection);

	if (!priv->parent) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_MISSING_PROPERTY,
		             _("property is not specified"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_6LOWPAN_SETTING_NAME, NM_SETTING_6LOWPAN_PARENT);
		return FALSE;
	}



	if (nm_utils_is_uuid (priv->parent)) {
		/* If we have an NMSettingConnection:master with slave-type="6lowpan",
		 * then it must be the same UUID.
		 */
		if (s_con) {
			const char *master = NULL, *slave_type = NULL;

			slave_type = nm_setting_connection_get_slave_type (s_con);
			if (!g_strcmp0 (slave_type, NM_SETTING_6LOWPAN_SETTING_NAME))
				master = nm_setting_connection_get_master (s_con);

			if (master && g_strcmp0 (priv->parent, master) != 0) {
				g_set_error (error,
				             NM_CONNECTION_ERROR,
				             NM_CONNECTION_ERROR_INVALID_PROPERTY,
				             _("'%s' value doesn't match '%s=%s'"),
				             priv->parent, NM_SETTING_CONNECTION_MASTER, master);
				g_prefix_error (error, "%s.%s: ", NM_SETTING_6LOWPAN_SETTING_NAME, NM_SETTING_6LOWPAN_PARENT);
				return FALSE;
			}
		}
	} else if (!nm_utils_iface_valid_name (priv->parent)) {
		/* parent must be either a UUID or an interface name */
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("'%s' is neither an UUID nor an interface name"),
		             priv->parent);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_6LOWPAN_SETTING_NAME, NM_SETTING_6LOWPAN_PARENT);
		return FALSE;
	}

	return TRUE;
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSetting6Lowpan *setting = NM_SETTING_6LOWPAN (object);
	NMSetting6LowpanPrivate *priv = NM_SETTING_6LOWPAN_GET_PRIVATE (setting);

	switch (prop_id) {
	case PROP_PARENT:
		g_value_set_string (value, priv->parent);
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
	NMSetting6Lowpan *setting = NM_SETTING_6LOWPAN (object);
	NMSetting6LowpanPrivate *priv = NM_SETTING_6LOWPAN_GET_PRIVATE (setting);

	switch (prop_id) {
	case PROP_PARENT:
		g_free (priv->parent);
		priv->parent = g_value_dup_string (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_setting_6lowpan_init (NMSetting6Lowpan *setting)
{
}

/**
 * nm_setting_6lowpan_new:
 *
 * Creates a new #NMSetting6Lowpan object with default values.
 *
 * Returns: (transfer full): the new empty #NMSetting6Lowpan object
 *
 * Since: 1.14
 **/
NMSetting *
nm_setting_6lowpan_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_6LOWPAN, NULL);
}

static void
finalize (GObject *object)
{
	NMSetting6Lowpan *setting = NM_SETTING_6LOWPAN (object);
	NMSetting6LowpanPrivate *priv = NM_SETTING_6LOWPAN_GET_PRIVATE (setting);

	g_free (priv->parent);

	G_OBJECT_CLASS (nm_setting_6lowpan_parent_class)->finalize (object);
}

static void
nm_setting_6lowpan_class_init (NMSetting6LowpanClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMSettingClass *setting_class = NM_SETTING_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMSetting6LowpanPrivate));

	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->finalize     = finalize;

	setting_class->verify = verify;

	/**
	 * NMSetting6Lowpan:parent:
	 *
	 * If given, specifies the parent interface name or parent connection UUID
	 * from which this 6LowPAN interface should be created.
	 *
	 * Since: 1.14
	 **/
	obj_properties[PROP_PARENT] =
	    g_param_spec_string (NM_SETTING_6LOWPAN_PARENT, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_CONSTRUCT |
	                         NM_SETTING_PARAM_INFERRABLE |
	                         G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	_nm_setting_class_commit (setting_class, NM_META_SETTING_TYPE_6LOWPAN);
}
