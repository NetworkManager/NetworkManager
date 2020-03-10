// SPDX-License-Identifier: LGPL-2.1+

#include "nm-default.h"

#include "nm-setting-vrf.h"

#include "nm-connection-private.h"
#include "nm-setting-connection.h"
#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-vrf
 * @short_description: Describes connection properties for vrf interfaces
 *
 * The #NMSettingVrf object is a #NMSetting subclass that describes properties
 * necessary for connection to vrf devices
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_TABLE,
);

/**
 * NMSettingVrf:
 *
 * VRF settings
 *
 * Since: 1.24
 */
struct _NMSettingVrf {
	NMSetting parent;
	guint32 table;
};

struct _NMSettingVrfClass {
	NMSettingClass parent;
};

G_DEFINE_TYPE (NMSettingVrf, nm_setting_vrf, NM_TYPE_SETTING)

/*****************************************************************************/

/**
 * nm_setting_vrf_get_table:
 * @setting: the #NMSettingVrf
 *
 * Returns: the routing table for the VRF
 *
 * Since: 1.24
 **/
guint32
nm_setting_vrf_get_table (NMSettingVrf *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_VRF (setting), 0);

	return setting->table;
}

/*****************************************************************************/

static gboolean
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSettingVrf *self = NM_SETTING_VRF (setting);

	if (!_nm_connection_verify_required_interface_name (connection, error))
		return FALSE;

	if (self->table == 0) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("table cannot be zero"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_VRF_SETTING_NAME,
		                NM_SETTING_VRF_TABLE);
		return FALSE;
	}

	return TRUE;
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettingVrf *self = NM_SETTING_VRF (object);

	switch (prop_id) {
	case PROP_TABLE:
		g_value_set_uint (value, self->table);
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
	NMSettingVrf *self = NM_SETTING_VRF (object);

	switch (prop_id) {
	case PROP_TABLE:
		self->table = g_value_get_uint (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_setting_vrf_init (NMSettingVrf *setting)
{
}

/**
 * nm_setting_vrf_new:
 *
 * Creates a new #NMSettingVrf object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingVrf object
 *
 * Since: 1.24
 **/
NMSetting *
nm_setting_vrf_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_VRF, NULL);
}

static void
nm_setting_vrf_class_init (NMSettingVrfClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMSettingClass *setting_class = NM_SETTING_CLASS (klass);

	object_class->get_property = get_property;
	object_class->set_property = set_property;

	setting_class->verify = verify;

	/**
	 * NMSettingVrf:table:
	 *
	 * The routing table for this VRF.
	 *
	 * Since: 1.24
	 **/
	obj_properties[PROP_TABLE] =
	    g_param_spec_uint (NM_SETTING_VRF_TABLE, "", "",
	                       0, G_MAXUINT32, 0,
	                       G_PARAM_READWRITE |
	                       NM_SETTING_PARAM_INFERRABLE |
	                       G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	_nm_setting_class_commit (setting_class, NM_META_SETTING_TYPE_VRF);
}
