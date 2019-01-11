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

#include "nm-setting-ovs-patch.h"

#include "nm-connection-private.h"
#include "nm-setting-connection.h"
#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-ovs-patch
 * @short_description: Describes connection properties for Open vSwitch patch interfaces.
 *
 * The #NMSettingOvsPatch object is a #NMSetting subclass that describes properties
 * necessary for Open vSwitch interfaces of type "patch".
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_PEER,
);

/**
 * NMSettingOvsPatch:
 *
 * OvsPatch Link Settings
 */
struct _NMSettingOvsPatch {
	NMSetting parent;

	char *peer;
};

struct _NMSettingOvsPatchClass {
	NMSettingClass parent;
};

G_DEFINE_TYPE (NMSettingOvsPatch, nm_setting_ovs_patch, NM_TYPE_SETTING)

/*****************************************************************************/

/**
 * nm_setting_ovs_patch_get_peer:
 * @self: the #NMSettingOvsPatch
 *
 * Returns: the #NMSettingOvsPatch:peer property of the setting
 *
 * Since: 1.10
 **/
const char *
nm_setting_ovs_patch_get_peer (NMSettingOvsPatch *self)
{
	g_return_val_if_fail (NM_IS_SETTING_OVS_PATCH (self), NULL);

	return self->peer;
}

/*****************************************************************************/

static int
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSettingOvsPatch *self = NM_SETTING_OVS_PATCH (setting);

	if (!_nm_connection_verify_required_interface_name (connection, error))
		return FALSE;

	if (!self->peer) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_MISSING_PROPERTY,
		                     _("property is missing"));
		g_prefix_error (error, "%s.%s: ",
		                NM_SETTING_OVS_PATCH_SETTING_NAME,
		                NM_SETTING_OVS_PATCH_PEER);
		return FALSE;
	}

	if (   !nm_utils_ipaddr_valid (AF_INET, self->peer)
	    && !nm_utils_ipaddr_valid (AF_INET6, self->peer)) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("'%s' is not a valid IP address"),
		             self->peer);
		g_prefix_error (error, "%s.%s: ",
		                NM_SETTING_OVS_PATCH_SETTING_NAME,
		                NM_SETTING_OVS_PATCH_PEER);
		return FALSE;
	}

	return TRUE;
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettingOvsPatch *self = NM_SETTING_OVS_PATCH (object);

	switch (prop_id) {
	case PROP_PEER:
		g_value_set_string (value, self->peer);
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
	NMSettingOvsPatch *self = NM_SETTING_OVS_PATCH (object);

	switch (prop_id) {
	case PROP_PEER:
		g_free (self->peer);
		self->peer = g_value_dup_string (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_setting_ovs_patch_init (NMSettingOvsPatch *self)
{
}

/**
 * nm_setting_ovs_patch_new:
 *
 * Creates a new #NMSettingOvsPatch object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingOvsPatch object
 *
 * Since: 1.10
 **/
NMSetting *
nm_setting_ovs_patch_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_OVS_PATCH, NULL);
}

static void
finalize (GObject *object)
{
	NMSettingOvsPatch *self = NM_SETTING_OVS_PATCH (object);

	g_free (self->peer);

	G_OBJECT_CLASS (nm_setting_ovs_patch_parent_class)->finalize (object);
}

static void
nm_setting_ovs_patch_class_init (NMSettingOvsPatchClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMSettingClass *setting_class = NM_SETTING_CLASS (klass);

	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;

	setting_class->verify = verify;

	/**
	 * NMSettingOvsPatch:peer:
	 *
	 * Specifies the unicast destination IP address of a remote Open vSwitch
	 * bridge port to connect to.
	 *
	 * Since: 1.10
	 **/
	obj_properties[PROP_PEER] =
	    g_param_spec_string (NM_SETTING_OVS_PATCH_PEER, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_CONSTRUCT |
	                         NM_SETTING_PARAM_INFERRABLE |
	                         G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	_nm_setting_class_commit (setting_class, NM_META_SETTING_TYPE_OVS_PATCH);
}
