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

#include "nm-setting-dummy.h"

#include "nm-connection-private.h"
#include "nm-setting-connection.h"
#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-dummy
 * @short_description: Describes connection properties for dummy interfaces
 *
 * The #NMSettingDummy object is a #NMSetting subclass that describes properties
 * necessary for connection to dummy devices
 **/

G_DEFINE_TYPE_WITH_CODE (NMSettingDummy, nm_setting_dummy, NM_TYPE_SETTING,
                         _nm_register_setting (DUMMY, NM_SETTING_PRIORITY_HW_BASE))
NM_SETTING_REGISTER_TYPE (NM_TYPE_SETTING_DUMMY)

/**
 * nm_setting_dummy_new:
 *
 * Creates a new #NMSettingDummy object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingDummy object
 *
 * Since: 1.8
 **/
NMSetting *
nm_setting_dummy_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_DUMMY, NULL);
}

static gboolean
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	if (!_nm_connection_verify_required_interface_name (connection, error))
		return FALSE;

	return TRUE;
}

static void
nm_setting_dummy_init (NMSettingDummy *setting)
{
}

static void
nm_setting_dummy_class_init (NMSettingDummyClass *setting_class)
{
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	parent_class->verify           = verify;
}
