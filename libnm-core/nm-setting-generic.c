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
 * Copyright 2013 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-setting-generic.h"
#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-generic
 * @short_description: Describes connection properties for generic devices
 *
 * The #NMSettingGeneric object is a #NMSetting subclass that describes
 * optional properties that apply to "generic" devices (ie, devices that
 * NetworkManager does not specifically recognize).
 *
 * There are currently no properties on this object; it exists only to be
 * the "connection type" setting on #NMConnections for generic devices.
 **/

G_DEFINE_TYPE_WITH_CODE (NMSettingGeneric, nm_setting_generic, NM_TYPE_SETTING,
                         _nm_register_setting (GENERIC, NM_SETTING_PRIORITY_HW_BASE))

#define NM_SETTING_GENERIC_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_GENERIC, NMSettingGenericPrivate))

typedef struct {
	int dummy;
} NMSettingGenericPrivate;

/*****************************************************************************/

/**
 * nm_setting_generic_new:
 *
 * Creates a new #NMSettingGeneric object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingGeneric object
 **/
NMSetting *
nm_setting_generic_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_GENERIC, NULL);
}

static void
nm_setting_generic_init (NMSettingGeneric *setting)
{
}

static void
nm_setting_generic_class_init (NMSettingGenericClass *setting_class)
{
	g_type_class_add_private (setting_class, sizeof (NMSettingGenericPrivate));
}
