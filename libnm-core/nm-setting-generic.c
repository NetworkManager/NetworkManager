// SPDX-License-Identifier: LGPL-2.1+
/*
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

/*****************************************************************************/

typedef struct {
	int dummy;
} NMSettingGenericPrivate;

G_DEFINE_TYPE (NMSettingGeneric, nm_setting_generic, NM_TYPE_SETTING)

#define NM_SETTING_GENERIC_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_GENERIC, NMSettingGenericPrivate))

/*****************************************************************************/

static void
nm_setting_generic_init (NMSettingGeneric *setting)
{
}

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
nm_setting_generic_class_init (NMSettingGenericClass *klass)
{
	NMSettingClass *setting_class = NM_SETTING_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMSettingGenericPrivate));

	_nm_setting_class_commit (setting_class, NM_META_SETTING_TYPE_GENERIC);
}
