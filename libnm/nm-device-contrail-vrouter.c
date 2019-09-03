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

#include <string.h>

#include "nm-device-contrail-vrouter.h"
#include "nm-object-private.h"
#include "nm-setting-contrail-vrouter.h"
#include "nm-setting-connection.h"

/**
 * NMDeviceContrailVrouter:
 */
struct _NMDeviceContrailVrouter {
	NMDevice parent;
};

struct _NMDeviceContrailVrouterClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDeviceContrailVrouter, nm_device_contrail_vrouter, NM_TYPE_DEVICE)

/*****************************************************************************/

static const char *
get_type_description (NMDevice *device)
{
	return "contrail-vrouter";
}

static gboolean
connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	const char *iface_name;

	if (!NM_DEVICE_CLASS (nm_device_contrail_vrouter_parent_class)->connection_compatible (device, connection, error))
		return FALSE;

	if (!nm_connection_is_type (connection, NM_SETTING_CONTRAIL_VROUTER_SETTING_NAME)) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
		                     _("The connection was not a contrail_vrouter connection."));
		return FALSE;
	}

	iface_name = nm_connection_get_interface_name (connection);
	if (!iface_name) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INVALID_CONNECTION,
		                     _("The connection did not specify an interface name."));
		return FALSE;
	}

	return TRUE;
}

static GType
get_setting_type (NMDevice *device)
{
	return NM_TYPE_SETTING_CONTRAIL_VROUTER;
}

/*****************************************************************************/

static void
nm_device_contrail_vrouter_init (NMDeviceContrailVrouter *device)
{
}

static void
nm_device_contrail_vrouter_class_init (NMDeviceContrailVrouterClass *contrail_vrouter_class)
{
	NMDeviceClass *device_class = NM_DEVICE_CLASS (contrail_vrouter_class);

	device_class->get_type_description = get_type_description;
	device_class->connection_compatible = connection_compatible;
	device_class->get_setting_type = get_setting_type;
}
