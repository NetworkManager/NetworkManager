/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2009 Novell, Inc.
 */

#include <stdio.h>
#include <net/if.h>
#include <WiMaxAPI.h>

#include "nm-wimax-manager.h"
#include "nm-wimax-device.h"
#include "nm-wimax-util.h"

typedef struct {
	struct WIMAX_API_DEVICE_ID device_id;
	int refs;
} NMWimaxManager;

static NMWimaxManager *global_wimax_manager = NULL;

static NMWimaxManager *
nm_wimax_manager_get (void)
{
	WIMAX_API_RET result;

	if (!global_wimax_manager) {
		global_wimax_manager = g_new (NMWimaxManager, 1);
		global_wimax_manager->refs = 1;

		g_debug ("Opening WiMAX API");
		global_wimax_manager->device_id.structureSize = sizeof (NMWimaxManager);
		global_wimax_manager->device_id.privilege = WIMAX_API_PRIVILEGE_READ_WRITE;
		result = WiMaxAPIOpen (&global_wimax_manager->device_id);
		if (result != WIMAX_API_RET_SUCCESS) {
			nm_wimax_util_error (&global_wimax_manager->device_id, "Could not initialize WiMax", result);
			g_free (global_wimax_manager);
			global_wimax_manager = NULL;
		}
	} else
		global_wimax_manager->refs++;

	return global_wimax_manager;
}

static void
nm_wimax_manager_unref (NMWimaxManager *manager)
{
	if (--manager->refs == 0) {
		g_debug ("Closing WiMAX API");
		WiMaxAPIClose (&manager->device_id);
		g_free (manager);
		global_wimax_manager = NULL;
	}
}

static gboolean
wimax_device_matches (struct WIMAX_API_HW_DEVICE_ID *hw_id,
					  const char *ifname,
					  int ifindex)
{
	const char *device_name;
	char *s;
	char hw_ifname[16];

	if (!hw_id)
		return FALSE;

	device_name = (const char *) hw_id->deviceName;
	if (!device_name)
		return FALSE;

	s = g_strrstr (device_name, "if:");
	if (s == NULL || sscanf (s, "if:%15[^ \f\n\r\t\v]", hw_ifname) != 1)
		return FALSE;

	if (g_strcmp0 (ifname, hw_ifname))
		return FALSE;

	if (if_nametoindex (hw_ifname) != ifindex)
		return FALSE;

	return TRUE;
}

NMDevice *
nm_wimax_manager_create_device (const char *path,
								const char *ifname,
								const char *driver)
{
	NMWimaxManager *manager;
	struct WIMAX_API_HW_DEVICE_ID device_id_list[5];
	NMDevice *device = NULL;
    gsize device_id_list_size = 5;
	WIMAX_API_RET result;

	g_return_val_if_fail (path != NULL, NULL);
	g_return_val_if_fail (ifname != NULL, NULL);
	g_return_val_if_fail (driver != NULL, NULL);

	manager = nm_wimax_manager_get ();
	if (!manager)
		return NULL;

	result = GetListDevice (&manager->device_id, device_id_list, &device_id_list_size);
	if (result == WIMAX_API_RET_SUCCESS) {
		int i;

		for (i = 0; i < device_id_list_size; i++) {
			if (wimax_device_matches (&device_id_list[i], ifname, ifindex)) {
				device = nm_wimax_device_new (path, ifname, driver, device_id_list[0].deviceIndex);
				break;
			}
		}
	} else
		nm_wimax_util_error (&manager->device_id, "Could not get WiMax device list", result);

	if (device)
		g_object_weak_ref (G_OBJECT (device), (GWeakNotify) nm_wimax_manager_unref, manager);
	else
		nm_wimax_manager_unref (manager);

	return device;
}
