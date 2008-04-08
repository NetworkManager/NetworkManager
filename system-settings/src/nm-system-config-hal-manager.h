/*
 * Copyright (C) 2008 Dan Williams
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#ifndef NM_SYSTEM_CONFIG_HAL_MANAGER_H
#define NM_SYSTEM_CONFIG_HAL_MANAGER_H

#include <glib/gtypes.h>
#include <glib-object.h>
#include <dbus/dbus-glib.h>
#include "NetworkManager.h"

#define NM_TYPE_SYSTEM_CONFIG_HAL_MANAGER            (nm_system_config_hal_manager_get_type ())
#define NM_SYSTEM_CONFIG_HAL_MANAGER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SYSTEM_CONFIG_HAL_MANAGER, NMSystemConfigHalManager))
#define NM_SYSTEM_CONFIG_HAL_MANAGER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SYSTEM_CONFIG_HAL_MANAGER, NMSystemConfigHalManagerClass))
#define NM_IS_SYSTEM_CONFIG_HAL_MANAGER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SYSTEM_CONFIG_HAL_MANAGER))
#define NM_IS_SYSTEM_CONFIG_HAL_MANAGER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_SYSTEM_CONFIG_HAL_MANAGER))
#define NM_SYSTEM_CONFIG_HAL_MANAGER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SYSTEM_CONFIG_HAL_MANAGER, NMSystemConfigHalManagerClass))

typedef struct {
	GObject parent;
} NMSystemConfigHalManager;

typedef struct {
	GObjectClass parent;

	/* Signals */
	void (*device_added) (NMSystemConfigHalManager *manager, const char *udi, NMDeviceType type);
	void (*device_removed) (NMSystemConfigHalManager *manager, const char *udi, NMDeviceType type);
} NMSystemConfigHalManagerClass;

GType nm_system_config_hal_manager_get_type (void);

/* Returned list is allocated and must be freed by caller */
GSList *nm_system_config_hal_manager_get_devices_of_type (NMSystemConfigHalManager *manager, NMDeviceType devtype);

NMDeviceType nm_system_config_hal_manager_get_type_for_udi (NMSystemConfigHalManager *manager, const char *udi);

DBusGProxy *nm_system_config_hal_manager_get_hal_proxy (NMSystemConfigHalManager *manager);

#endif /* NM_SYSTEM_CONFIG_HAL_MANAGER_H */
