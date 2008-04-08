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

/* *** Not to be used by system settings service plugins *** */

#ifndef NM_SYSTEM_CONFIG_HAL_MANAGER_PRIVATE_H
#define NM_SYSTEM_CONFIG_HAL_MANAGER_PRIVATE_H

#include "nm-system-config-hal-manager.h"

NMSystemConfigHalManager *nm_system_config_hal_manager_get (DBusGConnection *g_connection);

void nm_system_config_hal_manager_reinit_dbus (NMSystemConfigHalManager *manager,
                                               DBusGConnection *g_connection);

void nm_system_config_hal_manager_deinit_dbus (NMSystemConfigHalManager *manager);

#endif /* NM_SYSTEM_CONFIG_HAL_MANAGER_PRIVATE_H */
