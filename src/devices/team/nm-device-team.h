/* NetworkManager -- Network link manager
 *
 * Copyright (C) 2013 Jiri Pirko <jiri@resnulli.us>
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
 */

#ifndef __NETWORKMANAGER_DEVICE_TEAM_H__
#define __NETWORKMANAGER_DEVICE_TEAM_H__

#include "devices/nm-device.h"

#define NM_TYPE_DEVICE_TEAM            (nm_device_team_get_type ())
#define NM_DEVICE_TEAM(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_TEAM, NMDeviceTeam))
#define NM_DEVICE_TEAM_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_DEVICE_TEAM, NMDeviceTeamClass))
#define NM_IS_DEVICE_TEAM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_TEAM))
#define NM_IS_DEVICE_TEAM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_DEVICE_TEAM))
#define NM_DEVICE_TEAM_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_DEVICE_TEAM, NMDeviceTeamClass))

/* Properties */
#define NM_DEVICE_TEAM_CONFIG          "config"

typedef struct _NMDeviceTeam NMDeviceTeam;
typedef struct _NMDeviceTeamClass NMDeviceTeamClass;

GType nm_device_team_get_type (void);

NMDevice *nm_device_team_new (const char *iface);

#endif /* __NETWORKMANAGER_DEVICE_TEAM_H__ */
