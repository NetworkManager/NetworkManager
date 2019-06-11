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
 * Copyright 2013 Jiri Pirko <jiri@resnulli.us>
 */

#ifndef __NM_DEVICE_TEAM_H__
#define __NM_DEVICE_TEAM_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_TEAM            (nm_device_team_get_type ())
#define NM_DEVICE_TEAM(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_TEAM, NMDeviceTeam))
#define NM_DEVICE_TEAM_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DEVICE_TEAM, NMDeviceTeamClass))
#define NM_IS_DEVICE_TEAM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_TEAM))
#define NM_IS_DEVICE_TEAM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DEVICE_TEAM))
#define NM_DEVICE_TEAM_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DEVICE_TEAM, NMDeviceTeamClass))

#define NM_DEVICE_TEAM_HW_ADDRESS  "hw-address"
#define NM_DEVICE_TEAM_CARRIER     "carrier"
#define NM_DEVICE_TEAM_SLAVES      "slaves"
#define NM_DEVICE_TEAM_CONFIG      "config"

/**
 * NMDeviceTeam:
 */
struct _NMDeviceTeam {
	NMDevice parent;
};

typedef struct {
	NMDeviceClass parent;

	/*< private >*/
	gpointer padding[4];
} NMDeviceTeamClass;

GType nm_device_team_get_type (void);

const char      *nm_device_team_get_hw_address (NMDeviceTeam *device);
gboolean         nm_device_team_get_carrier    (NMDeviceTeam *device);
const GPtrArray *nm_device_team_get_slaves     (NMDeviceTeam *device);
NM_AVAILABLE_IN_1_4
const char      *nm_device_team_get_config     (NMDeviceTeam *device);

G_END_DECLS

#endif /* __NM_DEVICE_TEAM_H__ */
