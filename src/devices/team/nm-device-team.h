// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2013 Jiri Pirko <jiri@resnulli.us>
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
