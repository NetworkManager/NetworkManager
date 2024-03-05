/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2012 - 2016 Red Hat, Inc.
 * Author: Matthias Clasen <mclasen@redhat.com>
 */

#ifndef __NETWORKMANAGER_POWER_MONITOR_H__
#define __NETWORKMANAGER_POWER_MONITOR_H__

#define NM_TYPE_POWER_MONITOR (nm_power_monitor_get_type())
#define NM_POWER_MONITOR(o) \
    (_NM_G_TYPE_CHECK_INSTANCE_CAST((o), NM_TYPE_POWER_MONITOR, NMPowerMonitor))
#define NM_POWER_MONITOR_CLASS(k) \
    (G_TYPE_CHECK_CLASS_CAST((k), NM_TYPE_POWER_MONITOR, NMPowerMonitorClass))
#define NM_POWER_MONITOR_GET_CLASS(o) \
    (G_TYPE_INSTANCE_GET_CLASS((o), NM_TYPE_POWER_MONITOR, NMPowerMonitorClass))
#define NM_IS_POWER_MONITOR(o)       (G_TYPE_CHECK_INSTANCE_TYPE((o), NM_TYPE_POWER_MONITOR))
#define NM_IS_POWER_MONITOR_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE((k), NM_TYPE_POWER_MONITOR))

#define NM_POWER_MONITOR_SLEEPING "sleeping"
#define NM_POWER_MONITOR_SHUTDOWN "shutdown"

typedef struct _NMPowerMonitorClass NMPowerMonitorClass;

GType nm_power_monitor_get_type(void) G_GNUC_CONST;

NMPowerMonitor *nm_power_monitor_new(void);

typedef struct _NMPowerMonitorInhibitorHandle NMPowerMonitorInhibitorHandle;

NMPowerMonitorInhibitorHandle *nm_power_monitor_inhibit_take(NMPowerMonitor *self);
void nm_power_monitor_inhibit_release(NMPowerMonitor *self, NMPowerMonitorInhibitorHandle *handle);

#endif /* __NETWORKMANAGER_POWER_MONITOR_H__ */
