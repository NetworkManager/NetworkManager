// SPDX-License-Identifier: GPL-2.0+
/*
 * (C) Copyright 2012-2016 Red Hat, Inc.
 * Author: Matthias Clasen <mclasen@redhat.com>
 */

#ifndef __NETWORKMANAGER_SLEEP_MONITOR_H__
#define __NETWORKMANAGER_SLEEP_MONITOR_H__

#define NM_TYPE_SLEEP_MONITOR         (nm_sleep_monitor_get_type ())
#define NM_SLEEP_MONITOR(o)           (G_TYPE_CHECK_INSTANCE_CAST ((o), NM_TYPE_SLEEP_MONITOR, NMSleepMonitor))
#define NM_SLEEP_MONITOR_CLASS(k)     (G_TYPE_CHECK_CLASS_CAST ((k), NM_TYPE_SLEEP_MONITOR, NMSleepMonitorClass))
#define NM_SLEEP_MONITOR_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), NM_TYPE_SLEEP_MONITOR, NMSleepMonitorClass))
#define NM_IS_SLEEP_MONITOR(o)        (G_TYPE_CHECK_INSTANCE_TYPE ((o), NM_TYPE_SLEEP_MONITOR))
#define NM_IS_SLEEP_MONITOR_CLASS(k)  (G_TYPE_CHECK_CLASS_TYPE ((k), NM_TYPE_SLEEP_MONITOR))

#define NM_SLEEP_MONITOR_SLEEPING "sleeping"

typedef struct _NMSleepMonitorClass NMSleepMonitorClass;

GType           nm_sleep_monitor_get_type (void) G_GNUC_CONST;

NMSleepMonitor *nm_sleep_monitor_new (void);

typedef struct _NMSleepMonitorInhibitorHandle NMSleepMonitorInhibitorHandle;

NMSleepMonitorInhibitorHandle *nm_sleep_monitor_inhibit_take    (NMSleepMonitor *self);
void                           nm_sleep_monitor_inhibit_release (NMSleepMonitor *self,
                                                                 NMSleepMonitorInhibitorHandle *handle);

#endif /* __NETWORKMANAGER_SLEEP_MONITOR_H__ */

