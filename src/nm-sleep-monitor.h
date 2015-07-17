/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* This program is free software; you can redistribute it and/or modify
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
 * (C) Copyright 2012 Red Hat, Inc.
 * Author: Matthias Clasen <mclasen@redhat.com>
 */

#ifndef __NETWORKMANAGER_SLEEP_MONITOR_H__
#define __NETWORKMANAGER_SLEEP_MONITOR_H__


#include "nm-default.h"

G_BEGIN_DECLS

#define NM_TYPE_SLEEP_MONITOR         (nm_sleep_monitor_get_type ())
#define NM_SLEEP_MONITOR(o)           (G_TYPE_CHECK_INSTANCE_CAST ((o), NM_TYPE_SLEEP_MONITOR, NMSleepMonitor))
#define NM_SLEEP_MONITOR_CLASS(k)     (G_TYPE_CHECK_CLASS_CAST ((k), NM_TYPE_SLEEP_MONITOR, NMSleepMonitorClass))
#define NM_SLEEP_MONITOR_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), NM_TYPE_SLEEP_MONITOR, NMSleepMonitorClass))
#define NM_IS_SLEEP_MONITOR(o)        (G_TYPE_CHECK_INSTANCE_TYPE ((o), NM_TYPE_SLEEP_MONITOR))
#define NM_IS_SLEEP_MONITOR_CLASS(k)  (G_TYPE_CHECK_CLASS_TYPE ((k), NM_TYPE_SLEEP_MONITOR))

#define NM_SLEEP_MONITOR_SLEEPING "sleeping"
#define NM_SLEEP_MONITOR_RESUMING "resuming"

typedef struct _NMSleepMonitorClass    NMSleepMonitorClass;

GType           nm_sleep_monitor_get_type     (void) G_GNUC_CONST;
NMSleepMonitor *nm_sleep_monitor_get          (void);

G_END_DECLS

#endif /* __NETWORKMANAGER_SLEEP_MONITOR_H__ */

