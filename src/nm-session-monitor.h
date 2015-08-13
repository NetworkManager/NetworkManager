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
 * (C) Copyright 2008 - 2010 Red Hat, Inc.
 * Author: David Zeuthen <davidz@redhat.com>
 * Author: Dan Williams <dcbw@redhat.com>
 */

#ifndef __NETWORKMANAGER_SESSION_MONITOR_H__
#define __NETWORKMANAGER_SESSION_MONITOR_H__


#include "nm-default.h"

G_BEGIN_DECLS

#define NM_TYPE_SESSION_MONITOR         (nm_session_monitor_get_type ())
#define NM_SESSION_MONITOR(o)           (G_TYPE_CHECK_INSTANCE_CAST ((o), NM_TYPE_SESSION_MONITOR, NMSessionMonitor))
#define NM_SESSION_MONITOR_CLASS(k)     (G_TYPE_CHECK_CLASS_CAST ((k), NM_TYPE_SESSION_MONITOR, NMSessionMonitorClass))
#define NM_SESSION_MONITOR_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), NM_TYPE_SESSION_MONITOR, NMSessionMonitorClass))
#define NM_IS_SESSION_MONITOR(o)        (G_TYPE_CHECK_INSTANCE_TYPE ((o), NM_TYPE_SESSION_MONITOR))
#define NM_IS_SESSION_MONITOR_CLASS(k)  (G_TYPE_CHECK_CLASS_TYPE ((k), NM_TYPE_SESSION_MONITOR))

#define NM_SESSION_MONITOR_CHANGED "changed"

typedef struct _NMSessionMonitorClass    NMSessionMonitorClass;

typedef void (*NMSessionCallback) (NMSessionMonitor *monitor, gpointer user_data);

GType             nm_session_monitor_get_type       (void) G_GNUC_CONST;

NMSessionMonitor *nm_session_monitor_get (void);

gulong            nm_session_monitor_connect        (NMSessionMonitor *self,
                                                     NMSessionCallback callback,
                                                     gpointer user_data);
void              nm_session_monitor_disconnect     (NMSessionMonitor *self,
                                                     gulong handler_id);

gboolean          nm_session_monitor_uid_to_user    (uid_t uid, const char **out_user);
gboolean          nm_session_monitor_user_to_uid    (const char *user, uid_t *out_uid);
gboolean          nm_session_monitor_session_exists (NMSessionMonitor *self,
                                                     uid_t uid,
                                                     gboolean active);

G_END_DECLS

#endif /* __NETWORKMANAGER_SESSION_MONITOR_H__ */

