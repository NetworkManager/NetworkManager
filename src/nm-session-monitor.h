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

#ifndef NM_SESSION_MONITOR_H
#define NM_SESSION_MONITOR_H

#include <glib-object.h>

G_BEGIN_DECLS

#define NM_TYPE_SESSION_MONITOR         (nm_session_monitor_get_type ())
#define NM_SESSION_MONITOR(o)           (G_TYPE_CHECK_INSTANCE_CAST ((o), NM_TYPE_SESSION_MONITOR, NMSessionMonitor))
#define NM_SESSION_MONITOR_CLASS(k)     (G_TYPE_CHECK_CLASS_CAST ((k), NM_TYPE_SESSION_MONITOR, NMSessionMonitorClass))
#define NM_SESSION_MONITOR_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), NM_TYPE_SESSION_MONITOR, NMSessionMonitorClass))
#define NM_IS_SESSION_MONITOR(o)        (G_TYPE_CHECK_INSTANCE_TYPE ((o), NM_TYPE_SESSION_MONITOR))
#define NM_IS_SESSION_MONITOR_CLASS(k)  (G_TYPE_CHECK_CLASS_TYPE ((k), NM_TYPE_SESSION_MONITOR))

#define NM_SESSION_MONITOR_CHANGED "changed"

typedef struct _NMSessionMonitor         NMSessionMonitor;
typedef struct _NMSessionMonitorClass    NMSessionMonitorClass;

GType             nm_session_monitor_get_type     (void) G_GNUC_CONST;
NMSessionMonitor *nm_session_monitor_get          (void);

gboolean          nm_session_monitor_user_has_session (NMSessionMonitor *monitor,
                                                       const char *username,
                                                       uid_t *out_uid,
                                                       GError **error);

gboolean          nm_session_monitor_uid_has_session  (NMSessionMonitor *monitor,
                                                       uid_t uid,
                                                       const char **out_user,
                                                       GError **error);

gboolean          nm_session_monitor_user_active      (NMSessionMonitor *monitor,
                                                       const char *username,
                                                       GError **error);

gboolean          nm_session_monitor_uid_active       (NMSessionMonitor *monitor,
                                                       uid_t uid,
                                                       GError **error);

G_END_DECLS

#endif /* NM_SESSION_MONITOR_H */

