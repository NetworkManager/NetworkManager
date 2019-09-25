// SPDX-License-Identifier: GPL-2.0+
/*
 * (C) Copyright 2008 - 2010 Red Hat, Inc.
 * Author: David Zeuthen <davidz@redhat.com>
 * Author: Dan Williams <dcbw@redhat.com>
 */

#ifndef __NETWORKMANAGER_SESSION_MONITOR_H__
#define __NETWORKMANAGER_SESSION_MONITOR_H__

#define NM_TYPE_SESSION_MONITOR         (nm_session_monitor_get_type ())
#define NM_SESSION_MONITOR(o)           (G_TYPE_CHECK_INSTANCE_CAST ((o), NM_TYPE_SESSION_MONITOR, NMSessionMonitor))
#define NM_SESSION_MONITOR_CLASS(k)     (G_TYPE_CHECK_CLASS_CAST ((k), NM_TYPE_SESSION_MONITOR, NMSessionMonitorClass))
#define NM_SESSION_MONITOR_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), NM_TYPE_SESSION_MONITOR, NMSessionMonitorClass))
#define NM_IS_SESSION_MONITOR(o)        (G_TYPE_CHECK_INSTANCE_TYPE ((o), NM_TYPE_SESSION_MONITOR))
#define NM_IS_SESSION_MONITOR_CLASS(k)  (G_TYPE_CHECK_CLASS_TYPE ((k), NM_TYPE_SESSION_MONITOR))

#define NM_SESSION_MONITOR_CHANGED "changed"

typedef struct _NMSessionMonitorClass NMSessionMonitorClass;

GType nm_session_monitor_get_type (void) G_GNUC_CONST;

NMSessionMonitor *nm_session_monitor_get (void);

gboolean nm_session_monitor_uid_to_user    (uid_t uid, const char **out_user);
gboolean nm_session_monitor_user_to_uid    (const char *user, uid_t *out_uid);
gboolean nm_session_monitor_session_exists (NMSessionMonitor *self,
                                            uid_t uid,
                                            gboolean active);

#endif /* __NETWORKMANAGER_SESSION_MONITOR_H__ */
