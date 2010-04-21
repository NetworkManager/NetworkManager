/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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
 *
 * Copyright (C) 2005 - 2010 Red Hat, Inc.
 * Copyright (C) 2005 - 2008 Novell, Inc.
 * Copyright (C) 2005 Ray Strode
 */

#ifndef NM_NETLINK_MONITOR_H
#define NM_NETLINK_MONITOR_H

#include <glib.h>
#include <glib-object.h>
#include <netlink/netlink.h>
#include <netlink/route/link.h>

#define NM_TYPE_NETLINK_MONITOR            (nm_netlink_monitor_get_type ())
#define NM_NETLINK_MONITOR(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_NETLINK_MONITOR, NMNetlinkMonitor))
#define NM_NETLINK_MONITOR_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_NETLINK_MONITOR, NMNetlinkMonitorClass))
#define NM_IS_NETLINK_MONITOR(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_NETLINK_MONITOR))
#define NM_IS_NETLINK_MONITOR_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_NETLINK_MONITOR))
#define NM_NETLINK_MONITOR_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_NETLINK_MONITOR, NMNetlinkMonitorClass))

typedef enum {
	NM_NETLINK_MONITOR_ERROR_GENERIC = 0,
	NM_NETLINK_MONITOR_ERROR_NETLINK_ALLOC_HANDLE,
	NM_NETLINK_MONITOR_ERROR_NETLINK_CONNECT,
	NM_NETLINK_MONITOR_ERROR_NETLINK_JOIN_GROUP,
	NM_NETLINK_MONITOR_ERROR_NETLINK_ALLOC_LINK_CACHE,
	NM_NETLINK_MONITOR_ERROR_PROCESSING_MESSAGE,
	NM_NETLINK_MONITOR_ERROR_BAD_ALLOC,
	NM_NETLINK_MONITOR_ERROR_WAITING_FOR_SOCKET_DATA,
	NM_NETLINK_MONITOR_ERROR_LINK_CACHE_UPDATE
} NMNetlinkMonitorError;

typedef struct {
	GObject parent; 
} NMNetlinkMonitor;

typedef struct {
	GObjectClass parent_class;

	/* Signals */
	void (*notification) (NMNetlinkMonitor *monitor, struct nl_msg *msg);
	void (*carrier_on)   (NMNetlinkMonitor *monitor, int index);
	void (*carrier_off)  (NMNetlinkMonitor *monitor, int index);
	void (*error)        (NMNetlinkMonitor *monitor, GError *error);
} NMNetlinkMonitorClass;


#define NM_NETLINK_MONITOR_ERROR      (nm_netlink_monitor_error_quark ())
GType  nm_netlink_monitor_get_type    (void) G_GNUC_CONST;
GQuark nm_netlink_monitor_error_quark (void) G_GNUC_CONST;

NMNetlinkMonitor *nm_netlink_monitor_get (void);

gboolean          nm_netlink_monitor_open_connection  (NMNetlinkMonitor *monitor,
                                                       GError **error);
void              nm_netlink_monitor_close_connection (NMNetlinkMonitor *monitor);
void              nm_netlink_monitor_attach           (NMNetlinkMonitor *monitor);
void              nm_netlink_monitor_detach           (NMNetlinkMonitor *monitor);

gboolean          nm_netlink_monitor_subscribe        (NMNetlinkMonitor *monitor,
                                                       int group,
                                                       GError **error);
void              nm_netlink_monitor_unsubscribe      (NMNetlinkMonitor *monitor,
                                                       int group);

gboolean          nm_netlink_monitor_request_ip6_info (NMNetlinkMonitor *monitor,
                                                       GError **error);

gboolean          nm_netlink_monitor_request_status   (NMNetlinkMonitor *monitor,
                                                       GError **error);
gboolean          nm_netlink_monitor_get_flags_sync   (NMNetlinkMonitor *monitor,
                                                       guint32 ifindex,
                                                       guint32 *ifflags,
                                                       GError **error);

/* Generic utility functions */
int               nm_netlink_iface_to_index     (const char *iface);
char *            nm_netlink_index_to_iface     (int idx);
struct rtnl_link *nm_netlink_index_to_rtnl_link (int idx);
struct nl_handle *nm_netlink_get_default_handle (void);

#endif  /* NM_NETLINK_MONITOR_H */
