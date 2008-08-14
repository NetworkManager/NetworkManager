/* nm-netlink-monitor.h - monitor netlink socket for network 
 *			  interface eventss
 *
 * Copyright (C) 2005 Ray Strode
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
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
 */
#ifndef NM_NETLINK_MONITOR_H
#define NM_NETLINK_MONITOR_H

#include <glib.h>
#include <glib-object.h>

G_BEGIN_DECLS

#define NM_TYPE_NETLINK_MONITOR	    (nm_netlink_monitor_get_type ())
#define NM_NETLINK_MONITOR(obj)	    (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_NETLINK_MONITOR, NMNetlinkMonitor))
#define NM_NETLINK_MONITOR_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_NETLINK_MONITOR, NMNetlinkMonitorClass))
#define NM_IS_NETLINK_MONITOR(obj)	 (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_NETLINK_MONITOR))
#define NM_IS_NETLINK_MONITOR_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_NETLINK_MONITOR))
#define NM_NETLINK_MONITOR_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_NETLINK_MONITOR, NMNetlinkMonitorClass))
#define NM_NETLINK_MONITOR_ERROR	   (nm_netlink_monitor_error_quark ())

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
	void (*carrier_on)    (NMNetlinkMonitor *monitor, int index);
	void (*carrier_off)   (NMNetlinkMonitor *monitor, int index);
	void (*error)         (NMNetlinkMonitor *monitor, GError *error);
} NMNetlinkMonitorClass;


GType	nm_netlink_monitor_get_type	(void)	G_GNUC_CONST;
GQuark	nm_netlink_monitor_error_quark	(void)	G_GNUC_CONST;

NMNetlinkMonitor *nm_netlink_monitor_get (void);

gboolean          nm_netlink_monitor_open_connection (NMNetlinkMonitor *monitor,
													  GError **error);
void              nm_netlink_monitor_close_connection (NMNetlinkMonitor *monitor);
void              nm_netlink_monitor_attach	          (NMNetlinkMonitor	*monitor,
													   GMainContext *context);
void              nm_netlink_monitor_detach	          (NMNetlinkMonitor *monitor);
gboolean          nm_netlink_monitor_request_status   (NMNetlinkMonitor *monitor,
													   GError **error);
G_END_DECLS

#endif  /* NM_NETLINK_MONITOR_H */
