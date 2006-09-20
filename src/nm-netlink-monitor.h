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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */
#ifndef NM_NETLINK_MONITOR_H
#define NM_NETLINK_MONITOR_H

#include <glib.h>
#include <glib-object.h>

G_BEGIN_DECLS

#define NM_TYPE_NETLINK_MONITOR	    (nm_netlink_monitor_get_type ())
#define NM_NETLINK_MONITOR(obj)	    (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_NETLINK_MONITOR, NmNetlinkMonitor))
#define NM_NETLINK_MONITOR_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_NETLINK_MONITOR, NmNetlinkMonitorClass))
#define NM_IS_NETLINK_MONITOR(obj)	 (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_NETLINK_MONITOR))
#define NM_IS_NETLINK_MONITOR_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_NETLINK_MONITOR))
#define NM_NETLINK_MONITOR_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_NETLINK_MONITOR, NmNetlinkMonitorClass))
#define NM_NETLINK_MONITOR_ERROR	   (nm_netlink_monitor_error_quark ())


typedef struct _NmNetlinkMonitor	NmNetlinkMonitor;
typedef struct _NmNetlinkMonitorClass   NmNetlinkMonitorClass;
typedef struct _NmNetlinkMonitorPrivate NmNetlinkMonitorPrivate;
typedef enum   _NmNetlinkMonitorError   NmNetlinkMonitorError;

struct _NmNetlinkMonitor 
{
	GObject parent; 

	/*< private >*/
	NmNetlinkMonitorPrivate *priv;
};

struct _NmNetlinkMonitorClass 
{
	GObjectClass parent_class;

	/* Signals */
	void	(* interface_connected)		(NmNetlinkMonitor * monitor,
						 GObject *dev);
	void	(* interface_disconnected)	(NmNetlinkMonitor * monitor,
						 GObject *dev);
	void (* wireless_event)			(NmNetlinkMonitor * monitor,
						 GObject *dev,
						 const gchar * data,
						 int data_len);
	void	(* error)			(NmNetlinkMonitor * monitor,
						 GError * error);
};

enum _NmNetlinkMonitorError 
{
	NM_NETLINK_MONITOR_ERROR_GENERIC = 0,
	NM_NETLINK_MONITOR_ERROR_OPENING_SOCKET,
	NM_NETLINK_MONITOR_ERROR_BINDING_TO_SOCKET,
	NM_NETLINK_MONITOR_ERROR_BAD_SENDER,
	NM_NETLINK_MONITOR_ERROR_BAD_SOCKET_DATA,
	NM_NETLINK_MONITOR_ERROR_WAITING_FOR_SOCKET_DATA,
	NM_NETLINK_MONITOR_ERROR_READING_FROM_SOCKET,
	NM_NETLINK_MONITOR_ERROR_SENDING_TO_SOCKET
};

GType	nm_netlink_monitor_get_type	(void)	G_GNUC_CONST;
GQuark	nm_netlink_monitor_error_quark	(void)	G_GNUC_CONST;

struct NMData;
NmNetlinkMonitor	*nm_netlink_monitor_new	(struct NMData *data);

gboolean
nm_netlink_monitor_open_connection (NmNetlinkMonitor  *monitor,
				    GError	     **error);

void
nm_netlink_monitor_close_connection (NmNetlinkMonitor  *monitor);

void	nm_netlink_monitor_attach	(NmNetlinkMonitor	*monitor,
					 GMainContext		*context);
void	nm_netlink_monitor_detach	(NmNetlinkMonitor	*monitor);

gboolean	nm_netlink_monitor_request_status	(NmNetlinkMonitor *monitor,
							 GError		**error);
G_END_DECLS
#endif  /* NM_NETLINK_MONITOR_H */
