// SPDX-License-Identifier: GPL-2.0+
/* Copyright 2014 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DHCP_LISTENER_H__
#define __NETWORKMANAGER_DHCP_LISTENER_H__

#define NM_TYPE_DHCP_LISTENER           (nm_dhcp_listener_get_type ())
#define NM_DHCP_LISTENER(obj)           (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DHCP_LISTENER, NMDhcpListener))
#define NM_IS_DHCP_LISTENER(obj)        (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DHCP_LISTENER))
#define NM_DHCP_LISTENER_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DHCP_LISTENER, NMDhcpListenerClass))

#define NM_DHCP_LISTENER_EVENT "event"

typedef struct _NMDhcpListener NMDhcpListener;
typedef struct _NMDhcpListenerClass NMDhcpListenerClass;

GType nm_dhcp_listener_get_type (void);

NMDhcpListener *nm_dhcp_listener_get (void);

#endif /* __NETWORKMANAGER_DHCP_LISTENER_H__ */
