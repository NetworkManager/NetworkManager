/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* This program is free software; you can redistribute it and/or modify
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
 * Copyright 2014 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DHCP_LISTENER_H__
#define __NETWORKMANAGER_DHCP_LISTENER_H__

#include "nm-glib.h"

#define NM_TYPE_DHCP_LISTENER           (nm_dhcp_listener_get_type ())
#define NM_DHCP_LISTENER(obj)           (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DHCP_LISTENER, NMDhcpListener))
#define NM_IS_DHCP_LISTENER(obj)        (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DHCP_LISTENER))
#define NM_DHCP_LISTENER_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DHCP_LISTENER, NMDhcpListenerClass))

#define NM_DHCP_LISTENER_EVENT "event"

typedef GObject NMDhcpListener;
typedef GObjectClass NMDhcpListenerClass;

GType nm_dhcp_listener_get_type (void);

NMDhcpListener *nm_dhcp_listener_get (void);

#endif /* __NETWORKMANAGER_DHCP_LISTENER_H__ */
