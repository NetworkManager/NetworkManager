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
 * Copyright (C) 2005 - 2011 Red Hat, Inc.
 * Copyright (C) 2005 - 2008 Novell, Inc.
 */

#ifndef NM_VPN_SERVICE_H
#define NM_VPN_SERVICE_H

#include <glib.h>
#include <glib-object.h>
#include "nm-device.h"
#include "nm-vpn-connection.h"

#define NM_TYPE_VPN_SERVICE            (nm_vpn_service_get_type ())
#define NM_VPN_SERVICE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_VPN_SERVICE, NMVPNService))
#define NM_VPN_SERVICE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_VPN_SERVICE, NMVPNServiceClass))
#define NM_IS_VPN_SERVICE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_VPN_SERVICE))
#define NM_IS_VPN_SERVICE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_VPN_SERVICE))
#define NM_VPN_SERVICE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_VPN_SERVICE, NMVPNServiceClass))

typedef struct {
	GObject parent;
} NMVPNService;

typedef struct {
	GObjectClass parent;
} NMVPNServiceClass;

GType nm_vpn_service_get_type (void);

NMVPNService * nm_vpn_service_new (const char *namefile, GError **error);

/* Returns the VPN service's D-Bus service name */
const char *nm_vpn_service_get_dbus_service (NMVPNService *service);

/* Returns the path of the VPN service's .name file */
const char *nm_vpn_service_get_name_file (NMVPNService *service);

gboolean nm_vpn_service_activate (NMVPNService *service,
                                  NMVPNConnection *vpn,
                                  GError **error);

void nm_vpn_service_stop_connections (NMVPNService *service,
                                      gboolean quitting,
                                      NMVPNConnectionStateReason reason);

#endif  /* NM_VPN_VPN_SERVICE_H */
