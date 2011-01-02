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
 * Copyright (C) 2005 - 2008 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#ifndef NM_VPN_MANAGER_H
#define NM_VPN_MANAGER_H

#include <glib.h>
#include <glib-object.h>
#include "nm-vpn-connection.h"
#include "nm-activation-request.h"

#define NM_TYPE_VPN_MANAGER            (nm_vpn_manager_get_type ())
#define NM_VPN_MANAGER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_VPN_MANAGER, NMVPNManager))
#define NM_VPN_MANAGER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_VPN_MANAGER, NMVPNManagerClass))
#define NM_IS_VPN_MANAGER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_VPN_MANAGER))
#define NM_IS_VPN_MANAGER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_VPN_MANAGER))
#define NM_VPN_MANAGER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_VPN_MANAGER, NMVPNManagerClass))

typedef enum
{
	NM_VPN_MANAGER_ERROR_DEVICE_NOT_ACTIVE = 0,
	NM_VPN_MANAGER_ERROR_CONNECTION_INVALID,
	NM_VPN_MANAGER_ERROR_SERVICE_INVALID,
	NM_VPN_MANAGER_ERROR_SERVICE_START_FAILED,
} NMVPNManagerError;

#define NM_VPN_MANAGER_ERROR (nm_vpn_manager_error_quark ())
#define NM_TYPE_VPN_MANAGER_ERROR (nm_vpn_manager_error_get_type ()) 

GQuark nm_vpn_manager_error_quark (void);
GType nm_vpn_manager_error_get_type (void);


typedef struct {
	GObject parent;
} NMVPNManager;

typedef struct {
	GObjectClass parent;

	/* Signals */
	void (*connection_deactivated) (NMVPNManager *manager,
	                                NMVPNConnection *connection,
	                                NMVPNConnectionState state,
	                                NMVPNConnectionStateReason reason);
} NMVPNManagerClass;

GType nm_vpn_manager_get_type (void);

NMVPNManager *nm_vpn_manager_get (void);

NMVPNConnection *nm_vpn_manager_activate_connection (NMVPNManager *manager,
                                                     NMConnection *connection,
                                                     NMActRequest *act_request,
                                                     NMDevice *device,
                                                     GError **error);

gboolean nm_vpn_manager_deactivate_connection (NMVPNManager *manager,
                                               const char *path,
                                               NMVPNConnectionStateReason reason);

void nm_vpn_manager_add_active_connections (NMVPNManager *manager,
                                            NMConnection *filter,
                                            GPtrArray *list);

GSList *nm_vpn_manager_get_active_connections (NMVPNManager *manager);

NMConnection *nm_vpn_manager_get_connection_for_active (NMVPNManager *manager,
                                                        const char *active_path);

#endif /* NM_VPN_VPN_MANAGER_H */
