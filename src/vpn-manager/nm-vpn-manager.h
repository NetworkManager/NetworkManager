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
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#ifndef __NM_VPN_MANAGER_H__
#define __NM_VPN_MANAGER_H__

#include "nm-vpn-connection.h"

#define NM_TYPE_VPN_MANAGER            (nm_vpn_manager_get_type ())
#define NM_VPN_MANAGER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_VPN_MANAGER, NMVpnManager))
#define NM_VPN_MANAGER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_VPN_MANAGER, NMVpnManagerClass))
#define NM_IS_VPN_MANAGER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_VPN_MANAGER))
#define NM_IS_VPN_MANAGER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_VPN_MANAGER))
#define NM_VPN_MANAGER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_VPN_MANAGER, NMVpnManagerClass))

typedef struct _NMVpnManager NMVpnManager;
typedef struct _NMVpnManagerClass NMVpnManagerClass;

GType nm_vpn_manager_get_type (void);

NMVpnManager *nm_vpn_manager_get (void);

gboolean nm_vpn_manager_activate_connection (NMVpnManager *manager,
                                             NMVpnConnection *vpn,
                                             GError **error);

#endif /* __NM_VPN_MANAGER_H__ */
