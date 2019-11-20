// SPDX-License-Identifier: GPL-2.0+
/*
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
