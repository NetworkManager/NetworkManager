/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2005 - 2010 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#ifndef __NETWORKMANAGER_DHCP_MANAGER_H__
#define __NETWORKMANAGER_DHCP_MANAGER_H__

#include "nm-dhcp-client.h"
#include "nm-dhcp-config.h"

#define NM_TYPE_DHCP_MANAGER (nm_dhcp_manager_get_type())
#define NM_DHCP_MANAGER(obj) \
    (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DHCP_MANAGER, NMDhcpManager))
#define NM_DHCP_MANAGER_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DHCP_MANAGER, NMDhcpManagerClass))
#define NM_IS_DHCP_MANAGER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DHCP_MANAGER))
#define NM_IS_DHCP_MANAGER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DHCP_MANAGER))
#define NM_DHCP_MANAGER_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DHCP_MANAGER, NMDhcpManagerClass))

typedef struct _NMDhcpManager      NMDhcpManager;
typedef struct _NMDhcpManagerClass NMDhcpManagerClass;

GType nm_dhcp_manager_get_type(void);

NMDhcpManager *nm_dhcp_manager_get(void);

const char *nm_dhcp_manager_get_config(NMDhcpManager *self);

void nm_dhcp_manager_set_default_hostname(NMDhcpManager *manager, const char *hostname);

NMDhcpClient *
nm_dhcp_manager_start_client(NMDhcpManager *manager, NMDhcpClientConfig *config, GError **error);

/* For testing only */
extern const char *nm_dhcp_helper_path;

extern const NMDhcpClientFactory *const _nm_dhcp_manager_factories[6];

void nmtst_dhcp_manager_unget(gpointer singleton_instance);

#endif /* __NETWORKMANAGER_DHCP_MANAGER_H__ */
