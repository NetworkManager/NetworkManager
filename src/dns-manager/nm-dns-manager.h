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
 * Copyright (C) 2004 - 2005 Colin Walters <walters@redhat.com>
 * Copyright (C) 2004 - 2013 Red Hat, Inc.
 * Copyright (C) 2005 - 2008 Novell, Inc.
 *   and others
 */

#ifndef __NETWORKMANAGER_DNS_MANAGER_H__
#define __NETWORKMANAGER_DNS_MANAGER_H__

#include "nm-glib.h"
#include "nm-ip4-config.h"
#include "nm-ip6-config.h"

typedef enum {
	NM_DNS_IP_CONFIG_TYPE_DEFAULT = 0,
	NM_DNS_IP_CONFIG_TYPE_BEST_DEVICE,
	NM_DNS_IP_CONFIG_TYPE_VPN
} NMDnsIPConfigType;

G_BEGIN_DECLS

#define NM_TYPE_DNS_MANAGER (nm_dns_manager_get_type ())
#define NM_DNS_MANAGER(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), NM_TYPE_DNS_MANAGER, NMDnsManager))
#define NM_DNS_MANAGER_CLASS(k) (G_TYPE_CHECK_CLASS_CAST((k), NM_TYPE_DNS_MANAGER, NMDnsManagerClass))
#define NM_IS_DNS_MANAGER(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), NM_TYPE_DNS_MANAGER))
#define NM_IS_DNS_MANAGER_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), NM_TYPE_DNS_MANAGER))
#define NM_DNS_MANAGER_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), NM_TYPE_DNS_MANAGER, NMDnsManagerClass)) 

typedef struct {
	GObject parent;
} NMDnsManager;

typedef struct {
	GObjectClass parent;

	/* Signals */
	void (*config_changed) (NMDnsManager *mgr);
} NMDnsManagerClass;

GType nm_dns_manager_get_type (void);

NMDnsManager * nm_dns_manager_get (void);

/* Allow changes to be batched together */
void nm_dns_manager_begin_updates (NMDnsManager *mgr, const char *func);
void nm_dns_manager_end_updates (NMDnsManager *mgr, const char *func);

gboolean nm_dns_manager_add_ip4_config (NMDnsManager *mgr,
                                        const char *iface,
                                        NMIP4Config *config,
                                        NMDnsIPConfigType cfg_type);

gboolean nm_dns_manager_remove_ip4_config (NMDnsManager *mgr, NMIP4Config *config);

gboolean nm_dns_manager_add_ip6_config (NMDnsManager *mgr,
                                        const char *iface,
                                        NMIP6Config *config,
                                        NMDnsIPConfigType cfg_type);

gboolean nm_dns_manager_remove_ip6_config (NMDnsManager *mgr, NMIP6Config *config);

void nm_dns_manager_set_initial_hostname (NMDnsManager *mgr,
                                          const char *hostname);
void nm_dns_manager_set_hostname         (NMDnsManager *mgr,
                                          const char *hostname);

/**
 * NMDnsManagerResolvConfMode:
 * @NM_DNS_MANAGER_RESOLV_CONF_UNMANAGED: NM is not managing resolv.conf
 * @NM_DNS_MANAGER_RESOLV_CONF_EXPLICIT: NM is managing resolv.conf by
 *   adding and removing "nameserver" lines corresponding to the currently
 *   active connections
 * @NM_DNS_MANAGER_RESOLV_CONF_PROXY: NM is managing resolv.conf by
 *   pointing it to some other service (eg, dnsmasq) that knows the
 *   nameservers corresponding to the currently active connections.
 *
 * NMDnsManager's behavior toward /etc/resolv.conf.
 */
typedef enum {
	NM_DNS_MANAGER_RESOLV_CONF_UNMANAGED,
	NM_DNS_MANAGER_RESOLV_CONF_EXPLICIT,
	NM_DNS_MANAGER_RESOLV_CONF_PROXY
} NMDnsManagerResolvConfMode;

/**
 * NMDnsManagerResolvConfManager
 * @NM_DNS_MANAGER_RESOLV_CONF_MAN_NONE: NM directly writes resolv.conf
 * @NM_DNS_MANAGER_RESOLV_CONF_MAN_RESOLVCONF: NM is managing resolv.conf
     through resolvconf
 * @NM_DNS_MANAGER_RESOLV_CONF_MAN_NETCONFIG: NM is managing resolv.conf
     through netconfig
 *
 * NMDnsManager's management of resolv.conf
 */
typedef enum {
	NM_DNS_MANAGER_RESOLV_CONF_MAN_NONE,
	NM_DNS_MANAGER_RESOLV_CONF_MAN_RESOLVCONF,
	NM_DNS_MANAGER_RESOLV_CONF_MAN_NETCONFIG,
} NMDnsManagerResolvConfManager;

NMDnsManagerResolvConfMode nm_dns_manager_get_resolv_conf_mode (NMDnsManager *mgr);

G_END_DECLS

#endif /* __NETWORKMANAGER_DNS_MANAGER_H__ */
