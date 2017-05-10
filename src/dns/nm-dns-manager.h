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

#include "nm-ip4-config.h"
#include "nm-ip6-config.h"

typedef enum {
	NM_DNS_IP_CONFIG_TYPE_DEFAULT = 0,
	NM_DNS_IP_CONFIG_TYPE_BEST_DEVICE,
	NM_DNS_IP_CONFIG_TYPE_VPN
} NMDnsIPConfigType;

enum {
	NM_DNS_PRIORITY_DEFAULT_NORMAL  = 100,
	NM_DNS_PRIORITY_DEFAULT_VPN     = 50,
};

typedef struct {
	gpointer config;
	NMDnsIPConfigType type;
	char *iface;
} NMDnsIPConfigData;

#define NM_TYPE_DNS_MANAGER (nm_dns_manager_get_type ())
#define NM_DNS_MANAGER(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), NM_TYPE_DNS_MANAGER, NMDnsManager))
#define NM_DNS_MANAGER_CLASS(k) (G_TYPE_CHECK_CLASS_CAST((k), NM_TYPE_DNS_MANAGER, NMDnsManagerClass))
#define NM_IS_DNS_MANAGER(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), NM_TYPE_DNS_MANAGER))
#define NM_IS_DNS_MANAGER_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), NM_TYPE_DNS_MANAGER))
#define NM_DNS_MANAGER_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), NM_TYPE_DNS_MANAGER, NMDnsManagerClass))

/* properties */
#define NM_DNS_MANAGER_MODE "mode"
#define NM_DNS_MANAGER_RC_MANAGER "rc-manager"
#define NM_DNS_MANAGER_CONFIGURATION "configuration"

/* internal signals */
#define NM_DNS_MANAGER_CONFIG_CHANGED "config-changed"

typedef struct _NMDnsManager NMDnsManager;
typedef struct _NMDnsManagerClass NMDnsManagerClass;

GType nm_dns_manager_get_type (void);

NMDnsManager * nm_dns_manager_get (void);

/* Allow changes to be batched together */
void nm_dns_manager_begin_updates (NMDnsManager *self, const char *func);
void nm_dns_manager_end_updates (NMDnsManager *self, const char *func);

gboolean nm_dns_manager_add_ip_config (NMDnsManager *self,
                                       const char *iface,
                                       gpointer config,
                                       NMDnsIPConfigType cfg_type);

gboolean nm_dns_manager_remove_ip_config (NMDnsManager *self, gpointer config);

void nm_dns_manager_set_initial_hostname (NMDnsManager *self,
                                          const char *hostname);
void nm_dns_manager_set_hostname         (NMDnsManager *self,
                                          const char *hostname,
                                          gboolean skip_update);

/**
 * NMDnsManagerResolvConfManager
 * @NM_DNS_MANAGER_RESOLV_CONF_MAN_UNKNOWN: unspecified rc-manager.
 * @NM_DNS_MANAGER_RESOLV_CONF_MAN_UNMANAGED: do not touch /etc/resolv.conf
 *   (but still write the internal copy -- unless it is symlinked by
 *   /etc/resolv.conf)
 * @NM_DNS_MANAGER_RESOLV_CONF_MAN_IMMUTABLE: similar to "unmanaged",
 *   but indicates that resolv.conf cannot be modified.
 * @NM_DNS_MANAGER_RESOLV_CONF_MAN_SYMLINK: NM writes resolv.conf
 *   by symlinking it to the run state directory.
 * @NM_DNS_MANAGER_RESOLV_CONF_MAN_FILE: Like SYMLINK, but instead of
 *   symlinking /etc/resolv.conf, write it as a file.
 * @NM_DNS_MANAGER_RESOLV_CONF_MAN_RESOLVCONF: NM is managing resolv.conf
     through resolvconf
 * @NM_DNS_MANAGER_RESOLV_CONF_MAN_NETCONFIG: NM is managing resolv.conf
     through netconfig
 *
 * NMDnsManager's management of resolv.conf
 */
typedef enum {
	NM_DNS_MANAGER_RESOLV_CONF_MAN_UNKNOWN,
	NM_DNS_MANAGER_RESOLV_CONF_MAN_UNMANAGED,
	NM_DNS_MANAGER_RESOLV_CONF_MAN_IMMUTABLE,
	NM_DNS_MANAGER_RESOLV_CONF_MAN_SYMLINK,
	NM_DNS_MANAGER_RESOLV_CONF_MAN_FILE,
	NM_DNS_MANAGER_RESOLV_CONF_MAN_RESOLVCONF,
	NM_DNS_MANAGER_RESOLV_CONF_MAN_NETCONFIG,
} NMDnsManagerResolvConfManager;

gboolean nm_dns_manager_get_resolv_conf_explicit (NMDnsManager *self);

void nm_dns_manager_stop (NMDnsManager *self);

#endif /* __NETWORKMANAGER_DNS_MANAGER_H__ */
