/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2004 - 2005 Colin Walters <walters@redhat.com>
 * Copyright (C) 2004 - 2013 Red Hat, Inc.
 * Copyright (C) 2005 - 2008 Novell, Inc.
 */

#ifndef __NETWORKMANAGER_DNS_MANAGER_H__
#define __NETWORKMANAGER_DNS_MANAGER_H__

#include "c-list/src/c-list.h"
#include "nm-setting-connection.h"
#include "nm-dns-plugin.h"

struct _NMDnsConfigData;
struct _NMDnsManager;

typedef struct {
    struct _NMDnsConfigData *data;
    gconstpointer            source_tag;
    const NML3ConfigData    *l3cd;
    CList                    data_lst;
    CList                    ip_data_lst;
    NMDnsIPConfigType        ip_config_type;
    int                      addr_family;
    struct {
        const char **search;
        char       **reverse;

        /* Whether "search" explicitly contains a default route "~"
         * or "". It is redundant information, but for faster lookup. */
        bool has_default_route_explicit : 1;

        /* Whether an explicit "~" search domain should be added.
         * For systemd-resolved, this configured an explicit wildcard
         * search domain, and should be used for profiles with negative
         * DNS priority.
         *
         * If "has_default_route_explicit", this is always TRUE and implied.
         *
         * With systemd-resolved, if TRUE we will set a "." search domain.
         */
        bool has_default_route_exclusive : 1;

        /* Whether the device should be used for any domains "~".
         *
         * If "has_default_route_exclusive", this is always TRUE and implied.
         *
         * With systemd-resolved, this is the value for SetLinkDefaultRoute(). */
        bool has_default_route : 1;
    } domains;
} NMDnsConfigIPData;

typedef struct _NMDnsConfigData {
    int                   ifindex;
    struct _NMDnsManager *self;
    CList                 data_lst_head;
    CList                 configs_lst;
} NMDnsConfigData;

/*****************************************************************************/

#define NM_TYPE_DNS_MANAGER (nm_dns_manager_get_type())
#define NM_DNS_MANAGER(o)   (_NM_G_TYPE_CHECK_INSTANCE_CAST((o), NM_TYPE_DNS_MANAGER, NMDnsManager))
#define NM_DNS_MANAGER_CLASS(k) \
    (G_TYPE_CHECK_CLASS_CAST((k), NM_TYPE_DNS_MANAGER, NMDnsManagerClass))
#define NM_IS_DNS_MANAGER(o)       (G_TYPE_CHECK_INSTANCE_TYPE((o), NM_TYPE_DNS_MANAGER))
#define NM_IS_DNS_MANAGER_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE((k), NM_TYPE_DNS_MANAGER))
#define NM_DNS_MANAGER_GET_CLASS(o) \
    (G_TYPE_INSTANCE_GET_CLASS((o), NM_TYPE_DNS_MANAGER, NMDnsManagerClass))

/* properties */
#define NM_DNS_MANAGER_MODE           "mode"
#define NM_DNS_MANAGER_RC_MANAGER     "rc-manager"
#define NM_DNS_MANAGER_CONFIGURATION  "configuration"
#define NM_DNS_MANAGER_UPDATE_PENDING "update-pending"

/* internal signals */
#define NM_DNS_MANAGER_CONFIG_CHANGED "config-changed"

typedef struct _NMDnsManager      NMDnsManager;
typedef struct _NMDnsManagerClass NMDnsManagerClass;

GType nm_dns_manager_get_type(void);

NMDnsManager *nm_dns_manager_get(void);

/* Allow changes to be batched together */
void nm_dns_manager_begin_updates(NMDnsManager *self, const char *func);
void nm_dns_manager_end_updates(NMDnsManager *self, const char *func);

gboolean nm_dns_manager_set_ip_config(NMDnsManager         *self,
                                      int                   addr_family,
                                      gconstpointer         source_tag,
                                      const NML3ConfigData *l3cd,
                                      NMDnsIPConfigType     ip_config_type,
                                      gboolean              replace_all);

void nm_dns_manager_set_hostname(NMDnsManager *self, const char *hostname, gboolean skip_update);

/**
 * NMDnsManagerResolvConfManager
 * @NM_DNS_MANAGER_RESOLV_CONF_MAN_UNKNOWN: unspecified rc-manager.
 * @NM_DNS_MANAGER_RESOLV_CONF_MAN_UNMANAGED: do not touch /etc/resolv.conf
 *   (but still write the internal copy -- unless it is symlinked by
 *   /etc/resolv.conf)
 * @NM_DNS_MANAGER_RESOLV_CONF_MAN_AUTO: if /etc/resolv.conf is marked
 *   as an immutable file, use "unmanaged" and don't touch /etc/resolv.conf.
 *   Otherwise, if "systemd-resolved" is enabled (or detected), configure systemd-resolved via D-Bus
 *   and don't touch /etc/resolv.conf.
 *   Otherwise, if "resolvconf" application is found, use it.
 *   As last resort, fallback to "symlink" which writes to /etc/resolv.conf
 *   if (and only if) the file is missing or not a symlink.
 * @NM_DNS_MANAGER_RESOLV_CONF_MAN_IMMUTABLE: similar to "unmanaged",
 *   but indicates that resolv.conf cannot be modified.
 * @NM_DNS_MANAGER_RESOLV_CONF_MAN_SYMLINK: NM writes /etc/resolv.conf
 *   if the file is missing or not a symlink. An existing symlink is
 *   left untouched.
 * @NM_DNS_MANAGER_RESOLV_CONF_MAN_FILE: Write to /etc/resolv.conf directly.
 *   If it is a file, write it as file, otherwise follow symlinks.
 * @NM_DNS_MANAGER_RESOLV_CONF_MAN_RESOLVCONF: NM is managing resolv.conf
     through resolvconf
 * @NM_DNS_MANAGER_RESOLV_CONF_MAN_NETCONFIG: NM is managing resolv.conf
     through netconfig
 *
 * NMDnsManager's management of resolv.conf
 */
typedef enum {
    NM_DNS_MANAGER_RESOLV_CONF_MAN_UNKNOWN,
    NM_DNS_MANAGER_RESOLV_CONF_MAN_AUTO,
    NM_DNS_MANAGER_RESOLV_CONF_MAN_UNMANAGED,
    NM_DNS_MANAGER_RESOLV_CONF_MAN_IMMUTABLE,
    NM_DNS_MANAGER_RESOLV_CONF_MAN_SYMLINK,
    NM_DNS_MANAGER_RESOLV_CONF_MAN_FILE,
    NM_DNS_MANAGER_RESOLV_CONF_MAN_RESOLVCONF,
    NM_DNS_MANAGER_RESOLV_CONF_MAN_NETCONFIG,
} NMDnsManagerResolvConfManager;

void nm_dns_manager_stop(NMDnsManager *self);

NMDnsPlugin *nm_dns_manager_get_systemd_resolved(NMDnsManager *self);

gboolean nm_dns_manager_get_update_pending(NMDnsManager *self);

/*****************************************************************************/

char *nmtst_dns_create_resolv_conf(const char *const *searches,
                                   const char *const *nameservers,
                                   const char *const *options);

#endif /* __NETWORKMANAGER_DNS_MANAGER_H__ */
