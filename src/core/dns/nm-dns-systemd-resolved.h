/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2010 Red Hat, Inc.
 * Copyright (C) 2016 Sjoerd Simons <sjoerd@luon.net>
 */

#ifndef __NETWORKMANAGER_DNS_SYSTEMD_RESOLVED_H__
#define __NETWORKMANAGER_DNS_SYSTEMD_RESOLVED_H__

#include "nm-dns-plugin.h"
#include "nm-dns-manager.h"

#define NM_TYPE_DNS_SYSTEMD_RESOLVED (nm_dns_systemd_resolved_get_type())
#define NM_DNS_SYSTEMD_RESOLVED(obj) \
    (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DNS_SYSTEMD_RESOLVED, NMDnsSystemdResolved))
#define NM_DNS_SYSTEMD_RESOLVED_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DNS_SYSTEMD_RESOLVED, NMDnsSystemdResolvedClass))
#define NM_IS_DNS_SYSTEMD_RESOLVED(obj) \
    (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DNS_SYSTEMD_RESOLVED))
#define NM_IS_DNS_SYSTEMD_RESOLVED_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DNS_SYSTEMD_RESOLVED))
#define NM_DNS_SYSTEMD_RESOLVED_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DNS_SYSTEMD_RESOLVED, NMDnsSystemdResolvedClass))

typedef struct _NMDnsSystemdResolved      NMDnsSystemdResolved;
typedef struct _NMDnsSystemdResolvedClass NMDnsSystemdResolvedClass;

GType nm_dns_systemd_resolved_get_type(void);

NMDnsPlugin *nm_dns_systemd_resolved_new(void);

gboolean nm_dns_systemd_resolved_is_running(NMDnsSystemdResolved *self);

/*****************************************************************************/

typedef struct _NMDnsSystemdResolvedResolveHandle NMDnsSystemdResolvedResolveHandle;

typedef struct {
    const char *name;
    int         ifindex;
} NMDnsSystemdResolvedAddressResult;

typedef void (*NMDnsSystemdResolvedResolveAddressCallback)(
    NMDnsSystemdResolved                    *self,
    NMDnsSystemdResolvedResolveHandle       *handle,
    const NMDnsSystemdResolvedAddressResult *names,
    guint                                    names_len,
    guint64                                  flags,
    GError                                  *error,
    gpointer                                 user_data);

NMDnsSystemdResolvedResolveHandle *
nm_dns_systemd_resolved_resolve_address(NMDnsSystemdResolved                      *self,
                                        int                                        ifindex,
                                        int                                        addr_family,
                                        const NMIPAddr                            *addr,
                                        guint64                                    flags,
                                        guint                                      timeout_msec,
                                        NMDnsSystemdResolvedResolveAddressCallback callback,
                                        gpointer                                   user_data);

void nm_dns_systemd_resolved_resolve_cancel(NMDnsSystemdResolvedResolveHandle *handle);

#endif /* __NETWORKMANAGER_DNS_SYSTEMD_RESOLVED_H__ */
