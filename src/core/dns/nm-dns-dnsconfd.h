/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2024 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DNS_DNSCONFD_H__
#define __NETWORKMANAGER_DNS_DNSCONFD_H__

#include "nm-dns-plugin.h"
#include "nm-dns-manager.h"

#define NM_TYPE_DNS_DNSCONFD (nm_dns_dnsconfd_get_type())
#define NM_DNS_DNSCONFD(obj) \
    (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DNS_DNSCONFD, NMDnsDnsconfd))
#define NM_DNS_DNSCONFD_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DNS_DNSCONFD, NMDnsDnsconfdClass))
#define NM_IS_DNS_DNSCONFD(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DNS_DNSCONFD))
#define NM_IS_DNS_DNSCONFD_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DNS_DNSCONFD))
#define NM_DNS_DNSCONFD_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DNS_DNSCONFD, NMDnsDnsconfdClass))

typedef struct _NMDnsDnsconfd      NMDnsDnsconfd;
typedef struct _NMDnsDnsconfdClass NMDnsDnsconfdClass;

GType nm_dns_dnsconfd_get_type(void);

NMDnsPlugin *nm_dns_dnsconfd_new(void);

#endif /* __NETWORKMANAGER_DNS_DNSCONFD_H__ */
