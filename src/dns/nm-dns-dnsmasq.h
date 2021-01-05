/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2010 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DNS_DNSMASQ_H__
#define __NETWORKMANAGER_DNS_DNSMASQ_H__

#include "nm-dns-plugin.h"

#define NM_TYPE_DNS_DNSMASQ (nm_dns_dnsmasq_get_type())
#define NM_DNS_DNSMASQ(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DNS_DNSMASQ, NMDnsDnsmasq))
#define NM_DNS_DNSMASQ_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DNS_DNSMASQ, NMDnsDnsmasqClass))
#define NM_IS_DNS_DNSMASQ(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DNS_DNSMASQ))
#define NM_IS_DNS_DNSMASQ_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DNS_DNSMASQ))
#define NM_DNS_DNSMASQ_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DNS_DNSMASQ, NMDnsDnsmasqClass))

typedef struct _NMDnsDnsmasq      NMDnsDnsmasq;
typedef struct _NMDnsDnsmasqClass NMDnsDnsmasqClass;

GType nm_dns_dnsmasq_get_type(void);

NMDnsPlugin *nm_dns_dnsmasq_new(void);

#endif /* __NETWORKMANAGER_DNS_DNSMASQ_H__ */
