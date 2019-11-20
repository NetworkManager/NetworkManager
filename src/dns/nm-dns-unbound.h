// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2014 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DNS_UNBOUND_H__
#define __NETWORKMANAGER_DNS_UNBOUND_H__

#include "nm-dns-plugin.h"

#define NM_TYPE_DNS_UNBOUND            (nm_dns_unbound_get_type ())
#define NM_DNS_UNBOUND(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DNS_UNBOUND, NMDnsUnbound))
#define NM_DNS_UNBOUND_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DNS_UNBOUND, NMDnsUnboundClass))
#define NM_IS_DNS_UNBOUND(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DNS_UNBOUND))
#define NM_IS_DNS_UNBOUND_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DNS_UNBOUND))
#define NM_DNS_UNBOUND_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DNS_UNBOUND, NMDnsUnboundClass))

typedef struct _NMDnsUnbound NMDnsUnbound;
typedef struct _NMDnsUnboundClass NMDnsUnboundClass;

GType nm_dns_unbound_get_type (void);

NMDnsPlugin *nm_dns_unbound_new (void);

#endif /* __NETWORKMANAGER_DNS_UNBOUND_H__ */
