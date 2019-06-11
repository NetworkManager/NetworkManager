/* This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
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
 * Copyright (C) 2010 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DNS_DNSMASQ_H__
#define __NETWORKMANAGER_DNS_DNSMASQ_H__

#include "nm-dns-plugin.h"

#define NM_TYPE_DNS_DNSMASQ            (nm_dns_dnsmasq_get_type ())
#define NM_DNS_DNSMASQ(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DNS_DNSMASQ, NMDnsDnsmasq))
#define NM_DNS_DNSMASQ_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DNS_DNSMASQ, NMDnsDnsmasqClass))
#define NM_IS_DNS_DNSMASQ(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DNS_DNSMASQ))
#define NM_IS_DNS_DNSMASQ_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DNS_DNSMASQ))
#define NM_DNS_DNSMASQ_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DNS_DNSMASQ, NMDnsDnsmasqClass))

typedef struct _NMDnsDnsmasq NMDnsDnsmasq;
typedef struct _NMDnsDnsmasqClass NMDnsDnsmasqClass;

GType nm_dns_dnsmasq_get_type (void);

NMDnsPlugin *nm_dns_dnsmasq_new (void);

#endif /* __NETWORKMANAGER_DNS_DNSMASQ_H__ */
