/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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
 * Copyright (C) 2016 Sjoerd Simons <sjoerd@luon.net>
 */

#ifndef __NETWORKMANAGER_DNS_SYSTEMD_RESOLVED_H__
#define __NETWORKMANAGER_DNS_SYSTEMD_RESOLVED_H__

#include "nm-dns-plugin.h"

#define NM_TYPE_DNS_SYSTEMD_RESOLVED            (nm_dns_systemd_resolved_get_type ())
#define NM_DNS_SYSTEMD_RESOLVED(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DNS_SYSTEMD_RESOLVED, NMDnsSystemdResolved))
#define NM_DNS_SYSTEMD_RESOLVED_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DNS_SYSTEMD_RESOLVED, NMDnsSystemdResolvedClass))
#define NM_IS_DNS_SYSTEMD_RESOLVED(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DNS_SYSTEMD_RESOLVED))
#define NM_IS_DNS_SYSTEMD_RESOLVED_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DNS_SYSTEMD_RESOLVED))
#define NM_DNS_SYSTEMD_RESOLVED_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DNS_SYSTEMD_RESOLVED, NMDnsSystemdResolvedClass))

typedef struct _NMDnsSystemdResolved NMDnsSystemdResolved;
typedef struct _NMDnsSystemdResolvedClass NMDnsSystemdResolvedClass;

GType nm_dns_systemd_resolved_get_type (void);

NMDnsPlugin *nm_dns_systemd_resolved_new (void);

gboolean nm_dns_systemd_resolved_is_running (NMDnsSystemdResolved *self);

#endif /* __NETWORKMANAGER_DNS_SYSTEMD_RESOLVED_H__ */
