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
 */

#ifndef NM_DNS_BIND_H
#define NM_DNS_BIND_H

#include <glib.h>
#include <glib-object.h>

#include "nm-dns-plugin.h"

#define NM_TYPE_DNS_BIND            (nm_dns_bind_get_type ())
#define NM_DNS_BIND(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DNS_BIND, NMDnsBind))
#define NM_DNS_BIND_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DNS_BIND, NMDnsBindClass))
#define NM_IS_DNS_BIND(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DNS_BIND))
#define NM_IS_DNS_BIND_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_DNS_BIND))
#define NM_DNS_BIND_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DNS_BIND, NMDnsBindClass))

typedef struct {
	NMDnsPlugin parent;
} NMDnsBind;

typedef struct {
	NMDnsPluginClass parent;
} NMDnsBindClass;

GType nm_dns_bind_get_type (void);

NMDnsBind *nm_dns_bind_new (void);

#endif /* NM_DNS_BIND_H */

