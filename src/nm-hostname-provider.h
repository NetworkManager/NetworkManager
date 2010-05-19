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
 * Copyright (C) 2009 Novell, Inc.
 */

#ifndef NM_HOSTNAME_PROVIDER_H
#define NM_HOSTNAME_PROVIDER_H

#include <glib-object.h>

#define NM_TYPE_HOSTNAME_PROVIDER (nm_hostname_provider_get_type ())
#define NM_HOSTNAME_PROVIDER(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_HOSTNAME_PROVIDER, NMHostnameProvider))
#define NM_IS_HOSTNAME_PROVIDER(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_HOSTNAME_PROVIDER))
#define NM_HOSTNAME_PROVIDER_GET_INTERFACE(obj) (G_TYPE_INSTANCE_GET_INTERFACE ((obj), NM_TYPE_HOSTNAME_PROVIDER, NMHostnameProvider))

typedef struct _NMHostnameProvider NMHostnameProvider;

struct _NMHostnameProvider {
	GTypeInterface g_iface;

	/* Methods */
	const char *(*get_hostname) (NMHostnameProvider *self);
};

GType nm_hostname_provider_get_type (void);

const char *nm_hostname_provider_get_hostname (NMHostnameProvider *self);

#endif /* NM_HOSTNAME_PROVIDER_H */
