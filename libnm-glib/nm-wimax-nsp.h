/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * libnm_glib -- Access network status & information from glib applications
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2011 Red Hat, Inc.
 * Copyright (C) 2009 Novell, Inc.
 */

#ifndef NM_WIMAX_NSP_H
#define NM_WIMAX_NSP_H

#include <glib.h>
#include <glib-object.h>
#include <NetworkManager.h>
#include "nm-object.h"

G_BEGIN_DECLS

#define NM_TYPE_WIMAX_NSP            (nm_wimax_nsp_get_type ())
#define NM_WIMAX_NSP(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_WIMAX_NSP, NMWimaxNsp))
#define NM_WIMAX_NSP_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_WIMAX_NSP, NMWimaxNspClass))
#define NM_IS_WIMAX_NSP(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_WIMAX_NSP))
#define NM_IS_WIMAX_NSP_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_WIMAX_NSP))
#define NM_WIMAX_NSP_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_WIMAX_NSP, NMWimaxNspClass))

#define NM_WIMAX_NSP_NAME           "name"
#define NM_WIMAX_NSP_SIGNAL_QUALITY "signal-quality"
#define NM_WIMAX_NSP_NETWORK_TYPE   "network-type"

typedef enum {
	NM_WIMAX_NSP_NETWORK_TYPE_UNKNOWN         = 0,
	NM_WIMAX_NSP_NETWORK_TYPE_HOME            = 1,
	NM_WIMAX_NSP_NETWORK_TYPE_PARTNER         = 2,
	NM_WIMAX_NSP_NETWORK_TYPE_ROAMING_PARTNER = 3
} NMWimaxNspNetworkType;

typedef struct {
	NMObject parent;
} NMWimaxNsp;

typedef struct {
	NMObjectClass parent;

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
	void (*_reserved5) (void);
	void (*_reserved6) (void);
} NMWimaxNspClass;

GType nm_wimax_nsp_get_type (void);

GObject *nm_wimax_nsp_new (DBusGConnection *connection, const char *path);

const char           * nm_wimax_nsp_get_name           (NMWimaxNsp *nsp);
guint32                nm_wimax_nsp_get_signal_quality (NMWimaxNsp *nsp);
NMWimaxNspNetworkType  nm_wimax_nsp_get_network_type   (NMWimaxNsp *nsp);

GSList *               nm_wimax_nsp_filter_connections (NMWimaxNsp *nsp,
                                                        const GSList *connections);

gboolean               nm_wimax_nsp_connection_valid   (NMWimaxNsp *nsp,
                                                        NMConnection *connection);

G_END_DECLS

#endif /* NM_WIMAX_NSP_H */
