/*
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
 * Copyright 2011 Red Hat, Inc.
 * Copyright 2009 Novell, Inc.
 */

#ifndef __NM_WIMAX_NSP_H__
#define __NM_WIMAX_NSP_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

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

/**
 * NMWimaxNsp:
 */
struct _NMWimaxNsp {
	NMObject parent;
};

typedef struct {
	NMObjectClass parent;

	/*< private >*/
	gpointer padding[4];
} NMWimaxNspClass;

GType nm_wimax_nsp_get_type (void);

const char           * nm_wimax_nsp_get_name           (NMWimaxNsp *nsp);
guint32                nm_wimax_nsp_get_signal_quality (NMWimaxNsp *nsp);
NMWimaxNspNetworkType  nm_wimax_nsp_get_network_type   (NMWimaxNsp *nsp);

GPtrArray *            nm_wimax_nsp_filter_connections (NMWimaxNsp *nsp,
                                                        const GPtrArray *connections);

gboolean               nm_wimax_nsp_connection_valid   (NMWimaxNsp *nsp,
                                                        NMConnection *connection);

G_END_DECLS

#endif /* __NM_WIMAX_NSP_H__ */
