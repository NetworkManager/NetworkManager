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

#ifndef NM_WIMAX_NSP_H
#define NM_WIMAX_NSP_H

#include <glib-object.h>
#include "nm-wimax-types.h"
#include "nm-connection.h"

#define NM_TYPE_WIMAX_NSP			(nm_wimax_nsp_get_type ())
#define NM_WIMAX_NSP(obj)			(G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_WIMAX_NSP, NMWimaxNsp))
#define NM_WIMAX_NSP_CLASS(klass)	(G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_WIMAX_NSP, NMWimaxNspClass))
#define NM_IS_WIMAX_NSP(obj)		(G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_WIMAX_NSP))
#define NM_IS_WIMAX_NSP_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_WIMAX_NSP))
#define NM_WIMAX_NSP_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_WIMAX_NSP, NMWimaxNspClass))

#define NM_WIMAX_NSP_NAME           "name"
#define NM_WIMAX_NSP_SIGNAL_QUALITY "signal-quality"
#define NM_WIMAX_NSP_NETWORK_TYPE   "network-type"

typedef struct {
	GObject parent;
} NMWimaxNsp;

typedef struct {
	GObjectClass parent;

	/* Signals */
	void (*properties_changed) (NMWimaxNsp *nsp, GHashTable *properties);
} NMWimaxNspClass;

GType nm_wimax_nsp_get_type (void);

NMWimaxNsp            *nm_wimax_nsp_new                (const char *name);
const char            *nm_wimax_nsp_get_name           (NMWimaxNsp *self);
guint32                nm_wimax_nsp_get_signal_quality (NMWimaxNsp *self);
NMWimaxNspNetworkType  nm_wimax_nsp_get_network_type   (NMWimaxNsp *self);

void                   nm_wimax_nsp_export_to_dbus     (NMWimaxNsp *self);
const char            *nm_wimax_nsp_get_dbus_path      (NMWimaxNsp *self);

gboolean               nm_wimax_nsp_check_compatible   (NMWimaxNsp *self,
														NMConnection *connection);

#endif	/* NM_WIMAX_NSP_H */
