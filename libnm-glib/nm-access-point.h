/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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
 * Copyright 2007 - 2008 Novell, Inc.
 * Copyright 2007 - 2011 Red Hat, Inc.
 */

#ifndef NM_ACCESS_POINT_H
#define NM_ACCESS_POINT_H

#include <glib.h>
#include <glib-object.h>
#include "NetworkManager.h"
#include "nm-connection.h"
#include "nm-object.h"

G_BEGIN_DECLS

#define NM_TYPE_ACCESS_POINT            (nm_access_point_get_type ())
#define NM_ACCESS_POINT(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_ACCESS_POINT, NMAccessPoint))
#define NM_ACCESS_POINT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_ACCESS_POINT, NMAccessPointClass))
#define NM_IS_ACCESS_POINT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_ACCESS_POINT))
#define NM_IS_ACCESS_POINT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_ACCESS_POINT))
#define NM_ACCESS_POINT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_ACCESS_POINT, NMAccessPointClass))

#define NM_ACCESS_POINT_FLAGS       "flags"
#define NM_ACCESS_POINT_WPA_FLAGS   "wpa-flags"
#define NM_ACCESS_POINT_RSN_FLAGS   "rsn-flags"
#define NM_ACCESS_POINT_SSID        "ssid"
#define NM_ACCESS_POINT_BSSID       "bssid"
#define NM_ACCESS_POINT_FREQUENCY   "frequency"
#define NM_ACCESS_POINT_MODE        "mode"
#define NM_ACCESS_POINT_MAX_BITRATE "max-bitrate"
#define NM_ACCESS_POINT_STRENGTH    "strength"
#define NM_ACCESS_POINT_LAST_SEEN   "last-seen"

/* DEPRECATED */
#define NM_ACCESS_POINT_HW_ADDRESS  "hw-address"

typedef struct {
	NMObject parent;
} NMAccessPoint;

typedef struct {
	NMObjectClass parent;

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
	void (*_reserved5) (void);
	void (*_reserved6) (void);
} NMAccessPointClass;

GType nm_access_point_get_type (void);

GObject *nm_access_point_new (DBusGConnection *connection, const char *path);

NM80211ApFlags         nm_access_point_get_flags        (NMAccessPoint *ap);
NM80211ApSecurityFlags nm_access_point_get_wpa_flags    (NMAccessPoint *ap);
NM80211ApSecurityFlags nm_access_point_get_rsn_flags    (NMAccessPoint *ap);
const GByteArray *     nm_access_point_get_ssid         (NMAccessPoint *ap);
const char *           nm_access_point_get_bssid        (NMAccessPoint *ap);
guint32                nm_access_point_get_frequency    (NMAccessPoint *ap);
NM80211Mode            nm_access_point_get_mode         (NMAccessPoint *ap);
guint32                nm_access_point_get_max_bitrate  (NMAccessPoint *ap);
guint8                 nm_access_point_get_strength     (NMAccessPoint *ap);
NM_AVAILABLE_IN_1_2
int                    nm_access_point_get_last_seen    (NMAccessPoint *ap);

GSList *               nm_access_point_filter_connections (NMAccessPoint *ap,
                                                           const GSList *connections);

gboolean               nm_access_point_connection_valid   (NMAccessPoint *ap,
                                                           NMConnection *connection);

/* DEPRECATED */
NM_DEPRECATED_IN_0_9_10
const char *           nm_access_point_get_hw_address   (NMAccessPoint *ap);

G_END_DECLS

#endif /* NM_ACCESS_POINT_H */
