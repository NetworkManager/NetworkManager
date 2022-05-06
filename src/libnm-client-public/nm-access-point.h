/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2011 Red Hat, Inc.
 */

#ifndef __NM_ACCESS_POINT_H__
#define __NM_ACCESS_POINT_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-object.h"

G_BEGIN_DECLS

#define NM_TYPE_ACCESS_POINT (nm_access_point_get_type())
#define NM_ACCESS_POINT(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_ACCESS_POINT, NMAccessPoint))
#define NM_ACCESS_POINT_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_ACCESS_POINT, NMAccessPointClass))
#define NM_IS_ACCESS_POINT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_ACCESS_POINT))
#define NM_IS_ACCESS_POINT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_ACCESS_POINT))
#define NM_ACCESS_POINT_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_ACCESS_POINT, NMAccessPointClass))

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
#define NM_ACCESS_POINT_HW_ADDRESS "hw-address"

/**
 * NMAccessPoint:
 */
typedef struct _NMAccessPoint      NMAccessPoint;
typedef struct _NMAccessPointClass NMAccessPointClass;

GType nm_access_point_get_type(void);

NM80211ApFlags         nm_access_point_get_flags(NMAccessPoint *ap);
NM80211ApSecurityFlags nm_access_point_get_wpa_flags(NMAccessPoint *ap);
NM80211ApSecurityFlags nm_access_point_get_rsn_flags(NMAccessPoint *ap);
GBytes                *nm_access_point_get_ssid(NMAccessPoint *ap);
const char            *nm_access_point_get_bssid(NMAccessPoint *ap);
guint32                nm_access_point_get_frequency(NMAccessPoint *ap);
NM80211Mode            nm_access_point_get_mode(NMAccessPoint *ap);
guint32                nm_access_point_get_max_bitrate(NMAccessPoint *ap);
guint8                 nm_access_point_get_strength(NMAccessPoint *ap);
NM_AVAILABLE_IN_1_2
int nm_access_point_get_last_seen(NMAccessPoint *ap);

GPtrArray *nm_access_point_filter_connections(NMAccessPoint *ap, const GPtrArray *connections);

gboolean nm_access_point_connection_valid(NMAccessPoint *ap, NMConnection *connection);

G_END_DECLS

#endif /* __NM_ACCESS_POINT_H__ */
