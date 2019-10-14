// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2011 - 2018 Red Hat, Inc.
 */

#ifndef __WIFI_UTILS_WEXT_H__
#define __WIFI_UTILS_WEXT_H__

#include "nm-wifi-utils.h"

#define NM_TYPE_WIFI_UTILS_WEXT            (nm_wifi_utils_wext_get_type ())
#define NM_WIFI_UTILS_WEXT(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_WIFI_UTILS_WEXT, NMWifiUtilsWext))
#define NM_WIFI_UTILS_WEXT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_WIFI_UTILS_WEXT, NMWifiUtilsWextClass))
#define NM_IS_WIFI_UTILS_WEXT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_WIFI_UTILS_WEXT))
#define NM_IS_WIFI_UTILS_WEXT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_WIFI_UTILS_WEXT))
#define NM_WIFI_UTILS_WEXT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_WIFI_UTILS_WEXT, NMWifiUtilsWextClass))

GType nm_wifi_utils_wext_get_type (void);

NMWifiUtils *nm_wifi_utils_wext_new (int ifindex, gboolean check_scan);

gboolean nm_wifi_utils_wext_is_wifi (const char *iface);

#endif  /* __WIFI_UTILS_WEXT_H__ */
