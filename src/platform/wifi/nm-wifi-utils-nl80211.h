// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2011 Intel Corporation. All rights reserved.
 * Copyright (C) 2018 Red Hat, Inc.
 */

#ifndef __WIFI_UTILS_NL80211_H__
#define __WIFI_UTILS_NL80211_H__

#include "nm-wifi-utils.h"
#include "platform/nm-netlink.h"

#define NM_TYPE_WIFI_UTILS_NL80211            (nm_wifi_utils_nl80211_get_type ())
#define NM_WIFI_UTILS_NL80211(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_WIFI_UTILS_NL80211, NMWifiUtilsNl80211))
#define NM_WIFI_UTILS_NL80211_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_WIFI_UTILS_NL80211, NMWifiUtilsNl80211Class))
#define NM_IS_WIFI_UTILS_NL80211(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_WIFI_UTILS_NL80211))
#define NM_IS_WIFI_UTILS_NL80211_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_WIFI_UTILS_NL80211))
#define NM_WIFI_UTILS_NL80211_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_WIFI_UTILS_NL80211, NMWifiUtilsNl80211Class))

GType nm_wifi_utils_nl80211_get_type (void);

NMWifiUtils *nm_wifi_utils_nl80211_new (int ifindex, struct nl_sock *genl);

#endif  /* __WIFI_UTILS_NL80211_H__ */
