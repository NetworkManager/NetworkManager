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
