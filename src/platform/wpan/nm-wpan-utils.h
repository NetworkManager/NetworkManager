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
 * Copyright (C) 2018 Red Hat, Inc.
 */

#ifndef __WPAN_UTILS_H__
#define __WPAN_UTILS_H__

#include <net/ethernet.h>

#include "nm-dbus-interface.h"
#include "platform/nm-netlink.h"

typedef struct NMWpanUtils NMWpanUtils;

#define NM_TYPE_WPAN_UTILS            (nm_wpan_utils_get_type ())
#define NM_WPAN_UTILS(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_WPAN_UTILS, NMWpanUtils))
#define NM_WPAN_UTILS_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_WPAN_UTILS, NMWpanUtilsClass))
#define NM_IS_WPAN_UTILS(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_WPAN_UTILS))
#define NM_IS_WPAN_UTILS_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_WPAN_UTILS))
#define NM_WPAN_UTILS_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_WPAN_UTILS, NMWpanUtilsClass))

GType nm_wpan_utils_get_type (void);

NMWpanUtils *nm_wpan_utils_new (int ifindex, struct nl_sock *genl, gboolean check_scan);

guint16 nm_wpan_utils_get_pan_id (NMWpanUtils *self);
gboolean nm_wpan_utils_set_pan_id (NMWpanUtils *self, guint16 pan_id);

guint16 nm_wpan_utils_get_short_addr (NMWpanUtils *self);
gboolean nm_wpan_utils_set_short_addr (NMWpanUtils *self, guint16 short_addr);

gboolean nm_wpan_utils_set_channel (NMWpanUtils *self, guint8 page, guint8 channel);

#endif  /* __WPAN_UTILS_H__ */
