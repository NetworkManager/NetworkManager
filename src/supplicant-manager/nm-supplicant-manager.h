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
 * Copyright (C) 2006 - 2008 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#ifndef NM_SUPPLICANT_MANAGER_H
#define NM_SUPPLICANT_MANAGER_H

#include <glib-object.h>
#include "nm-supplicant-types.h"
#include "nm-device.h"

#define WPAS_DBUS_SERVICE	"fi.w1.wpa_supplicant1"
#define WPAS_DBUS_PATH		"/fi/w1/wpa_supplicant1"
#define WPAS_DBUS_INTERFACE	"fi.w1.wpa_supplicant1"


G_BEGIN_DECLS

#define NM_TYPE_SUPPLICANT_MANAGER				(nm_supplicant_manager_get_type ())
#define NM_SUPPLICANT_MANAGER(obj)				(G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SUPPLICANT_MANAGER, NMSupplicantManager))
#define NM_SUPPLICANT_MANAGER_CLASS(klass)		(G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_SUPPLICANT_MANAGER, NMSupplicantManagerClass))
#define NM_IS_SUPPLICANT_MANAGER(obj)			(G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SUPPLICANT_MANAGER))
#define NM_IS_SUPPLICANT_MANAGER_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_SUPPLICANT_MANAGER))
#define NM_SUPPLICANT_MANAGER_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_SUPPLICANT_MANAGER, NMSupplicantManagerClass))

#define NM_SUPPLICANT_MANAGER_AVAILABLE "available"

struct _NMSupplicantManager
{
	GObject parent;
};

typedef struct
{
	GObjectClass parent;
} NMSupplicantManagerClass;

GType nm_supplicant_manager_get_type (void);

NMSupplicantManager *nm_supplicant_manager_get (void);

NMSupplicantInterface *nm_supplicant_manager_iface_get (NMSupplicantManager *mgr,
                                                        const char *ifname,
                                                        gboolean is_wireless);

void nm_supplicant_manager_iface_release (NMSupplicantManager *mgr,
                                          NMSupplicantInterface *iface);

gboolean nm_supplicant_manager_available (NMSupplicantManager *mgr);

#endif /* NM_SUPPLICANT_MANAGER_H */
