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
 * Copyright (C) 2011 Red Hat, Inc.
 */

#ifndef NM_FIREWALL_MANAGER_H
#define NM_FIREWALL_MANAGER_H

#include <glib-object.h>
#include <dbus/dbus-glib.h>

#define FIREWALL_DBUS_SERVICE         "org.fedoraproject.FirewallD1"
#define FIREWALL_DBUS_PATH            "/org/fedoraproject/FirewallD1"
#define FIREWALL_DBUS_INTERFACE       "org.fedoraproject.FirewallD1"
#define FIREWALL_DBUS_INTERFACE_ZONE  "org.fedoraproject.FirewallD1.zone"


G_BEGIN_DECLS

#define NM_TYPE_FIREWALL_MANAGER				(nm_firewall_manager_get_type ())
#define NM_FIREWALL_MANAGER(obj)				(G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_FIREWALL_MANAGER, NMFirewallManager))
#define NM_FIREWALL_MANAGER_CLASS(klass)		(G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_FIREWALL_MANAGER, NMFirewallManagerClass))
#define NM_IS_FIREWALL_MANAGER(obj)				(G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_FIREWALL_MANAGER))
#define NM_IS_FIREWALL_MANAGER_CLASS(klass)		(G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_FIREWALL_MANAGER))
#define NM_FIREWALL_MANAGER_GET_CLASS(obj)		(G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_FIREWALL_MANAGER, NMFirewallManagerClass))

#define NM_FIREWALL_MANAGER_AVAILABLE "available"

typedef struct {
	GObject parent;
} NMFirewallManager;

typedef struct {
	GObjectClass parent;

	/* Signals */
	void (*started) (NMFirewallManager *manager);
} NMFirewallManagerClass;

GType nm_firewall_manager_get_type (void);

NMFirewallManager *nm_firewall_manager_get (void);

typedef void (*FwAddToZoneFunc) (GError *error, gpointer user_data);

gpointer nm_firewall_manager_add_or_change_zone (NMFirewallManager *mgr,
                                                 const char *iface,
                                                 const char *zone,
                                                 gboolean add,
                                                 FwAddToZoneFunc callback,
                                                 gpointer user_data);
gpointer nm_firewall_manager_remove_from_zone (NMFirewallManager *mgr,
                                               const char *iface,
                                               const char *zone);

void nm_firewall_manager_cancel_call (NMFirewallManager *mgr, gpointer fw_call);

#endif /* NM_FIREWALL_MANAGER_H */
