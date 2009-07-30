/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-ip6-manager.c - Handle IPv6 address configuration for NetworkManager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
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
 * Copyright (C) 2009 Red Hat, Inc.
 */

#ifndef NM_IP6_MANAGER_H
#define NM_IP6_MANAGER_H

#include <glib.h>
#include <glib-object.h>

#include <nm-setting-ip6-config.h>

#include "nm-ip6-config.h"

#define NM_TYPE_IP6_MANAGER            (nm_ip6_manager_get_type ())
#define NM_IP6_MANAGER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_IP6_MANAGER, NMIP6Manager))
#define NM_IP6_MANAGER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_IP6_MANAGER, NMIP6ManagerClass))
#define NM_IS_IP6_MANAGER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_IP6_MANAGER))
#define NM_IS_IP6_MANAGER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_IP6_MANAGER))
#define NM_IP6_MANAGER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_IP6_MANAGER, NMIP6ManagerClass))

typedef struct {
	GObject parent;
} NMIP6Manager;

typedef struct {
	GObjectClass parent;

	/* Signals */
	void (*addrconf_complete) (NMIP6Manager *manager, char *iface, gboolean success);

	void (*config_changed)    (NMIP6Manager *manager, char *iface);
} NMIP6ManagerClass;

GType nm_ip6_manager_get_type (void);

NMIP6Manager *nm_ip6_manager_get                  (void);
void          nm_ip6_manager_prepare_interface    (NMIP6Manager *manager,
												   const char *iface,
												   NMSettingIP6Config *s_ip6);
void          nm_ip6_manager_begin_addrconf       (NMIP6Manager *manager,
												   const char *iface);
void          nm_ip6_manager_cancel_addrconf      (NMIP6Manager *manager,
												   const char *iface);

NMIP6Config * nm_ip6_manager_get_ip6_config       (NMIP6Manager *manager,
												   const char *iface);

#endif /* NM_IP6_MANAGER_H */
