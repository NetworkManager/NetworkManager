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
 * Copyright (C) 2009 - 2010 Red Hat, Inc.
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

enum {
	IP6_DHCP_OPT_NONE = 0,
	IP6_DHCP_OPT_OTHERCONF,
	IP6_DHCP_OPT_MANAGED
};

typedef struct {
	GObject parent;
} NMIP6Manager;

typedef struct {
	GObjectClass parent;

	/* Signals */

	/* addrconf_complete is emitted only during initial configuration to indicate
	 * that the initial configuration is complete.
	 */
	void (*addrconf_complete) (NMIP6Manager *manager,
	                           guint32 ifindex,
	                           guint dhcp_opts,
	                           gboolean success);

	/* config_changed gets emitted only *after* initial configuration is
	 * complete; it's like DHCP renew and indicates that the existing config
	 * of the interface has changed.
	 */
	void (*config_changed)    (NMIP6Manager *manager,
	                           guint32 ifindex,
	                           guint dhcp_opts,
	                           gboolean success);
} NMIP6ManagerClass;

GType nm_ip6_manager_get_type (void);

NMIP6Manager *nm_ip6_manager_get               (void);
void          nm_ip6_manager_prepare_interface (NMIP6Manager *manager,
                                                int ifindex,
                                                NMSettingIP6Config *s_ip6,
                                                const char *accept_ra_path);
void          nm_ip6_manager_begin_addrconf    (NMIP6Manager *manager,
                                                int ifindex);
void          nm_ip6_manager_cancel_addrconf   (NMIP6Manager *manager,
                                                int ifindex);

NMIP6Config * nm_ip6_manager_get_ip6_config    (NMIP6Manager *manager,
                                                int ifindex);

#endif /* NM_IP6_MANAGER_H */
