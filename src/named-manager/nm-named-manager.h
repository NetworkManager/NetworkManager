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
 * Copyright (C) 2004 - 2005 Colin Walters <walters@redhat.com>
 * Copyright (C) 2004 - 2010 Red Hat, Inc.
 * Copyright (C) 2005 - 2008 Novell, Inc.
 *   and others
 */

#ifndef __NM_NAMED_MANAGER_H__
#define __NM_NAMED_MANAGER_H__

#include "config.h"
#include <glib-object.h>
#include <dbus/dbus.h>
#include "nm-ip4-config.h"
#include "nm-ip6-config.h"

typedef enum {
	NM_NAMED_MANAGER_ERROR_SYSTEM,
	NM_NAMED_MANAGER_ERROR_INVALID_NAMESERVER,
	NM_NAMED_MANAGER_ERROR_INVALID_HOST,
	NM_NAMED_MANAGER_ERROR_INVALID_ID
} NMNamedManagerError;

typedef enum {
	NM_NAMED_IP_CONFIG_TYPE_DEFAULT = 0,
	NM_NAMED_IP_CONFIG_TYPE_BEST_DEVICE,
	NM_NAMED_IP_CONFIG_TYPE_VPN
} NMNamedIPConfigType;

#define NM_NAMED_MANAGER_ERROR nm_named_manager_error_quark ()
GQuark nm_named_manager_error_quark (void);

G_BEGIN_DECLS

#define NM_TYPE_NAMED_MANAGER (nm_named_manager_get_type ())
#define NM_NAMED_MANAGER(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), NM_TYPE_NAMED_MANAGER, NMNamedManager))
#define NM_NAMED_MANAGER_CLASS(k) (G_TYPE_CHECK_CLASS_CAST((k), NM_TYPE_NAMED_MANAGER, NMNamedManagerClass))
#define NM_IS_NAMED_MANAGER(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), NM_TYPE_NAMED_MANAGER))
#define NM_IS_NAMED_MANAGER_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), NM_TYPE_NAMED_MANAGER))
#define NM_NAMED_MANAGER_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), NM_TYPE_NAMED_MANAGER, NMNamedManagerClass)) 

typedef struct NMNamedManagerPrivate NMNamedManagerPrivate;

typedef struct {
	GObject parent;
} NMNamedManager;

typedef struct {
	GObjectClass parent;
} NMNamedManagerClass;

GType nm_named_manager_get_type (void);

NMNamedManager * nm_named_manager_get (void);

gboolean nm_named_manager_add_ip4_config (NMNamedManager *mgr,
										  const char *iface,
                                          NMIP4Config *config,
                                          NMNamedIPConfigType cfg_type);

gboolean nm_named_manager_remove_ip4_config (NMNamedManager *mgr,
											 const char *iface,
											 NMIP4Config *config);

gboolean nm_named_manager_add_ip6_config (NMNamedManager *mgr,
										  const char *iface,
                                          NMIP6Config *config,
                                          NMNamedIPConfigType cfg_type);

gboolean nm_named_manager_remove_ip6_config (NMNamedManager *mgr,
											 const char *iface,
											 NMIP6Config *config);

void nm_named_manager_set_hostname (NMNamedManager *mgr,
                                    const char *hostname);

G_END_DECLS

#endif /* __NM_NAMED_MANAGER_H__ */
