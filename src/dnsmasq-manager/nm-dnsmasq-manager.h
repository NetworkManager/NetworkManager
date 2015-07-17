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
 * Copyright (C) 2008 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DNSMASQ_MANAGER_H__
#define __NETWORKMANAGER_DNSMASQ_MANAGER_H__


#include "nm-default.h"
#include "nm-ip4-config.h"

#define NM_TYPE_DNSMASQ_MANAGER            (nm_dnsmasq_manager_get_type ())
#define NM_DNSMASQ_MANAGER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DNSMASQ_MANAGER, NMDnsMasqManager))
#define NM_DNSMASQ_MANAGER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DNSMASQ_MANAGER, NMDnsMasqManagerClass))
#define NM_IS_DNSMASQ_MANAGER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DNSMASQ_MANAGER))
#define NM_IS_DNSMASQ_MANAGER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DNSMASQ_MANAGER))
#define NM_DNSMASQ_MANAGER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DNSMASQ_MANAGER, NMDnsMasqManagerClass))

typedef enum {
	NM_DNSMASQ_STATUS_UNKNOWN,

	NM_DNSMASQ_STATUS_DEAD,
	NM_DNSMASQ_STATUS_RUNNING,
} NMDnsMasqStatus;

typedef struct {
	GObject parent;
} NMDnsMasqManager;

typedef struct {
	GObjectClass parent;

	/* Signals */
	void (*state_changed) (NMDnsMasqManager *manager, NMDnsMasqStatus status);
} NMDnsMasqManagerClass;

GType nm_dnsmasq_manager_get_type (void);

NMDnsMasqManager *nm_dnsmasq_manager_new (const char *iface);

gboolean nm_dnsmasq_manager_start (NMDnsMasqManager *manager,
                                   NMIP4Config *ip4_config,
                                   GError **error);

void     nm_dnsmasq_manager_stop  (NMDnsMasqManager *manager);

#endif /* __NETWORKMANAGER_DNSMASQ_MANAGER_H__ */
