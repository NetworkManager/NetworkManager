/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * Dan Williams <dcbw@redhat.com>
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
 * (C) Copyright 2004 Red Hat, Inc.
 */

#ifndef NETWORK_MANAGER_SYSTEM_H
#define NETWORK_MANAGER_SYSTEM_H

#include <glib.h>
#include "nm-device.h"
#include "nm-ip4-config.h"

/* Prototypes for system/distribution dependent functions,
 * implemented in the backend files in backends/ directory
 */

void			nm_system_device_flush_ip4_routes				(NMDevice *dev);
void			nm_system_device_flush_ip4_routes_with_iface	(const char *iface);

void			nm_system_device_replace_default_ip4_route   (const char *iface,
                                                             guint32 gw,
                                                             guint32 mss,
                                                             const char *parent_iface,
                                                             guint32 parent_mss);

void			nm_system_device_flush_ip4_addresses			(NMDevice *dev);
void			nm_system_device_flush_ip4_addresses_with_iface	(const char *iface);

void			nm_system_enable_loopback				(void);
void			nm_system_update_dns					(void);

gboolean		nm_system_apply_ip4_config              (NMDevice *device,
                                                         const char *iface,
                                                         NMIP4Config *config,
                                                         int priority,
                                                         gboolean is_vpn);

gboolean		nm_system_device_set_up_down				(NMDevice *dev,
                                                             gboolean up,
                                                             gboolean *no_firmware);
gboolean		nm_system_device_set_up_down_with_iface		(const char *iface,
                                                             gboolean up,
                                                             gboolean *no_firmware);

gboolean        nm_system_device_is_up (NMDevice *device);
gboolean        nm_system_device_is_up_with_iface (const char *iface);

gboolean		nm_system_device_set_mtu (const char *iface, guint32 mtu);

#endif
