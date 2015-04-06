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

#ifndef __NETWORKMANAGER_DHCP4_CONFIG_H__
#define __NETWORKMANAGER_DHCP4_CONFIG_H__


#include "nm-glib.h"
#include "nm-types.h"

#define NM_TYPE_DHCP4_CONFIG            (nm_dhcp4_config_get_type ())
#define NM_DHCP4_CONFIG(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DHCP4_CONFIG, NMDhcp4Config))
#define NM_DHCP4_CONFIG_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DHCP4_CONFIG, NMDhcp4ConfigClass))
#define NM_IS_DHCP4_CONFIG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DHCP4_CONFIG))
#define NM_IS_DHCP4_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DHCP4_CONFIG))
#define NM_DHCP4_CONFIG_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DHCP4_CONFIG, NMDhcp4ConfigClass))

struct _NMDhcp4Config {
	GObject parent;
};

typedef struct {
	GObjectClass parent;

} NMDhcp4ConfigClass;

#define NM_DHCP4_CONFIG_OPTIONS "options"

GType nm_dhcp4_config_get_type (void);

NMDhcp4Config *nm_dhcp4_config_new (void);

const char *nm_dhcp4_config_get_dbus_path (NMDhcp4Config *config);

void nm_dhcp4_config_add_option (NMDhcp4Config *config,
                                 const char *key,
                                 const char *option);

void nm_dhcp4_config_reset (NMDhcp4Config *config);

const char *nm_dhcp4_config_get_option (NMDhcp4Config *config, const char *option);

GSList *nm_dhcp4_config_list_options (NMDhcp4Config *config);

#endif /* __NETWORKMANAGER_DHCP4_CONFIG_H__ */
