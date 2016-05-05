/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2008 Red Hat, Inc.
 * Copyright 2008 Novell, Inc.
 */

#ifndef __NM_DHCP_CONFIG_H__
#define __NM_DHCP_CONFIG_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include <nm-object.h>

G_BEGIN_DECLS

#define NM_TYPE_DHCP_CONFIG            (nm_dhcp_config_get_type ())
#define NM_DHCP_CONFIG(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DHCP_CONFIG, NMDhcpConfig))
#define NM_DHCP_CONFIG_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DHCP_CONFIG, NMDhcpConfigClass))
#define NM_IS_DHCP_CONFIG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DHCP_CONFIG))
#define NM_IS_DHCP_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DHCP_CONFIG))

/**
 * NMDhcpConfig:
 */
struct _NMDhcpConfig {
	NMObject parent;
};

typedef struct {
	NMObjectClass parent;

	/*< private >*/
	gpointer padding[8];
} NMDhcpConfigClass;

#define NM_DHCP_CONFIG_FAMILY  "family"
#define NM_DHCP_CONFIG_OPTIONS "options"

GType nm_dhcp_config_get_type (void);

int         nm_dhcp_config_get_family     (NMDhcpConfig *config);

GHashTable *nm_dhcp_config_get_options    (NMDhcpConfig *config);
const char *nm_dhcp_config_get_one_option (NMDhcpConfig *config, const char *option);

G_END_DECLS

#endif /* __NM_DHCP_CONFIG_H__ */
