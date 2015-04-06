/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* This program is free software; you can redistribute it and/or modify
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
 * Copyright (C) 2005 - 2010 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DHCP_DHCPCD_H__
#define __NETWORKMANAGER_DHCP_DHCPCD_H__

#include "nm-dhcp-client.h"

#define NM_TYPE_DHCP_DHCPCD            (nm_dhcp_dhcpcd_get_type ())
#define NM_DHCP_DHCPCD(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DHCP_DHCPCD, NMDhcpDhcpcd))
#define NM_DHCP_DHCPCD_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DHCP_DHCPCD, NMDhcpDhcpcdClass))
#define NM_IS_DHCP_DHCPCD(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DHCP_DHCPCD))
#define NM_IS_DHCP_DHCPCD_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DHCP_DHCPCD))
#define NM_DHCP_DHCPCD_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DHCP_DHCPCD, NMDhcpDhcpcdClass))

typedef struct {
	NMDhcpClient parent;
} NMDhcpDhcpcd;

typedef struct {
	NMDhcpClientClass parent;
} NMDhcpDhcpcdClass;

GType nm_dhcp_dhcpcd_get_type (void);

#endif /* __NETWORKMANAGER_DHCP_DHCPCD_H__ */

