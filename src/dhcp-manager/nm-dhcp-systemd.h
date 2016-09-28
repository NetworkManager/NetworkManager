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
 * Copyright (C) 2014 Red Hat, Inc.
 */

#ifndef __NM_DHCP_SYSTEMD_H__
#define __NM_DHCP_SYSTEMD_H__

#include "nm-dhcp-client.h"

#define NM_TYPE_DHCP_SYSTEMD            (nm_dhcp_systemd_get_type ())
#define NM_DHCP_SYSTEMD(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DHCP_SYSTEMD, NMDhcpSystemd))
#define NM_DHCP_SYSTEMD_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DHCP_SYSTEMD, NMDhcpSystemdClass))
#define NM_IS_DHCP_SYSTEMD(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DHCP_SYSTEMD))
#define NM_IS_DHCP_SYSTEMD_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DHCP_SYSTEMD))
#define NM_DHCP_SYSTEMD_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DHCP_SYSTEMD, NMDhcpSystemdClass))

typedef struct _NMDhcpSystemd NMDhcpSystemd;
typedef struct _NMDhcpSystemdClass NMDhcpSystemdClass;

GType nm_dhcp_systemd_get_type (void);

#endif /* __NM_DHCP_SYSTEMD_H__ */

