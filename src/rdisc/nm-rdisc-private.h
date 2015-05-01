/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-rdisc.h - Perform IPv6 router discovery
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
 * Copyright 2015 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_RDISC_PRIVATE_H__
#define __NETWORKMANAGER_RDISC_PRIVATE_H__

#include "nm-rdisc.h"

/* Functions only used by rdisc implementations */

void nm_rdisc_ra_received (NMRDisc *rdisc, guint32 now, NMRDiscConfigMap changed);

gboolean nm_rdisc_add_gateway    (NMRDisc *rdisc, const NMRDiscGateway *new);
gboolean nm_rdisc_add_address    (NMRDisc *rdisc, const NMRDiscAddress *new);
gboolean nm_rdisc_add_route      (NMRDisc *rdisc, const NMRDiscRoute *new);
gboolean nm_rdisc_add_dns_server (NMRDisc *rdisc, const NMRDiscDNSServer *new);
gboolean nm_rdisc_add_dns_domain (NMRDisc *rdisc, const NMRDiscDNSDomain *new);

#endif /* __NETWORKMANAGER_RDISC_PRIVATE_H__ */
