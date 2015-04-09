/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-fake-rdisc.h - Fake implementation of router discovery
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
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_FAKE_RDISC_H__
#define __NETWORKMANAGER_FAKE_RDISC_H__

#include "nm-rdisc.h"

#define NM_TYPE_FAKE_RDISC            (nm_fake_rdisc_get_type ())
#define NM_FAKE_RDISC(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_FAKE_RDISC, NMFakeRDisc))
#define NM_FAKE_RDISC_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_FAKE_RDISC, NMFakeRDiscClass))
#define NM_IS_FAKE_RDISC(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_FAKE_RDISC))
#define NM_IS_FAKE_RDISC_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_FAKE_RDISC))
#define NM_FAKE_RDISC_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_FAKE_RDISC, NMFakeRDiscClass))

#define NM_FAKE_RDISC_RS_SENT "rs-sent"

typedef struct {
	NMRDisc parent;
} NMFakeRDisc;

typedef struct {
	NMRDiscClass parent;
} NMFakeRDiscClass;

/******************************************************************/

GType nm_fake_rdisc_get_type (void);

NMRDisc *nm_fake_rdisc_new (int ifindex, const char *ifname);

guint nm_fake_rdisc_add_ra (NMFakeRDisc *self,
                            guint seconds,
                            NMRDiscDHCPLevel dhcp_level,
                            int hop_limit,
                            guint32 mtu);

void nm_fake_rdisc_add_gateway    (NMFakeRDisc *self,
                                   guint ra_id,
                                   const char *addr,
                                   guint32 timestamp,
                                   guint32 lifetime,
                                   NMRDiscPreference preference);

void nm_fake_rdisc_add_address    (NMFakeRDisc *self,
                                   guint ra_id,
                                   const char *addr,
                                   guint32 timestamp,
                                   guint32 lifetime,
                                   guint32 preferred);

void nm_fake_rdisc_add_route      (NMFakeRDisc *self,
                                   guint ra_id,
                                   const char *network,
                                   guint plen,
                                   const char *gateway,
                                   guint32 timestamp,
                                   guint32 lifetime,
                                   NMRDiscPreference preference);

void nm_fake_rdisc_add_dns_server (NMFakeRDisc *self,
                                   guint ra_id,
                                   const char *address,
                                   guint32 timestamp,
                                   guint32 lifetime);

void nm_fake_rdisc_add_dns_domain (NMFakeRDisc *self,
                                   guint ra_id,
                                   const char *domain,
                                   guint32 timestamp,
                                   guint32 lifetime);

void nm_fake_rdisc_emit_new_ras (NMFakeRDisc *self);

gboolean nm_fake_rdisc_done (NMFakeRDisc *self);

#endif /* __NETWORKMANAGER_FAKE_RDISC_H__ */
