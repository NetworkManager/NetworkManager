// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_FAKE_NDISC_H__
#define __NETWORKMANAGER_FAKE_NDISC_H__

#include "nm-ndisc.h"

#define NM_TYPE_FAKE_NDISC            (nm_fake_ndisc_get_type ())
#define NM_FAKE_NDISC(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_FAKE_NDISC, NMFakeNDisc))
#define NM_FAKE_NDISC_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_FAKE_NDISC, NMFakeNDiscClass))
#define NM_IS_FAKE_NDISC(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_FAKE_NDISC))
#define NM_IS_FAKE_NDISC_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_FAKE_NDISC))
#define NM_FAKE_NDISC_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_FAKE_NDISC, NMFakeNDiscClass))

#define NM_FAKE_NDISC_RS_SENT "rs-sent"

typedef struct _NMFakeRNDisc NMFakeNDisc;
typedef struct _NMFakeRNDiscClass NMFakeNDiscClass;

GType nm_fake_ndisc_get_type (void);

NMNDisc *nm_fake_ndisc_new (int ifindex, const char *ifname);

guint nm_fake_ndisc_add_ra (NMFakeNDisc *self,
                            guint seconds,
                            NMNDiscDHCPLevel dhcp_level,
                            int hop_limit,
                            guint32 mtu);

void nm_fake_ndisc_add_gateway    (NMFakeNDisc *self,
                                   guint ra_id,
                                   const char *addr,
                                   guint32 timestamp,
                                   guint32 lifetime,
                                   NMIcmpv6RouterPref preference);

void nm_fake_ndisc_add_prefix     (NMFakeNDisc *self,
                                   guint ra_id,
                                   const char *network,
                                   guint plen,
                                   const char *gateway,
                                   guint32 timestamp,
                                   guint32 lifetime,
                                   guint32 preferred,
                                   NMIcmpv6RouterPref preference);

void nm_fake_ndisc_add_dns_server (NMFakeNDisc *self,
                                   guint ra_id,
                                   const char *address,
                                   guint32 timestamp,
                                   guint32 lifetime);

void nm_fake_ndisc_add_dns_domain (NMFakeNDisc *self,
                                   guint ra_id,
                                   const char *domain,
                                   guint32 timestamp,
                                   guint32 lifetime);

void nm_fake_ndisc_emit_new_ras (NMFakeNDisc *self);

gboolean nm_fake_ndisc_done (NMFakeNDisc *self);

#endif /* __NETWORKMANAGER_FAKE_NDISC_H__ */
