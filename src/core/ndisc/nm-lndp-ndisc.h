/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_LNDP_NDISC_H__
#define __NETWORKMANAGER_LNDP_NDISC_H__

#include "nm-ndisc.h"
#include "nm-core-utils.h"

#define NM_TYPE_LNDP_NDISC (nm_lndp_ndisc_get_type())
#define NM_LNDP_NDISC(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_LNDP_NDISC, NMLndpNDisc))
#define NM_LNDP_NDISC_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_LNDP_NDISC, NMLndpNDiscClass))
#define NM_IS_LNDP_NDISC(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_LNDP_NDISC))
#define NM_IS_LNDP_NDISC_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_LNDP_NDISC))
#define NM_LNDP_NDISC_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_LNDP_NDISC, NMLndpNDiscClass))

typedef struct _NMLndpNDisc      NMLndpNDisc;
typedef struct _NMLndpNDiscClass NMLndpNDiscClass;

GType nm_lndp_ndisc_get_type(void);

NMNDisc *nm_lndp_ndisc_new(NMPlatform *                  platform,
                           int                           ifindex,
                           const char *                  ifname,
                           NMUtilsStableType             stable_type,
                           const char *                  network_id,
                           NMSettingIP6ConfigAddrGenMode addr_gen_mode,
                           NMNDiscNodeType               node_type,
                           int                           max_addresses,
                           int                           router_solicitations,
                           int                           router_solicitation_interval,
                           guint32                       ra_timeout,
                           GError **                     error);

void nm_lndp_ndisc_get_sysctl(NMPlatform *platform,
                              const char *ifname,
                              int *       out_max_addresses,
                              int *       out_router_solicitations,
                              int *       out_router_solicitation_interval,
                              guint32 *   out_default_ra_timeout);

#endif /* __NETWORKMANAGER_LNDP_NDISC_H__ */
