/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#ifndef __NM_NETNS_H__
#define __NM_NETNS_H__

#include "libnm-platform/nmp-base.h"

#define NM_TYPE_NETNS            (nm_netns_get_type())
#define NM_NETNS(obj)            (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_NETNS, NMNetns))
#define NM_NETNS_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_NETNS, NMNetnsClass))
#define NM_IS_NETNS(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_NETNS))
#define NM_IS_NETNS_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_NETNS))
#define NM_NETNS_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_NETNS, NMNetnsClass))

#define NM_NETNS_PLATFORM "platform"

typedef struct _NMNetnsClass NMNetnsClass;

struct _NMPlatform;

GType nm_netns_get_type(void);

NMNetns *nm_netns_get(void);
NMNetns *nm_netns_new(struct _NMPlatform *platform);

struct _NMPlatform *nm_netns_get_platform(NMNetns *self);
NMPNetns           *nm_netns_get_platform_netns(NMNetns *self);

struct _NMPRouteManager *nm_netns_get_route_manager(NMNetns *self);

struct _NMDedupMultiIndex *nm_netns_get_multi_idx(NMNetns *self);

#define NM_NETNS_GET (nm_netns_get())

NML3Cfg *nm_netns_l3cfg_get(NMNetns *self, int ifindex);

NML3Cfg *nm_netns_l3cfg_acquire(NMNetns *netns, int ifindex);

/*****************************************************************************/

typedef struct {
    in_addr_t addr;
    int       _ref_count;
    NMNetns  *_self;
} NMNetnsSharedIPHandle;

NMNetnsSharedIPHandle *nm_netns_shared_ip_reserve(NMNetns *self);

void nm_netns_shared_ip_release(NMNetnsSharedIPHandle *handle);

#endif /* __NM_NETNS_H__ */
