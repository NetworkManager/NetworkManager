/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#ifndef __NM_NETNS_H__
#define __NM_NETNS_H__

#include "libnm-platform/nmp-base.h"

#define NM_TYPE_NETNS            (nm_netns_get_type())
#define NM_NETNS(obj)            (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_NETNS, NMNetns))
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

struct _NMPGlobalTracker *nm_netns_get_global_tracker(NMNetns *self);

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

/*****************************************************************************/

void nm_netns_ip_route_ecmp_register(NMNetns *self, NML3Cfg *l3cfg, const NMPObject *obj);
void nm_netns_ip_route_ecmp_commit(NMNetns    *self,
                                   NML3Cfg    *l3cfg,
                                   GPtrArray **routes,
                                   gboolean    is_reapply);

/*****************************************************************************/

typedef enum {
    NM_NETNS_WATCHER_TYPE_IP_ADDR,
} NMNetnsWatcherType;

typedef struct {
    union {
        struct {
            NMIPAddrTyped addr;
        } ip_addr;
    };
} NMNetnsWatcherData;

typedef struct {
    union {
        struct {
            const NMPObject           *obj;
            NMPlatformSignalChangeType change_type;
        } ip_addr;
    };
} NMNetnsWatcherEventData;

typedef struct _NMNetnsWatcherHandle NMNetnsWatcherHandle;

typedef void (*NMNetnsWatcherCallback)(NMNetns                       *self,
                                       NMNetnsWatcherType             watcher_type,
                                       const NMNetnsWatcherData      *watcher_data,
                                       gconstpointer                  tag,
                                       const NMNetnsWatcherEventData *event_data,
                                       gpointer                       user_data);

void nm_netns_watcher_add(NMNetns                  *self,
                          NMNetnsWatcherType        watcher_type,
                          const NMNetnsWatcherData *watcher_data,
                          gconstpointer             tag,
                          NMNetnsWatcherCallback    callback,
                          gpointer                  user_data);

void
nm_netns_watcher_remove_all(NMNetns *self, gconstpointer tag, gboolean all /* or only dirty */);

#endif /* __NM_NETNS_H__ */
