/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __NMP_GLOBAL_TRACKER_H__
#define __NMP_GLOBAL_TRACKER_H__

#include "nm-platform.h"

/*****************************************************************************/

#define NMP_GLOBAL_TRACKER_EXTERN_WEAKLY_TRACKED_USER_TAG ((const void *) nmp_global_tracker_new)

typedef struct _NMPGlobalTracker NMPGlobalTracker;

NMPGlobalTracker *nmp_global_tracker_new(NMPlatform *platform);

NMPGlobalTracker *nmp_global_tracker_ref(NMPGlobalTracker *self);
void              nmp_global_tracker_unref(NMPGlobalTracker *self);

#define nm_auto_unref_global_tracker nm_auto(_nmp_global_tracker_unref)
NM_AUTO_DEFINE_FCN0(NMPGlobalTracker *, _nmp_global_tracker_unref, nmp_global_tracker_unref);

gboolean nmp_global_tracker_track(NMPGlobalTracker *self,
                                  NMPObjectType     obj_type,
                                  gconstpointer     obj,
                                  gint32            track_priority,
                                  gconstpointer     user_tag,
                                  gconstpointer     user_tag_untrack);

static inline gboolean
nmp_global_tracker_track_rule(NMPGlobalTracker            *self,
                              const NMPlatformRoutingRule *routing_rule,
                              gint32                       track_priority,
                              gconstpointer                user_tag,
                              gconstpointer                user_tag_untrack)
{
    return nmp_global_tracker_track(self,
                                    NMP_OBJECT_TYPE_ROUTING_RULE,
                                    routing_rule,
                                    track_priority,
                                    user_tag,
                                    user_tag_untrack);
}

void nmp_global_tracker_track_rule_default(NMPGlobalTracker *self,
                                           int               addr_family,
                                           gint32            track_priority,
                                           gconstpointer     user_tag);

void nmp_global_tracker_track_local_rule(NMPGlobalTracker *self,
                                         int               addr_family,
                                         gint32            track_priority,
                                         gconstpointer     user_tag,
                                         gconstpointer     user_tag_untrack);

void nmp_global_tracker_track_rule_from_platform(NMPGlobalTracker *self,
                                                 NMPlatform       *platform,
                                                 int               addr_family,
                                                 gint32            tracking_priority,
                                                 gconstpointer     user_tag);

gboolean nmp_global_tracker_untrack(NMPGlobalTracker *self,
                                    NMPObjectType     obj_type,
                                    gconstpointer     obj,
                                    gconstpointer     user_tag);

static inline gboolean
nmp_global_tracker_untrack_rule(NMPGlobalTracker            *self,
                                const NMPlatformRoutingRule *routing_rule,
                                gconstpointer                user_tag)
{
    return nmp_global_tracker_untrack(self, NMP_OBJECT_TYPE_ROUTING_RULE, routing_rule, user_tag);
}

void nmp_global_tracker_set_dirty(NMPGlobalTracker *self, gconstpointer user_tag);

gboolean nmp_global_tracker_untrack_all(NMPGlobalTracker *self,
                                        gconstpointer     user_tag,
                                        gboolean          all /* or only dirty */,
                                        gboolean          make_survivors_dirty);

void nmp_global_tracker_sync(NMPGlobalTracker *self, NMPObjectType obj_type, gboolean keep_deleted);

void nmp_global_tracker_sync_mptcp_addrs(NMPGlobalTracker *self, gboolean reapply);

/*****************************************************************************/

const NMPlatformMptcpAddr *nmp_global_tracker_mptcp_addr_init_for_ifindex(NMPlatformMptcpAddr *addr,
                                                                          int ifindex);

#endif /* __NMP_GLOBAL_TRACKER_H__ */
