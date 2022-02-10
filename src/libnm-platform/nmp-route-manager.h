/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __NMP_ROUTE_MANAGER_H__
#define __NMP_ROUTE_MANAGER_H__

#include "nm-platform.h"

/*****************************************************************************/

#define NMP_ROUTE_MANAGER_EXTERN_WEAKLY_TRACKED_USER_TAG ((const void *) nmp_route_manager_new)

typedef struct _NMPRouteManager NMPRouteManager;

NMPRouteManager *nmp_route_manager_new(NMPlatform *platform);

NMPRouteManager *nmp_route_manager_ref(NMPRouteManager *self);
void             nmp_route_manager_unref(NMPRouteManager *self);

#define nm_auto_unref_route_manager nm_auto(_nmp_route_manager_unref)
NM_AUTO_DEFINE_FCN0(NMPRouteManager *, _nmp_route_manager_unref, nmp_route_manager_unref);

gboolean nmp_route_manager_track(NMPRouteManager *self,
                                 NMPObjectType    obj_type,
                                 gconstpointer    obj,
                                 gint32           track_priority,
                                 gconstpointer    user_tag,
                                 gconstpointer    user_tag_untrack);

static inline gboolean
nmp_route_manager_track_rule(NMPRouteManager             *self,
                             const NMPlatformRoutingRule *routing_rule,
                             gint32                       track_priority,
                             gconstpointer                user_tag,
                             gconstpointer                user_tag_untrack)
{
    return nmp_route_manager_track(self,
                                   NMP_OBJECT_TYPE_ROUTING_RULE,
                                   routing_rule,
                                   track_priority,
                                   user_tag,
                                   user_tag_untrack);
}

void nmp_route_manager_track_rule_default(NMPRouteManager *self,
                                          int              addr_family,
                                          gint32           track_priority,
                                          gconstpointer    user_tag);

void nmp_route_manager_track_rule_from_platform(NMPRouteManager *self,
                                                NMPlatform      *platform,
                                                int              addr_family,
                                                gint32           tracking_priority,
                                                gconstpointer    user_tag);

gboolean nmp_route_manager_untrack(NMPRouteManager *self,
                                   NMPObjectType    obj_type,
                                   gconstpointer    obj,
                                   gconstpointer    user_tag);

static inline gboolean
nmp_route_manager_untrack_rule(NMPRouteManager             *self,
                               const NMPlatformRoutingRule *routing_rule,
                               gconstpointer                user_tag)
{
    return nmp_route_manager_untrack(self, NMP_OBJECT_TYPE_ROUTING_RULE, routing_rule, user_tag);
}

void nmp_route_manager_set_dirty(NMPRouteManager *self, gconstpointer user_tag);

gboolean nmp_route_manager_untrack_all(NMPRouteManager *self,
                                       gconstpointer    user_tag,
                                       gboolean         all /* or only dirty */,
                                       gboolean         make_survivors_dirty);

void nmp_route_manager_sync(NMPRouteManager *self, NMPObjectType obj_type, gboolean keep_deleted);

/*****************************************************************************/

#endif /* __NMP_ROUTE_MANAGER_H__ */
