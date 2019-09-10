// SPDX-License-Identifier: LGPL-2.1+
/*
 */

#ifndef __NMP_RULES_MANAGER_H__
#define __NMP_RULES_MANAGER_H__

#include "nm-platform.h"

/*****************************************************************************/

#define NMP_RULES_MANAGER_EXTERN_WEAKLY_TRACKED_USER_TAG ((const void *) nmp_rules_manager_new)

typedef struct _NMPRulesManager NMPRulesManager;

NMPRulesManager *nmp_rules_manager_new (NMPlatform *platform);

void nmp_rules_manager_ref (NMPRulesManager *self);
void nmp_rules_manager_unref (NMPRulesManager *self);

#define nm_auto_unref_rules_manager nm_auto (_nmp_rules_manager_unref)
NM_AUTO_DEFINE_FCN0 (NMPRulesManager *, _nmp_rules_manager_unref, nmp_rules_manager_unref)

void nmp_rules_manager_track (NMPRulesManager *self,
                              const NMPlatformRoutingRule *routing_rule,
                              gint32 track_priority,
                              gconstpointer user_tag,
                              gconstpointer user_tag_untrack);

void nmp_rules_manager_track_default (NMPRulesManager *self,
                                      int addr_family,
                                      gint32 track_priority,
                                      gconstpointer user_tag);

void nmp_rules_manager_track_from_platform (NMPRulesManager *self,
                                            NMPlatform *platform,
                                            int addr_family,
                                            gint32 tracking_priority,
                                            gconstpointer user_tag);

void nmp_rules_manager_untrack (NMPRulesManager *self,
                                const NMPlatformRoutingRule *routing_rule,
                                gconstpointer user_tag);

void nmp_rules_manager_set_dirty (NMPRulesManager *self,
                                  gconstpointer user_tag);

void nmp_rules_manager_untrack_all (NMPRulesManager *self,
                                    gconstpointer user_tag,
                                    gboolean all /* or only dirty */);

void nmp_rules_manager_sync (NMPRulesManager *self,
                             gboolean keep_deleted_rules);

/*****************************************************************************/

#endif /* __NMP_RULES_MANAGER_H__ */
