/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 */

#ifndef __NMP_RULES_MANAGER_H__
#define __NMP_RULES_MANAGER_H__

#include "nm-platform.h"

/*****************************************************************************/

typedef struct _NMPRulesManager NMPRulesManager;

NMPRulesManager *nmp_rules_manager_new (NMPlatform *platform);

void nmp_rules_manager_ref (NMPRulesManager *self);
void nmp_rules_manager_unref (NMPRulesManager *self);

#define nm_auto_unref_rules_manager nm_auto (_nmp_rules_manager_unref)
NM_AUTO_DEFINE_FCN0 (NMPRulesManager *, _nmp_rules_manager_unref, nmp_rules_manager_unref)

void nmp_rules_manager_track (NMPRulesManager *self,
                              const NMPlatformRoutingRule *routing_rule,
                              gint32 track_priority,
                              gconstpointer user_tag);

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
