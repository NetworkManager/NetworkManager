/* NetworkManager -- Network link manager
 *
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
 *
 * (C) Copyright 2019 Red Hat, Inc.
 */

#ifndef __NM_LIBNM_CORE_AUX_H__
#define __NM_LIBNM_CORE_AUX_H__

#include "nm-setting-team.h"

char *nm_utils_team_link_watcher_to_string (NMTeamLinkWatcher *watcher);

NMTeamLinkWatcher *nm_utils_team_link_watcher_from_string (const char *str,
                                                           GError **error);

#endif /* __NM_LIBNM_CORE_AUX_H__ */
