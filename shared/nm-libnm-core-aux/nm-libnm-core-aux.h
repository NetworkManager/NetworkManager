// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2019 Red Hat, Inc.
 */

#ifndef __NM_LIBNM_CORE_AUX_H__
#define __NM_LIBNM_CORE_AUX_H__

#include "nm-setting-team.h"

typedef enum {
	NM_TEAM_LINK_WATCHER_TYPE_NONE     = 0,
	NM_TEAM_LINK_WATCHER_TYPE_ETHTOOL  = (1u << 0),
	NM_TEAM_LINK_WATCHER_TYPE_NSNAPING = (1u << 1),
	NM_TEAM_LINK_WATCHER_TYPE_ARPING   = (1u << 2),
} NMTeamLinkWatcherType;

typedef enum {
	NM_TEAM_LINK_WATCHER_KEY_NAME,
	NM_TEAM_LINK_WATCHER_KEY_DELAY_UP,
	NM_TEAM_LINK_WATCHER_KEY_DELAY_DOWN,
	NM_TEAM_LINK_WATCHER_KEY_INIT_WAIT,
	NM_TEAM_LINK_WATCHER_KEY_INTERVAL,
	NM_TEAM_LINK_WATCHER_KEY_MISSED_MAX,
	NM_TEAM_LINK_WATCHER_KEY_TARGET_HOST,
	NM_TEAM_LINK_WATCHER_KEY_VLANID,
	NM_TEAM_LINK_WATCHER_KEY_SOURCE_HOST,
	NM_TEAM_LINK_WATCHER_KEY_VALIDATE_ACTIVE,
	NM_TEAM_LINK_WATCHER_KEY_VALIDATE_INACTIVE,
	NM_TEAM_LINK_WATCHER_KEY_SEND_ALWAYS,
	_NM_TEAM_LINK_WATCHER_KEY_NUM,
} NMTeamLinkWatcherKeyId;

char *nm_utils_team_link_watcher_to_string (const NMTeamLinkWatcher *watcher);

NMTeamLinkWatcher *nm_utils_team_link_watcher_from_string (const char *str,
                                                           GError **error);

#endif /* __NM_LIBNM_CORE_AUX_H__ */
