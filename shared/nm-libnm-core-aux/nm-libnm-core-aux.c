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

#include "nm-default.h"

#include "nm-libnm-core-aux.h"

/*****************************************************************************/

char *
nm_utils_team_link_watcher_to_string (NMTeamLinkWatcher *watcher)
{
	const char *name;
	NMTeamLinkWatcherArpPingFlags flags;
	GString *w_dump;

	if (!watcher)
		return NULL;

	w_dump = g_string_new (NULL);
	name = nm_team_link_watcher_get_name (watcher);
	g_string_append_printf (w_dump, "name=%s", name);

#define DUMP_WATCHER_INT(str, watcher, name, key) \
	G_STMT_START { \
		int _val = nm_team_link_watcher_get_##key (watcher); \
		\
		if (_val) \
			g_string_append_printf (str, " %s=%d", name, _val); \
	} G_STMT_END;

	if (nm_streq (name, NM_TEAM_LINK_WATCHER_ETHTOOL)) {
		DUMP_WATCHER_INT (w_dump, watcher, "delay-up", delay_up);
		DUMP_WATCHER_INT (w_dump, watcher, "delay-down", delay_down);
		return g_string_free (w_dump, FALSE);
	}
	/* NM_TEAM_LINK_WATCHER_NSNA_PING and NM_TEAM_LINK_WATCHER_ARP_PING */
	DUMP_WATCHER_INT (w_dump, watcher, "init-wait", init_wait);
	DUMP_WATCHER_INT (w_dump, watcher, "interval", interval);

	if (nm_team_link_watcher_get_missed_max (watcher) != 3)
		g_string_append_printf (w_dump, " %s=%d", "missed-max", nm_team_link_watcher_get_missed_max (watcher));

	g_string_append_printf (w_dump, " target-host=%s",
	                        nm_team_link_watcher_get_target_host (watcher));

	if (nm_streq (name, NM_TEAM_LINK_WATCHER_NSNA_PING))
		return g_string_free (w_dump, FALSE);

	if (nm_team_link_watcher_get_vlanid (watcher) != -1)
		g_string_append_printf (w_dump, " %s=%d", "vlanid", nm_team_link_watcher_get_vlanid (watcher));

#undef DUMP_WATCHER_INT
	g_string_append_printf (w_dump, " source-host=%s",
	                        nm_team_link_watcher_get_source_host (watcher));
	flags = nm_team_link_watcher_get_flags (watcher);
	if (flags & NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_VALIDATE_ACTIVE)
		g_string_append_printf (w_dump, " validate-active=true");
	if (flags & NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_VALIDATE_INACTIVE)
		g_string_append_printf (w_dump, " validate-inactive=true");
	if (flags & NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_SEND_ALWAYS)
		g_string_append_printf (w_dump, " send-always=true");

	return g_string_free (w_dump, FALSE);
}

NMTeamLinkWatcher *
nm_utils_team_link_watcher_from_string (const char *str,
                                        GError **error)
{
	gs_free const char **watcherv = NULL;
	gs_free char *str_clean_free = NULL;
	const char *str_clean;
	guint i;
	gs_free const char *name = NULL;
	int val1 = 0, val2 = 0, val3 = 3, val4 = -1;
	gs_free const char *target_host = NULL;
	gs_free const char *source_host = NULL;
	NMTeamLinkWatcherArpPingFlags flags = 0;

	nm_assert (str);
	nm_assert (!error || !*error);

	str_clean = nm_strstrip_avoid_copy_a (300, str, &str_clean_free);
	watcherv = nm_utils_strsplit_set (str_clean, " \t");
	if (!watcherv) {
		g_set_error (error, 1, 0, "'%s' is not valid", str);
		return NULL;
	}

	for (i = 0; watcherv[i]; i++) {
		gs_free const char **pair = NULL;

		pair = nm_utils_strsplit_set (watcherv[i], "=");
		if (!pair) {
			g_set_error (error, 1, 0, "'%s' is not valid: %s", watcherv[i],
			             "properties should be specified as 'key=value'");
			return NULL;
		}
		if (!pair[1]) {
			g_set_error (error, 1, 0, "'%s' is not valid: %s", watcherv[i],
			             "missing key value");
			return NULL;
		}
		if (pair[2]) {
			g_set_error (error, 1, 0, "'%s' is not valid: %s", watcherv[i],
			             "properties should be specified as 'key=value'");
			return NULL;
		}

		if (nm_streq (pair[0], "name"))
			name = g_strdup (pair[1]);
		else if (   nm_streq (pair[0], "delay-up")
		         || nm_streq (pair[0], "init-wait"))
			val1 = _nm_utils_ascii_str_to_int64 (pair[1], 10, 0, G_MAXINT32, -1);
		else if (   nm_streq (pair[0], "delay-down")
		         || nm_streq (pair[0], "interval"))
			val2 = _nm_utils_ascii_str_to_int64 (pair[1], 10, 0, G_MAXINT32, -1);
		else if (nm_streq (pair[0], "missed-max"))
			val3 = _nm_utils_ascii_str_to_int64 (pair[1], 10, 0, G_MAXINT32, -1);
		else if (nm_streq (pair[0], "vlanid"))
			val4 = _nm_utils_ascii_str_to_int64 (pair[1], 10, -1, 4094, -2);
		else if (nm_streq (pair[0], "target-host"))
			target_host = g_strdup (pair[1]);
		else if (nm_streq (pair[0], "source-host"))
			source_host = g_strdup (pair[1]);
		else if (nm_streq (pair[0], "validate-active")) {
			if (nm_streq (pair[1], "true"))
				flags |= NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_VALIDATE_ACTIVE;
		} else if (nm_streq (pair[0], "validate-inactive")) {
			if (nm_streq (pair[1], "true"))
				flags |= NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_VALIDATE_INACTIVE;
		} else if (nm_streq (pair[0], "send-always")) {
			if (nm_streq (pair[1], "true"))
				flags |= NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_SEND_ALWAYS;
		} else {
			g_set_error (error, 1, 0, "'%s' is not valid: %s", watcherv[i],
			             "unknown key");
			return NULL;
		}

		if ((val1 < 0) || (val2 < 0) || (val3 < 0)) {
			g_set_error (error, 1, 0, "'%s' is not valid: %s", watcherv[i],
			             "value is not a valid number [0, MAXINT]");
			return NULL;
		}
		if (val4 < -1) {
			g_set_error (error, 1, 0, "'%s' is not valid: %s", watcherv[i],
			             "value is not a valid number [-1, 4094]");
			return NULL;
		}
	}

	if (nm_streq0 (name, NM_TEAM_LINK_WATCHER_ETHTOOL))
		return nm_team_link_watcher_new_ethtool (val1, val2, error);
	else if (nm_streq0 (name, NM_TEAM_LINK_WATCHER_NSNA_PING))
		return nm_team_link_watcher_new_nsna_ping (val1, val2, val3, target_host, error);
	else if (nm_streq0 (name, NM_TEAM_LINK_WATCHER_ARP_PING))
		return nm_team_link_watcher_new_arp_ping2 (val1, val2, val3, val4, target_host, source_host, flags, error);

	if (!name)
		g_set_error (error, 1, 0, "link watcher name missing");
	else
		g_set_error (error, 1, 0, "unknown link watcher name: '%s'", name);
	return NULL;
}
