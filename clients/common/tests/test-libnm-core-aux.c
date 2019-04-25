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
 *
 * Copyright 2019 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-libnm-core-aux/nm-libnm-core-aux.h"
#include "nm-libnm-core-intern/nm-libnm-core-utils.h"

#include "nm-utils/nm-test-utils.h"

/*****************************************************************************/

static NMTeamLinkWatcher *
_team_link_watcher_from_string_impl (const char *str, gsize nextra, const char *const*vextra)
{
	NMTeamLinkWatcher *watcher;
	gs_free char *str1_free = NULL;
	gs_free_error GError *error = NULL;
	gsize i;

	g_assert (str);

	watcher = nm_utils_team_link_watcher_from_string (str, &error);
	nmtst_assert_success (watcher, error);

	for (i = 0; i < 1 + nextra; i++) {
		nm_auto_unref_team_link_watcher NMTeamLinkWatcher *watcher1 = NULL;
		const char *str1;

		if (i == 0) {
			str1_free = nm_utils_team_link_watcher_to_string (watcher);
			g_assert (str1_free);
			str1 = str1_free;
			g_assert_cmpstr (str, ==, str1);
		} else
			str1 = vextra[i - 1];

		watcher1 = nm_utils_team_link_watcher_from_string (str1, &error);
		nmtst_assert_success (watcher1, error);
		if (!nm_team_link_watcher_equal (watcher, watcher1)) {
			gs_free char *ss1 = NULL;
			gs_free char *ss2 = NULL;

			g_print (">>> watcher differs: \"%s\" vs. \"%s\"",
			         (ss1 = nm_utils_team_link_watcher_to_string (watcher)),
			         (ss2 = nm_utils_team_link_watcher_to_string (watcher1)));
			g_print (">>> ORIG: \"%s\" vs. \"%s\"", str, str1);
			g_assert_not_reached ();
		}
		g_assert (nm_team_link_watcher_equal (watcher1, watcher));
	}

	return watcher;
}
#define _team_link_watcher_from_string(str, ...) \
	_team_link_watcher_from_string_impl ((str), NM_NARG (__VA_ARGS__), NM_MAKE_STRV (__VA_ARGS__))

/*****************************************************************************/

static void
test_team_link_watcher_tofro_string (void)
{
	nm_auto_unref_team_link_watcher NMTeamLinkWatcher *w = NULL;

#define _team_link_watcher_cmp(watcher, \
                               name, \
                               delay_down, \
                               delay_up, \
                               init_wait, \
                               interval, \
                               missed_max, \
                               target_host, \
                               source_host, \
                               vlanid, \
                               arping_flags) \
	G_STMT_START { \
		nm_auto_unref_team_link_watcher NMTeamLinkWatcher *_w = g_steal_pointer (watcher); \
		\
		g_assert_cmpstr ((name),         ==, nm_team_link_watcher_get_name (_w)); \
		g_assert_cmpint ((delay_down),   ==, nm_team_link_watcher_get_delay_down (_w)); \
		g_assert_cmpint ((delay_up),     ==, nm_team_link_watcher_get_delay_up (_w)); \
		g_assert_cmpint ((init_wait),    ==, nm_team_link_watcher_get_init_wait (_w)); \
		g_assert_cmpint ((interval),     ==, nm_team_link_watcher_get_interval (_w)); \
		g_assert_cmpint ((missed_max),   ==, nm_team_link_watcher_get_missed_max (_w)); \
		g_assert_cmpstr ((target_host),  ==, nm_team_link_watcher_get_target_host (_w)); \
		g_assert_cmpstr ((source_host),  ==, nm_team_link_watcher_get_source_host (_w)); \
		g_assert_cmpint ((vlanid),       ==, nm_team_link_watcher_get_vlanid (_w)); \
		g_assert_cmpint ((arping_flags), ==, nm_team_link_watcher_get_flags (_w)); \
	} G_STMT_END

	w = _team_link_watcher_from_string ("name=ethtool",
	                                    "delay-up=0   name=ethtool",
	                                    "  delay-down=0   name=ethtool   ");
	_team_link_watcher_cmp (&w,
	                        "ethtool",
	                        0,
	                        0,
	                        -1,
	                        -1,
	                        -1,
	                        NULL,
	                        NULL,
	                        -1,
	                        NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_NONE);

	w = _team_link_watcher_from_string ("name=ethtool delay-up=10",
	                                    "   delay-down=0  delay-up=10   name=ethtool");
	_team_link_watcher_cmp (&w,
	                        "ethtool",
	                        0,
	                        10,
	                        -1,
	                        -1,
	                        -1,
	                        NULL,
	                        NULL,
	                        -1,
	                        NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_NONE);

	w = _team_link_watcher_from_string ("name=ethtool delay-up=10 delay-down=11",
	                                    "   delay-down=11  delay-up=10   name=ethtool");
	_team_link_watcher_cmp (&w,
	                        "ethtool",
	                        11,
	                        10,
	                        -1,
	                        -1,
	                        -1,
	                        NULL,
	                        NULL,
	                        -1,
	                        NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_NONE);

	w = _team_link_watcher_from_string ("name=nsna_ping target-host=xxx",
	                                    "name=nsna_ping target-host=xxx",
	                                    "  missed-max=3    target-host=xxx        name=nsna_ping   ");
	_team_link_watcher_cmp (&w,
	                        "nsna_ping",
	                        -1,
	                        -1,
	                        0,
	                        0,
	                        3,
	                        "xxx",
	                        NULL,
	                        -1,
	                        NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_NONE);

	w = _team_link_watcher_from_string ("name=arp_ping target-host=xxx source-host=yzd",
	                                    "  source-host=yzd target-host=xxx        name=arp_ping   ");
	_team_link_watcher_cmp (&w,
	                        "arp_ping",
	                        -1,
	                        -1,
	                        0,
	                        0,
	                        3,
	                        "xxx",
	                        "yzd",
	                        -1,
	                        NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_NONE);

	w = _team_link_watcher_from_string ("name=arp_ping missed-max=0 target-host=xxx vlanid=0 source-host=yzd");
	_team_link_watcher_cmp (&w,
	                        "arp_ping",
	                        -1,
	                        -1,
	                        0,
	                        0,
	                        0,
	                        "xxx",
	                        "yzd",
	                        0,
	                        NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_NONE);

	w = _team_link_watcher_from_string ("name=arp_ping target-host=xxx source-host=yzd validate-active=true",
	                                    "source-host=yzd send-always=false name=arp_ping validate-active=true validate-inactive=false target-host=xxx",
	                                    "  source-host=yzd target-host=xxx   validate-active=true      name=arp_ping   ");
	_team_link_watcher_cmp (&w,
	                        "arp_ping",
	                        -1,
	                        -1,
	                        0,
	                        0,
	                        3,
	                        "xxx",
	                        "yzd",
	                        -1,
	                        NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_VALIDATE_ACTIVE);

	w = _team_link_watcher_from_string ("name=arp_ping target-host=xxx source-host=yzd validate-active=true validate-inactive=true send-always=true",
	                                    "source-host=yzd send-always=true name=arp_ping validate-active=true validate-inactive=true target-host=xxx",
	                                    "source-host=yzd send-always=true name=arp_ping validate-active=1 validate-inactive=yes target-host=xxx",
	                                    "  source-host=yzd target-host=xxx   validate-inactive=true send-always=true    validate-active=true      name=arp_ping   ");
	_team_link_watcher_cmp (&w,
	                        "arp_ping",
	                        -1,
	                        -1,
	                        0,
	                        0,
	                        3,
	                        "xxx",
	                        "yzd",
	                        -1,
	                          NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_VALIDATE_ACTIVE
	                        | NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_VALIDATE_INACTIVE
	                        | NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_SEND_ALWAYS);

	w = _team_link_watcher_from_string ("name=arp_ping missed-max=0 target-host=xxx vlanid=0 source-host=yzd");
	_team_link_watcher_cmp (&w,
	                        "arp_ping",
	                        -1,
	                        -1,
	                        0,
	                        0,
	                        0,
	                        "xxx",
	                        "yzd",
	                        0,
	                        NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_NONE);
}

/*****************************************************************************/

NMTST_DEFINE ();

int main (int argc, char **argv)
{
	nmtst_init (&argc, &argv, TRUE);

	g_test_add_func ("/libnm-core-aux/test_team_link_watcher_tofro_string", test_team_link_watcher_tofro_string);

	return g_test_run ();
}
