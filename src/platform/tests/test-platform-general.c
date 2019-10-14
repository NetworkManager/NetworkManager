// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2015 - 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include <linux/rtnetlink.h>

#include "platform/nm-platform-utils.h"
#include "platform/nm-linux-platform.h"

#include "nm-test-utils-core.h"

/*****************************************************************************/

static void
test_init_linux_platform (void)
{
	gs_unref_object NMPlatform *platform = NULL;

	platform = nm_linux_platform_new (TRUE, NM_PLATFORM_NETNS_SUPPORT_DEFAULT);
}

/*****************************************************************************/

static void
test_link_get_all (void)
{
	gs_unref_object NMPlatform *platform = NULL;
	gs_unref_ptrarray GPtrArray *links = NULL;

	platform = nm_linux_platform_new (TRUE, NM_PLATFORM_NETNS_SUPPORT_DEFAULT);

	links = nm_platform_link_get_all (platform, TRUE);
}

/*****************************************************************************/

static void
test_nm_platform_link_flags2str (void)
{
	int i;

	for (i = 0; i < 100; i++) {
		char buf[NM_PLATFORM_LINK_FLAGS2STR_MAX_LEN + 100];
		const char *s;
		const guint flags = ((i == 0) ? ~0u : nmtst_get_rand_uint ());
		gsize l;

		s = nm_platform_link_flags2str (flags, buf, sizeof (buf));
		g_assert (s);

		l = strlen (s);
		if (l > NM_PLATFORM_LINK_FLAGS2STR_MAX_LEN)
			g_error ("nm_platform_link_flags2str(%x) produced a longer output than %zu chars: \"%s\"", flags, NM_PLATFORM_LINK_FLAGS2STR_MAX_LEN, s);
		if (   flags == ~0u
		    && l != NM_PLATFORM_LINK_FLAGS2STR_MAX_LEN)
			g_error ("nm_platform_link_flags2str(%x) is expected to produce %zu chars, but produced %zu: \"%s\"", flags, NM_PLATFORM_LINK_FLAGS2STR_MAX_LEN, l, s);
	}
}

/*****************************************************************************/

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	nmtst_init_assert_logging (&argc, &argv, "WARN", "DEFAULT");

	g_test_add_func ("/general/init_linux_platform", test_init_linux_platform);
	g_test_add_func ("/general/link_get_all", test_link_get_all);
	g_test_add_func ("/general/nm_platform_link_flags2str", test_nm_platform_link_flags2str);

	return g_test_run ();
}
