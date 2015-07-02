/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-platform.c - Handle runtime kernel networking configuration
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2015 Red Hat, Inc.
 */

#include "nm-platform-utils.h"

#include <linux/rtnetlink.h>

#include "nm-linux-platform.h"
#include "nm-logging.h"

#include "nm-test-utils.h"


/******************************************************************/

static void
test_init_linux_platform (void)
{
	gs_unref_object NMPlatform *platform = NULL;

	platform = g_object_new (NM_TYPE_LINUX_PLATFORM, NULL);
}

/******************************************************************/

static void
test_link_get_all (void)
{
	gs_unref_object NMPlatform *platform = NULL;
	gs_unref_array GArray *links = NULL;

	platform = g_object_new (NM_TYPE_LINUX_PLATFORM, NULL);

	links = nm_platform_link_get_all (platform);
}

/******************************************************************/

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	nmtst_init_assert_logging (&argc, &argv, "INFO", "DEFAULT");

	g_test_add_func ("/general/init_linux_platform", test_init_linux_platform);
	g_test_add_func ("/general/link_get_all", test_link_get_all);

	return g_test_run ();
}
