/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service - keyfile plugin
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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
 * Copyright (C) 2008 - 2011 Red Hat, Inc.
 */

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>

#include "common.h"
#include "utils.h"

#include "nm-test-utils.h"

static void
test_get_ifcfg_name (const char *desc,
                     const char *path,
                     gboolean only_ifcfg,
                     const char *expected)
{
	const char *result;

	result = utils_get_ifcfg_name (path, only_ifcfg);
	if (expected == NULL) {
		ASSERT (result == NULL, desc, "unexpected valid ifcfg name '%s'", result);
	} else {
		ASSERT (result != NULL, desc, "failed to create ifcfg name for '%s'", path);

		ASSERT (strcmp (result, expected) == 0,
		        desc, "unexpected ifcfg name '%s' created for '%s'", result, path);
	}
}

static void
test_get_ifcfg_path (const char *desc,
                     const char *path,
                     const char *expected)
{
	char *result;

	result = utils_get_ifcfg_path (path);
	if (expected == NULL) {
		ASSERT (result == NULL, desc, "unexpected valid ifcfg name '%s'", result);
	} else {
		ASSERT (result != NULL, desc, "failed to create ifcfg name for '%s'", path);

		ASSERT (strcmp (result, expected) == 0,
		        desc, "unexpected ifcfg name '%s' created for '%s'", result, path);
	}
	g_free (result);
}

static void
test_get_keys_path (const char *desc,
                    const char *path,
                    const char *expected)
{
	char *result;

	result = utils_get_keys_path (path);
	if (expected == NULL) {
		ASSERT (result == NULL, desc, "unexpected valid extra path '%s'", result);
	} else {
		ASSERT (result != NULL, desc, "failed to create extra path for '%s'", path);

		ASSERT (strcmp (result, expected) == 0,
		        desc, "unexpected extra path '%s' created for '%s'", result, path);
	}
	g_free (result);
}

static void
test_get_route_path (const char *desc,
                     const char *path,
                     const char *expected)
{
	char *result;

	result = utils_get_route_path (path);
	if (expected == NULL) {
		ASSERT (result == NULL, desc, "unexpected valid extra path '%s'", result);
	} else {
		ASSERT (result != NULL, desc, "failed to create extra path for '%s'", path);

		ASSERT (strcmp (result, expected) == 0,
		        desc, "unexpected extra path '%s' created for '%s'", result, path);
	}
	g_free (result);
}

static void
test_ignored (const char *desc, const char *path, gboolean expected_ignored)
{
	gboolean result;

	result = utils_should_ignore_file (path, FALSE);
	ASSERT (result == expected_ignored, desc, "unexpected ignore result for path '%s'", path);
}

NMTST_DEFINE ();

int main (int argc, char **argv)
{
	char *base;

	nmtst_init (&argc, &argv, TRUE);

	/* The tests */
	test_get_ifcfg_name ("get-ifcfg-name-bad", "/foo/bar/adfasdfadf", FALSE, NULL);
	test_get_ifcfg_name ("get-ifcfg-name-good", "/foo/bar/ifcfg-FooBar", FALSE, "FooBar");
	test_get_ifcfg_name ("get-ifcfg-name-keys", "/foo/bar/keys-BlahLbah", FALSE, "BlahLbah");
	test_get_ifcfg_name ("get-ifcfg-name-route", "/foo/bar/route-Lalalala", FALSE, "Lalalala");
	test_get_ifcfg_name ("get-ifcfg-name-only-ifcfg-route", "/foo/bar/route-Lalalala", TRUE, NULL);
	test_get_ifcfg_name ("get-ifcfg-name-only-ifcfg-keys", "/foo/bar/keys-Lalalala", TRUE, NULL);
	test_get_ifcfg_name ("get-ifcfg-name-no-path-ifcfg", "ifcfg-Lalalala", FALSE, "Lalalala");
	test_get_ifcfg_name ("get-ifcfg-name-no-path-keys", "keys-Lalalala", FALSE, "Lalalala");
	test_get_ifcfg_name ("get-ifcfg-name-no-path-route", "route-Lalalala", FALSE, "Lalalala");

	test_get_ifcfg_name ("get-ifcfg-name-bad2-ifcfg", "/foo/bar/asdfasifcfg-Foobar", FALSE, NULL);
	test_get_ifcfg_name ("get-ifcfg-name-bad2-keys", "/foo/bar/asdfaskeys-Foobar", FALSE, NULL);
	test_get_ifcfg_name ("get-ifcfg-name-bad2-route", "/foo/bar/asdfasroute-Foobar", FALSE, NULL);

	test_get_ifcfg_path ("ifcfg-path-bad", "/foo/bar/adfasdfasdf", NULL);
	test_get_ifcfg_path ("ifcfg-path-from-keys-no-path", "keys-BlahBlah", "ifcfg-BlahBlah");
	test_get_ifcfg_path ("ifcfg-path-from-keys", "/foo/bar/keys-BlahBlah", "/foo/bar/ifcfg-BlahBlah");
	test_get_ifcfg_path ("ifcfg-path-from-route", "/foo/bar/route-BlahBlah", "/foo/bar/ifcfg-BlahBlah");

	test_get_keys_path ("keys-path-bad", "/foo/bar/asdfasdfasdfasdf", NULL);
	test_get_keys_path ("keys-path-from-ifcfg-no-path", "ifcfg-FooBar", "keys-FooBar");
	test_get_keys_path ("keys-path-from-ifcfg", "/foo/bar/ifcfg-FooBar", "/foo/bar/keys-FooBar");
	test_get_keys_path ("keys-path-from-route", "/foo/bar/route-FooBar", "/foo/bar/keys-FooBar");

	test_get_route_path ("route-path-bad", "/foo/bar/asdfasdfasdfasdf", NULL);
	test_get_route_path ("route-path-from-ifcfg-no-path", "ifcfg-FooBar", "route-FooBar");
	test_get_route_path ("route-path-from-ifcfg", "/foo/bar/ifcfg-FooBar", "/foo/bar/route-FooBar");
	test_get_route_path ("route-path-from-keys", "/foo/bar/keys-FooBar", "/foo/bar/route-FooBar");

	test_ignored ("ignored-ifcfg", "ifcfg-FooBar", FALSE);
	test_ignored ("ignored-keys", "keys-FooBar", FALSE);
	test_ignored ("ignored-route", "route-FooBar", FALSE);
	test_ignored ("ignored-bak", "ifcfg-FooBar" BAK_TAG, TRUE);
	test_ignored ("ignored-tilde", "ifcfg-FooBar" TILDE_TAG, TRUE);
	test_ignored ("ignored-orig", "ifcfg-FooBar" ORIG_TAG, TRUE);
	test_ignored ("ignored-rej", "ifcfg-FooBar" REJ_TAG, TRUE);
	test_ignored ("ignored-rpmnew", "ifcfg-FooBar" RPMNEW_TAG, TRUE);
	test_ignored ("ignored-augnew", "ifcfg-FooBar" AUGNEW_TAG, TRUE);
	test_ignored ("ignored-augtmp", "ifcfg-FooBar" AUGTMP_TAG, TRUE);

	base = g_path_get_basename (argv[0]);
	fprintf (stdout, "%s: SUCCESS\n", base);
	g_free (base);
	return 0;
}

