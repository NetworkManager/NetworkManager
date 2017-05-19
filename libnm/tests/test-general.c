/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT SC WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-libnm-utils.h"

#include "nm-utils/nm-test-utils.h"

/*****************************************************************************/

static void
do_test_fixup_desc_string (const char *desc, const char *expected)
{
	gs_free char *result = NULL;

	result = nm_utils_fixup_desc_string (desc);
	g_assert_cmpstr (result, ==, expected);
}

#define do_test_fixup_desc_string_same(desc) (do_test_fixup_desc_string (""desc"", ""desc""))

static void
test_fixup_desc_string (void)
{
	do_test_fixup_desc_string (NULL, NULL);
	do_test_fixup_desc_string ("", NULL);
	do_test_fixup_desc_string_same ("a");
	do_test_fixup_desc_string_same ("a b");
	do_test_fixup_desc_string ("a b ", "a b");
	do_test_fixup_desc_string ("  a   bbc ", "a bbc");
	do_test_fixup_desc_string ("  a \xcc  bbc ", "a bbc");
	do_test_fixup_desc_string ("  a\xcc  bbc ", "a bbc");
	do_test_fixup_desc_string ("  a\xcc""bbc Wireless PC", "a bbc");
	do_test_fixup_desc_string ("  a\xcc""bbc Wireless PC ", "a bbc");
	do_test_fixup_desc_string ("  a\xcc""bbcWireless PC ", "a bbcWireless PC");
	do_test_fixup_desc_string ("  a\xcc""bbc Wireless PCx", "a bbc Wireless PCx");
	do_test_fixup_desc_string ("  a\xcc""bbc Inc Wireless PC ", "a bbc");
}

/*****************************************************************************/

NMTST_DEFINE ();

int main (int argc, char **argv)
{
	nmtst_init (&argc, &argv, TRUE);

	g_test_add_func ("/libnm/general/fixup_desc_string", test_fixup_desc_string);

	return g_test_run ();
}
