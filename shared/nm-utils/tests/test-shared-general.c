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
 * Copyright 2018 Red Hat, Inc.
 */

#define NM_TEST_UTILS_NO_LIBNM 1

#include "nm-default.h"

#include "nm-utils/nm-time-utils.h"
#include "nm-utils/nm-random-utils.h"

#include "nm-utils/nm-test-utils.h"

/*****************************************************************************/

static int _monotonic_timestamp_initialized;

void
_nm_utils_monotonic_timestamp_initialized (const struct timespec *tp,
                                           gint64 offset_sec,
                                           gboolean is_boottime)
{
	g_assert (!_monotonic_timestamp_initialized);
	_monotonic_timestamp_initialized = 1;
}

/*****************************************************************************/

static void
test_monotonic_timestamp (void)
{
	g_assert (nm_utils_get_monotonic_timestamp_s () > 0);
	g_assert (_monotonic_timestamp_initialized);
}

/*****************************************************************************/

static void
test_nmhash (void)
{
	int rnd;

	nm_utils_random_bytes (&rnd, sizeof (rnd));

	g_assert (nm_hash_val (555, 4) != 0);
}

/*****************************************************************************/

NMTST_DEFINE ();

int main (int argc, char **argv)
{
	nmtst_init (&argc, &argv, TRUE);

	g_test_add_func ("/general/test_monotonic_timestamp", test_monotonic_timestamp);
	g_test_add_func ("/general/test_nmhash", test_nmhash);

	return g_test_run ();
}

