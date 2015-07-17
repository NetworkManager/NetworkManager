/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
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
 * Copyright 2014 Red Hat, Inc.
 *
 */

#include "config.h"

#include <nm-utils.h>

#include "nm-default.h"

extern GType nm_state_get_type (void);

int
main (int argc, char **argv)
{
	/* If we reach main(), then the test has failed. */
	g_printerr ("libnm/libnm-util constructor failed to detect symbol mixing\n");

	/* This is just to ensure that both libnm.so and libnm-util.so get pulled
	 * in; libnm-util doesn't have "nm_state_get_type" and libnm doesn't have
	 * "nm_utils_slist_free". (We intentionally choose different symbols than the
	 * ones that the libraries check for.)
	 */
	nm_state_get_type ();
	G_GNUC_BEGIN_IGNORE_DEPRECATIONS;
	nm_utils_slist_free (NULL, g_free);
	G_GNUC_END_IGNORE_DEPRECATIONS;

	g_assert_not_reached ();
}
