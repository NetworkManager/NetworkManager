/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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
 * Copyright (C) 2012 Red Hat, Inc.
 */

#ifndef NM_POSIX_SIGNALS_H
#define NM_POSIX_SIGNALS_H

#include <glib.h>
#include <signal.h>

/*
 * This function can be used in g_spawn_* as GSpawnChildSetupFunc()
 * callback.
 */
void nm_unblock_posix_signals (gpointer user_data);

void nm_save_original_signal_mask (sigset_t sig_mask);
const sigset_t *nm_get_original_signal_mask (void);

#endif /* NM_POSIX_SIGNALS_H */
