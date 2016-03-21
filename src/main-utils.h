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
 * Copyright (C) 2014 Red Hat, Inc.
 */

#ifndef __MAIN_UTILS_H__
#define __MAIN_UTILS_H__

#include "nm-default.h"

void     nm_main_utils_ensure_root (void);

void     nm_main_utils_setup_signals (GMainLoop *main_loop);

void     nm_main_utils_ensure_statedir (void);
void     nm_main_utils_ensure_rundir (void);

gboolean nm_main_utils_write_pidfile (const char *pidfile);

void     nm_main_utils_ensure_not_running_pidfile (const char *pidfile);

gboolean nm_main_utils_early_setup (const char *progname,
                                    int *argc,
                                    char **argv[],
                                    GOptionEntry *options,
                                    void (*option_context_hook) (gpointer user_data, GOptionContext *opt_ctx),
                                    gpointer option_context_hook_data,
                                    const char *summary);

/* The following functions are not implemented inside nm-main-utils.c, instead
 * main.c and nm-iface-helper.c */

void nm_main_config_reload (int signal);

#endif /* __MAIN_UTILS_H__ */
