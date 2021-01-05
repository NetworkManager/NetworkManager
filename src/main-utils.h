/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2014 Red Hat, Inc.
 */

#ifndef __MAIN_UTILS_H__
#define __MAIN_UTILS_H__

void nm_main_utils_ensure_root(void);

void nm_main_utils_setup_signals(GMainLoop *main_loop);

void nm_main_utils_ensure_statedir(void);
void nm_main_utils_ensure_rundir(void);

gboolean nm_main_utils_write_pidfile(const char *pidfile);

void nm_main_utils_ensure_not_running_pidfile(const char *pidfile);

gboolean nm_main_utils_early_setup(const char *  progname,
                                   int *         argc,
                                   char **       argv[],
                                   GOptionEntry *options,
                                   void (*option_context_hook)(gpointer        user_data,
                                                               GOptionContext *opt_ctx),
                                   gpointer    option_context_hook_data,
                                   const char *summary);

/* The following functions are not implemented inside nm-main-utils.c, instead
 * main.c and nm-iface-helper.c */

void nm_main_config_reload(int signal);

#endif /* __MAIN_UTILS_H__ */
