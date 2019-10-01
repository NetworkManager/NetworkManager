// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2015 Red Hat, Inc.
 */

#include "nm-default.h"

#include <stdlib.h>
#include <syslog.h>

#include "platform/nm-linux-platform.h"

#include "nm-test-utils-core.h"

NMTST_DEFINE ();

static struct {
	gboolean persist;
} global_opt = {
	.persist = TRUE,
};

static gboolean
read_argv (int *argc, char ***argv)
{
	GOptionContext *context;
	GOptionEntry options[] = {
		{ "no-persist", 'P', G_OPTION_FLAG_REVERSE, G_OPTION_ARG_NONE, &global_opt.persist, "Exit after processing netlink messages", NULL },
		{ 0 },
	};
	gs_free_error GError *error = NULL;

	context = g_option_context_new (NULL);
	g_option_context_set_summary (context, "Monitor netlink events in NMPlatform.");
	g_option_context_add_main_entries (context, options, NULL);

	if (!g_option_context_parse (context, argc, argv, &error)) {
		g_warning ("Error parsing command line arguments: %s", error->message);
		g_option_context_free (context);
		return FALSE;
	}

	g_option_context_free (context);
	return TRUE;
}

int
main (int argc, char **argv)
{
	GMainLoop *loop;

	if (!g_getenv ("G_MESSAGES_DEBUG"))
		g_setenv ("G_MESSAGES_DEBUG", "all", TRUE);

	nmtst_init_with_logging (&argc, &argv, "DEBUG", "ALL");

	if (!read_argv (&argc, &argv))
		return 2;

	nm_log_info (LOGD_PLATFORM, "platform monitor start");

	loop = g_main_loop_new (NULL, FALSE);

	nm_linux_platform_setup ();

	if (global_opt.persist)
		g_main_loop_run (loop);

	g_main_loop_unref (loop);

	return EXIT_SUCCESS;
}
