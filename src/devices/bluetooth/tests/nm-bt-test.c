// SPDX-License-Identifier: LGPL-2.1+

#include "nm-default.h"

#include "devices/bluetooth/nm-bluez5-dun.h"

#include "nm-test-utils-core.h"

/*****************************************************************************/

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	NMBluez5DunContext *dun_context;
	GMainLoop *loop;

	if (!g_getenv ("G_MESSAGES_DEBUG"))
		g_setenv ("G_MESSAGES_DEBUG", "all", TRUE);

	nmtst_init_with_logging (&argc, &argv, "DEBUG", "ALL");

	nm_log_info (LOGD_BT, "bluetooth test util start");

	dun_context = nm_bluez5_dun_new ("aa:bb:cc:dd:ee:ff",
	                                 "aa:bb:cc:dd:ee:fa");

	loop = g_main_loop_new (NULL, FALSE);

	g_main_loop_unref (loop);

	nm_bluez5_dun_free (dun_context);

	return EXIT_SUCCESS;
}
