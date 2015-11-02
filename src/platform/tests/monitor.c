#include "config.h"

#include <stdlib.h>
#include <syslog.h>

#include "nm-default.h"
#include "nm-linux-platform.h"

#include "nm-test-utils.h"

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	GMainLoop *loop;

	if (!g_getenv ("G_MESSAGES_DEBUG"))
		g_setenv ("G_MESSAGES_DEBUG", "all", TRUE);

	nmtst_init_with_logging (&argc, &argv, "DEBUG", "ALL");

	nm_log_info (LOGD_PLATFORM, "platform monitor start");

	loop = g_main_loop_new (NULL, FALSE);

	nm_linux_platform_setup ();

	g_main_loop_run (loop);

	return EXIT_SUCCESS;
}
