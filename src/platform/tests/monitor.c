#include <stdlib.h>
#include <syslog.h>

#include "nm-fake-platform.h"
#include "nm-linux-platform.h"
#include "nm-logging.h"

int
main (int argc, char **argv)
{
	GMainLoop *loop;

#if !GLIB_CHECK_VERSION (2, 35, 0)
	g_type_init ();
#endif

	loop = g_main_loop_new (NULL, FALSE);
	nm_logging_setup ("debug", NULL, NULL, NULL);
	openlog (G_LOG_DOMAIN, LOG_CONS | LOG_PERROR, LOG_DAEMON);

	g_assert (argc <= 2);
	if (argc > 1 && !g_strcmp0 (argv[1], "--fake"))
		nm_fake_platform_setup ();
	else
		nm_linux_platform_setup ();

	g_main_loop_run (loop);

	return EXIT_SUCCESS;
}
