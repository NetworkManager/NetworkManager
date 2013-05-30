#include <syslog.h>

#include "nm-rdisc.h"
#include "nm-fake-rdisc.h"
#include "nm-logging.h"

int
main (int argc, char **argv)
{
	GMainLoop *loop;
	NMRDisc *rdisc;

	g_type_init ();
	loop = g_main_loop_new (NULL, FALSE);
	nm_logging_setup ("debug", NULL, NULL);
	openlog (G_LOG_DOMAIN, LOG_CONS | LOG_PERROR, LOG_DAEMON);

	rdisc = nm_fake_rdisc_new (1);

	nm_rdisc_start (rdisc);
	g_main_loop_run (loop);

	g_clear_object (&rdisc);

	return EXIT_SUCCESS;
}
