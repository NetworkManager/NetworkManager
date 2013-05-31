#include <string.h>
#include <syslog.h>
#include <net/if.h>

#include "nm-rdisc.h"
#include "nm-fake-rdisc.h"
#include "nm-lndp-rdisc.h"
#include "nm-logging.h"

int
main (int argc, char **argv)
{
	GMainLoop *loop;
	NMRDisc *rdisc;
	NMRDisc *(*new) (int ifindex, const char *ifname) = nm_lndp_rdisc_new;
	int ifindex = 1;
	char ifname[IF_NAMESIZE];
	char mac[6] = { 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee };

	if_indextoname (ifindex, ifname);

	g_type_init ();
	loop = g_main_loop_new (NULL, FALSE);
	nm_logging_setup ("debug", NULL, NULL);
	openlog (G_LOG_DOMAIN, LOG_CONS | LOG_PERROR, LOG_DAEMON);

	argv++;
	for (; *argv; argv++) {
		if (!g_strcmp0 (*argv, "--fake"))
			new = nm_fake_rdisc_new;
		else {
			strncpy (ifname, *argv, IF_NAMESIZE);
			ifindex = if_nametoindex (ifname);
		}
	}

	rdisc = new (ifindex, ifname);
	nm_rdisc_set_lladdr (rdisc, mac, 6);

	nm_rdisc_start (rdisc);
	g_main_loop_run (loop);

	g_clear_object (&rdisc);

	return EXIT_SUCCESS;
}
