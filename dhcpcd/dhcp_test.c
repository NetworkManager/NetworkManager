#include "dhcpcd.h"
#include "client.h"
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main (int argc, char **argv)
{
	dhcp_client_options	opts;
	dhcp_interface	*iface;

	if (argc < 2 || argv[1] == NULL)
	{
		fprintf (stderr, "Need an interface\n");
		exit (1);
	}

	memset (&opts, 0, sizeof (dhcp_client_options));
	opts.base_timeout = 5;

	openlog ("dhcp_test", LOG_CONS | LOG_PERROR, LOG_USER);

	if (!(iface = dhcp_interface_init (argv[1], &opts)))
		exit (1);

	dhcp_init (iface);

	dhcp_interface_free (iface);

	exit (0);
}
