#include <stdio.h>
#include <stdlib.h>

#include "nm-platform.h"
#include "nm-linux-platform.h"
#include "nm-fake-platform.h"

static const char *
type_to_string (NMLinkType type)
{
	switch (type) {
	case NM_LINK_TYPE_LOOPBACK:
		return "loopback";
	case NM_LINK_TYPE_ETHERNET:
		return "ethernet";
	case NM_LINK_TYPE_DUMMY:
		return "dummy";
	default:
		return "unknown-type";
	}
}

static void
dump_interface (NMPlatformLink *link)
{
	printf ("%d: %s: %s", link->ifindex, link->name, type_to_string (link->type));
	printf ("\n");
}

static void
dump_all (void)
{
	GArray *links = nm_platform_link_get_all ();
	int i;

	for (i = 0; i < links->len; i++)
		dump_interface (&g_array_index (links, NMPlatformLink, i));
}

int
main (int argc, char **argv)
{
	g_type_init ();

	g_assert (argc <= 2);
	if (argc > 1 && !g_strcmp0 (argv[1], "--fake"))
		nm_fake_platform_setup ();
	else
		nm_linux_platform_setup ();

	dump_all ();

	return EXIT_SUCCESS;
}
