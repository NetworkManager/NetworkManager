/* NetworkManager -- Network link manager
 *
 * Dan Williams <dcbw@redhat.com>
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2004 Red Hat, Inc.
 */

#include <glib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/sockios.h>
#include <syslog.h>
#include <stdarg.h>
#include <sys/time.h>
#include <string.h>
#include <signal.h>

#include "NetworkManager.h"
#include "NetworkManagerUtils.h"
#include "nm-utils.h"
#include "nm-device.h"
#include "nm-device-802-11-wireless.h"
#include "nm-device-802-3-ethernet.h"

#include <netlink/addr.h>
#include <netinet/in.h>

/*
 * nm_null_safe_strcmp
 *
 * Doesn't freaking segfault if s1/s2 are NULL
 *
 */
int nm_null_safe_strcmp (const char *s1, const char *s2)
{
	if (!s1 && !s2)
		return 0;
	if (!s1 && s2)
		return -1;
	if (s1 && !s2)
		return 1;
		
	return (strcmp (s1, s2));
}


/*
 * nm_ethernet_address_is_valid
 *
 * Compares an Ethernet address against known invalid addresses.
 *
 */
gboolean
nm_ethernet_address_is_valid (const struct ether_addr *test_addr)
{
	guint8 invalid_addr1[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	guint8 invalid_addr2[ETH_ALEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	guint8 invalid_addr3[ETH_ALEN] = {0x44, 0x44, 0x44, 0x44, 0x44, 0x44};
	guint8 invalid_addr4[ETH_ALEN] = {0x00, 0x30, 0xb4, 0x00, 0x00, 0x00}; /* prism54 dummy MAC */

	g_return_val_if_fail (test_addr != NULL, FALSE);

	/* Compare the AP address the card has with invalid ethernet MAC addresses. */
	if (!memcmp (test_addr->ether_addr_octet, &invalid_addr1, ETH_ALEN))
		return FALSE;

	if (!memcmp (test_addr->ether_addr_octet, &invalid_addr2, ETH_ALEN))
		return FALSE;

	if (!memcmp (test_addr->ether_addr_octet, &invalid_addr3, ETH_ALEN))
		return FALSE;

	if (!memcmp (test_addr->ether_addr_octet, &invalid_addr4, ETH_ALEN))
		return FALSE;

	if (test_addr->ether_addr_octet[0] & 1)			/* Multicast addresses */
		return FALSE;
	
	return TRUE;
}


/*
 * nm_ethernet_addresses_are_equal
 *
 * Compare two Ethernet addresses and return TRUE if equal and FALSE if not.
 */
gboolean
nm_ethernet_addresses_are_equal (const struct ether_addr *a, const struct ether_addr *b)
{
	g_return_val_if_fail (a != NULL, FALSE);
	g_return_val_if_fail (b != NULL, FALSE);

	if (memcmp (a, b, sizeof (struct ether_addr)))
		return FALSE;
	return TRUE;
}


/*
 * nm_spawn_process
 *
 * Wrap g_spawn_sync in a usable manner
 *
 */
int nm_spawn_process (const char *args)
{
	gint		  num_args;
	char		**argv = NULL;
	int		  exit_status = -1;
	GError	 *error = NULL;
	char		 *so = NULL;
	char		 *se = NULL;

	g_return_val_if_fail (args != NULL, -1);

	if (g_shell_parse_argv (args, &num_args, &argv, &error))
	{
		GError *error2 = NULL;

		if (!g_spawn_sync ("/", argv, NULL, 0, NULL, NULL, &so, &se, &exit_status, &error2))
			nm_warning ("nm_spawn_process('%s'): could not spawn process. (%s)\n", args, error2->message);

		if (so)    g_free(so);
		if (se)    g_free(se);
		if (argv)  g_strfreev (argv);
		if (error2) g_error_free (error2);
	} else nm_warning ("nm_spawn_process('%s'): could not parse arguments (%s)\n", args, error->message);

	if (error) g_error_free (error);

	return (exit_status);
}


/*
 * nm_print_device_capabilities
 *
 * Return the capabilities for a particular device.
 *
 */
void nm_print_device_capabilities (NMDevice *dev)
{
	gboolean		full_support = TRUE;
	guint32		caps;
	const char *	driver = NULL;

	g_return_if_fail (dev != NULL);

	caps = nm_device_get_capabilities (dev);
	driver = nm_device_get_driver (dev);
	if (!driver)
		driver = "<unknown>";

	if (caps == NM_DEVICE_CAP_NONE || !(NM_DEVICE_CAP_NM_SUPPORTED))
	{
		nm_info ("%s: Driver support level for '%s' is unsupported",
				nm_device_get_iface (dev), driver);
		return;
	}

	if (NM_IS_DEVICE_802_3_ETHERNET (dev))
	{
		if (!(caps & NM_DEVICE_CAP_CARRIER_DETECT))
		{
			nm_info ("%s: Driver '%s' does not support carrier detection.\n"
					"\tYou must switch to it manually.",
					nm_device_get_iface (dev), driver);
			full_support = FALSE;
		}
	}
	else if (NM_IS_DEVICE_802_11_WIRELESS (dev))
	{
		/* Print out WPA support */
	}

	if (full_support)
	{
		nm_info ("%s: Device is fully-supported using driver '%s'.",
				nm_device_get_iface (dev), driver);
	}
}

static inline int nm_timeval_cmp(const struct timeval *a,
				 const struct timeval *b)
{
	int x;
	x = a->tv_sec - b->tv_sec;
	x *= G_USEC_PER_SEC;
	if (x)
		return x;
	x = a->tv_usec - b->tv_usec;
	if (x)
		return x;
	return 0;
}

static inline int nm_timeval_has_passed(const struct timeval *a)
{
	struct timeval current;

	gettimeofday(&current, NULL);

	return (nm_timeval_cmp(&current, a) >= 0);
}

static inline void nm_timeval_add(struct timeval *a,
				  const struct timeval *b)
{
	struct timeval b1;

	memmove(&b1, b, sizeof b1);

	/* normalize a and b to be positive for everything */
	while (a->tv_usec < 0)
	{
		a->tv_sec--;
		a->tv_usec += G_USEC_PER_SEC;
	}
	while (b1.tv_usec < 0)
	{
		b1.tv_sec--;
		b1.tv_usec += G_USEC_PER_SEC;
	}

	/* now add secs and usecs */
	a->tv_sec += b1.tv_sec;
	a->tv_usec += b1.tv_usec;

	/* and handle our overflow */
	if (a->tv_usec > G_USEC_PER_SEC)
	{
		a->tv_sec++;
		a->tv_usec -= G_USEC_PER_SEC;
	}
}


gchar *nm_utils_inet_ip4_address_as_string (guint32 ip)
{
	struct in_addr tmp_addr;
	gchar *ip_string;

	tmp_addr.s_addr = ip;
	ip_string = inet_ntoa (tmp_addr);

	return g_strdup (ip_string);
}


struct nl_addr * nm_utils_ip4_addr_to_nl_addr (guint32 ip4_addr)
{
	struct nl_addr * nla = NULL;

	if (!(nla = nl_addr_alloc (sizeof (in_addr_t))))
		return NULL;
	nl_addr_set_family (nla, AF_INET);
	nl_addr_set_binary_addr (nla, &ip4_addr, sizeof (guint32));

	return nla;
}

/*
 * nm_utils_ip4_netmask_to_prefix
 *
 * Figure out the network prefix from a netmask.  Netmask
 * MUST be in network byte order.
 *
 */
int nm_utils_ip4_netmask_to_prefix (guint32 ip4_netmask)
{
	int i = 1;

	g_return_val_if_fail (ip4_netmask != 0, 0);

	/* Just count how many bit shifts we need */
	ip4_netmask = ntohl (ip4_netmask);
	while (!(ip4_netmask & 0x1) && ++i)
		ip4_netmask = ip4_netmask >> 1;
	return (32 - (i-1));
}

/* From hostap, Copyright (c) 2002-2005, Jouni Malinen <jkmaline@cc.hut.fi> */

static int hex2num (char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static int hex2byte (const char *hex)
{
	int a, b;
	a = hex2num(*hex++);
	if (a < 0)
		return -1;
	b = hex2num(*hex++);
	if (b < 0)
		return -1;
	return (a << 4) | b;
}

char *
nm_utils_hexstr2bin (const char *hex,
                     size_t len)
{
	size_t       i;
	int          a;
	const char * ipos = hex;
	char *       buf = NULL;
	char *       opos;

	/* Length must be a multiple of 2 */
	if ((len % 2) != 0)
		return NULL;

	opos = buf = g_malloc0 ((len / 2) + 1);
	for (i = 0; i < len; i += 2) {
		a = hex2byte (ipos);
		if (a < 0) {
			g_free (buf);
			return NULL;
		}
		*opos++ = a;
		ipos += 2;
	}
	return buf;
}

/* End from hostap */

char *
nm_ether_ntop (const struct ether_addr *mac)
{
	/* we like leading zeros */
	return g_strdup_printf ("%02X:%02X:%02X:%02X:%02X:%02X",
	                        mac->ether_addr_octet[0], mac->ether_addr_octet[1],
	                        mac->ether_addr_octet[2], mac->ether_addr_octet[3],
	                        mac->ether_addr_octet[4], mac->ether_addr_octet[5]);
}

