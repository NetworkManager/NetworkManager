/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2014 Red Hat, Inc.
 */

#ifndef __NM_TEST_UTILS_H__
#define __NM_TEST_UTILS_H__


#include <arpa/inet.h>
#include <glib.h>
#include <glib-object.h>


struct __nmtst_internal
{
	GRand *rand0;
	guint32 rand_seed;
	GRand *rand;
};

extern struct __nmtst_internal __nmtst_internal;

#define NMTST_DEFINE() \
	struct __nmtst_internal __nmtst_internal = { 0 };

inline static void
nmtst_init (int *argc, char ***argv, const char *log_level, const char *log_domains)
{
	g_assert (!__nmtst_internal.rand0);

	g_assert (!((!!argc) ^ (!!argv)));
	if (argc) {
		/* g_test_init() is a variadic function, so we cannot pass it
		 * (variadic) arguments. If you need to pass additional parameters,
		 * call nmtst_init() with argc==NULL and call g_test_init() yourself. */
		g_test_init (argc, argv, NULL);
	}

#if !GLIB_CHECK_VERSION (2, 35, 0)
	g_type_init ();
#endif

	__nmtst_internal.rand0 = g_rand_new_with_seed (0);

	if (log_level || log_domains) {
		gboolean success = FALSE;
#ifdef NM_LOGGING_H
		success = nm_logging_setup (log_level, log_domains, NULL, NULL);
#endif
		g_assert (success);
	}
}

inline static GRand *
nmtst_get_rand0 ()
{
	g_assert (__nmtst_internal.rand0);
	return __nmtst_internal.rand0;
}

inline static GRand *
nmtst_get_rand ()
{
	if (G_UNLIKELY (!__nmtst_internal.rand)) {
		guint32 seed;
		const char *str;

		if ((str = g_getenv ("NMTST_SEED_RAND"))) {
			gchar *s;
			gint64 i;

			i = g_ascii_strtoll (str, &s, 0);
			g_assert (s[0] == '\0' && i >= 0 && i < G_MAXINT32);

			seed = i;
			__nmtst_internal.rand = g_rand_new_with_seed (seed);
		} else {
			__nmtst_internal.rand = g_rand_new ();

			seed = g_rand_int (__nmtst_internal.rand);
			g_rand_set_seed (__nmtst_internal.rand, seed);
		}
		__nmtst_internal.rand_seed = seed;

		g_message (">> initialize nmtst_get_rand() with seed=%u", seed);
	}
	return __nmtst_internal.rand;
}

#define NMTST_SWAP(x,y) \
	G_STMT_START { \
		char __nmtst_swap_temp[sizeof(x) == sizeof(y) ? (signed) sizeof(x) : -1]; \
		memcpy(__nmtst_swap_temp, &y, sizeof(x)); \
		memcpy(&y,                &x, sizeof(x)); \
		memcpy(&x, __nmtst_swap_temp, sizeof(x)); \
	} G_STMT_END

inline static guint32
nmtst_inet4_from_string (const char *str)
{
	guint32 addr;
	int success;

	if (!str)
		return 0;

	success = inet_pton (AF_INET, str, &addr);

	g_assert (success == 1);

	return addr;
}

inline static const struct in6_addr *
nmtst_inet6_from_string (const char *str)
{
	static struct in6_addr addr;
	int success;

	if (!str)
		addr = in6addr_any;
	else {
		success = inet_pton (AF_INET6, str, &addr);
		g_assert (success == 1);
	}

	return &addr;
}

#ifdef NM_PLATFORM_H

inline static NMPlatformIP6Address *
nmtst_platform_ip6_address (const char *address, const char *peer_address, guint plen)
{
	static NMPlatformIP6Address addr;

	memset (&addr, 0, sizeof (addr));
	addr.address = *nmtst_inet6_from_string (address);
	addr.peer_address = *nmtst_inet6_from_string (peer_address);
	addr.plen = plen;

	return &addr;
}

inline static NMPlatformIP6Address *
nmtst_platform_ip6_address_full (const char *address, const char *peer_address, guint plen,
                                 int ifindex, NMPlatformSource source, guint32 timestamp,
                                 guint32 lifetime, guint32 preferred, guint flags)
{
	NMPlatformIP6Address *addr = nmtst_platform_ip6_address (address, peer_address, plen);

	addr->ifindex = ifindex;
	addr->source = source;
	addr->timestamp = timestamp;
	addr->lifetime = lifetime;
	addr->preferred = preferred;
	addr->flags = flags;

	return addr;
}

inline static NMPlatformIP6Route *
nmtst_platform_ip6_route (const char *network, guint plen, const char *gateway)
{
	static NMPlatformIP6Route route;

	memset (&route, 0, sizeof (route));
	route.network = *nmtst_inet6_from_string (network);
	route.plen = plen;
	route.gateway = *nmtst_inet6_from_string (gateway);

	return &route;
}

inline static NMPlatformIP6Route *
nmtst_platform_ip6_route_full (const char *network, guint plen, const char *gateway,
                               int ifindex, NMPlatformSource source,
                               guint metric, guint mss)
{
	NMPlatformIP6Route *route = nmtst_platform_ip6_route (network, plen, gateway);

	route->ifindex = ifindex;
	route->source = source;
	route->metric = metric;
	route->mss = mss;

	return route;
}

#endif


#ifdef NM_IP4_CONFIG_H

inline static NMIP4Config *
nmtst_ip4_config_clone (NMIP4Config *config)
{
	NMIP4Config *copy = nm_ip4_config_new ();

	g_assert (copy);
	g_assert (config);
	nm_ip4_config_replace (copy, config, NULL);
	return copy;
}

#endif


#ifdef NM_IP6_CONFIG_H

inline static NMIP6Config *
nmtst_ip6_config_clone (NMIP6Config *config)
{
	NMIP6Config *copy = nm_ip6_config_new ();

	g_assert (copy);
	g_assert (config);
	nm_ip6_config_replace (copy, config, NULL);
	return copy;
}

#endif


#endif /* __NM_TEST_UTILS_H__ */

