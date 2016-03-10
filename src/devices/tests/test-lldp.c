/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-platform.c - Handle runtime kernel networking configuration
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2015 Red Hat, Inc.
 */

#include "nm-default.h"

#include <fcntl.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "nm-lldp-listener.h"

#include "test-common.h"

#include "nm-test-utils.h"

/*****************************************************************************/

static GVariant *
get_lldp_neighbor_attribute (GVariant *neighbors,
                             const char *chassis, const char *port,
                             const char *name)
{
	GVariantIter iter, attrs_iter;
	GVariant *variant, *attr_variant;
	const char *attr_name;

	g_return_val_if_fail (g_variant_is_of_type (neighbors,
	                                            G_VARIANT_TYPE ("aa{sv}")),
	                      NULL);
	g_variant_iter_init (&iter, neighbors);

	while (g_variant_iter_next (&iter, "@a{sv}", &variant)) {
		gs_unref_variant GVariant *chassis_v = NULL;
		gs_unref_variant GVariant *port_v = NULL;
		gs_unref_variant GVariant *attr_v = NULL;

		g_variant_iter_init (&attrs_iter, variant);
		while (g_variant_iter_next (&attrs_iter, "{&sv}", &attr_name, &attr_variant)) {
			if (!g_strcmp0 (attr_name, NM_LLDP_ATTR_CHASSIS_ID)) {
				g_assert (!chassis_v);
				chassis_v = attr_variant;
			} else if (!g_strcmp0 (attr_name, NM_LLDP_ATTR_PORT_ID)) {
				g_assert (!port_v);
				port_v = attr_variant;
			} else if (!g_strcmp0 (attr_name, name)) {
				g_assert (!attr_v);
				attr_v = attr_variant;
			} else
				g_variant_unref (attr_variant);
		}

		g_variant_unref (variant);

		if (   chassis_v
		    && port_v
		    && g_variant_is_of_type (chassis_v, G_VARIANT_TYPE_STRING)
		    && g_variant_is_of_type (port_v, G_VARIANT_TYPE_STRING)
		    && !g_strcmp0 (chassis, g_variant_get_string (chassis_v, NULL))
		    && !g_strcmp0 (port, g_variant_get_string (port_v, NULL)))
			return g_variant_ref (attr_v);
	}

	/* neighbor not found */
	return NULL;
}

typedef struct {
	int ifindex;
	int fd;
	guint8 mac[ETH_ALEN];
} TestRecvFixture;

typedef struct {
	gsize frame_len;
	const uint8_t *frame;
} TestRecvFrame;
#define TEST_RECV_FRAME_DEFINE(name, ...) \
	static const guint8 _##name##_v[] = { __VA_ARGS__ }; \
	static const TestRecvFrame name = { \
		.frame_len = sizeof (_##name##_v), \
		.frame = _##name##_v, \
	}

typedef struct {
	guint expected_num_called;
	gsize frames_len;
	const TestRecvFrame *frames[10];
	void (*check) (NMLldpListener *listener);
} TestRecvData;
#define TEST_RECV_DATA_DEFINE(name, _expected_num_called, _check, ...) \
	static const TestRecvData name = { \
		.expected_num_called = _expected_num_called, \
		.check = _check, \
		.frames_len = NM_NARG (__VA_ARGS__), \
		.frames = { __VA_ARGS__ }, \
	}

#define TEST_IFNAME "nm-tap-test0"

TEST_RECV_FRAME_DEFINE (_test_recv_data0_frame0,
	/* Ethernet header */
	0x01, 0x80, 0xc2, 0x00, 0x00, 0x03,     /* Destination MAC */
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06,     /* Source MAC */
	0x88, 0xcc,                             /* Ethertype */
	/* LLDP mandatory TLVs */
	0x02, 0x07, 0x04, 0x00, 0x01, 0x02,     /* Chassis: MAC, 00:01:02:03:04:05 */
	0x03, 0x04, 0x05,
	0x04, 0x04, 0x05, 0x31, 0x2f, 0x33,     /* Port: interface name, "1/3" */
	0x06, 0x02, 0x00, 0x78,                 /* TTL: 120 seconds */
	/* LLDP optional TLVs */
	0x08, 0x04, 0x50, 0x6f, 0x72, 0x74,     /* Port Description: "Port" */
	0x0a, 0x03, 0x53, 0x59, 0x53,           /* System Name: "SYS" */
	0x0c, 0x04, 0x66, 0x6f, 0x6f, 0x00,     /* System Description: "foo" (NULL-terminated) */
	0x00, 0x00                              /* End Of LLDPDU */
);

static void
_test_recv_data0_check (NMLldpListener *listener)
{
	GVariant *neighbors, *attr;

	neighbors = nm_lldp_listener_get_neighbors (listener);
	nmtst_assert_variant_is_of_type (neighbors, G_VARIANT_TYPE ("aa{sv}"));
	g_assert_cmpint (g_variant_n_children (neighbors), ==, 1);

	/* Check port description */
	attr = get_lldp_neighbor_attribute (neighbors, "00:01:02:03:04:05", "1/3",
	                                    NM_LLDP_ATTR_PORT_DESCRIPTION);
	g_assert (attr != NULL);
	g_assert (g_variant_is_of_type (attr, G_VARIANT_TYPE_STRING));
	g_assert_cmpstr (g_variant_get_string (attr, NULL), ==, "Port");
	nm_clear_g_variant (&attr);

	/* Check system name */
	attr = get_lldp_neighbor_attribute (neighbors, "00:01:02:03:04:05", "1/3",
	                                    NM_LLDP_ATTR_SYSTEM_NAME);
	g_assert (attr != NULL);
	g_assert (g_variant_is_of_type (attr, G_VARIANT_TYPE_STRING));
	g_assert_cmpstr (g_variant_get_string (attr, NULL), ==, "SYS");
	nm_clear_g_variant (&attr);

	/* Check destination */
	attr = get_lldp_neighbor_attribute (neighbors, "00:01:02:03:04:05", "1/3",
	                                    NM_LLDP_ATTR_DESTINATION);
	g_assert (attr != NULL);
	g_assert (g_variant_is_of_type (attr, G_VARIANT_TYPE_STRING));
	g_assert_cmpstr (g_variant_get_string (attr, NULL), ==,
	                 NM_LLDP_DEST_NEAREST_NON_TPMR_BRIDGE);
	nm_clear_g_variant (&attr);
}

TEST_RECV_DATA_DEFINE (_test_recv_data0,       1, _test_recv_data0_check,  &_test_recv_data0_frame0);
TEST_RECV_DATA_DEFINE (_test_recv_data0_twice, 1, _test_recv_data0_check,  &_test_recv_data0_frame0, &_test_recv_data0_frame0);

static void
_test_recv_fixture_setup (TestRecvFixture *fixture, gconstpointer user_data)
{
	const NMPlatformLink *link;
	struct ifreq ifr = { };
	int fd, s;

	fd = open ("/dev/net/tun", O_RDWR);
	g_assert (fd >= 0);

	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	nm_utils_ifname_cpy (ifr.ifr_name, TEST_IFNAME);
	g_assert (ioctl (fd, TUNSETIFF, &ifr) >= 0);

	/* Bring the interface up */
	s = socket (AF_INET, SOCK_DGRAM, 0);
	g_assert (s >= 0);
	ifr.ifr_flags |= IFF_UP;
	g_assert (ioctl (s, SIOCSIFFLAGS, &ifr) >= 0);
	close (s);

	link = nmtstp_assert_wait_for_link (TEST_IFNAME, NM_LINK_TYPE_TAP, 100);
	fixture->ifindex = link->ifindex;
	fixture->fd = fd;
	memcpy (fixture->mac, link->addr.data, ETH_ALEN);
}

typedef struct {
	int num_called;
} TestRecvCallbackInfo;

static gboolean
loop_quit (gpointer user_data)
{
	g_main_loop_quit ((GMainLoop *) user_data);
	return G_SOURCE_REMOVE;
}

static void
lldp_neighbors_changed (NMLldpListener *lldp_listener, GParamSpec *pspec,
                        gpointer user_data)
{
	TestRecvCallbackInfo *info = user_data;

	info->num_called++;
}

static void
test_recv (TestRecvFixture *fixture, gconstpointer user_data)
{
	const TestRecvData *data = user_data;
	gs_unref_object NMLldpListener *listener = NULL;
	GMainLoop *loop;
	TestRecvCallbackInfo info = { };
	gsize i_frames;

	listener = nm_lldp_listener_new ();
	g_assert (listener != NULL);
	g_assert (nm_lldp_listener_start (listener, fixture->ifindex, TEST_IFNAME, fixture->mac, ETH_ALEN, NULL));

	g_signal_connect (listener, "notify::" NM_LLDP_LISTENER_NEIGHBORS,
	                  (GCallback) lldp_neighbors_changed, &info);
	loop = g_main_loop_new (NULL, FALSE);
	g_timeout_add (500, loop_quit, loop);

	for (i_frames = 0; i_frames < data->frames_len; i_frames++) {
		const TestRecvFrame *f = data->frames[i_frames];

		g_assert (write (fixture->fd, f->frame, f->frame_len) == f->frame_len);
	}

	g_main_loop_run (loop);

	g_assert_cmpint (info.num_called, ==, data->expected_num_called);

	data->check (listener);

	g_clear_pointer (&loop, g_main_loop_unref);
}

static void
_test_recv_fixture_teardown (TestRecvFixture *fixture, gconstpointer user_data)
{
	nm_platform_link_delete (NM_PLATFORM_GET, fixture->ifindex);
}

/*****************************************************************************/

void
init_tests (int *argc, char ***argv)
{
	nmtst_init_assert_logging (argc, argv, "WARN", "ALL");
}

void
setup_tests (void)
{
#define _TEST_ADD_RECV(testpath, testdata) \
	g_test_add (testpath, TestRecvFixture, testdata, _test_recv_fixture_setup, test_recv, _test_recv_fixture_teardown)
	_TEST_ADD_RECV ("/lldp/recv/0",       &_test_recv_data0);
	_TEST_ADD_RECV ("/lldp/recv/0_twice", &_test_recv_data0_twice);
}
