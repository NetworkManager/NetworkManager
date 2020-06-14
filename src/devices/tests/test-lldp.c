// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2015 Red Hat, Inc.
 */

#include "nm-default.h"

#include <fcntl.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "devices/nm-lldp-listener.h"
#include "systemd/nm-sd.h"

#include "platform/tests/test-common.h"

#include "nm-test-utils-core.h"

/*****************************************************************************/

static GVariant *
get_lldp_neighbor (GVariant *neighbors,
                   int chassis_id_type,
                   const char *chassis_id,
                   int port_id_type,
                   const char *port_id)
{
	GVariantIter iter;
	GVariant *variant;
	GVariant *result = NULL;

	nmtst_assert_variant_is_of_type (neighbors, G_VARIANT_TYPE ("aa{sv}"));

	g_assert (chassis_id_type >= -1 && chassis_id_type <= G_MAXUINT8);
	g_assert (port_id_type >= -1 && port_id_type <= G_MAXUINT8);

	g_variant_iter_init (&iter, neighbors);
	while (g_variant_iter_next (&iter, "@a{sv}", &variant)) {
		gs_unref_variant GVariant *v_chassis_id_type = NULL;
		gs_unref_variant GVariant *v_chassis_id = NULL;
		gs_unref_variant GVariant *v_port_id_type = NULL;
		gs_unref_variant GVariant *v_port_id = NULL;

		v_chassis_id_type = g_variant_lookup_value (variant, NM_LLDP_ATTR_CHASSIS_ID_TYPE, G_VARIANT_TYPE_UINT32);
		g_assert (v_chassis_id_type);

		v_chassis_id = g_variant_lookup_value (variant, NM_LLDP_ATTR_CHASSIS_ID, G_VARIANT_TYPE_STRING);
		g_assert (v_chassis_id);

		v_port_id_type = g_variant_lookup_value (variant, NM_LLDP_ATTR_PORT_ID_TYPE, G_VARIANT_TYPE_UINT32);
		g_assert (v_port_id_type);

		v_port_id = g_variant_lookup_value (variant, NM_LLDP_ATTR_PORT_ID, G_VARIANT_TYPE_STRING);
		g_assert (v_port_id);

		if (   nm_streq (g_variant_get_string (v_chassis_id, NULL), chassis_id)
		    && nm_streq (g_variant_get_string (v_port_id, NULL), port_id)
		    && NM_IN_SET (chassis_id_type, -1, g_variant_get_uint32 (v_chassis_id_type))
		    && NM_IN_SET (port_id_type, -1, g_variant_get_uint32 (v_port_id_type))) {
			g_assert (!result);
			result = variant;
		} else
			g_variant_unref (variant);
	}

	return result;
}

typedef struct {
	int ifindex;
	int fd;
	guint8 mac[ETH_ALEN];
} TestRecvFixture;

typedef struct {
	gsize frame_len;
	const uint8_t *frame;
	const char *as_variant;
} TestRecvFrame;
#define TEST_RECV_FRAME_DEFINE(name, _as_variant, ...) \
	static const guint8 _##name##_v[] = { __VA_ARGS__ }; \
	static const TestRecvFrame name = { \
		.as_variant = _as_variant, \
		.frame_len = sizeof (_##name##_v), \
		.frame = _##name##_v, \
	}

typedef struct {
	guint expected_num_called;
	gsize frames_len;
	const TestRecvFrame *frames[10];
	void (*check) (GMainLoop *loop, NMLldpListener *listener);
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
	"{'raw': <[byte 0x01, 0x80, 0xc2, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x88, 0xcc, 0x02, 0x07, 0x04, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x04, 0x04, 0x05, 0x31, 0x2f, 0x33, 0x06, 0x02, 0x00, 0x78, 0x08, 0x04, 0x50, 0x6f, 0x72, 0x74, 0x0a, 0x03, 0x53, 0x59, 0x53, 0x0c, 0x04, 0x66, 0x6f, 0x6f, 0x00, 0x00, 0x00]>, 'chassis-id-type': <uint32 4>, 'chassis-id': <'00:01:02:03:04:05'>, 'port-id-type': <uint32 5>, 'port-id': <'1/3'>, 'destination': <'nearest-non-tpmr-bridge'>, 'port-description': <'Port'>, 'system-name': <'SYS'>, 'system-description': <'foo'>}",
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
_test_recv_data0_check_do (GMainLoop *loop, NMLldpListener *listener, const TestRecvFrame *frame)
{
	GVariant *neighbors, *attr;
	gs_unref_variant GVariant *neighbor = NULL;

	neighbors = nm_lldp_listener_get_neighbors (listener);
	nmtst_assert_variant_is_of_type (neighbors, G_VARIANT_TYPE ("aa{sv}"));
	g_assert_cmpint (g_variant_n_children (neighbors), ==, 1);

	neighbor = get_lldp_neighbor (neighbors,
	                              SD_LLDP_CHASSIS_SUBTYPE_MAC_ADDRESS, "00:01:02:03:04:05",
	                              SD_LLDP_PORT_SUBTYPE_INTERFACE_NAME, "1/3");
	g_assert (neighbor);
	g_assert_cmpint (g_variant_n_children (neighbor), ==, 1 + 4 + 4);

	attr = g_variant_lookup_value (neighbor, NM_LLDP_ATTR_RAW, G_VARIANT_TYPE_BYTESTRING);
	nmtst_assert_variant_bytestring (attr, frame->frame, frame->frame_len);
	nm_clear_g_variant (&attr);

	attr = g_variant_lookup_value (neighbor, NM_LLDP_ATTR_PORT_DESCRIPTION, G_VARIANT_TYPE_STRING);
	nmtst_assert_variant_string (attr, "Port");
	nm_clear_g_variant (&attr);

	attr = g_variant_lookup_value (neighbor, NM_LLDP_ATTR_SYSTEM_NAME, G_VARIANT_TYPE_STRING);
	nmtst_assert_variant_string (attr, "SYS");
	nm_clear_g_variant (&attr);

	attr = g_variant_lookup_value (neighbor, NM_LLDP_ATTR_DESTINATION, G_VARIANT_TYPE_STRING);
	nmtst_assert_variant_string (attr, NM_LLDP_DEST_NEAREST_NON_TPMR_BRIDGE);
	nm_clear_g_variant (&attr);

	attr = g_variant_lookup_value (neighbor, NM_LLDP_ATTR_SYSTEM_DESCRIPTION, G_VARIANT_TYPE_STRING);
	nmtst_assert_variant_string (attr, "foo");
	nm_clear_g_variant (&attr);
}

static void
_test_recv_data0_check (GMainLoop *loop, NMLldpListener *listener)
{
	_test_recv_data0_check_do (loop, listener, &_test_recv_data0_frame0);
}

TEST_RECV_DATA_DEFINE (_test_recv_data0,       1, _test_recv_data0_check,  &_test_recv_data0_frame0);
TEST_RECV_DATA_DEFINE (_test_recv_data0_twice, 1, _test_recv_data0_check,  &_test_recv_data0_frame0, &_test_recv_data0_frame0);

TEST_RECV_FRAME_DEFINE (_test_recv_data1_frame0,
	/* lldp.detailed.pcap from
	 * https://wiki.wireshark.org/SampleCaptures#Link_Layer_Discovery_Protocol_.28LLDP.29 */
	"{'raw': <[byte 0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e, 0x00, 0x01, 0x30, 0xf9, 0xad, 0xa0, 0x88, 0xcc, 0x02, 0x07, 0x04, 0x00, 0x01, 0x30, 0xf9, 0xad, 0xa0, 0x04, 0x04, 0x05, 0x31, 0x2f, 0x31, 0x06, 0x02, 0x00, 0x78, 0x08, 0x17, 0x53, 0x75, 0x6d, 0x6d, 0x69, 0x74, 0x33, 0x30, 0x30, 0x2d, 0x34, 0x38, 0x2d, 0x50, 0x6f, 0x72, 0x74, 0x20, 0x31, 0x30, 0x30, 0x31, 0x00, 0x0a, 0x0d, 0x53, 0x75, 0x6d, 0x6d, 0x69, 0x74, 0x33, 0x30, 0x30, 0x2d, 0x34, 0x38, 0x00, 0x0c, 0x4c, 0x53, 0x75, 0x6d, 0x6d, 0x69, 0x74, 0x33, 0x30, 0x30, 0x2d, 0x34, 0x38, 0x20, 0x2d, 0x20, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x20, 0x37, 0x2e, 0x34, 0x65, 0x2e, 0x31, 0x20, 0x28, 0x42, 0x75, 0x69, 0x6c, 0x64, 0x20, 0x35, 0x29, 0x20, 0x62, 0x79, 0x20, 0x52, 0x65, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x5f, 0x4d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x30, 0x35, 0x2f, 0x32, 0x37, 0x2f, 0x30, 0x35, 0x20, 0x30, 0x34, 0x3a, 0x35, 0x33, 0x3a, 0x31, 0x31, 0x00, 0x0e, 0x04, 0x00, 0x14, 0x00, 0x14, 0x10, 0x0e, 0x07, 0x06, 0x00, 0x01, 0x30, 0xf9, 0xad, 0xa0, 0x02, 0x00, 0x00, 0x03, 0xe9, 0x00, 0xfe, 0x07, 0x00, 0x12, 0x0f, 0x02, 0x07, 0x01, 0x00, 0xfe, 0x09, 0x00, 0x12, 0x0f, 0x01, 0x03, 0x6c, 0x00, 0x00, 0x10, 0xfe, 0x09, 0x00, 0x12, 0x0f, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x06, 0x00, 0x12, 0x0f, 0x04, 0x05, 0xf2, 0xfe, 0x06, 0x00, 0x80, 0xc2, 0x01, 0x01, 0xe8, 0xfe, 0x07, 0x00, 0x80, 0xc2, 0x02, 0x01, 0x00, 0x00, 0xfe, 0x16, 0x00, 0x80, 0xc2, 0x03, 0x01, 0xe8, 0x0f, 0x76, 0x32, 0x2d, 0x30, 0x34, 0x38, 0x38, 0x2d, 0x30, 0x33, 0x2d, 0x30, 0x35, 0x30, 0x35, 0xfe, 0x05, 0x00, 0x80, 0xc2, 0x04, 0x00, 0x00, 0x00]>, 'chassis-id-type': <uint32 4>, 'chassis-id': <'00:01:30:F9:AD:A0'>, 'port-id-type': <uint32 5>, 'port-id': <'1/1'>, 'destination': <'nearest-bridge'>, 'port-description': <'Summit300-48-Port 1001'>, 'system-name': <'Summit300-48'>, 'system-description': <'Summit300-48 - Version 7.4e.1 (Build 5) by Release_Master 05/27/05 04:53:11'>, 'system-capabilities': <uint32 20>, 'management-addresses': <[{'address-subtype': <uint32 6>, 'address': <[byte 0x00, 0x01, 0x30, 0xf9, 0xad, 0xa0]>, 'interface-number-subtype': <uint32 2>, 'interface-number': <uint32 1001>, 'object-id': <@ay []>}]>, 'ieee-802-1-pvid': <uint32 488>, 'ieee-802-1-ppvid': <uint32 0>, 'ieee-802-1-ppvid-flags': <uint32 1>, 'ieee-802-1-ppvids': <[{'ppvid': <uint32 0>, 'flags': <uint32 1>}]>, 'ieee-802-1-vid': <uint32 488>, 'ieee-802-1-vlan-name': <'v2-0488-03-0505'>, 'ieee-802-1-vlans': <[{'vid': <uint32 488>, 'name': <'v2-0488-03-0505'>}]>, 'ieee-802-3-mac-phy-conf': <{'autoneg': <uint32 3>, 'pmd-autoneg-cap': <uint32 27648>, 'operational-mau-type': <uint32 16>}>, 'ieee-802-3-power-via-mdi': <{'mdi-power-support': <uint32 7>, 'pse-power-pair': <uint32 1>, 'power-class': <uint32 0>}>, 'ieee-802-3-max-frame-size': <uint32 1522>}",
	/* ethernet header */
	0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e, /* destination mac */
	0x00, 0x01, 0x30, 0xf9, 0xad, 0xa0, /* source mac */
	0x88, 0xcc,                         /* ethernet type */

	0x02, 0x07, 0x04, 0x00, 0x01, 0x30, /* Chassis Subtype */
	0xf9, 0xad, 0xa0,
	0x04, 0x04, 0x05, 0x31, 0x2f, 0x31, /* Port Subtype */
	0x06, 0x02, 0x00, 0x78,             /* Time To Live */
	0x08, 0x17, 0x53, 0x75, 0x6d, 0x6d, /* Port Description */
	0x69, 0x74, 0x33, 0x30, 0x30, 0x2d,
	0x34, 0x38, 0x2d, 0x50, 0x6f, 0x72,
	0x74, 0x20, 0x31, 0x30, 0x30, 0x31,
	0x00,
	0x0a, 0x0d, 0x53, 0x75, 0x6d, 0x6d, /* System Name */
	0x69, 0x74, 0x33, 0x30, 0x30, 0x2d,
	0x34, 0x38, 0x00,
	0x0c, 0x4c, 0x53, 0x75, 0x6d, 0x6d, /* System Description */
	0x69, 0x74, 0x33, 0x30, 0x30, 0x2d,
	0x34, 0x38, 0x20, 0x2d, 0x20, 0x56,
	0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
	0x20, 0x37, 0x2e, 0x34, 0x65, 0x2e,
	0x31, 0x20, 0x28, 0x42, 0x75, 0x69,
	0x6c, 0x64, 0x20, 0x35, 0x29, 0x20,
	0x62, 0x79, 0x20, 0x52, 0x65, 0x6c,
	0x65, 0x61, 0x73, 0x65, 0x5f, 0x4d,
	0x61, 0x73, 0x74, 0x65, 0x72, 0x20,
	0x30, 0x35, 0x2f, 0x32, 0x37, 0x2f,
	0x30, 0x35, 0x20, 0x30, 0x34, 0x3a,
	0x35, 0x33, 0x3a, 0x31, 0x31, 0x00,
	0x0e, 0x04, 0x00, 0x14, 0x00, 0x14, /* Capabilities */
	0x10, 0x0e, 0x07, 0x06, 0x00, 0x01, /* Management Address */
	0x30, 0xf9, 0xad, 0xa0, 0x02, 0x00,
	0x00, 0x03, 0xe9, 0x00,
	0xfe, 0x07, 0x00, 0x12, 0x0f, 0x02, /* IEEE 802.3 - Power Via MDI */
	0x07, 0x01, 0x00,
	0xfe, 0x09, 0x00, 0x12, 0x0f, 0x01, /* IEEE 802.3 - MAC/PHY Configuration/Status */
	0x03, 0x6c, 0x00, 0x00, 0x10,
	0xfe, 0x09, 0x00, 0x12, 0x0f, 0x03, /* IEEE 802.3 - Link Aggregation */
	0x01, 0x00, 0x00, 0x00, 0x00,
	0xfe, 0x06, 0x00, 0x12, 0x0f, 0x04, /* IEEE 802.3 - Maximum Frame Size */
	0x05, 0xf2,
	0xfe, 0x06, 0x00, 0x80, 0xc2, 0x01, /* IEEE 802.1 - Port VLAN ID */
	0x01, 0xe8,
	0xfe, 0x07, 0x00, 0x80, 0xc2, 0x02, /* IEEE 802.1 - Port and Protocol VLAN ID */
	0x01, 0x00, 0x00,
	0xfe, 0x16, 0x00, 0x80, 0xc2, 0x03, /* IEEE 802.1 - VLAN Name */
	0x01, 0xe8, 0x0f, 0x76, 0x32, 0x2d,
	0x30, 0x34, 0x38, 0x38, 0x2d, 0x30,
	0x33, 0x2d, 0x30, 0x35, 0x30, 0x35,
	0xfe, 0x05, 0x00, 0x80, 0xc2, 0x04, /* IEEE 802.1 - Protocol Identity */
	0x00,
	0x00, 0x00                          /* End of LLDPDU */
);

static void
_test_recv_data1_check (GMainLoop *loop, NMLldpListener *listener)
{
	GVariant *neighbors, *attr, *child;
	gs_unref_variant GVariant *neighbor = NULL;
	guint v_uint = 0;
	const char *v_str = NULL;

	neighbors = nm_lldp_listener_get_neighbors (listener);
	nmtst_assert_variant_is_of_type (neighbors, G_VARIANT_TYPE ("aa{sv}"));
	g_assert_cmpint (g_variant_n_children (neighbors), ==, 1);

	neighbor = get_lldp_neighbor (neighbors,
	                              SD_LLDP_CHASSIS_SUBTYPE_MAC_ADDRESS, "00:01:30:F9:AD:A0",
	                              SD_LLDP_PORT_SUBTYPE_INTERFACE_NAME, "1/1");
	g_assert (neighbor);
	g_assert_cmpint (g_variant_n_children (neighbor), ==, 1 + 4 + 16);

	attr = g_variant_lookup_value (neighbor, NM_LLDP_ATTR_RAW, G_VARIANT_TYPE_BYTESTRING);
	nmtst_assert_variant_bytestring (attr, _test_recv_data1_frame0.frame, _test_recv_data1_frame0.frame_len);
	nm_clear_g_variant (&attr);

	attr = g_variant_lookup_value (neighbor, NM_LLDP_ATTR_DESTINATION, G_VARIANT_TYPE_STRING);
	nmtst_assert_variant_string (attr, NM_LLDP_DEST_NEAREST_BRIDGE);
	nm_clear_g_variant (&attr);

	/* unsupported: Time To Live */

	/* Port Description */
	attr = g_variant_lookup_value (neighbor, NM_LLDP_ATTR_PORT_DESCRIPTION, G_VARIANT_TYPE_STRING);
	nmtst_assert_variant_string (attr, "Summit300-48-Port 1001");
	nm_clear_g_variant (&attr);

	/* System Name */
	attr = g_variant_lookup_value (neighbor, NM_LLDP_ATTR_SYSTEM_NAME, G_VARIANT_TYPE_STRING);
	nmtst_assert_variant_string (attr, "Summit300-48");
	nm_clear_g_variant (&attr);

	/* System Description */
	attr = g_variant_lookup_value (neighbor, NM_LLDP_ATTR_SYSTEM_DESCRIPTION, G_VARIANT_TYPE_STRING);
	nmtst_assert_variant_string (attr, "Summit300-48 - Version 7.4e.1 (Build 5) by Release_Master 05/27/05 04:53:11");
	nm_clear_g_variant (&attr);

	/* Capabilities */
	attr = g_variant_lookup_value (neighbor, NM_LLDP_ATTR_SYSTEM_CAPABILITIES, G_VARIANT_TYPE_UINT32);
	nmtst_assert_variant_uint32 (attr, 20);
	nm_clear_g_variant (&attr);

	/* Management Address */
	attr = g_variant_lookup_value (neighbor, NM_LLDP_ATTR_MANAGEMENT_ADDRESSES, G_VARIANT_TYPE ("aa{sv}"));
	g_assert (attr);
	g_assert_cmpuint (g_variant_n_children (attr), ==, 1);
	child = g_variant_get_child_value (attr, 0);
	g_assert (child);
	g_assert (g_variant_lookup (child, "interface-number", "u", &v_uint));
	g_assert_cmpint (v_uint, ==, 1001);
	g_assert (g_variant_lookup (child, "interface-number-subtype", "u", &v_uint));
	g_assert_cmpint (v_uint, ==, 2);
	g_assert (g_variant_lookup (child, "address-subtype", "u", &v_uint));
	g_assert_cmpint (v_uint, ==, 6);
	nm_clear_g_variant (&child);
	nm_clear_g_variant (&attr);

	/* IEEE 802.3 - Power Via MDI */
	attr = g_variant_lookup_value (neighbor, NM_LLDP_ATTR_IEEE_802_3_POWER_VIA_MDI, G_VARIANT_TYPE_VARDICT);
	g_assert (attr);
	g_assert (g_variant_lookup (attr, "mdi-power-support", "u", &v_uint));
	g_assert_cmpint (v_uint, ==, 7);
	g_assert (g_variant_lookup (attr, "pse-power-pair", "u", &v_uint));
	g_assert_cmpint (v_uint, ==, 1);
	g_assert (g_variant_lookup (attr, "power-class", "u", &v_uint));
	g_assert_cmpint (v_uint, ==, 0);
	nm_clear_g_variant (&attr);

	/* IEEE 802.3 - MAC/PHY Configuration/Status */
	attr = g_variant_lookup_value (neighbor, NM_LLDP_ATTR_IEEE_802_3_MAC_PHY_CONF, G_VARIANT_TYPE_VARDICT);
	g_assert (attr);
	g_assert (g_variant_lookup (attr, "autoneg", "u", &v_uint));
	g_assert_cmpint (v_uint, ==, 3);
	g_assert (g_variant_lookup (attr, "pmd-autoneg-cap", "u", &v_uint));
	g_assert_cmpint (v_uint, ==, 0x6c00);
	g_assert (g_variant_lookup (attr, "operational-mau-type", "u", &v_uint));
	g_assert_cmpint (v_uint, ==, 16);
	nm_clear_g_variant (&attr);

	/* unsupported: IEEE 802.3 - Link Aggregation */

	/* Maximum Frame Size */
	attr = g_variant_lookup_value (neighbor, NM_LLDP_ATTR_IEEE_802_3_MAX_FRAME_SIZE, G_VARIANT_TYPE_UINT32);
	nmtst_assert_variant_uint32 (attr, 1522);
	nm_clear_g_variant (&attr);

	/* IEEE 802.1 - Port VLAN ID */
	attr = g_variant_lookup_value (neighbor, NM_LLDP_ATTR_IEEE_802_1_PVID, G_VARIANT_TYPE_UINT32);
	nmtst_assert_variant_uint32 (attr, 488);
	nm_clear_g_variant (&attr);

	/* IEEE 802.1 - Port and Protocol VLAN ID */
	attr = g_variant_lookup_value (neighbor, NM_LLDP_ATTR_IEEE_802_1_PPVID, G_VARIANT_TYPE_UINT32);
	nmtst_assert_variant_uint32 (attr, 0);
	nm_clear_g_variant (&attr);
	attr = g_variant_lookup_value (neighbor, NM_LLDP_ATTR_IEEE_802_1_PPVID_FLAGS, G_VARIANT_TYPE_UINT32);
	nmtst_assert_variant_uint32 (attr, 1);
	nm_clear_g_variant (&attr);

	/* new PPVID attributes */
	attr = g_variant_lookup_value (neighbor, NM_LLDP_ATTR_IEEE_802_1_PPVIDS, G_VARIANT_TYPE ("aa{sv}"));
	g_assert_cmpuint (g_variant_n_children (attr), ==, 1);
	child = g_variant_get_child_value (attr, 0);
	g_assert (child);
	g_assert (g_variant_lookup (child, "ppvid", "u", &v_uint));
	g_assert_cmpint (v_uint, ==, 0);
	g_assert (g_variant_lookup (child, "flags", "u", &v_uint));
	g_assert_cmpint (v_uint, ==, 1);
	nm_clear_g_variant (&child);
	nm_clear_g_variant (&attr);

	/* IEEE 802.1 - VLAN Name */
	attr = g_variant_lookup_value (neighbor, NM_LLDP_ATTR_IEEE_802_1_VLAN_NAME, G_VARIANT_TYPE_STRING);
	nmtst_assert_variant_string (attr, "v2-0488-03-0505");
	nm_clear_g_variant (&attr);
	attr = g_variant_lookup_value (neighbor, NM_LLDP_ATTR_IEEE_802_1_VID, G_VARIANT_TYPE_UINT32);
	nmtst_assert_variant_uint32 (attr, 488);
	nm_clear_g_variant (&attr);

	/* new VLAN attributes */
	attr = g_variant_lookup_value (neighbor, NM_LLDP_ATTR_IEEE_802_1_VLANS, G_VARIANT_TYPE ("aa{sv}"));
	g_assert_cmpuint (g_variant_n_children (attr), ==, 1);
	child = g_variant_get_child_value (attr, 0);
	g_assert (child);
	g_assert (g_variant_lookup (child, "vid", "u", &v_uint));
	g_assert_cmpint (v_uint, ==, 488);
	g_assert (g_variant_lookup (child, "name", "&s", &v_str));
	g_assert_cmpstr (v_str, ==, "v2-0488-03-0505");
	nm_clear_g_variant (&child);
	nm_clear_g_variant (&attr);

	/* unsupported: IEEE 802.1 - Protocol Identity */
}

TEST_RECV_DATA_DEFINE (_test_recv_data1,       1, _test_recv_data1_check,  &_test_recv_data1_frame0);

TEST_RECV_FRAME_DEFINE (_test_recv_data2_frame0_ttl1,
	"{'raw': <[byte 0x01, 0x80, 0xc2, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x88, 0xcc, 0x02, 0x07, 0x04, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x04, 0x04, 0x05, 0x31, 0x2f, 0x33, 0x06, 0x02, 0x00, 0x01, 0x08, 0x04, 0x50, 0x6f, 0x72, 0x74, 0x0a, 0x03, 0x53, 0x59, 0x53, 0x0c, 0x04, 0x66, 0x6f, 0x6f, 0x00, 0x00, 0x00]>, 'chassis-id-type': <uint32 4>, 'chassis-id': <'00:01:02:03:04:05'>, 'port-id-type': <uint32 5>, 'port-id': <'1/3'>, 'destination': <'nearest-non-tpmr-bridge'>, 'port-description': <'Port'>, 'system-name': <'SYS'>, 'system-description': <'foo'>}",
	/* Ethernet header */
	0x01, 0x80, 0xc2, 0x00, 0x00, 0x03,     /* Destination MAC */
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06,     /* Source MAC */
	0x88, 0xcc,                             /* Ethertype */
	/* LLDP mandatory TLVs */
	0x02, 0x07, 0x04, 0x00, 0x01, 0x02,     /* Chassis: MAC, 00:01:02:03:04:05 */
	0x03, 0x04, 0x05,
	0x04, 0x04, 0x05, 0x31, 0x2f, 0x33,     /* Port: interface name, "1/3" */
	0x06, 0x02, 0x00, 0x01,                 /* TTL: 1 seconds */
	/* LLDP optional TLVs */
	0x08, 0x04, 0x50, 0x6f, 0x72, 0x74,     /* Port Description: "Port" */
	0x0a, 0x03, 0x53, 0x59, 0x53,           /* System Name: "SYS" */
	0x0c, 0x04, 0x66, 0x6f, 0x6f, 0x00,     /* System Description: "foo" (NULL-terminated) */
	0x00, 0x00                              /* End Of LLDPDU */
);

static void
_test_recv_data2_ttl1_check (GMainLoop *loop, NMLldpListener *listener)
{
	gulong notify_id;
	GVariant *neighbors;

	_test_recv_data0_check_do (loop, listener, &_test_recv_data2_frame0_ttl1);

	/* wait for signal. */
	notify_id = g_signal_connect (listener, "notify::" NM_LLDP_LISTENER_NEIGHBORS,
	                              nmtst_main_loop_quit_on_notify, loop);
	if (!nmtst_main_loop_run (loop, 5000))
		g_assert_not_reached ();
	nm_clear_g_signal_handler (listener, &notify_id);

	neighbors = nm_lldp_listener_get_neighbors (listener);
	nmtst_assert_variant_is_of_type (neighbors, G_VARIANT_TYPE ("aa{sv}"));
	g_assert_cmpint (g_variant_n_children (neighbors), ==, 0);
}

TEST_RECV_DATA_DEFINE (_test_recv_data2_ttl1, 1, _test_recv_data2_ttl1_check,  &_test_recv_data2_frame0_ttl1);

static void
_test_recv_fixture_setup (TestRecvFixture *fixture, gconstpointer user_data)
{
	const NMPlatformLink *link;
	nm_auto_close int fd = -1;

	fd = open ("/dev/net/tun", O_RDWR | O_CLOEXEC);
	if (fd == -1) {
		g_test_skip ("Unable to open /dev/net/tun");
		fixture->ifindex = 0;
		return;
	}

	if (nmtst_get_rand_bool ()) {
		const NMPlatformLnkTun lnk = {
			.type = IFF_TAP,
			.pi = FALSE,
			.vnet_hdr = FALSE,
			.multi_queue = FALSE,
			.persist = FALSE,
		};

		nm_close (nm_steal_fd (&fd));

		link = nmtstp_link_tun_add (NM_PLATFORM_GET,
		                            FALSE,
		                            TEST_IFNAME,
		                            &lnk,
		                            &fd);
		g_assert (link);
		nmtstp_link_set_updown (NM_PLATFORM_GET, -1, link->ifindex, TRUE);
		link = nmtstp_assert_wait_for_link (NM_PLATFORM_GET, TEST_IFNAME, NM_LINK_TYPE_TUN, 0);
	} else {
		int s;
		struct ifreq ifr = { };

		ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
		nm_utils_ifname_cpy (ifr.ifr_name, TEST_IFNAME);
		g_assert (ioctl (fd, TUNSETIFF, &ifr) >= 0);

		/* Bring the interface up */
		s = socket (AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
		g_assert (s >= 0);
		ifr.ifr_flags |= IFF_UP;
		g_assert (ioctl (s, SIOCSIFFLAGS, &ifr) >= 0);
		nm_close (s);

		link = nmtstp_assert_wait_for_link (NM_PLATFORM_GET, TEST_IFNAME, NM_LINK_TYPE_TUN, 100);
	}

	fixture->ifindex = link->ifindex;
	fixture->fd = nm_steal_fd (&fd);
	memcpy (fixture->mac, link->l_address.data, ETH_ALEN);
}

typedef struct {
	int num_called;
} TestRecvCallbackInfo;

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
	gulong notify_id;
	GError *error = NULL;
	guint sd_id;

	if (fixture->ifindex == 0) {
		g_test_skip ("Tun device not available");
		return;
	}

	listener = nm_lldp_listener_new ();
	g_assert (listener != NULL);
	g_assert (nm_lldp_listener_start (listener, fixture->ifindex, &error));
	g_assert_no_error (error);

	notify_id = g_signal_connect (listener, "notify::" NM_LLDP_LISTENER_NEIGHBORS,
	                              (GCallback) lldp_neighbors_changed, &info);
	loop = g_main_loop_new (NULL, FALSE);
	sd_id = nm_sd_event_attach_default ();

	for (i_frames = 0; i_frames < data->frames_len; i_frames++) {
		const TestRecvFrame *f = data->frames[i_frames];

		g_assert (write (fixture->fd, f->frame, f->frame_len) == f->frame_len);
	}

	if (nmtst_main_loop_run (loop, 500))
		g_assert_not_reached ();

	g_assert_cmpint (info.num_called, ==, data->expected_num_called);

	nm_clear_g_signal_handler (listener, &notify_id);

	data->check (loop, listener);

	nm_clear_g_source (&sd_id);
	nm_clear_pointer (&loop, g_main_loop_unref);
}

static void
_test_recv_fixture_teardown (TestRecvFixture *fixture, gconstpointer user_data)
{
	if (fixture->ifindex)
		nm_platform_link_delete (NM_PLATFORM_GET, fixture->ifindex);
}

/*****************************************************************************/

static void
test_parse_frames (gconstpointer test_data)
{
	const TestRecvFrame *frame = test_data;
	gs_unref_variant GVariant *v_neighbor = NULL;
	gs_unref_variant GVariant *attr = NULL;
	gs_free char *as_variant = NULL;

	v_neighbor = nmtst_lldp_parse_from_raw (frame->frame, frame->frame_len);
	g_assert (v_neighbor);

	attr = g_variant_lookup_value (v_neighbor, NM_LLDP_ATTR_RAW, G_VARIANT_TYPE_BYTESTRING);
	nmtst_assert_variant_bytestring (attr, frame->frame, frame->frame_len);
	nm_clear_g_variant (&attr);

	as_variant = g_variant_print (v_neighbor, TRUE);
	g_assert (as_variant);
	g_assert_cmpstr (frame->as_variant, ==, as_variant);
}

/*****************************************************************************/

TEST_RECV_FRAME_DEFINE (_test_parse_frames_3,
	/* https://github.com/the-tcpdump-group/tcpdump/blob/c4f8796bf8bec740621a360eded236d8991ea00f/tests/lldp_mudurl.pcap */
	"{'raw': <[byte 0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e, 0x00, 0x23, 0x54, 0xc2, 0x57, 0x02, 0x88, 0xcc, 0x02, 0x07, 0x04, 0x00, 0x23, 0x54, 0xc2, 0x57, 0x02, 0x04, 0x07, 0x03, 0x00, 0x23, 0x54, 0xc2, 0x57, 0x02, 0x06, 0x02, 0x00, 0x78, 0x0a, 0x1c, 0x75, 0x70, 0x73, 0x74, 0x61, 0x69, 0x72, 0x73, 0x2e, 0x6f, 0x66, 0x63, 0x6f, 0x75, 0x72, 0x73, 0x65, 0x69, 0x6d, 0x72, 0x69, 0x67, 0x68, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x0c, 0x5c, 0x55, 0x62, 0x75, 0x6e, 0x74, 0x75, 0x20, 0x31, 0x34, 0x2e, 0x30, 0x34, 0x2e, 0x35, 0x20, 0x4c, 0x54, 0x53, 0x20, 0x4c, 0x69, 0x6e, 0x75, 0x78, 0x20, 0x33, 0x2e, 0x31, 0x33, 0x2e, 0x30, 0x2d, 0x31, 0x30, 0x36, 0x2d, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x69, 0x63, 0x20, 0x23, 0x31, 0x35, 0x33, 0x2d, 0x55, 0x62, 0x75, 0x6e, 0x74, 0x75, 0x20, 0x53, 0x4d, 0x50, 0x20, 0x54, 0x75, 0x65, 0x20, 0x44, 0x65, 0x63, 0x20, 0x36, 0x20, 0x31, 0x35, 0x3a, 0x34, 0x35, 0x3a, 0x31, 0x33, 0x20, 0x55, 0x54, 0x43, 0x20, 0x32, 0x30, 0x31, 0x36, 0x20, 0x69, 0x36, 0x38, 0x36, 0x0e, 0x04, 0x00, 0x9c, 0x00, 0x08, 0x10, 0x0c, 0x05, 0x01, 0x3e, 0x0c, 0xad, 0x72, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x10, 0x18, 0x11, 0x02, 0x20, 0x01, 0x08, 0xa8, 0x10, 0x06, 0x00, 0x04, 0x02, 0x23, 0x54, 0xff, 0xfe, 0xc2, 0x57, 0x02, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x08, 0x04, 0x65, 0x74, 0x68, 0x30, 0xfe, 0x09, 0x00, 0x12, 0x0f, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x09, 0x00, 0x12, 0x0f, 0x01, 0x03, 0xec, 0xc3, 0x00, 0x10, 0xfe, 0x40, 0x00, 0x00, 0x5e, 0x01, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x69, 0x6d, 0x72, 0x69, 0x67, 0x68, 0x74, 0x2e, 0x6d, 0x75, 0x64, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x2e, 0x77, 0x65, 0x6c, 0x6c, 0x2d, 0x6b, 0x6e, 0x6f, 0x77, 0x6e, 0x2f, 0x6d, 0x75, 0x64, 0x2f, 0x76, 0x31, 0x2f, 0x76, 0x6f, 0x6d, 0x69, 0x74, 0x76, 0x32, 0x2e, 0x30, 0x00, 0x00]>, 'chassis-id-type': <uint32 4>, 'chassis-id': <'00:23:54:C2:57:02'>, 'port-id-type': <uint32 3>, 'port-id': <'00:23:54:C2:57:02'>, 'destination': <'nearest-bridge'>, 'port-description': <'eth0'>, 'system-name': <'upstairs.ofcourseimright.com'>, 'system-description': <'Ubuntu 14.04.5 LTS Linux 3.13.0-106-generic #153-Ubuntu SMP Tue Dec 6 15:45:13 UTC 2016 i686'>, 'system-capabilities': <uint32 156>, 'management-addresses': <[{'address-subtype': <uint32 1>, 'address': <[byte 0x3e, 0x0c, 0xad, 0x72]>, 'interface-number-subtype': <uint32 2>, 'interface-number': <uint32 2>, 'object-id': <@ay []>}, {'address-subtype': <uint32 2>, 'address': <[byte 0x20, 0x01, 0x08, 0xa8, 0x10, 0x06, 0x00, 0x04, 0x02, 0x23, 0x54, 0xff, 0xfe, 0xc2, 0x57, 0x02]>, 'interface-number-subtype': <uint32 2>, 'interface-number': <uint32 2>, 'object-id': <@ay []>}]>, 'ieee-802-3-mac-phy-conf': <{'autoneg': <uint32 3>, 'pmd-autoneg-cap': <uint32 60611>, 'operational-mau-type': <uint32 16>}>, 'mud-url': <'https://imright.mud.example.com/.well-known/mud/v1/vomitv2.0'>}",
	0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e, /* ethernet destination */
	0x00, 0x23, 0x54, 0xc2, 0x57, 0x02, /* ethernet source */
	0x88, 0xcc, /* ethernet type */

	0x02, 0x07, 0x04, 0x00, 0x23, 0x54, 0xc2, 0x57, 0x02, 0x04, 0x07, 0x03, 0x00, 0x23,
	0x54, 0xc2, 0x57, 0x02, 0x06, 0x02, 0x00, 0x78, 0x0a, 0x1c, 0x75, 0x70, 0x73, 0x74,
	0x61, 0x69, 0x72, 0x73, 0x2e, 0x6f, 0x66, 0x63, 0x6f, 0x75, 0x72, 0x73, 0x65, 0x69,
	0x6d, 0x72, 0x69, 0x67, 0x68, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x0c, 0x5c, 0x55, 0x62,
	0x75, 0x6e, 0x74, 0x75, 0x20, 0x31, 0x34, 0x2e, 0x30, 0x34, 0x2e, 0x35, 0x20, 0x4c,
	0x54, 0x53, 0x20, 0x4c, 0x69, 0x6e, 0x75, 0x78, 0x20, 0x33, 0x2e, 0x31, 0x33, 0x2e,
	0x30, 0x2d, 0x31, 0x30, 0x36, 0x2d, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x69, 0x63, 0x20,
	0x23, 0x31, 0x35, 0x33, 0x2d, 0x55, 0x62, 0x75, 0x6e, 0x74, 0x75, 0x20, 0x53, 0x4d,
	0x50, 0x20, 0x54, 0x75, 0x65, 0x20, 0x44, 0x65, 0x63, 0x20, 0x36, 0x20, 0x31, 0x35,
	0x3a, 0x34, 0x35, 0x3a, 0x31, 0x33, 0x20, 0x55, 0x54, 0x43, 0x20, 0x32, 0x30, 0x31,
	0x36, 0x20, 0x69, 0x36, 0x38, 0x36, 0x0e, 0x04, 0x00, 0x9c, 0x00, 0x08, 0x10, 0x0c,
	0x05, 0x01, 0x3e, 0x0c, 0xad, 0x72, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x10, 0x18,
	0x11, 0x02, 0x20, 0x01, 0x08, 0xa8, 0x10, 0x06, 0x00, 0x04, 0x02, 0x23, 0x54, 0xff,
	0xfe, 0xc2, 0x57, 0x02, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x08, 0x04, 0x65, 0x74,
	0x68, 0x30, 0xfe, 0x09, 0x00, 0x12, 0x0f, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0xfe,
	0x09, 0x00, 0x12, 0x0f, 0x01, 0x03, 0xec, 0xc3, 0x00, 0x10, 0xfe, 0x40, 0x00, 0x00,
	0x5e, 0x01, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x69, 0x6d, 0x72, 0x69,
	0x67, 0x68, 0x74, 0x2e, 0x6d, 0x75, 0x64, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
	0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x2e, 0x77, 0x65, 0x6c, 0x6c, 0x2d, 0x6b, 0x6e,
	0x6f, 0x77, 0x6e, 0x2f, 0x6d, 0x75, 0x64, 0x2f, 0x76, 0x31, 0x2f, 0x76, 0x6f, 0x6d,
	0x69, 0x74, 0x76, 0x32, 0x2e,

	0x30, 0x00, 0x00, /* ethernet trailer */
);

/*****************************************************************************/

NMTstpSetupFunc const _nmtstp_setup_platform_func = nm_linux_platform_setup;

void
_nmtstp_init_tests (int *argc, char ***argv)
{
	nmtst_init_assert_logging (argc, argv, "WARN", "ALL");
}

void
_nmtstp_setup_tests (void)
{
#define _TEST_ADD_RECV(testpath, testdata) \
	g_test_add (testpath, TestRecvFixture, testdata, _test_recv_fixture_setup, test_recv, _test_recv_fixture_teardown)
	_TEST_ADD_RECV ("/lldp/recv/0",       &_test_recv_data0);
	_TEST_ADD_RECV ("/lldp/recv/0_twice", &_test_recv_data0_twice);
	_TEST_ADD_RECV ("/lldp/recv/1",       &_test_recv_data1);
	_TEST_ADD_RECV ("/lldp/recv/2_ttl1",  &_test_recv_data2_ttl1);

	g_test_add_data_func ("/lldp/parse-frames/0", &_test_recv_data0_frame0, test_parse_frames);
	g_test_add_data_func ("/lldp/parse-frames/1", &_test_recv_data1_frame0, test_parse_frames);
	g_test_add_data_func ("/lldp/parse-frames/2", &_test_recv_data2_frame0_ttl1, test_parse_frames);
	g_test_add_data_func ("/lldp/parse-frames/3", &_test_parse_frames_3, test_parse_frames);
}
