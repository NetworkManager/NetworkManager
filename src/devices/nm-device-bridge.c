// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2011 - 2015 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-device-bridge.h"

#include <stdlib.h>

#include "NetworkManagerUtils.h"
#include "nm-device-private.h"
#include "platform/nm-platform.h"
#include "nm-device-factory.h"
#include "nm-core-internal.h"

#include "nm-device-logging.h"
_LOG_DECLARE_SELF(NMDeviceBridge);

/*****************************************************************************/

struct _NMDeviceBridge {
	NMDevice parent;
	GCancellable *bt_cancellable;
	bool vlan_configured:1;
	bool bt_registered:1;
};

struct _NMDeviceBridgeClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDeviceBridge, nm_device_bridge, NM_TYPE_DEVICE)

/*****************************************************************************/

const NMBtVTableNetworkServer *nm_bt_vtable_network_server = NULL;

/*****************************************************************************/

static NMDeviceCapabilities
get_generic_capabilities (NMDevice *dev)
{
	return NM_DEVICE_CAP_CARRIER_DETECT | NM_DEVICE_CAP_IS_SOFTWARE;
}

static gboolean
check_connection_available (NMDevice *device,
                            NMConnection *connection,
                            NMDeviceCheckConAvailableFlags flags,
                            const char *specific_object,
                            GError **error)
{
	NMDeviceBridge *self = NM_DEVICE_BRIDGE (device);
	NMSettingBluetooth *s_bt;

	if (!NM_DEVICE_CLASS (nm_device_bridge_parent_class)->check_connection_available (device, connection, flags, specific_object, error))
		return FALSE;

	s_bt = _nm_connection_get_setting_bluetooth_for_nap (connection);
	if (s_bt) {
		const char *bdaddr;

		if (!nm_bt_vtable_network_server) {
			nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
			                            "bluetooth plugin not available to activate NAP profile");
			return FALSE;
		}

		bdaddr = nm_setting_bluetooth_get_bdaddr (s_bt);
		if (!nm_bt_vtable_network_server->is_available (nm_bt_vtable_network_server,
		                                                bdaddr,
		                                                  (   self->bt_cancellable
		                                                   || self->bt_registered)
		                                                ? device
		                                                : NULL)) {
			if (bdaddr)
				nm_utils_error_set (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
				                    "no suitable NAP device \"%s\" available", bdaddr);
			else
				nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
				                            "no suitable NAP device available");
			return FALSE;
		}
	}

	return TRUE;
}

static gboolean
check_connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	NMSettingBridge *s_bridge;
	const char *mac_address;

	if (!NM_DEVICE_CLASS (nm_device_bridge_parent_class)->check_connection_compatible (device, connection, error))
		return FALSE;

	if (   nm_connection_is_type (connection, NM_SETTING_BLUETOOTH_SETTING_NAME)
	    && _nm_connection_get_setting_bluetooth_for_nap (connection)) {
		s_bridge = nm_connection_get_setting_bridge (connection);
		if (!s_bridge) {
			nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
			                            "missing bridge setting for bluetooth NAP profile");
			return FALSE;
		}

		/* a bluetooth NAP connection is handled by the bridge.
		 *
		 * Proceed... */
	} else {
		s_bridge = _nm_connection_check_main_setting (connection, NM_SETTING_BRIDGE_SETTING_NAME, error);
		if (!s_bridge)
			return FALSE;
	}

	mac_address = nm_setting_bridge_get_mac_address (s_bridge);
	if (mac_address && nm_device_is_real (device)) {
		const char *hw_addr;

		hw_addr = nm_device_get_hw_address (device);
		if (!hw_addr || !nm_utils_hwaddr_matches (hw_addr, -1, mac_address, -1)) {
			nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
			                            "mac address mismatches");
			return FALSE;
		}
	}

	return TRUE;
}

static gboolean
complete_connection (NMDevice *device,
                     NMConnection *connection,
                     const char *specific_object,
                     NMConnection *const*existing_connections,
                     GError **error)
{
	NMSettingBridge *s_bridge;

	nm_utils_complete_generic (nm_device_get_platform (device),
	                           connection,
	                           NM_SETTING_BRIDGE_SETTING_NAME,
	                           existing_connections,
	                           NULL,
	                           _("Bridge connection"),
	                           "bridge",
	                           NULL,
	                           TRUE);

	s_bridge = nm_connection_get_setting_bridge (connection);
	if (!s_bridge) {
		s_bridge = (NMSettingBridge *) nm_setting_bridge_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_bridge));
	}

	return TRUE;
}

static void
from_sysfs_group_address (const char *value, GValue *out)
{
	if (!nm_utils_hwaddr_matches (value, -1, "01:80:C2:00:00:00", -1))
		g_value_set_string (out, value);
}

static const char *
to_sysfs_group_address (GValue *value)
{
	return g_value_get_string (value) ?: "01:80:C2:00:00:00";
}

static void
from_sysfs_vlan_protocol (const char *value, GValue *out)
{
	switch (_nm_utils_ascii_str_to_uint64 (value, 16, 0, G_MAXUINT, -1)) {
	case ETH_P_8021Q:
		/* default value */
		break;
	case ETH_P_8021AD:
		g_value_set_string (out, "802.1ad");
		break;
	}
}

static const char *
to_sysfs_vlan_protocol (GValue *value)
{
	const char *str = g_value_get_string (value);

	if (nm_streq0 (str, "802.1ad")) {
		G_STATIC_ASSERT_EXPR (ETH_P_8021AD == 0x88A8);
		return "0x88A8";
	}

	G_STATIC_ASSERT_EXPR (ETH_P_8021Q == 0x8100);
	return "0x8100";
}

static const char *
to_sysfs_multicast_router (GValue *value)
{
	const char *str = g_value_get_string (value);

	if (nm_streq0 (str, "disabled"))
		return "0";
	if (nm_streq0 (str, "auto"))
		return "1";
	if (nm_streq0 (str, "enabled"))
		return "2";

	return "1";
}

static void
from_sysfs_multicast_router (const char *value, GValue *out)
{
	switch (_nm_utils_ascii_str_to_uint64 (value, 10, 0, G_MAXUINT, -1)) {
	case 0:
		g_value_set_string (out, "disabled");
		break;
	case 2:
		g_value_set_string (out, "enabled");
		break;
	case 1:
	default:
		/* default value */
		break;
	}
}

/*****************************************************************************/

typedef struct {
	const char *name;
	const char *sysname;
	const char *(*to_sysfs) (GValue *value);
	void (*from_sysfs) (const char *value, GValue *out);
	guint64 nm_min;
	guint64 nm_max;
	guint64 nm_default;
	bool default_if_zero;
	bool user_hz_compensate;
	bool only_with_stp;
} Option;

static const Option master_options[] = {
	{ NM_SETTING_BRIDGE_STP,                                     "stp_state", /* this must stay as the first item */
	                                                             NULL, NULL,
	                                                             FALSE, TRUE, NM_BRIDGE_STP_DEF,
	                                                             FALSE, FALSE, FALSE },
	{ NM_SETTING_BRIDGE_PRIORITY,                                "priority",
	                                                             NULL, NULL,
	                                                             0, G_MAXUINT16, 0x8000,
	                                                             TRUE, FALSE, TRUE },
	{ NM_SETTING_BRIDGE_FORWARD_DELAY,                           "forward_delay",
	                                                             NULL, NULL,
	                                                             NM_BRIDGE_FORWARD_DELAY_MIN, NM_BRIDGE_FORWARD_DELAY_MAX, NM_BRIDGE_FORWARD_DELAY_DEF,
	                                                             TRUE, TRUE, TRUE},
	{ NM_SETTING_BRIDGE_HELLO_TIME,                              "hello_time",
	                                                             NULL, NULL,
	                                                             NM_BRIDGE_HELLO_TIME_MIN, NM_BRIDGE_HELLO_TIME_MAX, NM_BRIDGE_HELLO_TIME_DEF,
	                                                             TRUE, TRUE, TRUE },
	{ NM_SETTING_BRIDGE_MAX_AGE,                                 "max_age",
	                                                             NULL, NULL,
	                                                             0, NM_BR_MAX_MAX_AGE, 20,
	                                                             TRUE, TRUE, TRUE },
	{ NM_SETTING_BRIDGE_AGEING_TIME,                             "ageing_time",
	                                                             NULL, NULL,
	                                                             NM_BRIDGE_AGEING_TIME_MIN, NM_BRIDGE_AGEING_TIME_MAX, NM_BRIDGE_AGEING_TIME_DEF,
	                                                             TRUE, TRUE, FALSE },
	{ NM_SETTING_BRIDGE_GROUP_FORWARD_MASK,                      "group_fwd_mask",
	                                                             NULL, NULL,
	                                                             0, 0xFFFF, 0,
	                                                             TRUE, FALSE, FALSE },
	{ NM_SETTING_BRIDGE_MULTICAST_HASH_MAX,                      "hash_max",
	                                                             NULL, NULL,
	                                                             NM_BRIDGE_MULTICAST_HASH_MAX_MIN, NM_BRIDGE_MULTICAST_HASH_MAX_MAX, NM_BRIDGE_MULTICAST_HASH_MAX_DEF,
	                                                             FALSE, FALSE, FALSE },
	{ NM_SETTING_BRIDGE_MULTICAST_LAST_MEMBER_COUNT,             "multicast_last_member_count",
	                                                             NULL, NULL,
	                                                             0, G_MAXUINT32, 2,
	                                                             FALSE, FALSE, FALSE },
	{ NM_SETTING_BRIDGE_MULTICAST_LAST_MEMBER_INTERVAL,          "multicast_last_member_interval",
	                                                             NULL, NULL,
	                                                             0, G_MAXUINT64, 100,
	                                                             FALSE, FALSE, FALSE },
	{ NM_SETTING_BRIDGE_MULTICAST_MEMBERSHIP_INTERVAL,           "multicast_membership_interval",
	                                                             NULL, NULL,
	                                                             0, G_MAXUINT64, 26000,
	                                                             FALSE, FALSE, FALSE },
	{ NM_SETTING_BRIDGE_MULTICAST_QUERIER,                       "multicast_querier",
	                                                             NULL, NULL,
	                                                             0, 1, 0,
	                                                             FALSE, FALSE, FALSE },
	{ NM_SETTING_BRIDGE_MULTICAST_QUERIER_INTERVAL,              "multicast_querier_interval",
	                                                             NULL, NULL,
	                                                             0, G_MAXUINT64, 25500,
	                                                             FALSE, FALSE, FALSE },
	{ NM_SETTING_BRIDGE_MULTICAST_QUERY_INTERVAL,                "multicast_query_interval",
	                                                             NULL, NULL,
	                                                             0, G_MAXUINT64, 12500,
	                                                             FALSE, FALSE, FALSE },
	{ NM_SETTING_BRIDGE_MULTICAST_QUERY_RESPONSE_INTERVAL,       "multicast_query_response_interval",
	                                                             NULL, NULL,
	                                                             0, G_MAXUINT64, 1000,
	                                                             FALSE, FALSE, FALSE },
	{ NM_SETTING_BRIDGE_MULTICAST_QUERY_USE_IFADDR,              "multicast_query_use_ifaddr",
	                                                             NULL, NULL,
	                                                             0, 1, 0,
	                                                             FALSE, FALSE, FALSE },
	{ NM_SETTING_BRIDGE_MULTICAST_SNOOPING,                      "multicast_snooping",
	                                                             NULL, NULL,
	                                                             0, 1, 1,
	                                                             FALSE, FALSE, FALSE },
	{ NM_SETTING_BRIDGE_MULTICAST_ROUTER,                        "multicast_router",
	                                                             to_sysfs_multicast_router, from_sysfs_multicast_router,
	                                                             0, 0, 0,
	                                                             FALSE, FALSE, FALSE },
	{ NM_SETTING_BRIDGE_MULTICAST_STARTUP_QUERY_COUNT,           "multicast_startup_query_count",
	                                                             NULL, NULL,
	                                                             0, G_MAXUINT32, 2,
	                                                             FALSE, FALSE, FALSE },
	{ NM_SETTING_BRIDGE_MULTICAST_STARTUP_QUERY_INTERVAL,        "multicast_startup_query_interval",
	                                                             NULL, NULL,
	                                                             0, G_MAXUINT64, 3125,
	                                                             FALSE, FALSE, FALSE },
	{ NM_SETTING_BRIDGE_GROUP_ADDRESS,                           "group_addr",
	                                                             to_sysfs_group_address, from_sysfs_group_address,
	                                                             0, 0, 0,
	                                                             FALSE, FALSE, FALSE },
	{ NM_SETTING_BRIDGE_VLAN_PROTOCOL,                           "vlan_protocol",
	                                                             to_sysfs_vlan_protocol, from_sysfs_vlan_protocol,
	                                                             0, 0, 0,
	                                                             FALSE, FALSE, FALSE },
	{ NM_SETTING_BRIDGE_VLAN_STATS_ENABLED,                      "vlan_stats_enabled",
	                                                             NULL, NULL,
	                                                             0, 1, 0,
	                                                             FALSE, FALSE, FALSE },
	{ NULL, NULL }
};

static const Option slave_options[] = {
	{ NM_SETTING_BRIDGE_PORT_PRIORITY,     "priority",
	                                       NULL, NULL,
	                                       0, NM_BR_PORT_MAX_PRIORITY, NM_BR_PORT_DEF_PRIORITY,
	                                       TRUE, FALSE },
	{ NM_SETTING_BRIDGE_PORT_PATH_COST,    "path_cost",
	                                       NULL, NULL,
	                                       0, NM_BR_PORT_MAX_PATH_COST, 100,
	                                       TRUE, FALSE },
	{ NM_SETTING_BRIDGE_PORT_HAIRPIN_MODE, "hairpin_mode",
	                                       NULL, NULL,
	                                       0, 1, 0,
	                                       FALSE, FALSE },
	{ NULL, NULL }
};

static void
commit_option (NMDevice *device, NMSetting *setting, const Option *option, gboolean slave)
{
	int ifindex = nm_device_get_ifindex (device);
	nm_auto_unset_gvalue GValue val = G_VALUE_INIT;
	GParamSpec *pspec;
	const char *value;
	char value_buf[100];

	if (slave)
		nm_assert (NM_IS_SETTING_BRIDGE_PORT (setting));
	else
		nm_assert (NM_IS_SETTING_BRIDGE (setting));

	pspec = g_object_class_find_property (G_OBJECT_GET_CLASS (setting), option->name);
	nm_assert (pspec);

	g_value_init (&val, G_PARAM_SPEC_VALUE_TYPE (pspec));
	g_object_get_property ((GObject *) setting, option->name, &val);

	if (option->to_sysfs) {
		value = option->to_sysfs (&val);
		goto out;
	}

	switch (pspec->value_type) {
	case G_TYPE_BOOLEAN:
		value = g_value_get_boolean (&val) ? "1" : "0";
		break;
	case G_TYPE_UINT64:
	case G_TYPE_UINT: {
			guint64 uval;

			if (pspec->value_type == G_TYPE_UINT64)
				uval = g_value_get_uint64 (&val);
			else
				uval = (guint) g_value_get_uint (&val);

			/* zero means "unspecified" for some NM properties but isn't in the
			 * allowed kernel range, so reset the property to the default value.
			 */
			if (   option->default_if_zero
			    && uval == 0) {
				if (pspec->value_type == G_TYPE_UINT64)
					uval = NM_G_PARAM_SPEC_GET_DEFAULT_UINT64 (pspec);
				else
					uval = NM_G_PARAM_SPEC_GET_DEFAULT_UINT (pspec);
			}

			/* Linux kernel bridge interfaces use 'centiseconds' for time-based values.
			 * In reality it's not centiseconds, but depends on HZ and USER_HZ, which
			 * is almost always works out to be a multiplier of 100, so we can assume
			 * centiseconds.  See clock_t_to_jiffies().
			 */
			if (option->user_hz_compensate)
				uval *= 100;

			if (pspec->value_type == G_TYPE_UINT64)
				nm_sprintf_buf (value_buf, "%"G_GUINT64_FORMAT, uval);
			else
				nm_sprintf_buf (value_buf, "%u", (guint) uval);

			value = value_buf;
		}
		break;
	case G_TYPE_STRING:
		value = g_value_get_string (&val);
		break;
	default:
		nm_assert_not_reached ();
		value = NULL;
		break;
	}

out:
	if (!value)
		return;

	if (slave) {
		nm_platform_sysctl_slave_set_option (nm_device_get_platform (device),
		                                     ifindex,
		                                     option->sysname,
		                                     value);
	} else {
		nm_platform_sysctl_master_set_option (nm_device_get_platform (device),
		                                      ifindex,
		                                      option->sysname,
		                                      value);
	}
}

static const NMPlatformBridgeVlan **
setting_vlans_to_platform (GPtrArray *array)
{
	NMPlatformBridgeVlan **arr;
	NMPlatformBridgeVlan *p_data;
	guint i;

	if (!array || !array->len)
		return NULL;

	G_STATIC_ASSERT_EXPR (_nm_alignof (NMPlatformBridgeVlan *) >= _nm_alignof (NMPlatformBridgeVlan));
	arr = g_malloc (  (sizeof (NMPlatformBridgeVlan *) * (array->len + 1))
	                + (sizeof (NMPlatformBridgeVlan  ) * (array->len    )));
	p_data = (NMPlatformBridgeVlan *) &arr[array->len + 1];

	for (i = 0; i < array->len; i++) {
		NMBridgeVlan *vlan = array->pdata[i];
		guint16 vid_start, vid_end;

		nm_bridge_vlan_get_vid_range (vlan, &vid_start, &vid_end);

		p_data[i] = (NMPlatformBridgeVlan) {
			.vid_start = vid_start,
			.vid_end   = vid_end,
			.pvid      = nm_bridge_vlan_is_pvid (vlan),
			.untagged  = nm_bridge_vlan_is_untagged (vlan),
		};
		arr[i] = &p_data[i];
	}
	arr[i] = NULL;
	return (const NMPlatformBridgeVlan **) arr;
}

static void
commit_slave_options (NMDevice *device, NMSettingBridgePort *setting)
{
	const Option *option;
	NMSetting *s;
	gs_unref_object NMSetting *s_clear = NULL;

	if (setting)
		s = NM_SETTING (setting);
	else
		s = s_clear = nm_setting_bridge_port_new ();

	for (option = slave_options; option->name; option++)
		commit_option (device, s, option, TRUE);
}

static void
update_connection (NMDevice *device, NMConnection *connection)
{
	NMDeviceBridge *self = NM_DEVICE_BRIDGE (device);
	NMSettingBridge *s_bridge = nm_connection_get_setting_bridge (connection);
	int ifindex = nm_device_get_ifindex (device);
	const Option *option;
	gs_free char *stp = NULL;
	int stp_value;

	if (!s_bridge) {
		s_bridge = (NMSettingBridge *) nm_setting_bridge_new ();
		nm_connection_add_setting (connection, (NMSetting *) s_bridge);
	}

	option = master_options;
	nm_assert (nm_streq (option->sysname, "stp_state"));

	stp = nm_platform_sysctl_master_get_option (nm_device_get_platform (device), ifindex, option->sysname);
	stp_value = _nm_utils_ascii_str_to_int64 (stp, 10, option->nm_min, option->nm_max, option->nm_default);
	g_object_set (s_bridge, option->name, stp_value, NULL);
	option++;

	for (; option->name; option++) {
		nm_auto_unset_gvalue GValue value = G_VALUE_INIT;
		gs_free char *str = NULL;
		GParamSpec *pspec;

		str = nm_platform_sysctl_master_get_option (nm_device_get_platform (device), ifindex, option->sysname);
		pspec = g_object_class_find_property (G_OBJECT_GET_CLASS (s_bridge), option->name);

		if (!stp_value && option->only_with_stp)
			continue;

		if (!str) {
			_LOGW (LOGD_BRIDGE, "failed to read bridge setting '%s'", option->sysname);
			continue;
		}

		g_value_init (&value, G_PARAM_SPEC_VALUE_TYPE (pspec));

		if (option->from_sysfs) {
			option->from_sysfs (str, &value);
			goto out;
		}

		switch (pspec->value_type) {
		case G_TYPE_UINT64:
		case G_TYPE_UINT: {
				guint64 uvalue;

				/* See comments in set_sysfs_uint() about centiseconds. */
				if (option->user_hz_compensate) {
					uvalue = _nm_utils_ascii_str_to_int64 (str, 10,
					                                       option->nm_min * 100,
					                                       option->nm_max * 100,
					                                       option->nm_default * 100);
					uvalue /= 100;
				} else {
					uvalue = _nm_utils_ascii_str_to_uint64 (str, 10,
					                                        option->nm_min,
					                                        option->nm_max,
					                                        option->nm_default);
				}

				if (pspec->value_type == G_TYPE_UINT64)
					g_value_set_uint64(&value, uvalue);
				else
					g_value_set_uint (&value, (guint) uvalue);
			}
			break;
		case G_TYPE_BOOLEAN: {
				gboolean bvalue;

				bvalue = _nm_utils_ascii_str_to_int64 (str, 10,
				                                       option->nm_min,
				                                       option->nm_max,
				                                       option->nm_default);
				g_value_set_boolean (&value, bvalue);
			}
			break;
		case G_TYPE_STRING:
			g_value_set_string (&value, str);
			break;
		default:
			nm_assert_not_reached ();
			break;
		}

out:
		g_object_set_property (G_OBJECT (s_bridge), option->name, &value);
	}
}

static gboolean
master_update_slave_connection (NMDevice *device,
                                NMDevice *slave,
                                NMConnection *connection,
                                GError **error)
{
	NMDeviceBridge *self = NM_DEVICE_BRIDGE (device);
	NMSettingConnection *s_con;
	NMSettingBridgePort *s_port;
	int ifindex_slave = nm_device_get_ifindex (slave);
	const char *iface = nm_device_get_iface (device);
	const Option *option;

	g_return_val_if_fail (ifindex_slave > 0, FALSE);

	s_con = nm_connection_get_setting_connection (connection);
	s_port = nm_connection_get_setting_bridge_port (connection);
	if (!s_port) {
		s_port = (NMSettingBridgePort *) nm_setting_bridge_port_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_port));
	}

	for (option = slave_options; option->name; option++) {
		gs_free char *str = nm_platform_sysctl_slave_get_option (nm_device_get_platform (device), ifindex_slave, option->sysname);
		uint value;

		if (str) {
			/* See comments in set_sysfs_uint() about centiseconds. */
			if (option->user_hz_compensate) {
				value = _nm_utils_ascii_str_to_int64 (str, 10,
				                                      option->nm_min * 100,
				                                      option->nm_max * 100,
				                                      option->nm_default * 100);
				value /= 100;
			} else {
				value = _nm_utils_ascii_str_to_int64 (str, 10,
				                                      option->nm_min,
				                                      option->nm_max,
				                                      option->nm_default);
			}
			g_object_set (s_port, option->name, value, NULL);
		} else
			_LOGW (LOGD_BRIDGE, "failed to read bridge port setting '%s'", option->sysname);
	}

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_MASTER, iface,
	              NM_SETTING_CONNECTION_SLAVE_TYPE, NM_SETTING_BRIDGE_SETTING_NAME,
	              NULL);
	return TRUE;
}

static gboolean
bridge_set_vlan_options (NMDevice *device, NMSettingBridge *s_bridge)
{
	NMDeviceBridge *self = NM_DEVICE_BRIDGE (device);
	gconstpointer hwaddr;
	size_t length;
	gboolean enabled;
	guint16 pvid;
	NMPlatform *plat;
	int ifindex;
	gs_unref_ptrarray GPtrArray *vlans = NULL;
	gs_free const NMPlatformBridgeVlan **plat_vlans = NULL;

	if (self->vlan_configured)
		return TRUE;

	plat = nm_device_get_platform (device);
	ifindex = nm_device_get_ifindex (device);
	enabled = nm_setting_bridge_get_vlan_filtering (s_bridge);

	if (!enabled) {
		nm_platform_sysctl_master_set_option (plat, ifindex, "vlan_filtering", "0");
		nm_platform_sysctl_master_set_option (plat, ifindex, "default_pvid", "1");
		nm_platform_link_set_bridge_vlans (plat, ifindex, FALSE, NULL);
		return TRUE;
	}

	hwaddr = nm_platform_link_get_address (plat, ifindex, &length);
	g_return_val_if_fail (length == ETH_ALEN, FALSE);
	if (nm_utils_hwaddr_matches (hwaddr, ETH_ALEN, nm_ip_addr_zero.addr_eth, ETH_ALEN)) {
		/* We need a non-zero MAC address to set the default pvid.
		 * Retry later. */
		return TRUE;
	}

	self->vlan_configured = TRUE;

	/* Filtering must be disabled to change the default PVID */
	if (!nm_platform_sysctl_master_set_option (plat, ifindex, "vlan_filtering", "0"))
		return FALSE;

	/* Clear the default PVID so that we later can force the re-creation of
	 * default PVID VLANs by writing the option again. */
	if (!nm_platform_sysctl_master_set_option (plat, ifindex, "default_pvid", "0"))
		return FALSE;

	/* Clear all existing VLANs */
	if (!nm_platform_link_set_bridge_vlans (plat, ifindex, FALSE, NULL))
		return FALSE;

	/* Now set the default PVID. After this point the kernel creates
	 * a PVID VLAN on each port, including the bridge itself. */
	pvid = nm_setting_bridge_get_vlan_default_pvid (s_bridge);
	if (pvid) {
		char value[32];

		nm_sprintf_buf (value, "%u", pvid);
		if (!nm_platform_sysctl_master_set_option (plat, ifindex, "default_pvid", value))
			return FALSE;
	}

	/* Create VLANs only after setting the default PVID, so that
	 * any PVID VLAN overrides the bridge's default PVID. */
	g_object_get (s_bridge, NM_SETTING_BRIDGE_VLANS, &vlans, NULL);
	plat_vlans = setting_vlans_to_platform (vlans);
	if (   plat_vlans
	    && !nm_platform_link_set_bridge_vlans (plat, ifindex, FALSE, plat_vlans))
		return FALSE;

	if (!nm_platform_sysctl_master_set_option (plat, ifindex, "vlan_filtering", "1"))
		return FALSE;

	return TRUE;
}

static NMActStageReturn
act_stage1_prepare (NMDevice *device, NMDeviceStateReason *out_failure_reason)
{
	NMConnection *connection;
	NMSetting *s_bridge;
	const Option *option;

	connection = nm_device_get_applied_connection (device);
	g_return_val_if_fail (connection, NM_ACT_STAGE_RETURN_FAILURE);

	s_bridge = (NMSetting *) nm_connection_get_setting_bridge (connection);
	g_return_val_if_fail (s_bridge, NM_ACT_STAGE_RETURN_FAILURE);

	for (option = master_options; option->name; option++)
		commit_option (device, s_bridge, option, FALSE);

	if (!bridge_set_vlan_options (device, (NMSettingBridge *) s_bridge)) {
		NM_SET_OUT (out_failure_reason, NM_DEVICE_STATE_REASON_CONFIG_FAILED);
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	return NM_ACT_STAGE_RETURN_SUCCESS;
}

static void
_bt_register_bridge_cb (GError *error,
                        gpointer user_data)
{
	NMDeviceBridge *self;

	if (nm_utils_error_is_cancelled (error))
		return;

	self = user_data;

	g_clear_object (&self->bt_cancellable);

	if (error) {
		_LOGD (LOGD_DEVICE, "bluetooth NAP server failed to register bridge: %s", error->message);
		nm_device_state_changed (NM_DEVICE (self), NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_BT_FAILED);
		return;
	}

	nm_device_activate_schedule_stage2_device_config (NM_DEVICE (self), FALSE);
}

void
_nm_device_bridge_notify_unregister_bt_nap (NMDevice *device,
                                            const char *reason)
{
	NMDeviceBridge *self = NM_DEVICE_BRIDGE (device);

	_LOGD (LOGD_DEVICE, "bluetooth NAP server unregistered from bridge: %s%s",
	       reason,
	       self->bt_registered ? "" : " (was no longer registered)");

	nm_clear_g_cancellable (&self->bt_cancellable);

	if (self->bt_registered) {
		self->bt_registered = FALSE;
		nm_device_state_changed (device,
		                         NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_BT_FAILED);
	}
}

static NMActStageReturn
act_stage2_config (NMDevice *device, NMDeviceStateReason *out_failure_reason)
{
	NMDeviceBridge *self = NM_DEVICE_BRIDGE (device);
	NMConnection *connection;
	NMSettingBluetooth *s_bt;
	gs_free_error GError *error = NULL;

	connection = nm_device_get_applied_connection (device);

	s_bt = _nm_connection_get_setting_bluetooth_for_nap (connection);
	if (!s_bt)
		return NM_ACT_STAGE_RETURN_SUCCESS;

	if (!nm_bt_vtable_network_server) {
		_LOGD (LOGD_DEVICE, "bluetooth NAP server failed because bluetooth plugin not available");
		*out_failure_reason = NM_DEVICE_STATE_REASON_BT_FAILED;
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	if (self->bt_cancellable)
		return NM_ACT_STAGE_RETURN_POSTPONE;

	if (self->bt_registered)
		return NM_ACT_STAGE_RETURN_POSTPONE;

	self->bt_cancellable = g_cancellable_new ();
	if (!nm_bt_vtable_network_server->register_bridge (nm_bt_vtable_network_server,
	                                                   nm_setting_bluetooth_get_bdaddr (s_bt),
	                                                   device,
	                                                   self->bt_cancellable,
	                                                   _bt_register_bridge_cb,
	                                                   device,
	                                                   &error)) {
		_LOGD (LOGD_DEVICE, "bluetooth NAP server failed to register bridge: %s", error->message);
		*out_failure_reason = NM_DEVICE_STATE_REASON_BT_FAILED;
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	self->bt_registered = TRUE;
	return NM_ACT_STAGE_RETURN_POSTPONE;
}

static void
deactivate (NMDevice *device)
{
	NMDeviceBridge *self = NM_DEVICE_BRIDGE (device);

	_LOGD (LOGD_DEVICE, "deactivate bridge%s",
	       self->bt_registered ? " (registered as NAP bluetooth device)" : "");

	self->vlan_configured = FALSE;

	nm_clear_g_cancellable (&self->bt_cancellable);

	if (self->bt_registered) {
		self->bt_registered = FALSE;
		nm_bt_vtable_network_server->unregister_bridge (nm_bt_vtable_network_server,
		                                                device);
	}
}

static gboolean
enslave_slave (NMDevice *device,
               NMDevice *slave,
               NMConnection *connection,
               gboolean configure)
{
	NMDeviceBridge *self = NM_DEVICE_BRIDGE (device);
	NMConnection *master_connection;
	NMSettingBridge *s_bridge;
	NMSettingBridgePort *s_port;

	if (configure) {
		if (!nm_platform_link_enslave (nm_device_get_platform (device), nm_device_get_ip_ifindex (device), nm_device_get_ip_ifindex (slave)))
			return FALSE;

		master_connection = nm_device_get_applied_connection (device);
		nm_assert (master_connection);
		s_bridge = nm_connection_get_setting_bridge (master_connection);
		nm_assert (s_bridge);
		s_port = nm_connection_get_setting_bridge_port (connection);

		bridge_set_vlan_options (device, s_bridge);

		if (nm_setting_bridge_get_vlan_filtering (s_bridge)) {
			gs_free const NMPlatformBridgeVlan **plat_vlans = NULL;
			gs_unref_ptrarray GPtrArray *vlans = NULL;

			if (s_port)
				g_object_get (s_port, NM_SETTING_BRIDGE_PORT_VLANS, &vlans, NULL);

			plat_vlans = setting_vlans_to_platform (vlans);

			/* Since the link was just enslaved, there are no existing VLANs
			 * (except for the default one) and so there's no need to flush. */

			if (   plat_vlans
			    && !nm_platform_link_set_bridge_vlans (nm_device_get_platform (slave),
			                                           nm_device_get_ifindex (slave),
			                                           TRUE,
			                                           plat_vlans))
				return FALSE;
		}

		commit_slave_options (slave, s_port);

		_LOGI (LOGD_BRIDGE, "attached bridge port %s",
		       nm_device_get_ip_iface (slave));
	} else {
		_LOGI (LOGD_BRIDGE, "bridge port %s was attached",
		       nm_device_get_ip_iface (slave));
	}

	return TRUE;
}

static void
release_slave (NMDevice *device,
               NMDevice *slave,
               gboolean configure)
{
	NMDeviceBridge *self = NM_DEVICE_BRIDGE (device);
	gboolean success;
	int ifindex_slave;
	int ifindex;

	if (configure) {
		ifindex = nm_device_get_ifindex (device);
		if (   ifindex <= 0
		    || !nm_platform_link_get (nm_device_get_platform (device), ifindex))
			configure = FALSE;
	}

	ifindex_slave = nm_device_get_ip_ifindex (slave);

	if (ifindex_slave <= 0) {
		_LOGD (LOGD_TEAM, "bond slave %s is already released", nm_device_get_ip_iface (slave));
		return;
	}

	if (configure) {
		success = nm_platform_link_release (nm_device_get_platform (device),
		                                    nm_device_get_ip_ifindex (device),
		                                    ifindex_slave);

		if (success) {
			_LOGI (LOGD_BRIDGE, "detached bridge port %s",
			       nm_device_get_ip_iface (slave));
		} else {
			_LOGW (LOGD_BRIDGE, "failed to detach bridge port %s",
			       nm_device_get_ip_iface (slave));
		}
	} else {
		_LOGI (LOGD_BRIDGE, "bridge port %s was detached",
		       nm_device_get_ip_iface (slave));
	}
}

static gboolean
create_and_realize (NMDevice *device,
                    NMConnection *connection,
                    NMDevice *parent,
                    const NMPlatformLink **out_plink,
                    GError **error)
{
	NMSettingBridge *s_bridge;
	const char *iface = nm_device_get_iface (device);
	const char *hwaddr;
	gs_free char *hwaddr_cloned = NULL;
	guint8 mac_address[NM_UTILS_HWADDR_LEN_MAX];
	int r;

	nm_assert (iface);

	s_bridge = nm_connection_get_setting_bridge (connection);
	nm_assert (s_bridge);

	hwaddr = nm_setting_bridge_get_mac_address (s_bridge);
	if (   !hwaddr
	    && nm_device_hw_addr_get_cloned (device, connection, FALSE,
	                                     &hwaddr_cloned, NULL, NULL)) {
		/* FIXME: we set the MAC address when creating the interface, while the
		 * NMDevice is still unrealized. As we afterwards realize the device, it
		 * forgets the parameters for the cloned MAC address, and in stage 1
		 * it might create a different MAC address. That should be fixed by
		 * better handling device realization. */
		hwaddr = hwaddr_cloned;
	}

	if (hwaddr) {
		if (!nm_utils_hwaddr_aton (hwaddr, mac_address, ETH_ALEN)) {
			g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
			             "Invalid hardware address '%s'",
			             hwaddr);
			g_return_val_if_reached (FALSE);
		}
	}

	r = nm_platform_link_bridge_add (nm_device_get_platform (device),
	                                 iface,
	                                 hwaddr ? mac_address : NULL,
	                                 hwaddr ? ETH_ALEN : 0,
	                                 out_plink);
	if (r < 0) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_CREATION_FAILED,
		             "Failed to create bridge interface '%s' for '%s': %s",
		             iface,
		             nm_connection_get_id (connection),
		             nm_strerror (r));
		return FALSE;
	}

	return TRUE;
}

/*****************************************************************************/

static void
nm_device_bridge_init (NMDeviceBridge * self)
{
	nm_assert (nm_device_is_master (NM_DEVICE (self)));
}

static const NMDBusInterfaceInfoExtended interface_info_device_bridge = {
	.parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT (
		NM_DBUS_INTERFACE_DEVICE_BRIDGE,
		.signals = NM_DEFINE_GDBUS_SIGNAL_INFOS (
			&nm_signal_info_property_changed_legacy,
		),
		.properties = NM_DEFINE_GDBUS_PROPERTY_INFOS (
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("HwAddress", "s",  NM_DEVICE_HW_ADDRESS),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Carrier",   "b",  NM_DEVICE_CARRIER),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Slaves",    "ao", NM_DEVICE_SLAVES),
		),
	),
	.legacy_property_changed = TRUE,
};

static void
nm_device_bridge_class_init (NMDeviceBridgeClass *klass)
{
	NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS (&interface_info_device_bridge);

	device_class->connection_type_supported = NM_SETTING_BRIDGE_SETTING_NAME;
	device_class->link_types = NM_DEVICE_DEFINE_LINK_TYPES (NM_LINK_TYPE_BRIDGE);

	device_class->is_master = TRUE;
	device_class->get_generic_capabilities = get_generic_capabilities;
	device_class->check_connection_compatible = check_connection_compatible;
	device_class->check_connection_available = check_connection_available;
	device_class->complete_connection = complete_connection;

	device_class->update_connection = update_connection;
	device_class->master_update_slave_connection = master_update_slave_connection;

	device_class->create_and_realize = create_and_realize;
	device_class->act_stage1_prepare_set_hwaddr_ethernet = TRUE;
	device_class->act_stage1_prepare = act_stage1_prepare;
	device_class->act_stage2_config = act_stage2_config;
	device_class->deactivate = deactivate;
	device_class->enslave_slave = enslave_slave;
	device_class->release_slave = release_slave;
	device_class->get_configured_mtu = nm_device_get_configured_mtu_for_wired;
}

/*****************************************************************************/

#define NM_TYPE_BRIDGE_DEVICE_FACTORY (nm_bridge_device_factory_get_type ())
#define NM_BRIDGE_DEVICE_FACTORY(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_BRIDGE_DEVICE_FACTORY, NMBridgeDeviceFactory))

static NMDevice *
create_device (NMDeviceFactory *factory,
               const char *iface,
               const NMPlatformLink *plink,
               NMConnection *connection,
               gboolean *out_ignore)
{
	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_BRIDGE,
	                                  NM_DEVICE_IFACE, iface,
	                                  NM_DEVICE_DRIVER, "bridge",
	                                  NM_DEVICE_TYPE_DESC, "Bridge",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_BRIDGE,
	                                  NM_DEVICE_LINK_TYPE, NM_LINK_TYPE_BRIDGE,
	                                  NULL);
}

static gboolean
match_connection (NMDeviceFactory *factory,
                  NMConnection *connection)
{
	const char *type = nm_connection_get_connection_type (connection);

	if (nm_streq (type, NM_SETTING_BRIDGE_SETTING_NAME))
		return TRUE;

	nm_assert (nm_streq (type, NM_SETTING_BLUETOOTH_SETTING_NAME));

	if (!_nm_connection_get_setting_bluetooth_for_nap (connection))
		return FALSE;

	if (!g_type_from_name ("NMBluezManager")) {
		/* bluetooth NAP connections are handled by bridge factory. However,
		 * it needs help from the bluetooth plugin, so if the plugin is not loaded,
		 * we claim not to support it. */
		return FALSE;
	}

	return TRUE;
}

NM_DEVICE_FACTORY_DEFINE_INTERNAL (BRIDGE, Bridge, bridge,
	NM_DEVICE_FACTORY_DECLARE_LINK_TYPES    (NM_LINK_TYPE_BRIDGE)
	NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES (NM_SETTING_BRIDGE_SETTING_NAME, NM_SETTING_BLUETOOTH_SETTING_NAME),
	factory_class->create_device = create_device;
	factory_class->match_connection = match_connection;
);
