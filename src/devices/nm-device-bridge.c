/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright 2011 - 2015 Red Hat, Inc.
 */

#include "config.h"

#include <glib/gi18n.h>

#include <stdlib.h>

#include "nm-default.h"
#include "nm-device-bridge.h"
#include "NetworkManagerUtils.h"
#include "nm-device-private.h"
#include "nm-dbus-glib-types.h"
#include "nm-enum-types.h"
#include "nm-platform.h"
#include "nm-device-factory.h"
#include "nm-core-internal.h"

#include "nm-device-bridge-glue.h"

#include "nm-device-logging.h"
_LOG_DECLARE_SELF(NMDeviceBridge);

G_DEFINE_TYPE (NMDeviceBridge, nm_device_bridge, NM_TYPE_DEVICE)

#define NM_DEVICE_BRIDGE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_BRIDGE, NMDeviceBridgePrivate))

typedef struct {
	int dummy;
} NMDeviceBridgePrivate;

enum {
	PROP_0,
	PROP_SLAVES,

	LAST_PROP
};

/******************************************************************/

static NMDeviceCapabilities
get_generic_capabilities (NMDevice *dev)
{
	return NM_DEVICE_CAP_CARRIER_DETECT | NM_DEVICE_CAP_IS_SOFTWARE;
}

static gboolean
is_available (NMDevice *dev, NMDeviceCheckDevAvailableFlags flags)
{
	return TRUE;
}

static gboolean
check_connection_available (NMDevice *device,
                            NMConnection *connection,
                            NMDeviceCheckConAvailableFlags flags,
                            const char *specific_object)
{
	/* Connections are always available because the carrier state is determined
	 * by the bridge port carrier states, not the bridge's state.
	 */
	return TRUE;
}

static gboolean
check_connection_compatible (NMDevice *device, NMConnection *connection)
{
	const char *iface;
	NMSettingBridge *s_bridge;
	const char *mac_address;

	if (!NM_DEVICE_CLASS (nm_device_bridge_parent_class)->check_connection_compatible (device, connection))
		return FALSE;

	s_bridge = nm_connection_get_setting_bridge (connection);
	if (!s_bridge || !nm_connection_is_type (connection, NM_SETTING_BRIDGE_SETTING_NAME))
		return FALSE;

	/* Bridge connections must specify the virtual interface name */
	iface = nm_connection_get_interface_name (connection);
	if (!iface || strcmp (nm_device_get_iface (device), iface))
		return FALSE;

	mac_address = nm_setting_bridge_get_mac_address (s_bridge);
	if (mac_address) {
		const char *hw_addr;

		hw_addr = nm_device_get_hw_address (device);
		if (!hw_addr || !nm_utils_hwaddr_matches (hw_addr, -1, mac_address, -1))
			return FALSE;
	}

	return TRUE;
}

static gboolean
complete_connection (NMDevice *device,
                     NMConnection *connection,
                     const char *specific_object,
                     const GSList *existing_connections,
                     GError **error)
{
	NMSettingBridge *s_bridge;

	nm_utils_complete_generic (connection,
	                           NM_SETTING_BRIDGE_SETTING_NAME,
	                           existing_connections,
	                           NULL,
	                           _("Bridge connection"),
	                           "bridge",
	                           TRUE);

	s_bridge = nm_connection_get_setting_bridge (connection);
	if (!s_bridge) {
		s_bridge = (NMSettingBridge *) nm_setting_bridge_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_bridge));
	}

	return TRUE;
}

/******************************************************************/

typedef struct {
	const char *name;
	const char *sysname;
	gboolean default_if_zero;
	gboolean user_hz_compensate;
} Option;

static const Option master_options[] = {
	{ NM_SETTING_BRIDGE_STP, "stp_state", FALSE, FALSE },
	{ NM_SETTING_BRIDGE_PRIORITY, "priority", TRUE, FALSE },
	{ NM_SETTING_BRIDGE_FORWARD_DELAY, "forward_delay", TRUE, TRUE },
	{ NM_SETTING_BRIDGE_HELLO_TIME, "hello_time", TRUE, TRUE },
	{ NM_SETTING_BRIDGE_MAX_AGE, "max_age", TRUE, TRUE },
	{ NM_SETTING_BRIDGE_AGEING_TIME, "ageing_time", TRUE, TRUE },
	{ NM_SETTING_BRIDGE_MULTICAST_SNOOPING, "multicast_snooping", FALSE, FALSE },
	{ NULL, NULL }
};

static const Option slave_options[] = {
	{ NM_SETTING_BRIDGE_PORT_PRIORITY, "priority", TRUE, FALSE },
	{ NM_SETTING_BRIDGE_PORT_PATH_COST, "path_cost", TRUE, FALSE },
	{ NM_SETTING_BRIDGE_PORT_HAIRPIN_MODE, "hairpin_mode", FALSE, FALSE },
	{ NULL, NULL }
};

static void
commit_option (NMDevice *device, NMSetting *setting, const Option *option, gboolean slave)
{
	int ifindex = nm_device_get_ifindex (device);
	GParamSpec *pspec;
	GValue val = G_VALUE_INIT;
	guint32 uval = 0;
	gs_free char *value = NULL;

	g_assert (setting);

	pspec = g_object_class_find_property (G_OBJECT_GET_CLASS (setting), option->name);
	g_assert (pspec);

	/* Get the property's value */
	g_value_init (&val, G_PARAM_SPEC_VALUE_TYPE (pspec));
	g_object_get_property ((GObject *) setting, option->name, &val);
	if (G_VALUE_HOLDS_BOOLEAN (&val))
		uval = g_value_get_boolean (&val) ? 1 : 0;
	else if (G_VALUE_HOLDS_UINT (&val)) {
		uval = g_value_get_uint (&val);

		/* zero means "unspecified" for some NM properties but isn't in the
		 * allowed kernel range, so reset the property to the default value.
		 */
		if (option->default_if_zero && uval == 0) {
			g_value_unset (&val);
			g_value_init (&val, G_PARAM_SPEC_VALUE_TYPE (pspec));
			g_param_value_set_default (pspec, &val);
			uval = g_value_get_uint (&val);
		}

		/* Linux kernel bridge interfaces use 'centiseconds' for time-based values.
		 * In reality it's not centiseconds, but depends on HZ and USER_HZ, which
		 * is almost always works out to be a multiplier of 100, so we can assume
		 * centiseconds.  See clock_t_to_jiffies().
		 */
		if (option->user_hz_compensate)
			uval *= 100;
	} else
		g_assert_not_reached ();
	g_value_unset (&val);

	value = g_strdup_printf ("%u", uval);
	if (slave)
		nm_platform_slave_set_option (NM_PLATFORM_GET, ifindex, option->sysname, value);
	else
		nm_platform_master_set_option (NM_PLATFORM_GET, ifindex, option->sysname, value);
}

static void
commit_master_options (NMDevice *device, NMSettingBridge *setting)
{
	const Option *option;
	NMSetting *s = NM_SETTING (setting);

	for (option = master_options; option->name; option++)
		commit_option (device, s, option, FALSE);
}

static void
commit_slave_options (NMDevice *device, NMSettingBridgePort *setting)
{
	const Option *option;
	NMSetting *s, *s_clear = NULL;

	if (setting)
		s = NM_SETTING (setting);
	else
		s = s_clear = nm_setting_bridge_port_new ();

	for (option = slave_options; option->name; option++)
		commit_option (device, s, option, TRUE);

	g_clear_object (&s_clear);
}

static void
update_connection (NMDevice *device, NMConnection *connection)
{
	NMDeviceBridge *self = NM_DEVICE_BRIDGE (device);
	NMSettingBridge *s_bridge = nm_connection_get_setting_bridge (connection);
	int ifindex = nm_device_get_ifindex (device);
	const Option *option;

	if (!s_bridge) {
		s_bridge = (NMSettingBridge *) nm_setting_bridge_new ();
		nm_connection_add_setting (connection, (NMSetting *) s_bridge);
	}

	for (option = master_options; option->name; option++) {
		gs_free char *str = nm_platform_master_get_option (NM_PLATFORM_GET, ifindex, option->sysname);
		int value;

		if (str) {
			value = strtol (str, NULL, 10);

			/* See comments in set_sysfs_uint() about centiseconds. */
			if (option->user_hz_compensate)
				value /= 100;

			g_object_set (s_bridge, option->name, value, NULL);
		} else
			_LOGW (LOGD_BRIDGE, "failed to read bridge setting '%s'", option->sysname);
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
		gs_free char *str = nm_platform_slave_get_option (NM_PLATFORM_GET, ifindex_slave, option->sysname);
		int value;

		if (str) {
			value = strtol (str, NULL, 10);

			/* See comments in set_sysfs_uint() about centiseconds. */
			if (option->user_hz_compensate)
				value /= 100;

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

static NMActStageReturn
act_stage1_prepare (NMDevice *device, NMDeviceStateReason *reason)
{
	NMActStageReturn ret;
	NMConnection *connection = nm_device_get_connection (device);

	g_assert (connection);

	ret = NM_DEVICE_CLASS (nm_device_bridge_parent_class)->act_stage1_prepare (device, reason);
	if (ret != NM_ACT_STAGE_RETURN_SUCCESS)
		return ret;

	commit_master_options (device, nm_connection_get_setting_bridge (connection));

	return NM_ACT_STAGE_RETURN_SUCCESS;
}

static gboolean
enslave_slave (NMDevice *device,
               NMDevice *slave,
               NMConnection *connection,
               gboolean configure)
{
	NMDeviceBridge *self = NM_DEVICE_BRIDGE (device);

	if (configure) {
		if (!nm_platform_link_enslave (NM_PLATFORM_GET, nm_device_get_ip_ifindex (device), nm_device_get_ip_ifindex (slave)))
			return FALSE;

		commit_slave_options (slave, nm_connection_get_setting_bridge_port (connection));

		_LOGI (LOGD_BRIDGE, "attached bridge port %s",
		       nm_device_get_ip_iface (slave));
	} else {
		_LOGI (LOGD_BRIDGE, "bridge port %s was attached",
		       nm_device_get_ip_iface (slave));
	}

	g_object_notify (G_OBJECT (device), NM_DEVICE_BRIDGE_SLAVES);

	return TRUE;
}

static gboolean
release_slave (NMDevice *device,
               NMDevice *slave,
               gboolean configure)
{
	NMDeviceBridge *self = NM_DEVICE_BRIDGE (device);
	gboolean success = TRUE;

	if (configure) {
		success = nm_platform_link_release (NM_PLATFORM_GET,
		                                    nm_device_get_ip_ifindex (device),
		                                    nm_device_get_ip_ifindex (slave));

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

	g_object_notify (G_OBJECT (device), NM_DEVICE_BRIDGE_SLAVES);
	return success;
}

static gboolean
create_and_realize (NMDevice *device,
                    NMConnection *connection,
                    NMDevice *parent,
                    NMPlatformLink *out_plink,
                    GError **error)
{
	NMSettingBridge *s_bridge;
	const char *iface = nm_device_get_iface (device);
	const char *hwaddr;
	guint8 mac_address[NM_UTILS_HWADDR_LEN_MAX];
	NMPlatformError plerr;

	g_assert (iface);
	g_assert (nm_device_get_ifindex (device) <= 0);
	g_assert (out_plink);

	s_bridge = nm_connection_get_setting_bridge (connection);
	g_assert (s_bridge);
	hwaddr = nm_setting_bridge_get_mac_address (s_bridge);
	if (hwaddr) {
		if (!nm_utils_hwaddr_aton (hwaddr, mac_address, ETH_ALEN)) {
			g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
			             "Invalid hardware address '%s'",
			             hwaddr);
			return FALSE;
		}
	}

	plerr = nm_platform_bridge_add (NM_PLATFORM_GET,
	                                iface,
	                                hwaddr ? mac_address : NULL,
	                                hwaddr ? ETH_ALEN : 0,
	                                out_plink);
	if (plerr != NM_PLATFORM_ERROR_SUCCESS && plerr != NM_PLATFORM_ERROR_EXISTS) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_CREATION_FAILED,
		             "Failed to create bridge interface '%s' for '%s': %s",
		             iface,
		             nm_connection_get_id (connection),
		             nm_platform_error_to_string (plerr));
		return FALSE;
	}

	return TRUE;
}

/******************************************************************/

static void
nm_device_bridge_init (NMDeviceBridge * self)
{
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	GSList *list;

	switch (prop_id) {
		break;
	case PROP_SLAVES:
		list = nm_device_master_get_slaves (NM_DEVICE (object));
		nm_utils_g_value_set_object_path_array (value, list);
		g_slist_free (list);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object, guint prop_id,
			  const GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_device_bridge_class_init (NMDeviceBridgeClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *parent_class = NM_DEVICE_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMDeviceBridgePrivate));

	parent_class->connection_type = NM_SETTING_BRIDGE_SETTING_NAME;

	/* virtual methods */
	object_class->get_property = get_property;
	object_class->set_property = set_property;

	parent_class->get_generic_capabilities = get_generic_capabilities;
	parent_class->is_available = is_available;
	parent_class->check_connection_compatible = check_connection_compatible;
	parent_class->check_connection_available = check_connection_available;
	parent_class->complete_connection = complete_connection;

	parent_class->update_connection = update_connection;
	parent_class->master_update_slave_connection = master_update_slave_connection;

	parent_class->create_and_realize = create_and_realize;
	parent_class->act_stage1_prepare = act_stage1_prepare;
	parent_class->enslave_slave = enslave_slave;
	parent_class->release_slave = release_slave;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_SLAVES,
		 g_param_spec_boxed (NM_DEVICE_BRIDGE_SLAVES, "", "",
		                     DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (klass),
	                                        &dbus_glib_nm_device_bridge_object_info);
}

/*************************************************************/

#define NM_TYPE_BRIDGE_FACTORY (nm_bridge_factory_get_type ())
#define NM_BRIDGE_FACTORY(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_BRIDGE_FACTORY, NMBridgeFactory))

static NMDevice *
create_device (NMDeviceFactory *factory,
               const char *iface,
               NMPlatformLink *plink,
               NMConnection *connection,
               gboolean *out_ignore)
{
	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_BRIDGE,
	                                  NM_DEVICE_IFACE, iface,
	                                  NM_DEVICE_DRIVER, "bridge",
	                                  NM_DEVICE_TYPE_DESC, "Bridge",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_BRIDGE,
	                                  NM_DEVICE_IS_MASTER, TRUE,
	                                  NULL);
}

NM_DEVICE_FACTORY_DEFINE_INTERNAL (BRIDGE, Bridge, bridge,
	NM_DEVICE_FACTORY_DECLARE_LINK_TYPES    (NM_LINK_TYPE_BRIDGE)
	NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES (NM_SETTING_BRIDGE_SETTING_NAME),
	factory_iface->create_device = create_device;
	)

