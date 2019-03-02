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
 * Copyright 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-device-ovs-bridge.h"
#include "nm-device-ovs-port.h"
#include "nm-ovsdb.h"

#include "devices/nm-device-private.h"
#include "nm-active-connection.h"
#include "nm-setting-connection.h"
#include "nm-setting-ovs-bridge.h"

#include "devices/nm-device-logging.h"
_LOG_DECLARE_SELF (NMDeviceOvsBridge);

/*****************************************************************************/

struct _NMDeviceOvsBridge {
	NMDevice parent;
};

struct _NMDeviceOvsBridgeClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDeviceOvsBridge, nm_device_ovs_bridge, NM_TYPE_DEVICE)

/*****************************************************************************/

static const char *
get_type_description (NMDevice *device)
{
	return "ovs-bridge";
}

static gboolean
create_and_realize (NMDevice *device,
                    NMConnection *connection,
                    NMDevice *parent,
                    const NMPlatformLink **out_plink,
                    GError **error)
{
	/* The actual backing resources will be created on enslavement by the port
	 * when it can identify the port and the bridge. */

	return TRUE;
}

static gboolean
unrealize (NMDevice *device, GError **error)
{
	return TRUE;
}

static NMDeviceCapabilities
get_generic_capabilities (NMDevice *device)
{
	return NM_DEVICE_CAP_IS_SOFTWARE;
}

static NMActStageReturn
act_stage3_ip_config_start (NMDevice *device,
                            int addr_family,
                            gpointer *out_config,
                            NMDeviceStateReason *out_failure_reason)
{
	return NM_ACT_STAGE_RETURN_IP_FAIL;
}

static gboolean
enslave_slave (NMDevice *device, NMDevice *slave, NMConnection *connection, gboolean configure)
{
	if (!configure)
		return TRUE;

	if (!NM_IS_DEVICE_OVS_PORT (slave))
		return FALSE;

	return TRUE;
}

static void
release_slave (NMDevice *device, NMDevice *slave, gboolean configure)
{
}

/*****************************************************************************/

static void
nm_device_ovs_bridge_init (NMDeviceOvsBridge *self)
{
}

static const NMDBusInterfaceInfoExtended interface_info_device_ovs_bridge = {
	.parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT (
		NM_DBUS_INTERFACE_DEVICE_OVS_BRIDGE,
		.properties = NM_DEFINE_GDBUS_PROPERTY_INFOS (
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE ("Slaves", "ao", NM_DEVICE_SLAVES),
		),
		.signals = NM_DEFINE_GDBUS_SIGNAL_INFOS (
			&nm_signal_info_property_changed_legacy,
		),
	),
	.legacy_property_changed = TRUE,
};

static void
nm_device_ovs_bridge_class_init (NMDeviceOvsBridgeClass *klass)
{
	NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS (&interface_info_device_ovs_bridge);

	device_class->connection_type_supported = NM_SETTING_OVS_BRIDGE_SETTING_NAME;
	device_class->connection_type_check_compatible = NM_SETTING_OVS_BRIDGE_SETTING_NAME;
	device_class->link_types = NM_DEVICE_DEFINE_LINK_TYPES ();

	device_class->is_master = TRUE;
	device_class->get_type_description = get_type_description;
	device_class->create_and_realize = create_and_realize;
	device_class->unrealize = unrealize;
	device_class->get_generic_capabilities = get_generic_capabilities;
	device_class->act_stage3_ip_config_start = act_stage3_ip_config_start;
	device_class->enslave_slave = enslave_slave;
	device_class->release_slave = release_slave;
}
