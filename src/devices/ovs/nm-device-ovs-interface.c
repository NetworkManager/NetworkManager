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

#include "nm-device-ovs-interface.h"
#include "nm-ovsdb.h"

#include "devices/nm-device-private.h"
#include "nm-active-connection.h"
#include "nm-setting-connection.h"
#include "nm-setting-ovs-interface.h"
#include "nm-setting-ovs-port.h"

#include "devices/nm-device-logging.h"
_LOG_DECLARE_SELF(NMDeviceOvsInterface);

/*****************************************************************************/

typedef struct {
	bool waiting_for_interface:1;
} NMDeviceOvsInterfacePrivate;

struct _NMDeviceOvsInterface {
	NMDevice parent;
	NMDeviceOvsInterfacePrivate _priv;
};

struct _NMDeviceOvsInterfaceClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDeviceOvsInterface, nm_device_ovs_interface, NM_TYPE_DEVICE)

#define NM_DEVICE_OVS_INTERFACE_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMDeviceOvsInterface, NM_IS_DEVICE_OVS_INTERFACE, NMDevice)

/*****************************************************************************/

static const char *
get_type_description (NMDevice *device)
{
	return "ovs-interface";
}

static gboolean
create_and_realize (NMDevice *device,
                    NMConnection *connection,
                    NMDevice *parent,
                    const NMPlatformLink **out_plink,
                    GError **error)
{
	/* The actual backing resources will be created once an interface is
	 * added to a port of ours, since there can be neither an empty port nor
	 * an empty bridge. */

	return TRUE;
}

static NMDeviceCapabilities
get_generic_capabilities (NMDevice *device)
{
	return NM_DEVICE_CAP_CARRIER_DETECT | NM_DEVICE_CAP_IS_SOFTWARE;
}

static gboolean
is_available (NMDevice *device, NMDeviceCheckDevAvailableFlags flags)
{
	return TRUE;
}

static gboolean
check_connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	NMSettingOvsInterface *s_ovs_iface;

	if (!NM_DEVICE_CLASS (nm_device_ovs_interface_parent_class)->check_connection_compatible (device, connection, error))
		return FALSE;

	s_ovs_iface = nm_connection_get_setting_ovs_interface (connection);

	if (!NM_IN_STRSET (nm_setting_ovs_interface_get_interface_type (s_ovs_iface),
	                   "dpdk",
	                   "internal",
	                   "patch")) {
		nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
		                            "unsupported OVS interface type in profile");
		return FALSE;
	}

	return TRUE;
}

static void
link_changed (NMDevice *device,
              const NMPlatformLink *pllink)
{
	NMDeviceOvsInterfacePrivate *priv = NM_DEVICE_OVS_INTERFACE_GET_PRIVATE (device);

	if (pllink && priv->waiting_for_interface) {
		priv->waiting_for_interface = FALSE;
		nm_device_bring_up (device, TRUE, NULL);
		nm_device_activate_schedule_stage3_ip_config_start (device);
	}
}

static gboolean
_is_internal_interface (NMDevice *device)
{
	NMSettingOvsInterface *s_ovs_iface;

	s_ovs_iface = nm_device_get_applied_setting (device, NM_TYPE_SETTING_OVS_INTERFACE);

	g_return_val_if_fail (s_ovs_iface, FALSE);

	return nm_streq (nm_setting_ovs_interface_get_interface_type (s_ovs_iface), "internal");
}

static NMActStageReturn
act_stage3_ip_config_start (NMDevice *device,
                            int addr_family,
                            gpointer *out_config,
                            NMDeviceStateReason *out_failure_reason)
{
	NMDeviceOvsInterfacePrivate *priv = NM_DEVICE_OVS_INTERFACE_GET_PRIVATE (device);

	if (!_is_internal_interface (device))
		return NM_ACT_STAGE_RETURN_IP_FAIL;

	if (nm_device_get_ip_ifindex (device) <= 0) {
		priv->waiting_for_interface = TRUE;
		return NM_ACT_STAGE_RETURN_POSTPONE;
	}

	return NM_DEVICE_CLASS (nm_device_ovs_interface_parent_class)->act_stage3_ip_config_start (device, addr_family, out_config, out_failure_reason);
}

static gboolean
can_unmanaged_external_down (NMDevice *self)
{
	return FALSE;
}

/*****************************************************************************/

static void
nm_device_ovs_interface_init (NMDeviceOvsInterface *self)
{
}

static const NMDBusInterfaceInfoExtended interface_info_device_ovs_interface = {
	.parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT (
		NM_DBUS_INTERFACE_DEVICE_OVS_INTERFACE,
		.signals = NM_DEFINE_GDBUS_SIGNAL_INFOS (
			&nm_signal_info_property_changed_legacy,
		),
	),
	.legacy_property_changed = TRUE,
};

static void
nm_device_ovs_interface_class_init (NMDeviceOvsInterfaceClass *klass)
{
	NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS (&interface_info_device_ovs_interface);

	device_class->connection_type_supported = NM_SETTING_OVS_INTERFACE_SETTING_NAME;
	device_class->connection_type_check_compatible = NM_SETTING_OVS_INTERFACE_SETTING_NAME;
	device_class->link_types = NM_DEVICE_DEFINE_LINK_TYPES (NM_LINK_TYPE_OPENVSWITCH);

	device_class->get_type_description = get_type_description;
	device_class->create_and_realize = create_and_realize;
	device_class->get_generic_capabilities = get_generic_capabilities;
	device_class->is_available = is_available;
	device_class->check_connection_compatible = check_connection_compatible;
	device_class->link_changed = link_changed;
	device_class->act_stage3_ip_config_start = act_stage3_ip_config_start;
	device_class->can_unmanaged_external_down = can_unmanaged_external_down;
}
