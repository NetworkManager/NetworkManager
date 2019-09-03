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
 * Copyright 2019 Red Hat, Inc.
 */

#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

#include "nm-default.h"

#include "nm-device-contrail-vrouter.h"

#include "devices/nm-device-private.h"
#include "nm-active-connection.h"
#include "nm-setting-connection.h"
#include "nm-setting-contrail-vrouter.h"

#include "devices/nm-device-logging.h"
_LOG_DECLARE_SELF(NMDeviceContrailVrouter);

/*****************************************************************************/

typedef struct {
	bool waiting_for_interface:1;
} NMDeviceContrailVrouterPrivate;

struct _NMDeviceContrailVrouter {
	NMDevice parent;
	NMDeviceContrailVrouterPrivate _priv;
};

struct _NMDeviceContrailVrouterClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDeviceContrailVrouter, nm_device_contrail_vrouter, NM_TYPE_DEVICE)

#define NM_DEVICE_CONTRAIL_VROUTER_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMDeviceContrailVrouter, NM_IS_DEVICE_CONTRAIL_VROUTER, NMDevice)

/*****************************************************************************/

void
_get_mac (const char *physdev, char *mac_str)
{
	struct ifreq ifr;
	int fd;
	unsigned char *mac;
	int i;
	char *pos;

	nm_log_dbg (LOGD_DEVICE, "CONTRAIL: %s %s", __FILE__ , __func__);

	memset(&ifr, 0, sizeof(ifr));
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name , physdev , IFNAMSIZ-1);
	if (0 == ioctl(fd, SIOCGIFHWADDR, &ifr)) {
		mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
		i = 0;
		pos = mac_str;
		for ( ; i < 6; i++) {
			if (i) {
				pos += sprintf(pos, ":");
			}
			pos += sprintf(pos, "%02X", (unsigned char)mac[i]);
		}
	}
	close(fd);
}

void
_get_command (const char *iface,
              const char *physdev,
              char *command,
              const int command_size)
{
	char mac_str[19];

	nm_log_dbg (LOGD_DEVICE, "CONTRAIL: %s %s", __FILE__ , __func__);

	_get_mac(physdev, mac_str);
	nm_log_dbg (LOGD_DEVICE, "CONTRAIL: mac address: %s", mac_str);

	snprintf(command, command_size,
			"modprobe vrouter && "
			"vif --create %s --mac %s 2>&1 && "
			"vif --add %s --mac %s --vrf 0 --vhost-phys --type physical 2>&1 && "
			"vif --add %s --mac %s --vrf 0 --type vhost --xconnect %s 2>&1 && "
			"ip link set dev %s address %s 2>&1 && "
			"ip link set dev %s up 2>&1",
			iface, mac_str,
			physdev, mac_str,
			iface, mac_str, physdev,
			iface, mac_str,
			iface);
}

/*********************************************************************************/

static const char *
get_type_description (NMDevice *device)
{
	nm_log_dbg (LOGD_DEVICE, "CONTRAIL: %s %s", __FILE__ , __func__);

	return "contrail-vrouter";
}

static gboolean
create_and_realize (NMDevice *device,
                    NMConnection *connection,
                    NMDevice *parent,
                    const NMPlatformLink **out_plink,
                    GError **error)
{
	nm_log_dbg (LOGD_DEVICE, "CONTRAIL: %s %s", __FILE__ , __func__);

	return TRUE;
}

static NMDeviceCapabilities
get_generic_capabilities (NMDevice *device)
{
	nm_log_dbg (LOGD_DEVICE, "CONTRAIL: %s %s", __FILE__ , __func__);

	return NM_DEVICE_CAP_IS_SOFTWARE;
}

static gboolean
is_available (NMDevice *device, NMDeviceCheckDevAvailableFlags flags)
{
	nm_log_dbg (LOGD_DEVICE, "CONTRAIL: %s %s", __FILE__ , __func__);

	return TRUE;
}

static gboolean
check_connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	nm_log_dbg (LOGD_DEVICE, "CONTRAIL: %s %s", __FILE__ , __func__);

	return TRUE;
}

static void
link_changed (NMDevice *device,
              const NMPlatformLink *pllink)
{
	nm_log_dbg (LOGD_DEVICE, "CONTRAIL: %s %s", __FILE__ , __func__);

	NMDeviceContrailVrouterPrivate *priv = NM_DEVICE_CONTRAIL_VROUTER_GET_PRIVATE (device);

	if (pllink && priv->waiting_for_interface) {
		priv->waiting_for_interface = FALSE;
		nm_device_bring_up (device, TRUE, NULL);
		nm_device_activate_schedule_stage3_ip_config_start (device);
	}
}

static NMActStageReturn
act_stage1_prepare (NMDevice *device, NMDeviceStateReason *out_failure_reason)
{
	FILE *fp;
	int COMMAND_OUTPUT_SIZE = 512;
	char output[COMMAND_OUTPUT_SIZE];
	const char *iface;
	int COMMAND_SIZE = 512;
	const char command[COMMAND_SIZE];
	const char *physdev;

	nm_log_dbg (LOGD_DEVICE, "CONTRAIL: %s %s", __FILE__ , __func__);

	if (!device) {
		nm_log_err (LOGD_DEVICE, "CONTRAIL: device is null");
		return NM_ACT_STAGE_RETURN_FAILURE;
	}
	NMConnection *connection = nm_device_get_applied_connection (device);
	if (!connection) {
		nm_log_err (LOGD_DEVICE, "CONTRAIL: connection is null");
		return NM_ACT_STAGE_RETURN_FAILURE;
	}
	nm_connection_dump (connection);
	iface = nm_connection_get_interface_name (connection);
	nm_log_dbg (LOGD_DEVICE, "CONTRAIL: interface name: %s", iface);
	physdev = nm_setting_contrail_vrouter_get_physdev (nm_connection_get_setting_contrail_vrouter (connection));
	if (physdev) {
		nm_log_dbg (LOGD_DEVICE, "CONTRAIL: physical device name: %s", physdev);
		_get_command(iface, physdev, command, COMMAND_SIZE);
		nm_log_dbg (LOGD_DEVICE, "CONTRAIL: vrouter command: %s", command);
		fp = popen(command, "r");
		while (fgets(output, COMMAND_OUTPUT_SIZE, fp) != NULL){
			nm_log_err (LOGD_DEVICE, "CONTRAIL: %s", output);
		}
		pclose(fp);
	}
	else {
		nm_log_err (LOGD_DEVICE, "CONTRAIL: physical device name was not provided.");
		return NM_ACT_STAGE_RETURN_FAILURE;
	}
	return NM_ACT_STAGE_RETURN_SUCCESS;
}

static NMActStageReturn
act_stage3_ip4_config_start (NMDevice *device,
                             NMIP4Config **out_config,
                             NMDeviceStateReason *out_failure_reason)
{
	nm_log_dbg (LOGD_DEVICE, "CONTRAIL: %s %s", __FILE__ , __func__);

	NMDeviceContrailVrouterPrivate *priv = NM_DEVICE_CONTRAIL_VROUTER_GET_PRIVATE (device);

	if (!nm_device_get_ip_ifindex (device)) {
		priv->waiting_for_interface = TRUE;
		return NM_ACT_STAGE_RETURN_POSTPONE;
	}

	return NM_DEVICE_CLASS (nm_device_contrail_vrouter_parent_class)->act_stage3_ip4_config_start (device, out_config, out_failure_reason);
}

static NMActStageReturn
act_stage3_ip6_config_start (NMDevice *device,
                             NMIP6Config **out_config,
                             NMDeviceStateReason *out_failure_reason)
{
	nm_log_dbg (LOGD_DEVICE, "CONTRAIL: %s %s", __FILE__ , __func__);

	NMDeviceContrailVrouterPrivate *priv = NM_DEVICE_CONTRAIL_VROUTER_GET_PRIVATE (device);

	if (!nm_device_get_ip_ifindex (device)) {
		priv->waiting_for_interface = TRUE;
		return NM_ACT_STAGE_RETURN_POSTPONE;
	}

	return NM_DEVICE_CLASS (nm_device_contrail_vrouter_parent_class)->act_stage3_ip6_config_start (device, out_config, out_failure_reason);
}

static gboolean
can_unmanaged_external_down (NMDevice *self)
{
	nm_log_dbg (LOGD_DEVICE, "CONTRAIL: %s %s", __FILE__ , __func__);

	return FALSE;
}

/*****************************************************************************/

static void
nm_device_contrail_vrouter_init (NMDeviceContrailVrouter *self)
{
	nm_log_dbg (LOGD_DEVICE, "CONTRAIL: %s %s", __FILE__ , __func__);
}

static const NMDBusInterfaceInfoExtended interface_info_device_contrail_vrouter = {
	.parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT (
		NM_DBUS_INTERFACE_DEVICE_CONTRAIL_VROUTER,
		.signals = NM_DEFINE_GDBUS_SIGNAL_INFOS (
			&nm_signal_info_property_changed_legacy,
		),
	),
	.legacy_property_changed = TRUE,
};

static void
nm_device_contrail_vrouter_class_init (NMDeviceContrailVrouterClass *klass)
{
	NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS (&interface_info_device_contrail_vrouter);

	device_class->connection_type_supported = NM_SETTING_CONTRAIL_VROUTER_SETTING_NAME;
	device_class->connection_type_check_compatible = NM_SETTING_CONTRAIL_VROUTER_SETTING_NAME;
	device_class->link_types = NM_DEVICE_DEFINE_LINK_TYPES (NM_LINK_TYPE_CONTRAILVROUTER);

	device_class->get_type_description = get_type_description;
	device_class->create_and_realize = create_and_realize;
	device_class->get_generic_capabilities = get_generic_capabilities;
	device_class->is_available = is_available;
	device_class->check_connection_compatible = check_connection_compatible;
	device_class->link_changed = link_changed;
	device_class->act_stage1_prepare = act_stage1_prepare;
	device_class->act_stage3_ip4_config_start = act_stage3_ip4_config_start;
	device_class->act_stage3_ip6_config_start = act_stage3_ip6_config_start;
	device_class->can_unmanaged_external_down = can_unmanaged_external_down;
}
