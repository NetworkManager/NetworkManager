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
 * Copyright 2018 Lubomir Rintel <lkundrak@v3.sk>
 */

#include "nm-default.h"

#include "nm-manager.h"
#include "nm-device-wpan.h"

#include <stdlib.h>
#include <sys/types.h>
#include <linux/if.h>

#include "nm-act-request.h"
#include "nm-device-private.h"
#include "nm-ip4-config.h"
#include "platform/nm-platform.h"
#include "nm-device-factory.h"
#include "nm-setting-wpan.h"
#include "nm-core-internal.h"

#include "nm-device-logging.h"
_LOG_DECLARE_SELF(NMDeviceWpan);

/*****************************************************************************/

struct _NMDeviceWpan {
	NMDevice parent;
};

struct _NMDeviceWpanClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDeviceWpan, nm_device_wpan, NM_TYPE_DEVICE)

/*****************************************************************************/

static gboolean
complete_connection (NMDevice *device,
                     NMConnection *connection,
                     const char *specific_object,
                     NMConnection *const*existing_connections,
                     GError **error)
{
	NMSettingWpan *s_wpan;

	nm_utils_complete_generic (nm_device_get_platform (device),
	                           connection,
	                           NM_SETTING_WPAN_SETTING_NAME,
	                           existing_connections,
	                           NULL,
	                           _("WPAN connection"),
	                           NULL,
	                           NULL,
	                           TRUE);

	s_wpan = NM_SETTING_WPAN (nm_connection_get_setting (connection, NM_TYPE_SETTING_WPAN));
	if (!s_wpan) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INVALID_CONNECTION,
		                     "A 'wpan' setting is required.");
		return FALSE;
	}

	return TRUE;
}

static void
update_connection (NMDevice *device, NMConnection *connection)
{
	NMSettingWpan *s_wpan = NM_SETTING_WPAN (nm_connection_get_setting (connection, NM_TYPE_SETTING_WPAN));

	if (!s_wpan) {
		s_wpan = (NMSettingWpan *) nm_setting_wpan_new ();
		nm_connection_add_setting (connection, (NMSetting *) s_wpan);
	}
}

static gboolean
check_connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	NMSettingWpan *s_wpan;
	const char *mac, *hw_addr;

	if (!NM_DEVICE_CLASS (nm_device_wpan_parent_class)->check_connection_compatible (device, connection, error))
		return FALSE;

	s_wpan = NM_SETTING_WPAN (nm_connection_get_setting (connection, NM_TYPE_SETTING_WPAN));

	mac = nm_setting_wpan_get_mac_address (s_wpan);
	if (mac) {
		hw_addr = nm_device_get_hw_address (device);
		if (!nm_utils_hwaddr_matches (mac, -1, hw_addr, -1)) {
			nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
			                            "MAC address mismatches");
			return FALSE;
		}
	}

	return TRUE;
}

static NMActStageReturn
act_stage1_prepare (NMDevice *device, NMDeviceStateReason *out_failure_reason)
{
	NMDeviceWpan *self = NM_DEVICE_WPAN (device);
	NMSettingWpan *s_wpan;
	NMPlatform *platform;
	guint16 pan_id;
	guint16 short_address;
	gint16 page, channel;
	int ifindex;
	const guint8 *hwaddr;
	gsize hwaddr_len = 0;
	const NMPlatformLink *lowpan_plink;
	NMDevice *lowpan_device = NULL;
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;

	ret = NM_DEVICE_CLASS (nm_device_wpan_parent_class)->act_stage1_prepare (device, out_failure_reason);
	if (ret != NM_ACT_STAGE_RETURN_SUCCESS)
		return ret;

	platform = nm_device_get_platform (device);
	g_return_val_if_fail (platform, NM_ACT_STAGE_RETURN_FAILURE);

	ifindex = nm_device_get_ifindex (device);

	g_return_val_if_fail (ifindex > 0, NM_ACT_STAGE_RETURN_FAILURE);

	s_wpan = nm_device_get_applied_setting (device, NM_TYPE_SETTING_WPAN);

	g_return_val_if_fail (s_wpan, NM_ACT_STAGE_RETURN_FAILURE);

	hwaddr = nm_platform_link_get_address (platform, ifindex, &hwaddr_len);
	g_return_val_if_fail (hwaddr, NM_ACT_STAGE_RETURN_FAILURE);

	/* As of kernel 4.16, the 6LoWPAN devices layered on top of WPANs
	 * need to be DOWN as well as the WPAN device itself in order to
	 * modify the WPAN properties. */
	lowpan_plink = nm_platform_link_get_by_address (platform,
	                                                NM_LINK_TYPE_6LOWPAN,
	                                                hwaddr,
	                                                hwaddr_len);
	if (lowpan_plink && NM_FLAGS_HAS (lowpan_plink->n_ifi_flags, IFF_UP)) {
		lowpan_device = nm_manager_get_device_by_ifindex (nm_manager_get (),
		                                                  lowpan_plink->ifindex);
	}

	if (lowpan_device)
		nm_device_take_down (lowpan_device, TRUE);

	nm_device_take_down (device, TRUE);

	pan_id = nm_setting_wpan_get_pan_id (s_wpan);
	if (pan_id != G_MAXUINT16) {
		if (!nm_platform_wpan_set_pan_id (platform, ifindex, pan_id)) {
			_LOGW (LOGD_DEVICE, "unable to set the PAN ID");
			goto out;
		}
	}

	short_address = nm_setting_wpan_get_short_address (s_wpan);
	if (short_address != G_MAXUINT16) {
		if (!nm_platform_wpan_set_short_addr (platform, ifindex, short_address)) {
			_LOGW (LOGD_DEVICE, "unable to set the short address");
			goto out;
		}
	}

	channel = nm_setting_wpan_get_channel (s_wpan);
	if (channel != NM_SETTING_WPAN_CHANNEL_DEFAULT) {
		page = nm_setting_wpan_get_page (s_wpan);
		if (!nm_platform_wpan_set_channel (platform, ifindex, page, channel)) {
			_LOGW (LOGD_DEVICE, "unable to set the channel");
			goto out;
		}
	}

	ret = NM_ACT_STAGE_RETURN_SUCCESS;
out:
	nm_device_bring_up (device, TRUE, NULL);

	if (lowpan_device)
		nm_device_bring_up (lowpan_device, TRUE, NULL);

	return ret;
}

/*****************************************************************************/

static void
nm_device_wpan_init (NMDeviceWpan *self)
{
}

static const NMDBusInterfaceInfoExtended interface_info_device_wpan = {
	.parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT (
		NM_DBUS_INTERFACE_DEVICE_WPAN,
		.properties = NM_DEFINE_GDBUS_PROPERTY_INFOS (
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE ("HwAddress", "s", NM_DEVICE_HW_ADDRESS),
		),
	),
};

static void
nm_device_wpan_class_init (NMDeviceWpanClass *klass)
{
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);
	NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS (klass);

	dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS (&interface_info_device_wpan);

	device_class->connection_type_supported = NM_SETTING_WPAN_SETTING_NAME;
	device_class->connection_type_check_compatible = NM_SETTING_WPAN_SETTING_NAME;
	device_class->link_types = NM_DEVICE_DEFINE_LINK_TYPES (NM_LINK_TYPE_WPAN);

	device_class->complete_connection = complete_connection;
	device_class->check_connection_compatible = check_connection_compatible;
	device_class->update_connection = update_connection;
	device_class->act_stage1_prepare = act_stage1_prepare;
}

/*****************************************************************************/

#define NM_TYPE_WPAN_DEVICE_FACTORY (nm_wpan_device_factory_get_type ())
#define NM_WPAN_DEVICE_FACTORY(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_WPAN_DEVICE_FACTORY, NMWpanDeviceFactory))

static NMDevice *
create_device (NMDeviceFactory *factory,
               const char *iface,
               const NMPlatformLink *plink,
               NMConnection *connection,
               gboolean *out_ignore)
{
	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_WPAN,
	                                  NM_DEVICE_IFACE, iface,
	                                  NM_DEVICE_TYPE_DESC, "WPAN",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_WPAN,
	                                  NM_DEVICE_LINK_TYPE, NM_LINK_TYPE_WPAN,
	                                  NULL);
}

NM_DEVICE_FACTORY_DEFINE_INTERNAL (WPAN, Wpan, wpan,
	NM_DEVICE_FACTORY_DECLARE_LINK_TYPES (NM_LINK_TYPE_WPAN)
	NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES (NM_SETTING_WPAN_SETTING_NAME),
	factory_class->create_device = create_device;
);
