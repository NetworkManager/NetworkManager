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
 * Copyright 2011 Red Hat, Inc.
 */

#include "config.h"

#include <glib.h>
#include <glib/gi18n.h>

#include <linux/if_infiniband.h>

#include "nm-device-infiniband.h"
#include "nm-logging.h"
#include "nm-utils.h"
#include "NetworkManagerUtils.h"
#include "nm-device-private.h"
#include "nm-enum-types.h"
#include "nm-dbus-manager.h"
#include "nm-activation-request.h"
#include "nm-ip4-config.h"
#include "nm-platform.h"

#include "nm-device-infiniband-glue.h"


G_DEFINE_TYPE (NMDeviceInfiniband, nm_device_infiniband, NM_TYPE_DEVICE)

#define NM_DEVICE_INFINIBAND_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_INFINIBAND, NMDeviceInfinibandPrivate))

#define NM_INFINIBAND_ERROR (nm_infiniband_error_quark ())

typedef struct {
	int dummy;
} NMDeviceInfinibandPrivate;

enum {
	PROP_0,

	LAST_PROP
};

static GQuark
nm_infiniband_error_quark (void)
{
	static GQuark quark = 0;
	if (!quark)
		quark = g_quark_from_static_string ("nm-infiniband-error");
	return quark;
}

static void
nm_device_infiniband_init (NMDeviceInfiniband * self)
{
}

NMDevice *
nm_device_infiniband_new (NMPlatformLink *platform_device)
{
	g_return_val_if_fail (platform_device != NULL, NULL);

	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_INFINIBAND,
	                                  NM_DEVICE_PLATFORM_DEVICE, platform_device,
	                                  NM_DEVICE_TYPE_DESC, "InfiniBand",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_INFINIBAND,
	                                  NULL);
}

NMDevice *
nm_device_infiniband_new_partition (NMConnection *connection,
                                    NMDevice     *parent)
{
	NMSettingInfiniband *s_infiniband;
	int p_key, parent_ifindex;
	const char *iface;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (NM_IS_DEVICE_INFINIBAND (parent), NULL);

	iface = nm_connection_get_virtual_iface_name (connection);
	g_return_val_if_fail (iface != NULL, NULL);

	parent_ifindex = nm_device_get_ifindex (parent);
	s_infiniband = nm_connection_get_setting_infiniband (connection);
	p_key = nm_setting_infiniband_get_p_key (s_infiniband);

	if (   !nm_platform_infiniband_partition_add (parent_ifindex, p_key)
	    && nm_platform_get_error () != NM_PLATFORM_ERROR_EXISTS) {
		nm_log_warn (LOGD_DEVICE | LOGD_INFINIBAND, "(%s): failed to add InfiniBand P_Key interface for '%s': %s",
		             iface, nm_connection_get_id (connection),
		             nm_platform_get_error_msg ());
		return NULL;
	}

	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_INFINIBAND,
	                                  NM_DEVICE_IFACE, iface,
	                                  NM_DEVICE_DRIVER, nm_device_get_driver (parent),
	                                  NM_DEVICE_TYPE_DESC, "InfiniBand",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_INFINIBAND,
	                                  NULL);
}

static guint32
get_generic_capabilities (NMDevice *dev)
{
	return NM_DEVICE_CAP_CARRIER_DETECT;
}

static NMActStageReturn
act_stage1_prepare (NMDevice *dev, NMDeviceStateReason *reason)
{
	NMActStageReturn ret;
	NMActRequest *req;
	NMConnection *connection;
	NMSettingInfiniband *s_infiniband;
	const char *transport_mode;
	char *mode_path;
	gboolean ok;

	g_return_val_if_fail (reason != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	ret = NM_DEVICE_CLASS (nm_device_infiniband_parent_class)->act_stage1_prepare (dev, reason);
	if (ret != NM_ACT_STAGE_RETURN_SUCCESS)
		return ret;

	req = nm_device_get_act_request (dev);
	g_return_val_if_fail (req != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	connection = nm_act_request_get_connection (req);
	g_assert (connection);
	s_infiniband = nm_connection_get_setting_infiniband (connection);
	g_assert (s_infiniband);

	transport_mode = nm_setting_infiniband_get_transport_mode (s_infiniband);

	mode_path = g_strdup_printf ("/sys/class/net/%s/mode",
	                             ASSERT_VALID_PATH_COMPONENT (nm_device_get_iface (dev)));
	if (!g_file_test (mode_path, G_FILE_TEST_EXISTS)) {
		g_free (mode_path);

		if (!strcmp (transport_mode, "datagram"))
			return NM_ACT_STAGE_RETURN_SUCCESS;
		else {
			*reason = NM_DEVICE_STATE_REASON_INFINIBAND_MODE;
			return NM_ACT_STAGE_RETURN_FAILURE;
		}
	}

	ok = nm_platform_sysctl_set (mode_path, transport_mode);
	g_free (mode_path);

	if (!ok) {
		*reason = NM_DEVICE_STATE_REASON_CONFIG_FAILED;
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	return NM_ACT_STAGE_RETURN_SUCCESS;
}

static void
ip4_config_pre_commit (NMDevice *self, NMIP4Config *config)
{
	NMConnection *connection;
	NMSettingInfiniband *s_infiniband;
	guint32 mtu;

	connection = nm_device_get_connection (self);
	g_assert (connection);
	s_infiniband = nm_connection_get_setting_infiniband (connection);
	g_assert (s_infiniband);

	/* MTU override */
	mtu = nm_setting_infiniband_get_mtu (s_infiniband);
	if (mtu)
		nm_ip4_config_set_mtu (config, mtu);
}

static gboolean
check_connection_compatible (NMDevice *device, NMConnection *connection)
{
	NMSettingInfiniband *s_infiniband;
	const GByteArray *mac;

	if (!NM_DEVICE_CLASS (nm_device_infiniband_parent_class)->check_connection_compatible (device, connection))
		return FALSE;

	if (!nm_connection_is_type (connection, NM_SETTING_INFINIBAND_SETTING_NAME))
		return FALSE;

	s_infiniband = nm_connection_get_setting_infiniband (connection);
	if (!s_infiniband)
		return FALSE;

	if (s_infiniband) {
		mac = nm_setting_infiniband_get_mac_address (s_infiniband);
		if (mac && !nm_utils_hwaddr_matches (mac->data, mac->len,
		                                     nm_device_get_hw_address (device), -1))
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
	NMSettingInfiniband *s_infiniband;
	const GByteArray *setting_mac;
	const char *hw_address;

	nm_utils_complete_generic (connection,
	                           NM_SETTING_INFINIBAND_SETTING_NAME,
	                           existing_connections,
	                           _("InfiniBand connection %d"),
	                           NULL,
	                           TRUE);

	s_infiniband = nm_connection_get_setting_infiniband (connection);
	if (!s_infiniband) {
		s_infiniband = (NMSettingInfiniband *) nm_setting_infiniband_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_infiniband));
	}

	setting_mac = nm_setting_infiniband_get_mac_address (s_infiniband);
	hw_address = nm_device_get_hw_address (device);
	if (setting_mac) {
		/* Make sure the setting MAC (if any) matches the device's MAC */
		if (!nm_utils_hwaddr_matches (setting_mac->data, setting_mac->len, hw_address, INFINIBAND_ALEN)) {
			g_set_error_literal (error,
			                     NM_SETTING_INFINIBAND_ERROR,
			                     NM_SETTING_INFINIBAND_ERROR_INVALID_PROPERTY,
			                     NM_SETTING_INFINIBAND_MAC_ADDRESS);
			return FALSE;
		}
	} else {
		GByteArray *mac;

		/* Lock the connection to this device by default */
		mac = nm_utils_hwaddr_atoba (hw_address, INFINIBAND_ALEN);
		g_object_set (G_OBJECT (s_infiniband), NM_SETTING_INFINIBAND_MAC_ADDRESS, mac, NULL);
		g_byte_array_free (mac, TRUE);
	}

	if (!nm_setting_infiniband_get_transport_mode (s_infiniband))
		g_object_set (G_OBJECT (s_infiniband), NM_SETTING_INFINIBAND_TRANSPORT_MODE, "datagram", NULL);

	return TRUE;
}

static void
update_connection (NMDevice *device, NMConnection *connection)
{
	NMSettingInfiniband *s_infiniband = nm_connection_get_setting_infiniband (connection);
	const char *mac = nm_device_get_hw_address (device);
	GByteArray *array;
	char *mode_path, *contents = NULL;
	const char *transport_mode = "datagram";

	if (!s_infiniband) {
		s_infiniband = (NMSettingInfiniband *) nm_setting_infiniband_new ();
		nm_connection_add_setting (connection, (NMSetting *) s_infiniband);
	}

	if (mac && !nm_utils_hwaddr_matches (mac, -1, NULL, INFINIBAND_ALEN)) {
		array = nm_utils_hwaddr_atoba (mac, INFINIBAND_ALEN);
		g_object_set (s_infiniband, NM_SETTING_INFINIBAND_MAC_ADDRESS, array, NULL);
		g_byte_array_unref (array);
	}

	mode_path = g_strdup_printf ("/sys/class/net/%s/mode",
	                             ASSERT_VALID_PATH_COMPONENT (nm_device_get_iface (device)));
	contents = nm_platform_sysctl_get (mode_path);
	g_free (mode_path);
	if (contents) {
		if (strstr (contents, "datagram"))
			transport_mode = "datagram";
		else if (strstr (contents, "connected"))
			transport_mode = "connected";
		g_free (contents);
	}
	g_object_set (G_OBJECT (s_infiniband), NM_SETTING_INFINIBAND_TRANSPORT_MODE, transport_mode, NULL);
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
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
nm_device_infiniband_class_init (NMDeviceInfinibandClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *parent_class = NM_DEVICE_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMDeviceInfinibandPrivate));

	/* virtual methods */
	object_class->get_property = get_property;
	object_class->set_property = set_property;

	parent_class->get_generic_capabilities = get_generic_capabilities;
	parent_class->check_connection_compatible = check_connection_compatible;
	parent_class->complete_connection = complete_connection;
	parent_class->update_connection = update_connection;

	parent_class->act_stage1_prepare = act_stage1_prepare;
	parent_class->ip4_config_pre_commit = ip4_config_pre_commit;

	/* properties */

	nm_dbus_manager_register_exported_type (nm_dbus_manager_get (),
	                                        G_TYPE_FROM_CLASS (klass),
	                                        &dbus_glib_nm_device_infiniband_object_info);

	dbus_g_error_domain_register (NM_INFINIBAND_ERROR, NULL, NM_TYPE_INFINIBAND_ERROR);
}
