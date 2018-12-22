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
 * Copyright 2011 - 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-device-infiniband.h"

#include <linux/if.h>
#include <linux/if_infiniband.h>

#include "NetworkManagerUtils.h"
#include "nm-device-private.h"
#include "nm-act-request.h"
#include "nm-ip4-config.h"
#include "platform/nm-platform.h"
#include "nm-device-factory.h"
#include "nm-core-internal.h"

#define NM_DEVICE_INFINIBAND_IS_PARTITION "is-partition"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_IS_PARTITION,
);

typedef struct {
	gboolean is_partition;
	int parent_ifindex;
	int p_key;
} NMDeviceInfinibandPrivate;

struct _NMDeviceInfiniband {
	NMDevice parent;
	NMDeviceInfinibandPrivate _priv;
};

struct _NMDeviceInfinibandClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDeviceInfiniband, nm_device_infiniband, NM_TYPE_DEVICE)

#define NM_DEVICE_INFINIBAND_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMDeviceInfiniband, NM_IS_DEVICE_INFINIBAND)

/*****************************************************************************/

static NMDeviceCapabilities
get_generic_capabilities (NMDevice *device)
{
	guint32 caps = NM_DEVICE_CAP_CARRIER_DETECT;

	if (NM_DEVICE_INFINIBAND_GET_PRIVATE ((NMDeviceInfiniband *) device)->is_partition)
		caps |= NM_DEVICE_CAP_IS_SOFTWARE;

	return caps;
}

static NMActStageReturn
act_stage1_prepare (NMDevice *device, NMDeviceStateReason *out_failure_reason)
{
	nm_auto_close int dirfd = -1;
	NMActStageReturn ret;
	NMSettingInfiniband *s_infiniband;
	char ifname_verified[IFNAMSIZ];
	const char *transport_mode;
	gboolean ok;

	ret = NM_DEVICE_CLASS (nm_device_infiniband_parent_class)->act_stage1_prepare (device, out_failure_reason);
	if (ret != NM_ACT_STAGE_RETURN_SUCCESS)
		return ret;

	s_infiniband = nm_device_get_applied_setting (device, NM_TYPE_SETTING_INFINIBAND);

	g_return_val_if_fail (s_infiniband, NM_ACT_STAGE_RETURN_FAILURE);

	transport_mode = nm_setting_infiniband_get_transport_mode (s_infiniband);

	dirfd = nm_platform_sysctl_open_netdir (nm_device_get_platform (device), nm_device_get_ifindex (device), ifname_verified);
	if (dirfd < 0) {
		if (!strcmp (transport_mode, "datagram"))
			return NM_ACT_STAGE_RETURN_SUCCESS;
		else {
			NM_SET_OUT (out_failure_reason, NM_DEVICE_STATE_REASON_INFINIBAND_MODE);
			return NM_ACT_STAGE_RETURN_FAILURE;
		}
	}

	/* With some drivers the interface must be down to set transport mode */
	nm_device_take_down (device, TRUE);
	ok = nm_platform_sysctl_set (nm_device_get_platform (device), NMP_SYSCTL_PATHID_NETDIR (dirfd, ifname_verified, "mode"), transport_mode);
	nm_device_bring_up (device, TRUE, NULL);

	if (!ok) {
		NM_SET_OUT (out_failure_reason, NM_DEVICE_STATE_REASON_CONFIG_FAILED);
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	return NM_ACT_STAGE_RETURN_SUCCESS;
}

static guint32
get_configured_mtu (NMDevice *device, NMDeviceMtuSource *out_source)
{
	return nm_device_get_configured_mtu_from_connection (device,
	                                                     NM_TYPE_SETTING_INFINIBAND,
	                                                     out_source);
}

static gboolean
check_connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	NMSettingInfiniband *s_infiniband;

	if (!NM_DEVICE_CLASS (nm_device_infiniband_parent_class)->check_connection_compatible (device, connection, error))
		return FALSE;

	if (nm_device_is_real (device)) {
		const char *mac;
		const char *hw_addr;

		s_infiniband = nm_connection_get_setting_infiniband (connection);

		mac = nm_setting_infiniband_get_mac_address (s_infiniband);
		if (mac) {
			hw_addr = nm_device_get_permanent_hw_address (device);
			if (   !hw_addr
			    || !nm_utils_hwaddr_matches (mac, -1, hw_addr, -1)) {
				nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
				                            "MAC address mismatches");
				return FALSE;
			}
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
	NMSettingInfiniband *s_infiniband;
	const char *setting_mac;
	const char *hw_address;

	nm_utils_complete_generic (nm_device_get_platform (device),
	                           connection,
	                           NM_SETTING_INFINIBAND_SETTING_NAME,
	                           existing_connections,
	                           NULL,
	                           _("InfiniBand connection"),
	                           NULL,
	                           TRUE);

	s_infiniband = nm_connection_get_setting_infiniband (connection);
	if (!s_infiniband) {
		s_infiniband = (NMSettingInfiniband *) nm_setting_infiniband_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_infiniband));
	}

	setting_mac = nm_setting_infiniband_get_mac_address (s_infiniband);
	hw_address = nm_device_get_permanent_hw_address (device);
	if (setting_mac) {
		/* Make sure the setting MAC (if any) matches the device's MAC */
		if (!nm_utils_hwaddr_matches (setting_mac, -1, hw_address, -1)) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("connection does not match device"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_INFINIBAND_SETTING_NAME, NM_SETTING_INFINIBAND_MAC_ADDRESS);
			return FALSE;
		}
	} else {
		/* Lock the connection to this device by default */
		g_object_set (G_OBJECT (s_infiniband), NM_SETTING_INFINIBAND_MAC_ADDRESS, hw_address, NULL);
	}

	if (!nm_setting_infiniband_get_transport_mode (s_infiniband))
		g_object_set (G_OBJECT (s_infiniband), NM_SETTING_INFINIBAND_TRANSPORT_MODE, "datagram", NULL);

	return TRUE;
}

static void
update_connection (NMDevice *device, NMConnection *connection)
{
	NMSettingInfiniband *s_infiniband = nm_connection_get_setting_infiniband (connection);
	const char *mac = nm_device_get_permanent_hw_address (device);
	const char *transport_mode = "datagram";
	int ifindex;

	if (!s_infiniband) {
		s_infiniband = (NMSettingInfiniband *) nm_setting_infiniband_new ();
		nm_connection_add_setting (connection, (NMSetting *) s_infiniband);
	}

	if (mac && !nm_utils_hwaddr_matches (mac, -1, NULL, INFINIBAND_ALEN))
		g_object_set (s_infiniband, NM_SETTING_INFINIBAND_MAC_ADDRESS, mac, NULL);

	ifindex = nm_device_get_ifindex (device);
	if (ifindex > 0) {
		if (!nm_platform_link_infiniband_get_properties (nm_device_get_platform (device), ifindex, NULL, NULL, &transport_mode))
			transport_mode = "datagram";
	}
	g_object_set (G_OBJECT (s_infiniband), NM_SETTING_INFINIBAND_TRANSPORT_MODE, transport_mode, NULL);
}

static gboolean
create_and_realize (NMDevice *device,
                    NMConnection *connection,
                    NMDevice *parent,
                    const NMPlatformLink **out_plink,
                    GError **error)
{
	NMDeviceInfinibandPrivate *priv = NM_DEVICE_INFINIBAND_GET_PRIVATE ((NMDeviceInfiniband *) device);
	NMSettingInfiniband *s_infiniband;
	int r;

	s_infiniband = nm_connection_get_setting_infiniband (connection);
	g_assert (s_infiniband);

	/* Can only create partitions at this time */
	priv->p_key = nm_setting_infiniband_get_p_key (s_infiniband);
	if (priv->p_key < 0) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
		                     "only InfiniBand partitions can be created");
		return FALSE;
	}

	if (!parent) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_MISSING_DEPENDENCIES,
		             "InfiniBand partitions can not be created without a parent interface");
		return FALSE;
	}

	if (!NM_IS_DEVICE_INFINIBAND (parent)) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_MISSING_DEPENDENCIES,
		             "Parent interface %s must be an InfiniBand interface",
		             nm_device_get_iface (parent));
		return FALSE;
	}

	priv->parent_ifindex = nm_device_get_ifindex (parent);
	if (priv->parent_ifindex <= 0) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_MISSING_DEPENDENCIES,
		             "failed to get InfiniBand parent %s ifindex",
		             nm_device_get_iface (parent));
		return FALSE;
	}

	r = nm_platform_link_infiniband_add (nm_device_get_platform (device), priv->parent_ifindex, priv->p_key, out_plink);
	if (r < 0) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_CREATION_FAILED,
		             "Failed to create InfiniBand P_Key interface '%s' for '%s': %s",
		             nm_device_get_iface (device),
		             nm_connection_get_id (connection),
		             nm_strerror (r));
		return FALSE;
	}

	priv->is_partition = TRUE;
	return TRUE;
}

static gboolean
unrealize (NMDevice *device, GError **error)
{
	NMDeviceInfinibandPrivate *priv;
	int r;

	g_return_val_if_fail (NM_IS_DEVICE_INFINIBAND (device), FALSE);

	priv = NM_DEVICE_INFINIBAND_GET_PRIVATE ((NMDeviceInfiniband *) device);

	if (priv->p_key < 0) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
		             "Only InfiniBand partitions can be removed");
		return FALSE;
	}

	r = nm_platform_link_infiniband_delete (nm_device_get_platform (device), priv->parent_ifindex, priv->p_key);
	if (r < 0) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_CREATION_FAILED,
		             "Failed to remove InfiniBand P_Key interface '%s': %s",
		             nm_device_get_iface (device),
		             nm_strerror (r));
		return FALSE;
	}

	return TRUE;
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	case PROP_IS_PARTITION:
		g_value_set_boolean (value, NM_DEVICE_INFINIBAND_GET_PRIVATE ((NMDeviceInfiniband *) object)->is_partition);
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
	case PROP_IS_PARTITION:
		NM_DEVICE_INFINIBAND_GET_PRIVATE ((NMDeviceInfiniband *) object)->is_partition = g_value_get_boolean (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_device_infiniband_init (NMDeviceInfiniband * self)
{
}

static const NMDBusInterfaceInfoExtended interface_info_device_infiniband = {
	.parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT (
		NM_DBUS_INTERFACE_DEVICE_INFINIBAND,
		.signals = NM_DEFINE_GDBUS_SIGNAL_INFOS (
			&nm_signal_info_property_changed_legacy,
		),
		.properties = NM_DEFINE_GDBUS_PROPERTY_INFOS (
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("HwAddress",       "s",  NM_DEVICE_HW_ADDRESS),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Carrier",         "b",  NM_DEVICE_CARRIER),
		),
	),
	.legacy_property_changed = TRUE,
};

static void
nm_device_infiniband_class_init (NMDeviceInfinibandClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	object_class->get_property = get_property;
	object_class->set_property = set_property;

	dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS (&interface_info_device_infiniband);

	device_class->connection_type_supported = NM_SETTING_INFINIBAND_SETTING_NAME;
	device_class->connection_type_check_compatible = NM_SETTING_INFINIBAND_SETTING_NAME;
	device_class->link_types = NM_DEVICE_DEFINE_LINK_TYPES (NM_LINK_TYPE_INFINIBAND);

	device_class->create_and_realize = create_and_realize;
	device_class->unrealize = unrealize;
	device_class->get_generic_capabilities = get_generic_capabilities;
	device_class->check_connection_compatible = check_connection_compatible;
	device_class->complete_connection = complete_connection;
	device_class->update_connection = update_connection;

	device_class->act_stage1_prepare = act_stage1_prepare;
	device_class->get_configured_mtu = get_configured_mtu;

	obj_properties[PROP_IS_PARTITION] =
	     g_param_spec_boolean (NM_DEVICE_INFINIBAND_IS_PARTITION, "", "",
	                           FALSE,
	                           G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
	                           G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}

/*****************************************************************************/

#define NM_TYPE_INFINIBAND_DEVICE_FACTORY (nm_infiniband_device_factory_get_type ())
#define NM_INFINIBAND_DEVICE_FACTORY(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_INFINIBAND_DEVICE_FACTORY, NMInfinibandDeviceFactory))

static NMDevice *
create_device (NMDeviceFactory *factory,
               const char *iface,
               const NMPlatformLink *plink,
               NMConnection *connection,
               gboolean *out_ignore)
{
	gboolean is_partition = FALSE;

	if (plink)
		is_partition = (plink->parent > 0 || plink->parent == NM_PLATFORM_LINK_OTHER_NETNS);
	else if (connection) {
		NMSettingInfiniband *s_infiniband;

		s_infiniband = nm_connection_get_setting_infiniband (connection);
		g_return_val_if_fail (s_infiniband, NULL);
		is_partition =    !!nm_setting_infiniband_get_parent (s_infiniband)
		               || (   nm_setting_infiniband_get_p_key (s_infiniband) >= 0
		                   && nm_setting_infiniband_get_mac_address (s_infiniband));
	}

	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_INFINIBAND,
	                                  NM_DEVICE_IFACE, iface,
	                                  NM_DEVICE_TYPE_DESC, "InfiniBand",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_INFINIBAND,
	                                  NM_DEVICE_LINK_TYPE, NM_LINK_TYPE_INFINIBAND,
	                                  /* NOTE: Partition should probably be a different link type! */
	                                  NM_DEVICE_INFINIBAND_IS_PARTITION, is_partition,
	                                  NULL);
}

static const char *
get_connection_parent (NMDeviceFactory *factory, NMConnection *connection)
{
	NMSettingInfiniband *s_infiniband;

	g_return_val_if_fail (nm_connection_is_type (connection, NM_SETTING_INFINIBAND_SETTING_NAME), NULL);

	s_infiniband = nm_connection_get_setting_infiniband (connection);
	g_assert (s_infiniband);

	return nm_setting_infiniband_get_parent (s_infiniband);
}

static char *
get_connection_iface (NMDeviceFactory *factory,
                      NMConnection *connection,
                      const char *parent_iface)
{
	NMSettingInfiniband *s_infiniband;

	g_return_val_if_fail (nm_connection_is_type (connection, NM_SETTING_INFINIBAND_SETTING_NAME), NULL);

	s_infiniband = nm_connection_get_setting_infiniband (connection);
	g_assert (s_infiniband);

	if (!parent_iface)
		return NULL;

	g_return_val_if_fail (g_strcmp0 (parent_iface, nm_setting_infiniband_get_parent (s_infiniband)) == 0, NULL);

	return g_strdup (nm_setting_infiniband_get_virtual_interface_name (s_infiniband));
}

NM_DEVICE_FACTORY_DEFINE_INTERNAL (INFINIBAND, Infiniband, infiniband,
	NM_DEVICE_FACTORY_DECLARE_LINK_TYPES    (NM_LINK_TYPE_INFINIBAND)
	NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES (NM_SETTING_INFINIBAND_SETTING_NAME),
	factory_class->create_device = create_device;
	factory_class->get_connection_parent = get_connection_parent;
	factory_class->get_connection_iface = get_connection_iface;
);
