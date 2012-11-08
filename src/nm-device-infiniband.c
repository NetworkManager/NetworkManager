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
#include <netinet/ether.h>

#include "nm-device-infiniband.h"
#include "nm-logging.h"
#include "nm-properties-changed-signal.h"
#include "nm-utils.h"
#include "NetworkManagerUtils.h"
#include "nm-device-private.h"
#include "nm-enum-types.h"

#include "nm-device-infiniband-glue.h"


G_DEFINE_TYPE (NMDeviceInfiniband, nm_device_infiniband, NM_TYPE_DEVICE_WIRED)

#define NM_DEVICE_INFINIBAND_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_INFINIBAND, NMDeviceInfinibandPrivate))

#define NM_INFINIBAND_ERROR (nm_infiniband_error_quark ())

typedef struct {
	guint8 hw_addr[INFINIBAND_ALEN];
} NMDeviceInfinibandPrivate;

enum {
	PROPERTIES_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,
	PROP_HW_ADDRESS,
	PROP_CARRIER,

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

static GObject*
constructor (GType type,
			 guint n_construct_params,
			 GObjectConstructParam *construct_params)
{
	GObject *object;
	NMDeviceInfinibandPrivate *priv;
	NMDevice *self;

	object = G_OBJECT_CLASS (nm_device_infiniband_parent_class)->constructor (type,
	                                                                        n_construct_params,
	                                                                        construct_params);
	if (!object)
		return NULL;

	self = NM_DEVICE (object);
	priv = NM_DEVICE_INFINIBAND_GET_PRIVATE (self);

	nm_log_dbg (LOGD_HW | LOGD_INFINIBAND, "(%s): kernel ifindex %d",
	            nm_device_get_iface (NM_DEVICE (self)),
	            nm_device_get_ifindex (NM_DEVICE (self)));

	return object;
}

static void
nm_device_infiniband_init (NMDeviceInfiniband * self)
{
}

NMDevice *
nm_device_infiniband_new (const char *udi,
						  const char *iface,
						  const char *driver)
{
	g_return_val_if_fail (udi != NULL, NULL);
	g_return_val_if_fail (iface != NULL, NULL);
	g_return_val_if_fail (driver != NULL, NULL);

	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_INFINIBAND,
	                                  NM_DEVICE_UDI, udi,
	                                  NM_DEVICE_IFACE, iface,
	                                  NM_DEVICE_DRIVER, driver,
	                                  NM_DEVICE_TYPE_DESC, "InfiniBand",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_INFINIBAND,
	                                  NULL);
}

static void
update_hw_address (NMDevice *dev)
{
	NMDeviceInfinibandPrivate *priv = NM_DEVICE_INFINIBAND_GET_PRIVATE (dev);
	gsize addrlen;
	gboolean changed = FALSE;

	addrlen = nm_device_read_hwaddr (dev, priv->hw_addr, sizeof (priv->hw_addr), &changed);
	if (addrlen) {
		g_return_if_fail (addrlen == INFINIBAND_ALEN);
		if (changed)
			g_object_notify (G_OBJECT (dev), NM_DEVICE_INFINIBAND_HW_ADDRESS);
	}
}

static const guint8 *
get_hw_address (NMDevice *device, guint *out_len)
{
	*out_len = INFINIBAND_ALEN;
	return NM_DEVICE_INFINIBAND_GET_PRIVATE (device)->hw_addr;
}

static guint32
get_generic_capabilities (NMDevice *dev)
{
	return NM_DEVICE_CAP_CARRIER_DETECT | NM_DEVICE_CAP_NM_SUPPORTED;
}

static NMConnection *
get_best_auto_connection (NMDevice *dev,
                          GSList *connections,
                          char **specific_object)
{
	NMDeviceInfinibandPrivate *priv = NM_DEVICE_INFINIBAND_GET_PRIVATE (dev);
	GSList *iter;

	for (iter = connections; iter; iter = g_slist_next (iter)) {
		NMConnection *connection = NM_CONNECTION (iter->data);
		NMSettingInfiniband *s_infiniband;

		if (!nm_connection_is_type (connection, NM_SETTING_INFINIBAND_SETTING_NAME))
			continue;

		s_infiniband = nm_connection_get_setting_infiniband (connection);
		if (!s_infiniband)
			continue;

		if (s_infiniband) {
			const GByteArray *mac;

			mac = nm_setting_infiniband_get_mac_address (s_infiniband);
			if (mac && memcmp (mac->data, priv->hw_addr, INFINIBAND_ALEN))
				continue;
		}

		return connection;
	}
	return NULL;
}

static NMActStageReturn
act_stage1_prepare (NMDevice *dev, NMDeviceStateReason *reason)
{
	NMActRequest *req;
	NMConnection *connection;
	NMSettingInfiniband *s_infiniband;
	const char *transport_mode;
	char *mode_path;
	gboolean ok;

	g_return_val_if_fail (reason != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	req = nm_device_get_act_request (dev);
	g_return_val_if_fail (req != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	connection = nm_act_request_get_connection (req);
	g_assert (connection);
	s_infiniband = nm_connection_get_setting_infiniband (connection);
	g_assert (s_infiniband);

	transport_mode = nm_setting_infiniband_get_transport_mode (s_infiniband);

	mode_path = g_strdup_printf ("/sys/class/net/%s/mode", nm_device_get_iface (dev));
	if (!g_file_test (mode_path, G_FILE_TEST_EXISTS)) {
		g_free (mode_path);

		if (!strcmp (transport_mode, "datagram"))
			return NM_ACT_STAGE_RETURN_SUCCESS;
		else {
			*reason = NM_DEVICE_STATE_REASON_INFINIBAND_MODE;
			return NM_ACT_STAGE_RETURN_FAILURE;
		}
	}

	ok = nm_utils_do_sysctl (mode_path, transport_mode);
	g_free (mode_path);

	if (!ok) {
		*reason = NM_DEVICE_STATE_REASON_CONFIG_FAILED;
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	return NM_DEVICE_CLASS (nm_device_infiniband_parent_class)->act_stage1_prepare (dev, reason);
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
check_connection_compatible (NMDevice *device,
                             NMConnection *connection,
                             GError **error)
{
	NMDeviceInfinibandPrivate *priv = NM_DEVICE_INFINIBAND_GET_PRIVATE (device);
	NMSettingInfiniband *s_infiniband;
	const GByteArray *mac;

	if (!nm_connection_is_type (connection, NM_SETTING_INFINIBAND_SETTING_NAME)) {
		g_set_error (error,
		             NM_INFINIBAND_ERROR,
					 NM_INFINIBAND_ERROR_CONNECTION_NOT_INFINIBAND,
		             "The connection was not an InfiniBand connection.");
		return FALSE;
	}

	s_infiniband = nm_connection_get_setting_infiniband (connection);
	if (!s_infiniband) {
		g_set_error (error,
		             NM_INFINIBAND_ERROR, NM_INFINIBAND_ERROR_CONNECTION_INVALID,
		             "The connection was not a valid infiniband connection.");
		return FALSE;
	}

	if (s_infiniband) {
		mac = nm_setting_infiniband_get_mac_address (s_infiniband);
		if (mac && memcmp (mac->data, priv->hw_addr, INFINIBAND_ALEN)) {
			g_set_error (error,
			             NM_INFINIBAND_ERROR,
			             NM_INFINIBAND_ERROR_CONNECTION_INCOMPATIBLE,
			             "The connection's MAC address did not match this device.");
			return FALSE;
		}
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
	NMDeviceInfinibandPrivate *priv = NM_DEVICE_INFINIBAND_GET_PRIVATE (device);
	NMSettingInfiniband *s_infiniband;
	const GByteArray *setting_mac;

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
	if (setting_mac) {
		/* Make sure the setting MAC (if any) matches the device's MAC */
		if (memcmp (setting_mac->data, priv->hw_addr, INFINIBAND_ALEN)) {
			g_set_error_literal (error,
			                     NM_SETTING_INFINIBAND_ERROR,
			                     NM_SETTING_INFINIBAND_ERROR_INVALID_PROPERTY,
			                     NM_SETTING_INFINIBAND_MAC_ADDRESS);
			return FALSE;
		}
	} else {
		GByteArray *mac;

		/* Lock the connection to this device by default */
		mac = g_byte_array_sized_new (sizeof (priv->hw_addr));
		g_byte_array_append (mac, priv->hw_addr, sizeof (priv->hw_addr));
		g_object_set (G_OBJECT (s_infiniband), NM_SETTING_INFINIBAND_MAC_ADDRESS, mac, NULL);
		g_byte_array_free (mac, TRUE);
	}

	if (!nm_setting_infiniband_get_transport_mode (s_infiniband))
		g_object_set (G_OBJECT (s_infiniband), NM_SETTING_INFINIBAND_TRANSPORT_MODE, "datagram", NULL);

	return TRUE;
}

static gboolean
spec_match_list (NMDevice *device, const GSList *specs)
{
	NMDeviceInfinibandPrivate *priv = NM_DEVICE_INFINIBAND_GET_PRIVATE (device);
	char *hwaddr;
	gboolean matched;

	hwaddr = nm_utils_hwaddr_ntoa (priv->hw_addr, ARPHRD_INFINIBAND);
	matched = nm_match_spec_hwaddr (specs, hwaddr);
	g_free (hwaddr);

	return matched;
}

static gboolean
infiniband_match_config (NMDevice *self, NMConnection *connection)
{
	NMDeviceInfinibandPrivate *priv = NM_DEVICE_INFINIBAND_GET_PRIVATE (self);
	NMSettingInfiniband *s_infiniband;
	const GByteArray *s_mac;

	s_infiniband = nm_connection_get_setting_infiniband (connection);
	if (!s_infiniband)
		return FALSE;

	/* MAC address check */
	s_mac = nm_setting_infiniband_get_mac_address (s_infiniband);
	if (s_mac && memcmp (s_mac->data, priv->hw_addr, INFINIBAND_ALEN))
		return FALSE;

	return TRUE;
}

static NMConnection *
connection_match_config (NMDevice *self, const GSList *connections)
{
	const GSList *iter;
	GSList *infiniband_matches;
	NMConnection *match;

	/* First narrow @connections down to those that match in their
	 * NMSettingInfiniband configuration.
	 */
	infiniband_matches = NULL;
	for (iter = connections; iter; iter = iter->next) {
		NMConnection *candidate = NM_CONNECTION (iter->data);

		if (!nm_connection_is_type (candidate, NM_SETTING_INFINIBAND_SETTING_NAME))
			continue;
		if (!infiniband_match_config (self, candidate))
			continue;

		infiniband_matches = g_slist_prepend (infiniband_matches, candidate);
	}

	/* Now pass those to the super method, which will check IP config */
	infiniband_matches = g_slist_reverse (infiniband_matches);
	match = NM_DEVICE_CLASS (nm_device_infiniband_parent_class)->connection_match_config (self, infiniband_matches);
	g_slist_free (infiniband_matches);

	return match;
}

static gboolean
hwaddr_matches (NMDevice *device,
                NMConnection *connection,
                const guint8 *other_hwaddr,
                guint other_hwaddr_len,
                gboolean fail_if_no_hwaddr)
{
	NMDeviceInfinibandPrivate *priv = NM_DEVICE_INFINIBAND_GET_PRIVATE (device);
	NMSettingInfiniband *s_ib;
	const GByteArray *mac = NULL;

	s_ib = nm_connection_get_setting_infiniband (connection);
	if (s_ib)
		mac = nm_setting_infiniband_get_mac_address (s_ib);

	if (mac) {
		g_return_val_if_fail (mac->len == INFINIBAND_ALEN, FALSE);
		if (other_hwaddr) {
			g_return_val_if_fail (other_hwaddr_len == INFINIBAND_ALEN, FALSE);
			if (memcmp (mac->data, other_hwaddr, mac->len) == 0)
				return TRUE;
		} else if (memcmp (mac->data, priv->hw_addr, mac->len) == 0)
			return TRUE;
	} else if (fail_if_no_hwaddr == FALSE)
		return TRUE;

	return FALSE;
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMDeviceInfinibandPrivate *priv = NM_DEVICE_INFINIBAND_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_HW_ADDRESS:
		g_value_take_string (value, nm_utils_hwaddr_ntoa (priv->hw_addr, ARPHRD_INFINIBAND));
		break;
	case PROP_CARRIER:
		g_value_set_boolean (value, nm_device_wired_get_carrier (NM_DEVICE_WIRED (object)));
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
nm_device_infiniband_class_init (NMDeviceInfinibandClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *parent_class = NM_DEVICE_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMDeviceInfinibandPrivate));

	/* virtual methods */
	object_class->constructor = constructor;
	object_class->get_property = get_property;
	object_class->set_property = set_property;

	parent_class->get_generic_capabilities = get_generic_capabilities;
	parent_class->update_hw_address = update_hw_address;
	parent_class->get_hw_address = get_hw_address;
	parent_class->get_best_auto_connection = get_best_auto_connection;
	parent_class->check_connection_compatible = check_connection_compatible;
	parent_class->complete_connection = complete_connection;

	parent_class->act_stage1_prepare = act_stage1_prepare;
	parent_class->ip4_config_pre_commit = ip4_config_pre_commit;
	parent_class->spec_match_list = spec_match_list;
	parent_class->connection_match_config = connection_match_config;
	parent_class->hwaddr_matches = hwaddr_matches;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_HW_ADDRESS,
		 g_param_spec_string (NM_DEVICE_INFINIBAND_HW_ADDRESS,
							  "Active MAC Address",
							  "Currently set hardware MAC address",
							  NULL,
							  G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_CARRIER,
		 g_param_spec_boolean (NM_DEVICE_INFINIBAND_CARRIER,
							   "Carrier",
							   "Carrier",
							   FALSE,
							   G_PARAM_READABLE));

	/* Signals */
	signals[PROPERTIES_CHANGED] =
		nm_properties_changed_signal_new (object_class,
										  G_STRUCT_OFFSET (NMDeviceInfinibandClass, properties_changed));

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (klass),
									 &dbus_glib_nm_device_infiniband_object_info);

	dbus_g_error_domain_register (NM_INFINIBAND_ERROR, NULL, NM_TYPE_INFINIBAND_ERROR);
}
