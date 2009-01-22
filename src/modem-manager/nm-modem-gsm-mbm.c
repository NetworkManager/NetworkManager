/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
  Additions to NetworkManager, network-manager-applet and modemmanager
  for supporting Ericsson modules like F3507g.

  Author: Per Hallsmark <per@hallsmark.se>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the

  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

*/

#include "nm-modem-gsm-mbm.h"
#include "nm-device-private.h"
#include "nm-device-interface.h"
#include "NetworkManagerSystem.h"
#include "nm-setting-connection.h"
#include "nm-setting-gsm.h"
#include "nm-modem-types.h"
#include "nm-utils.h"

G_DEFINE_TYPE (NMModemGsmMbm, nm_modem_gsm_mbm, NM_TYPE_MODEM_GSM)

#define NM_MODEM_GSM_MBM_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_MODEM_GSM_MBM, NMModemGsmMbmPrivate))

typedef struct {
	char *netdev_iface;
	NMIP4Config *pending_ip4_config;
} NMModemGsmMbmPrivate;

#define MBM_SECRETS_TRIES "gsm-secrets-tries"

static char *
get_network_device (NMDevice *device)
{
	char *result = NULL;
	GError *error = NULL;
	GValue value = { 0, };

	if (!dbus_g_proxy_call (nm_modem_get_proxy (NM_MODEM (device), "org.freedesktop.DBus.Properties"),
							"Get", &error,
							G_TYPE_STRING, MM_DBUS_INTERFACE_MODEM_GSM_MBM,
							G_TYPE_STRING, "NetworkDevice",
							G_TYPE_INVALID,
							G_TYPE_VALUE, &value,
							G_TYPE_INVALID)) {
		nm_warning ("Could not get MBM device's network interface: %s", error->message);
		g_error_free (error);
	} else {
		if (G_VALUE_HOLDS_STRING (&value))
			result = g_value_dup_string (&value);
		else
			nm_warning ("Could not get MBM device's network interface: wrong type '%s'",
						G_VALUE_TYPE_NAME (&value));

		g_value_unset (&value);
	}

	return result;
}

NMDevice *
nm_modem_gsm_mbm_new (const char *path,
					  const char *data_device,
					  const char *driver)
{
	NMDevice *device;

	g_return_val_if_fail (path != NULL, NULL);
	g_return_val_if_fail (data_device != NULL, NULL);
	g_return_val_if_fail (driver != NULL, NULL);

	device = (NMDevice *) g_object_new (NM_TYPE_MODEM_GSM_MBM,
										NM_DEVICE_INTERFACE_UDI, path,
										NM_DEVICE_INTERFACE_IFACE, data_device,
										NM_DEVICE_INTERFACE_DRIVER, driver,
										NM_DEVICE_INTERFACE_MANAGED, TRUE,
										NM_MODEM_PATH, path,
										NULL);

	if (device) {
		NMModemGsmMbmPrivate *priv;

		priv = NM_MODEM_GSM_MBM_GET_PRIVATE (device);
		priv->netdev_iface = get_network_device (device);
		if (!priv->netdev_iface) {
			g_object_unref (device);
			device = NULL;
		}
	}

	return device;
}

/*****************************************************************************/

#if 0
static NMSetting *
get_setting (NMModemGsmMbm *modem, GType setting_type)
{
	NMActRequest *req;
	NMSetting *setting = NULL;

	req = nm_device_get_act_request (NM_DEVICE (modem));
	if (req) {
		NMConnection *connection;

		connection = nm_act_request_get_connection (req);
		if (connection)
			setting = nm_connection_get_setting (connection, setting_type);
	}

	return setting;
}
#endif

#if 0
static NMActStageReturn
real_act_stage2_config (NMDevice *device, NMDeviceStateReason *reason)
{
	NMActRequest *req;
	NMConnection *connection;
	const char *setting_name;
	GPtrArray *hints = NULL;
	const char *hint1 = NULL, *hint2 = NULL;
	guint32 tries;

	req = nm_device_get_act_request (device);
	g_assert (req);
	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	setting_name = nm_connection_need_secrets (connection, &hints);
	if (!setting_name) {
		//			   do_mbm_auth (NM_MODEM_GSM_MBM (device));
		return NM_ACT_STAGE_RETURN_POSTPONE;
	}

	if (hints) {
		if (hints->len > 0)
			hint1 = g_ptr_array_index (hints, 0);
		if (hints->len > 1)
			hint2 = g_ptr_array_index (hints, 1);
	}

	nm_device_state_changed (device, NM_DEVICE_STATE_NEED_AUTH, NM_DEVICE_STATE_REASON_NONE);

	tries = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (connection), MBM_SECRETS_TRIES));
	nm_act_request_request_connection_secrets (req,
											   setting_name,
											   tries ? TRUE : FALSE,
											   SECRETS_CALLER_MBM_GSM,
											   hint1,
											   hint2);
	g_object_set_data (G_OBJECT (connection), MBM_SECRETS_TRIES, GUINT_TO_POINTER (++tries));

	if (hints)
		g_ptr_array_free (hints, TRUE);

	return NM_ACT_STAGE_RETURN_POSTPONE;
}
#endif

static void
real_deactivate (NMDevice *device)
{
	NMModemGsmMbmPrivate *priv = NM_MODEM_GSM_MBM_GET_PRIVATE (device);

	if (priv->pending_ip4_config) {
		g_object_unref (priv->pending_ip4_config);
		priv->pending_ip4_config = NULL;
	}

	if (priv->netdev_iface) {
		nm_system_device_flush_ip4_routes_with_iface (priv->netdev_iface);
		nm_system_device_flush_ip4_addresses_with_iface (priv->netdev_iface);
		nm_system_device_set_up_down_with_iface (priv->netdev_iface, FALSE, NULL);
	}
	nm_device_set_ip_iface (device, NULL);

	if (NM_DEVICE_CLASS (nm_modem_gsm_mbm_parent_class)->deactivate)
		NM_DEVICE_CLASS (nm_modem_gsm_mbm_parent_class)->deactivate (device);
}

static gboolean
real_hw_is_up (NMDevice *device)
{
	NMModemGsmMbmPrivate *priv = NM_MODEM_GSM_MBM_GET_PRIVATE (device);

	if (priv->netdev_iface)
		return nm_system_device_is_up_with_iface (priv->netdev_iface);

	return TRUE;
}

static gboolean
real_hw_bring_up (NMDevice *device, gboolean *no_firmware)
{
	NMModemGsmMbmPrivate *priv = NM_MODEM_GSM_MBM_GET_PRIVATE (device);

	if (priv->netdev_iface)
		return nm_system_device_set_up_down_with_iface (priv->netdev_iface, TRUE, no_firmware);

	return TRUE;
}

/*****************************************************************************/

static void
nm_modem_gsm_mbm_init (NMModemGsmMbm *self)
{
}

static void
finalize (GObject *object)
{
	NMModemGsmMbmPrivate *priv = NM_MODEM_GSM_MBM_GET_PRIVATE (object);

	g_free (priv->netdev_iface);

	G_OBJECT_CLASS (nm_modem_gsm_mbm_parent_class)->finalize (object);
}

static void
nm_modem_gsm_mbm_class_init (NMModemGsmMbmClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMModemGsmMbmPrivate));

	object_class->finalize = finalize;

#if 0
	device_class->act_stage2_config = real_act_stage2_config;
#endif
	device_class->deactivate = real_deactivate;
	device_class->hw_is_up = real_hw_is_up;
	device_class->hw_bring_up = real_hw_bring_up;
}
