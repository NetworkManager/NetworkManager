/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

#include "nm-modem-gsm-hso.h"
#include "nm-device-private.h"
#include "nm-device-interface.h"
#include "NetworkManagerSystem.h"
#include "nm-setting-connection.h"
#include "nm-setting-gsm.h"
#include "nm-modem-types.h"
#include "nm-utils.h"

G_DEFINE_TYPE (NMModemGsmHso, nm_modem_gsm_hso, NM_TYPE_MODEM_GSM)

#define NM_MODEM_GSM_HSO_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_MODEM_GSM_HSO, NMModemGsmHsoPrivate))

typedef struct {
	char *netdev_iface;
	NMIP4Config *pending_ip4_config;
} NMModemGsmHsoPrivate;

#define HSO_SECRETS_TRIES "gsm-secrets-tries"

static char *
get_network_device (NMDevice *device)
{
	char *result = NULL;
	GError *error = NULL;
	GValue value = { 0, };

	if (!dbus_g_proxy_call (nm_modem_get_proxy (NM_MODEM (device), "org.freedesktop.DBus.Properties"),
							"Get", &error,
							G_TYPE_STRING, MM_DBUS_INTERFACE_MODEM_GSM_HSO,
							G_TYPE_STRING, "NetworkDevice",
							G_TYPE_INVALID,
							G_TYPE_VALUE, &value,
							G_TYPE_INVALID)) {
		nm_warning ("Could not get HSO device's network interface: %s", error->message);
		g_error_free (error);
	} else {
		if (G_VALUE_HOLDS_STRING (&value))
			result = g_value_dup_string (&value);
		else
			nm_warning ("Could not get HSO device's network interface: wrong type '%s'",
						G_VALUE_TYPE_NAME (&value));

		g_value_unset (&value);
	}

	return result;
}

NMDevice *
nm_modem_gsm_hso_new (const char *path,
					  const char *data_device,
					  const char *driver)
{
	NMDevice *device;

	g_return_val_if_fail (path != NULL, NULL);
	g_return_val_if_fail (data_device != NULL, NULL);
	g_return_val_if_fail (driver != NULL, NULL);

	device = (NMDevice *) g_object_new (NM_TYPE_MODEM_GSM_HSO,
										NM_DEVICE_INTERFACE_UDI, path,
										NM_DEVICE_INTERFACE_IFACE, data_device,
										NM_DEVICE_INTERFACE_DRIVER, driver,
										NM_DEVICE_INTERFACE_MANAGED, TRUE,
										NM_MODEM_PATH, path,
										NULL);

	if (device) {
		NMModemGsmHsoPrivate *priv;

		priv = NM_MODEM_GSM_HSO_GET_PRIVATE (device);
		priv->netdev_iface = get_network_device (device);
		if (!priv->netdev_iface) {
			g_object_unref (device);
			device = NULL;
		}
	}

	return device;
}

/*****************************************************************************/

static NMSetting *
get_setting (NMModemGsmHso *modem, GType setting_type)
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

static void
hso_auth_done (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);
	GError *error = NULL;

	if (dbus_g_proxy_end_call (proxy, call_id, &error, G_TYPE_INVALID))
		nm_device_activate_schedule_stage3_ip_config_start (device);
	else {
		nm_warning ("Authentication failed: %s", error->message);
		g_error_free (error);
		nm_device_state_changed (device,
								 NM_DEVICE_STATE_FAILED,
								 NM_DEVICE_STATE_REASON_MODEM_DIAL_FAILED);
	}
}

static void
do_hso_auth (NMModemGsmHso *device)
{
	NMSettingGsm *s_gsm;
	const char *username;
	const char *password;

	s_gsm = NM_SETTING_GSM (get_setting (device, NM_TYPE_SETTING_GSM));
	username = nm_setting_gsm_get_username (s_gsm);
	password = nm_setting_gsm_get_password (s_gsm);

	dbus_g_proxy_begin_call (nm_modem_get_proxy (NM_MODEM (device), MM_DBUS_INTERFACE_MODEM_GSM_HSO),
							 "Authenticate", hso_auth_done,
							 device, NULL,
							 G_TYPE_STRING, username ? username : "",
							 G_TYPE_STRING, password ? password : "",
							 G_TYPE_INVALID);
}

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
		do_hso_auth (NM_MODEM_GSM_HSO (device));
		return NM_ACT_STAGE_RETURN_POSTPONE;
	}

	if (hints) {
		if (hints->len > 0)
			hint1 = g_ptr_array_index (hints, 0);
		if (hints->len > 1)
			hint2 = g_ptr_array_index (hints, 1);
	}

	nm_device_state_changed (device, NM_DEVICE_STATE_NEED_AUTH, NM_DEVICE_STATE_REASON_NONE);

	tries = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (connection), HSO_SECRETS_TRIES));
	nm_act_request_request_connection_secrets (req,
											   setting_name,
											   tries ? TRUE : FALSE,
											   SECRETS_CALLER_HSO_GSM,
											   hint1,
											   hint2);
	g_object_set_data (G_OBJECT (connection), HSO_SECRETS_TRIES, GUINT_TO_POINTER (++tries));

	if (hints)
		g_ptr_array_free (hints, TRUE);

	return NM_ACT_STAGE_RETURN_POSTPONE;
}

static void
get_ip4_config_done (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);
	guint32 ip4_address;
	GArray *dns_array;
	GError *error = NULL;

	if (dbus_g_proxy_end_call (proxy, call_id, &error,
							   G_TYPE_UINT, &ip4_address,
							   DBUS_TYPE_G_UINT_ARRAY, &dns_array,
							   G_TYPE_INVALID)) {

		NMModemGsmHsoPrivate *priv = NM_MODEM_GSM_HSO_GET_PRIVATE (device);
		NMIP4Address *addr;
		int i;

		addr = nm_ip4_address_new ();
		nm_ip4_address_set_address (addr, ip4_address);
		nm_ip4_address_set_prefix (addr, 32);

		priv->pending_ip4_config = nm_ip4_config_new ();
		nm_ip4_config_take_address (priv->pending_ip4_config, addr);

		for (i = 0; i < dns_array->len; i++)
			nm_ip4_config_add_nameserver (priv->pending_ip4_config,
										  g_array_index (dns_array, guint32, i));

		nm_device_activate_schedule_stage4_ip_config_get (device);
	} else {
		nm_warning ("Retrieving IP4 configuration failed: %s", error->message);
		g_error_free (error);
		nm_device_state_changed (device,
								 NM_DEVICE_STATE_FAILED,
								 NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE);
	}
}

static NMActStageReturn
real_act_stage3_ip_config_start (NMDevice *device, NMDeviceStateReason *reason)
{
	dbus_g_proxy_begin_call (nm_modem_get_proxy (NM_MODEM (device), MM_DBUS_INTERFACE_MODEM_GSM_HSO),
							 "GetIP4Config", get_ip4_config_done,
							 device, NULL,
							 G_TYPE_INVALID);

	return NM_ACT_STAGE_RETURN_POSTPONE;
}

static NMActStageReturn
real_act_stage4_get_ip4_config (NMDevice *device,
								NMIP4Config **config,
								NMDeviceStateReason *reason)
{
	NMModemGsmHso *self = NM_MODEM_GSM_HSO (device);
	NMModemGsmHsoPrivate *priv = NM_MODEM_GSM_HSO_GET_PRIVATE (self);
	gboolean no_firmware = FALSE;

	nm_device_set_ip_iface (device, priv->netdev_iface);
	if (!nm_device_hw_bring_up (device, TRUE, &no_firmware)) {
		if (no_firmware)
			*reason = NM_DEVICE_STATE_REASON_FIRMWARE_MISSING;
		else
			*reason = NM_DEVICE_STATE_REASON_CONFIG_FAILED;
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	*config = priv->pending_ip4_config;
	priv->pending_ip4_config = NULL;

	return NM_ACT_STAGE_RETURN_SUCCESS;
}

static void
real_deactivate (NMDevice *device)
{
	NMModemGsmHsoPrivate *priv = NM_MODEM_GSM_HSO_GET_PRIVATE (device);

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

	if (NM_DEVICE_CLASS (nm_modem_gsm_hso_parent_class)->deactivate)
		NM_DEVICE_CLASS (nm_modem_gsm_hso_parent_class)->deactivate (device);
}

static gboolean
real_hw_is_up (NMDevice *device)
{
	NMModemGsmHsoPrivate *priv = NM_MODEM_GSM_HSO_GET_PRIVATE (device);
	NMDeviceState state;

	state = nm_device_interface_get_state (NM_DEVICE_INTERFACE (device));
	if (priv->pending_ip4_config || state == NM_DEVICE_STATE_IP_CONFIG || state == NM_DEVICE_STATE_ACTIVATED)
		return nm_system_device_is_up_with_iface (priv->netdev_iface);

	return TRUE;
}

static gboolean
real_hw_bring_up (NMDevice *device, gboolean *no_firmware)
{
	NMModemGsmHsoPrivate *priv = NM_MODEM_GSM_HSO_GET_PRIVATE (device);
	NMDeviceState state;

	state = nm_device_interface_get_state (NM_DEVICE_INTERFACE (device));
	if (priv->pending_ip4_config || state == NM_DEVICE_STATE_IP_CONFIG || state == NM_DEVICE_STATE_ACTIVATED)
		return nm_system_device_set_up_down_with_iface (priv->netdev_iface, TRUE, no_firmware);

	return TRUE;
}

static void
real_connect (NMModem *modem, const char *number)
{
	nm_device_activate_schedule_stage2_device_config (NM_DEVICE (modem));
}

/*****************************************************************************/

static void
nm_modem_gsm_hso_init (NMModemGsmHso *self)
{
}

static void
finalize (GObject *object)
{
	NMModemGsmHsoPrivate *priv = NM_MODEM_GSM_HSO_GET_PRIVATE (object);

	g_free (priv->netdev_iface);

	G_OBJECT_CLASS (nm_modem_gsm_hso_parent_class)->finalize (object);
}

static void
nm_modem_gsm_hso_class_init (NMModemGsmHsoClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);
	NMModemClass *modem_class = NM_MODEM_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMModemGsmHsoPrivate));

	object_class->finalize = finalize;

	device_class->act_stage2_config = real_act_stage2_config;
	device_class->act_stage3_ip_config_start = real_act_stage3_ip_config_start;
	device_class->act_stage4_get_ip4_config = real_act_stage4_get_ip4_config;
	device_class->deactivate = real_deactivate;
	device_class->hw_is_up = real_hw_is_up;
	device_class->hw_bring_up = real_hw_bring_up;

	modem_class->connect = real_connect;
}
