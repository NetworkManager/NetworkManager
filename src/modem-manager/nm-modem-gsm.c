/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

#include <string.h>
#include "nm-modem-gsm.h"
#include "nm-device-private.h"
#include "nm-device-interface.h"
#include "nm-setting-connection.h"
#include "nm-setting-gsm.h"
#include "nm-modem-types.h"
#include "nm-utils.h"

#include "nm-device-gsm-glue.h"

G_DEFINE_TYPE (NMModemGsm, nm_modem_gsm, NM_TYPE_MODEM)

#define NM_MODEM_GSM_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_MODEM_GSM, NMModemGsmPrivate))

enum {
	MODEM_STATE_BEGIN,
	MODEM_STATE_ENABLE,
	MODEM_STATE_SET_PIN,
	MODEM_STATE_SET_APN,
	MODEM_STATE_SET_BAND,
	MODEM_STATE_SET_NETWORK_MODE,
	MODEM_STATE_REGISTER,
	MODEM_STATE_FAILED,
};

typedef struct {
	int modem_state;
} NMModemGsmPrivate;

NMDevice *
nm_modem_gsm_new (const char *path,
				  const char *data_device,
				  const char *driver)
{
	g_return_val_if_fail (path != NULL, NULL);
	g_return_val_if_fail (data_device != NULL, NULL);
	g_return_val_if_fail (driver != NULL, NULL);

	return (NMDevice *) g_object_new (NM_TYPE_MODEM_GSM,
									  NM_DEVICE_INTERFACE_UDI, path,
									  NM_DEVICE_INTERFACE_IFACE, data_device,
									  NM_DEVICE_INTERFACE_DRIVER, driver,
									  NM_DEVICE_INTERFACE_MANAGED, TRUE,
									  NM_MODEM_PATH, path,
									  NULL);
}

static NMSetting *
get_setting (NMModemGsm *modem, GType setting_type)
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

#define get_proxy(dev,iface) (nm_modem_get_proxy(NM_MODEM (dev), iface))

static void
state_machine (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMModemGsm *modem = NM_MODEM_GSM (user_data);
	NMModemGsmPrivate *priv = NM_MODEM_GSM_GET_PRIVATE (modem);
	NMSettingGsm *setting;
	const char *secret = NULL;
	const char *secret_name = NULL;
	const char *str;
	GError *error = NULL;
	int i;
	gboolean retry_secret = FALSE;

	setting = NM_SETTING_GSM (get_setting (modem, NM_TYPE_SETTING_GSM));

	if (call_id)
		dbus_g_proxy_end_call (proxy, call_id, &error, G_TYPE_INVALID);

	if (error) {
		g_debug ("%s", dbus_g_error_get_name (error));

		if (dbus_g_error_has_name (error, MM_MODEM_ERROR_SIM_PIN)) {
			secret = nm_setting_gsm_get_pin (setting);
			secret_name = NM_SETTING_GSM_PIN;
			priv->modem_state = MODEM_STATE_SET_PIN;
		} else if (dbus_g_error_has_name (error, MM_MODEM_ERROR_SIM_PUK)) {
			secret = nm_setting_gsm_get_puk (setting);
			secret_name = NM_SETTING_GSM_PUK;
			priv->modem_state = MODEM_STATE_SET_PIN;
		} else if (dbus_g_error_has_name (error, MM_MODEM_ERROR_SIM_WRONG)) {
			g_object_set (setting, NM_SETTING_GSM_PIN, NULL, NULL);
			secret_name = NM_SETTING_GSM_PIN;
			retry_secret = TRUE;
			priv->modem_state = MODEM_STATE_SET_PIN;
		}

		/* FIXME: Hacks to ignore failures of setting band and network mode for now
		   since only Huawei module supports it. Remove when ModemManager rules.
		*/
		else if (dbus_g_error_has_name (error, MM_MODEM_ERROR_OPERATION_NOT_SUPPORTED) &&
				 (priv->modem_state == MODEM_STATE_SET_BAND ||
				  priv->modem_state == MODEM_STATE_SET_NETWORK_MODE)) {

			nm_warning ("Modem does not support setting %s, ignoring",
						priv->modem_state == MODEM_STATE_SET_BAND ? "band" : "network mode");
		} else {
			priv->modem_state = MODEM_STATE_FAILED;
			nm_warning ("GSM modem connection failed: %s", error->message);
		}

		g_error_free (error);
	}

 again:

	switch (priv->modem_state) {
	case MODEM_STATE_BEGIN:
		priv->modem_state = MODEM_STATE_ENABLE;
		dbus_g_proxy_begin_call (get_proxy (modem, MM_DBUS_INTERFACE_MODEM),
								 "Enable", state_machine,
								 modem, NULL,
								 G_TYPE_BOOLEAN, TRUE,
								 G_TYPE_INVALID);
		break;

	case MODEM_STATE_SET_PIN:
		if (secret) {
			priv->modem_state = MODEM_STATE_ENABLE;
			dbus_g_proxy_begin_call (get_proxy (modem, MM_DBUS_INTERFACE_MODEM_GSM_CARD),
									 "SendPin", state_machine,
									 modem, NULL,
									 G_TYPE_STRING, secret,
									 G_TYPE_INVALID);
		} else {
			nm_device_state_changed (NM_DEVICE (modem), NM_DEVICE_STATE_NEED_AUTH, NM_DEVICE_STATE_REASON_NONE);
			nm_act_request_request_connection_secrets (nm_device_get_act_request (NM_DEVICE (modem)),
													   NM_SETTING_GSM_SETTING_NAME,
													   retry_secret,
													   SECRETS_CALLER_GSM,
													   secret_name,
													   NULL);

		}
		break;

	case MODEM_STATE_ENABLE:
		priv->modem_state = MODEM_STATE_SET_APN;
		str = nm_setting_gsm_get_apn (setting);

		if (str)
			dbus_g_proxy_begin_call (get_proxy (modem, MM_DBUS_INTERFACE_MODEM_GSM_NETWORK),
									 "SetApn", state_machine,
									 modem, NULL,
									 G_TYPE_STRING, str,
									 G_TYPE_INVALID);
		else
			goto again;

		break;
	case MODEM_STATE_SET_APN:
		priv->modem_state = MODEM_STATE_SET_BAND;
		i = nm_setting_gsm_get_band (setting);

		if (i)
			dbus_g_proxy_begin_call (get_proxy (modem, MM_DBUS_INTERFACE_MODEM_GSM_NETWORK),
									 "SetBand", state_machine,
									 modem, NULL,
									 G_TYPE_UINT, (guint32) i,
									 G_TYPE_INVALID);
		else
			goto again;

		break;

	case MODEM_STATE_SET_BAND:
		priv->modem_state = MODEM_STATE_SET_NETWORK_MODE;
		i = nm_setting_gsm_get_network_type (setting);

		if (i)
			dbus_g_proxy_begin_call (get_proxy (modem, MM_DBUS_INTERFACE_MODEM_GSM_NETWORK),
									 "SetNetworkMode", state_machine,
									 modem, NULL,
									 G_TYPE_UINT, (guint32) i,
									 G_TYPE_INVALID);
		else
			goto again;

		break;

	case MODEM_STATE_SET_NETWORK_MODE:
		priv->modem_state = MODEM_STATE_REGISTER;

		str = nm_setting_gsm_get_network_id (setting);
		dbus_g_proxy_begin_call_with_timeout (get_proxy (modem, MM_DBUS_INTERFACE_MODEM_GSM_NETWORK),
											  "Register", state_machine,
											  modem, NULL, 120000,
											  G_TYPE_STRING, str ? str : "",
											  G_TYPE_INVALID);
		break;

	case MODEM_STATE_REGISTER:
		nm_modem_connect (NM_MODEM (modem), nm_setting_gsm_get_number (setting));
		break;
	case MODEM_STATE_FAILED:
	default:
		nm_device_state_changed (NM_DEVICE (modem), NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_NONE);
		break;
	}
}

static NMActStageReturn
real_act_stage1_prepare (NMDevice *device, NMDeviceStateReason *reason)
{
	NMModemGsmPrivate *priv = NM_MODEM_GSM_GET_PRIVATE (device);

	priv->modem_state = MODEM_STATE_BEGIN;
	state_machine (NULL, NULL, device);

	return NM_ACT_STAGE_RETURN_POSTPONE;
}

static NMConnection *
real_get_best_auto_connection (NMDevice *dev,
							   GSList *connections,
							   char **specific_object)
{
	GSList *iter;

	for (iter = connections; iter; iter = g_slist_next (iter)) {
		NMConnection *connection = NM_CONNECTION (iter->data);
		NMSettingConnection *s_con;

		s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
		g_assert (s_con);

		if (!nm_setting_connection_get_autoconnect (s_con))
			continue;

		if (strcmp (nm_setting_connection_get_connection_type (s_con), NM_SETTING_GSM_SETTING_NAME))
			continue;

		return connection;
	}
	return NULL;
}

static void
real_connection_secrets_updated (NMDevice *dev,
								 NMConnection *connection,
								 GSList *updated_settings,
								 RequestSecretsCaller caller)
{
	NMActRequest *req;
	gboolean found = FALSE;
	GSList *iter;

	if (caller == SECRETS_CALLER_PPP) {
		NMPPPManager *ppp_manager;
		NMSettingGsm *s_gsm = NULL;

		ppp_manager = nm_modem_get_ppp_manager (NM_MODEM (dev));
		g_return_if_fail (ppp_manager != NULL);

		s_gsm = (NMSettingGsm *) nm_connection_get_setting (connection, NM_TYPE_SETTING_GSM);
		if (!s_gsm) {
			/* Shouldn't ever happen */
			nm_ppp_manager_update_secrets (ppp_manager,
										   nm_device_get_iface (dev),
										   NULL,
										   NULL,
										   "missing GSM setting; no secrets could be found.");
		} else {
			const char *username = nm_setting_gsm_get_username (s_gsm);
			const char *password = nm_setting_gsm_get_password (s_gsm);

			nm_ppp_manager_update_secrets (ppp_manager,
										   nm_device_get_iface (dev),
										   username ? username : "",
										   password ? password : "",
										   NULL);
		}
		return;
	}

	g_return_if_fail (caller == SECRETS_CALLER_GSM);
	g_return_if_fail (nm_device_get_state (dev) == NM_DEVICE_STATE_NEED_AUTH);

	for (iter = updated_settings; iter; iter = g_slist_next (iter)) {
		const char *setting_name = (const char *) iter->data;

		if (!strcmp (setting_name, NM_SETTING_GSM_SETTING_NAME))
			found = TRUE;
		else
			nm_warning ("Ignoring updated secrets for setting '%s'.", setting_name);
	}

	if (!found)
		return;

	req = nm_device_get_act_request (dev);
	g_assert (req);

	g_return_if_fail (nm_act_request_get_connection (req) == connection);

	nm_device_activate_schedule_stage1_device_prepare (dev);
}

static const char *
real_get_ppp_name (NMModem *device, NMConnection *connection)
{
	NMSettingGsm *s_gsm;

	s_gsm = (NMSettingGsm *) nm_connection_get_setting (connection, NM_TYPE_SETTING_GSM);
	g_assert (s_gsm);

	return nm_setting_gsm_get_username (s_gsm);
}

/*****************************************************************************/

static void
nm_modem_gsm_init (NMModemGsm *self)
{
	nm_device_set_device_type (NM_DEVICE (self), NM_DEVICE_TYPE_GSM);
}

static void
nm_modem_gsm_class_init (NMModemGsmClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);
	NMModemClass *modem_class = NM_MODEM_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMModemGsmPrivate));

	/* Virtual methods */
	device_class->get_best_auto_connection = real_get_best_auto_connection;
	device_class->connection_secrets_updated = real_connection_secrets_updated;
	device_class->act_stage1_prepare = real_act_stage1_prepare;
	modem_class->get_ppp_name = real_get_ppp_name;

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (klass),
									 &dbus_glib_nm_device_gsm_object_info);
}
