/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

#include <string.h>
#include "nm-dbus-glib-types.h"
#include "nm-modem-gsm.h"
#include "nm-device-private.h"
#include "nm-device-interface.h"
#include "nm-setting-connection.h"
#include "nm-setting-gsm.h"
#include "nm-modem-types.h"
#include "nm-utils.h"
#include "NetworkManagerUtils.h"

#include "nm-device-gsm-glue.h"

typedef enum {
    MM_MODEM_GSM_MODE_UNKNOWN      = 0x00000000,
    MM_MODEM_GSM_MODE_ANY          = 0x00000001,
    MM_MODEM_GSM_MODE_GPRS         = 0x00000002,
    MM_MODEM_GSM_MODE_EDGE         = 0x00000004,
    MM_MODEM_GSM_MODE_UMTS         = 0x00000008,
    MM_MODEM_GSM_MODE_HSDPA        = 0x00000010,
    MM_MODEM_GSM_MODE_2G_PREFERRED = 0x00000020,
    MM_MODEM_GSM_MODE_3G_PREFERRED = 0x00000040,
    MM_MODEM_GSM_MODE_2G_ONLY      = 0x00000080,
    MM_MODEM_GSM_MODE_3G_ONLY      = 0x00000100,
    MM_MODEM_GSM_MODE_HSUPA        = 0x00000200,
    MM_MODEM_GSM_MODE_HSPA         = 0x00000400,

    MM_MODEM_GSM_MODE_LAST = MM_MODEM_GSM_MODE_HSPA
} MMModemGsmMode;


#define GSM_SECRETS_TRIES "gsm-secrets-tries"

G_DEFINE_TYPE (NMModemGsm, nm_modem_gsm, NM_TYPE_MODEM)


typedef enum {
	NM_GSM_ERROR_CONNECTION_NOT_GSM = 0,
	NM_GSM_ERROR_CONNECTION_INVALID,
	NM_GSM_ERROR_CONNECTION_INCOMPATIBLE,
} NMGsmError;

#define NM_GSM_ERROR (nm_gsm_error_quark ())
#define NM_TYPE_GSM_ERROR (nm_gsm_error_get_type ())

static GQuark
nm_gsm_error_quark (void)
{
	static GQuark quark = 0;
	if (!quark)
		quark = g_quark_from_static_string ("nm-gsm-error");
	return quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

static GType
nm_gsm_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Connection was not a GSM connection. */
			ENUM_ENTRY (NM_GSM_ERROR_CONNECTION_NOT_GSM, "ConnectionNotGsm"),
			/* Connection was not a valid GSM connection. */
			ENUM_ENTRY (NM_GSM_ERROR_CONNECTION_INVALID, "ConnectionInvalid"),
			/* Connection does not apply to this device. */
			ENUM_ENTRY (NM_GSM_ERROR_CONNECTION_INCOMPATIBLE, "ConnectionIncompatible"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("NMGsmError", values);
	}
	return etype;
}


NMDevice *
nm_modem_gsm_new (const char *path,
                  const char *device,
                  const char *data_device,
                  const char *driver,
                  guint32 ip_method)
{
	g_return_val_if_fail (path != NULL, NULL);
	g_return_val_if_fail (device != NULL, NULL);
	g_return_val_if_fail (data_device != NULL, NULL);
	g_return_val_if_fail (driver != NULL, NULL);

	return (NMDevice *) g_object_new (NM_TYPE_MODEM_GSM,
	                                  NM_DEVICE_INTERFACE_UDI, path,
	                                  NM_DEVICE_INTERFACE_IFACE, data_device,
	                                  NM_DEVICE_INTERFACE_DRIVER, driver,
	                                  NM_MODEM_PATH, path,
	                                  NM_MODEM_IP_METHOD, ip_method,
	                                  NM_MODEM_DEVICE, device,
	                                  NM_DEVICE_INTERFACE_TYPE_DESC, "GSM",
	                                  NM_DEVICE_INTERFACE_DEVICE_TYPE, NM_DEVICE_TYPE_GSM,
	                                  NULL);
}

static NMDeviceStateReason
translate_mm_error (GError *error)
{
	NMDeviceStateReason reason;

	if (dbus_g_error_has_name (error, MM_MODEM_CONNECT_ERROR_NO_CARRIER))
		reason = NM_DEVICE_STATE_REASON_MODEM_NO_CARRIER;
	if (dbus_g_error_has_name (error, MM_MODEM_CONNECT_ERROR_NO_DIALTONE))
		reason = NM_DEVICE_STATE_REASON_MODEM_DIAL_TIMEOUT;
	if (dbus_g_error_has_name (error, MM_MODEM_CONNECT_ERROR_BUSY))
		reason = NM_DEVICE_STATE_REASON_MODEM_BUSY;
	if (dbus_g_error_has_name (error, MM_MODEM_CONNECT_ERROR_NO_ANSWER))
		reason = NM_DEVICE_STATE_REASON_MODEM_DIAL_TIMEOUT;
	if (dbus_g_error_has_name (error, MM_MODEM_ERROR_NETWORK_NOT_ALLOWED))
		reason = NM_DEVICE_STATE_REASON_GSM_REGISTRATION_DENIED;
	if (dbus_g_error_has_name (error, MM_MODEM_ERROR_NETWORK_TIMEOUT))
		reason = NM_DEVICE_STATE_REASON_GSM_REGISTRATION_TIMEOUT;
	if (dbus_g_error_has_name (error, MM_MODEM_ERROR_NO_NETWORK))
		reason = NM_DEVICE_STATE_REASON_GSM_REGISTRATION_NOT_SEARCHING;

	/* FIXME: We have only GSM error messages here, and we have no idea which 
	   activation state failed. Reasons like:
	   NM_DEVICE_STATE_REASON_MODEM_DIAL_FAILED,
	   NM_DEVICE_STATE_REASON_MODEM_INIT_FAILED,
	   NM_DEVICE_STATE_REASON_GSM_APN_FAILED,
	   NM_DEVICE_STATE_REASON_GSM_REGISTRATION_FAILED,
	   NM_DEVICE_STATE_REASON_GSM_PIN_CHECK_FAILED
	   are not used.
	*/
	else
		reason = NM_DEVICE_STATE_REASON_UNKNOWN;

	return reason;
}

static void
clear_pin (NMDevice *device)
{
	NMActRequest *req;
	NMConnection *connection;
	NMSettingGsm *setting;

	req = nm_device_get_act_request (device);
	g_assert (req);
	connection = nm_act_request_get_connection (req);
	g_assert (connection);
	setting = NM_SETTING_GSM (nm_connection_get_setting (connection, NM_TYPE_SETTING_GSM));
	g_assert (setting);

	g_object_set (G_OBJECT (setting), NM_SETTING_GSM_PIN, NULL, NULL);
}

static void
stage1_prepare_done (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);
	GError *error = NULL;

	dbus_g_proxy_end_call (proxy, call_id, &error, G_TYPE_INVALID);
	if (!error)
		nm_device_activate_schedule_stage2_device_config (device);
	else {
		const char *required_secret = NULL;
		gboolean retry_secret = FALSE;

		if (dbus_g_error_has_name (error, MM_MODEM_ERROR_SIM_PIN))
			required_secret = NM_SETTING_GSM_PIN;
		else if (dbus_g_error_has_name (error, MM_MODEM_ERROR_SIM_WRONG)) {
			clear_pin (device);
			required_secret = NM_SETTING_GSM_PIN;
			retry_secret = TRUE;
		} else
			nm_warning ("GSM modem connection failed: %s", error->message);

		if (required_secret) {
			nm_device_state_changed (device, NM_DEVICE_STATE_NEED_AUTH, NM_DEVICE_STATE_REASON_NONE);
			nm_act_request_get_secrets (nm_device_get_act_request (device),
			                            NM_SETTING_GSM_SETTING_NAME,
			                            retry_secret,
			                            SECRETS_CALLER_GSM,
			                            required_secret,
			                            NULL);
		} else
			nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, translate_mm_error (error));

		g_error_free (error);
	}
}

static GHashTable *
create_connect_properties (NMConnection *connection)
{
	NMSettingGsm *setting;
	GHashTable *properties;
	const char *str;

	setting = NM_SETTING_GSM (nm_connection_get_setting (connection, NM_TYPE_SETTING_GSM));
	properties = value_hash_create ();

	str = nm_setting_gsm_get_number (setting);
	if (str)
		value_hash_add_str (properties, "number", str);

	str = nm_setting_gsm_get_apn (setting);
	if (str)
		value_hash_add_str (properties, "apn", str);

	str = nm_setting_gsm_get_network_id (setting);
	if (str)
		value_hash_add_str (properties, "network_id", str);

	str = nm_setting_gsm_get_pin (setting);
	if (str)
		value_hash_add_str (properties, "pin", str);

	str = nm_setting_gsm_get_username (setting);
	if (str)
		value_hash_add_str (properties, "username", str);

	str = nm_setting_gsm_get_password (setting);
	if (str)
		value_hash_add_str (properties, "password", str);

	switch (nm_setting_gsm_get_network_type (setting)) {
	case NM_GSM_NETWORK_UMTS_HSPA:
		value_hash_add_uint (properties, "network_mode", MM_MODEM_GSM_MODE_3G_ONLY);
		break;
	case NM_GSM_NETWORK_GPRS_EDGE:
		value_hash_add_uint (properties, "network_mode", MM_MODEM_GSM_MODE_2G_ONLY);
		break;
	case NM_GSM_NETWORK_PREFER_UMTS_HSPA:
		value_hash_add_uint (properties, "network_mode", MM_MODEM_GSM_MODE_3G_PREFERRED);
		break;
	case NM_GSM_NETWORK_PREFER_GPRS_EDGE:
		value_hash_add_uint (properties, "network_mode", MM_MODEM_GSM_MODE_2G_PREFERRED);
		break;
	default:
		value_hash_add_uint (properties, "network_mode", MM_MODEM_GSM_MODE_ANY);
		break;
	}

	/* FIXME: band */
	return properties;
}

static NMActStageReturn
real_act_stage1_prepare (NMDevice *device, NMDeviceStateReason *reason)
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
		GHashTable *properties;

		properties = create_connect_properties (connection);
		dbus_g_proxy_begin_call_with_timeout (nm_modem_get_proxy (NM_MODEM (device), MM_DBUS_INTERFACE_MODEM_SIMPLE),
											  "Connect", stage1_prepare_done,
											  device, NULL, 120000,
											  DBUS_TYPE_G_MAP_OF_VARIANT, properties,
											  G_TYPE_INVALID);

		return NM_ACT_STAGE_RETURN_POSTPONE;
	}

	if (hints) {
		if (hints->len > 0)
			hint1 = g_ptr_array_index (hints, 0);
		if (hints->len > 1)
			hint2 = g_ptr_array_index (hints, 1);
	}

	nm_device_state_changed (device, NM_DEVICE_STATE_NEED_AUTH, NM_DEVICE_STATE_REASON_NONE);

	tries = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (connection), GSM_SECRETS_TRIES));
	nm_act_request_get_secrets (req,
	                            setting_name,
	                            tries ? TRUE : FALSE,
	                            SECRETS_CALLER_GSM,
	                            hint1,
	                            hint2);
	g_object_set_data (G_OBJECT (connection), GSM_SECRETS_TRIES, GUINT_TO_POINTER (++tries));

	if (hints)
		g_ptr_array_free (hints, TRUE);

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

static NMActStageReturn
real_act_stage2_config (NMDevice *device, NMDeviceStateReason *reason)
{
	NMActRequest *req;
	NMConnection *connection;

	req = nm_device_get_act_request (device);
	g_assert (req);

	/* Clear secrets tries counter since secrets were successfully used
	 * already if we get here.
	 */
	connection = nm_act_request_get_connection (req);
	g_assert (connection);
	g_object_set_data (G_OBJECT (connection), GSM_SECRETS_TRIES, NULL);

	if (NM_DEVICE_CLASS (nm_modem_gsm_parent_class)->act_stage2_config)
		return NM_DEVICE_CLASS (nm_modem_gsm_parent_class)->act_stage2_config (device, reason);

	return NM_ACT_STAGE_RETURN_SUCCESS;
}

static void
real_deactivate_quickly (NMDevice *device)
{
	NMActRequest *req;
	NMConnection *connection;

	req = nm_device_get_act_request (device);
	if (req) {
		/* Clear the secrets attempts counter */
		connection = nm_act_request_get_connection (req);
		g_assert (connection);
		g_object_set_data (G_OBJECT (connection), GSM_SECRETS_TRIES, NULL);
	}

	if (NM_DEVICE_CLASS (nm_modem_gsm_parent_class)->deactivate_quickly)
		NM_DEVICE_CLASS (nm_modem_gsm_parent_class)->deactivate_quickly (device);
}

static gboolean
real_check_connection_compatible (NMDevice *device,
                                  NMConnection *connection,
                                  GError **error)
{
	NMSettingConnection *s_con;
	NMSettingGsm *s_gsm;

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	g_assert (s_con);

	if (strcmp (nm_setting_connection_get_connection_type (s_con), NM_SETTING_GSM_SETTING_NAME)) {
		g_set_error (error,
		             NM_GSM_ERROR, NM_GSM_ERROR_CONNECTION_NOT_GSM,
		             "The connection was not a GSM connection.");
		return FALSE;
	}

	s_gsm = NM_SETTING_GSM (nm_connection_get_setting (connection, NM_TYPE_SETTING_GSM));
	if (!s_gsm) {
		g_set_error (error,
		             NM_GSM_ERROR, NM_GSM_ERROR_CONNECTION_INVALID,
		             "The connection was not a valid GSM connection.");
		return FALSE;
	}

	return TRUE;
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
}

static void
nm_modem_gsm_class_init (NMModemGsmClass *klass)
{
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);
	NMModemClass *modem_class = NM_MODEM_CLASS (klass);

	/* Virtual methods */
	device_class->get_best_auto_connection = real_get_best_auto_connection;
	device_class->connection_secrets_updated = real_connection_secrets_updated;
	device_class->act_stage1_prepare = real_act_stage1_prepare;
	device_class->act_stage2_config = real_act_stage2_config;
	device_class->deactivate_quickly = real_deactivate_quickly;
	device_class->check_connection_compatible = real_check_connection_compatible;

	modem_class->get_ppp_name = real_get_ppp_name;

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (klass),
									 &dbus_glib_nm_device_gsm_object_info);

	dbus_g_error_domain_register (NM_GSM_ERROR, NULL, NM_TYPE_GSM_ERROR);
}
