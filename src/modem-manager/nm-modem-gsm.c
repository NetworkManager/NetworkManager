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


G_DEFINE_TYPE (NMModemGsm, nm_modem_gsm, NM_TYPE_MODEM)

#define NM_MODEM_GSM_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_MODEM_GSM, NMModemGsmPrivate))

typedef struct {
	DBusGProxyCall *call;
} NMModemGsmPrivate;


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


NMModem *
nm_modem_gsm_new (const char *path,
                  const char *device,
                  const char *data_device,
                  guint32 ip_method)
{
	g_return_val_if_fail (path != NULL, NULL);
	g_return_val_if_fail (device != NULL, NULL);
	g_return_val_if_fail (data_device != NULL, NULL);

	return (NMModem *) g_object_new (NM_TYPE_MODEM_GSM,
	                                 NM_MODEM_PATH, path,
	                                 NM_MODEM_DEVICE, device,
	                                 NM_MODEM_IFACE, data_device,
	                                 NM_MODEM_IP_METHOD, ip_method,
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
stage1_prepare_done (DBusGProxy *proxy, DBusGProxyCall *call, gpointer user_data)
{
	NMModemGsm *self = NM_MODEM_GSM (user_data);
	NMModemGsmPrivate *priv = NM_MODEM_GSM_GET_PRIVATE (self);
	GError *error = NULL;

	priv->call = NULL;

	if (dbus_g_proxy_end_call (proxy, call, &error, G_TYPE_INVALID))
		g_signal_emit_by_name (self, NM_MODEM_PREPARE_RESULT, TRUE, NM_DEVICE_STATE_REASON_NONE);
	else {
		const char *required_secret = NULL;
		gboolean retry_secret = FALSE;

		if (dbus_g_error_has_name (error, MM_MODEM_ERROR_SIM_PIN))
			required_secret = NM_SETTING_GSM_PIN;
		else if (dbus_g_error_has_name (error, MM_MODEM_ERROR_SIM_WRONG)) {
			required_secret = NM_SETTING_GSM_PIN;
			retry_secret = TRUE;
		} else {
			nm_warning ("GSM connection failed: (%d) %s",
			            error ? error->code : -1,
			            error && error->message ? error->message : "(unknown)");
		}

		if (required_secret) {
			g_signal_emit_by_name (self, NM_MODEM_NEED_AUTH,
			                       NM_SETTING_GSM_SETTING_NAME,
			                       retry_secret,
			                       SECRETS_CALLER_MOBILE_BROADBAND,
			                       required_secret,
			                       NULL);
		} else
			g_signal_emit_by_name (self, NM_MODEM_PREPARE_RESULT, FALSE, translate_mm_error (error));

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
real_act_stage1_prepare (NMModem *modem,
                         NMActRequest *req,
                         GPtrArray **out_hints,
                         const char **out_setting_name,
                         NMDeviceStateReason *reason)
{
	NMModemGsm *self = NM_MODEM_GSM (modem);
	NMModemGsmPrivate *priv = NM_MODEM_GSM_GET_PRIVATE (self);
	NMConnection *connection;

	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	*out_setting_name = nm_connection_need_secrets (connection, out_hints);
	if (!*out_setting_name) {
		DBusGProxy *proxy;
		GHashTable *properties;

		properties = create_connect_properties (connection);
		proxy = nm_modem_get_proxy (modem, MM_DBUS_INTERFACE_MODEM_SIMPLE);
		priv->call = dbus_g_proxy_begin_call_with_timeout (proxy,
		                                                   "Connect", stage1_prepare_done,
		                                                   self, NULL, 120000,
		                                                   DBUS_TYPE_G_MAP_OF_VARIANT, properties,
		                                                   G_TYPE_INVALID);
		g_hash_table_destroy (properties);
	} else {
		/* NMModem will handle requesting secrets... */
	}

	return NM_ACT_STAGE_RETURN_POSTPONE;
}

static NMConnection *
real_get_best_auto_connection (NMModem *modem,
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

static gboolean
real_check_connection_compatible (NMModem *modem,
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

static gboolean
real_get_user_pass (NMModem *modem,
                    NMConnection *connection,
                    const char **user,
                    const char **pass)
{
	NMSettingGsm *s_gsm;

	s_gsm = (NMSettingGsm *) nm_connection_get_setting (connection, NM_TYPE_SETTING_GSM);
	if (!s_gsm)
		return FALSE;

	if (user)
		*user = nm_setting_gsm_get_username (s_gsm);
	if (pass)
		*pass = nm_setting_gsm_get_password (s_gsm);

	return TRUE;
}

static const char *
real_get_setting_name (NMModem *modem)
{
	return NM_SETTING_GSM_SETTING_NAME;
}

static void
real_deactivate_quickly (NMModem *modem, NMDevice *device)
{
	NMModemGsmPrivate *priv = NM_MODEM_GSM_GET_PRIVATE (modem);

	if (priv->call) {
		DBusGProxy *proxy;

		proxy = nm_modem_get_proxy (modem, MM_DBUS_INTERFACE_MODEM_SIMPLE);
		dbus_g_proxy_cancel_call (proxy, priv->call);
		priv->call = NULL;
	}

	NM_MODEM_CLASS (nm_modem_gsm_parent_class)->deactivate_quickly (modem, device);	
}


/*****************************************************************************/

static void
nm_modem_gsm_init (NMModemGsm *self)
{
}

static void
nm_modem_gsm_class_init (NMModemGsmClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMModemClass *modem_class = NM_MODEM_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMModemGsmPrivate));

	/* Virtual methods */
	modem_class->get_user_pass = real_get_user_pass;
	modem_class->get_setting_name = real_get_setting_name;
	modem_class->get_best_auto_connection = real_get_best_auto_connection;
	modem_class->check_connection_compatible = real_check_connection_compatible;
	modem_class->act_stage1_prepare = real_act_stage1_prepare;
	modem_class->deactivate_quickly = real_deactivate_quickly;

//	device_class->act_stage2_config = real_act_stage2_config;

	dbus_g_error_domain_register (NM_GSM_ERROR, NULL, NM_TYPE_GSM_ERROR);
}
