/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

#include <string.h>

#include "nm-dbus-glib-types.h"
#include "nm-modem-cdma.h"
#include "nm-modem-types.h"
#include "nm-device-interface.h"
#include "nm-device-private.h"
#include "nm-dbus-manager.h"
#include "nm-setting-connection.h"
#include "nm-setting-cdma.h"
#include "nm-utils.h"
#include "NetworkManagerUtils.h"

#include "nm-device-cdma-glue.h"

G_DEFINE_TYPE (NMModemCdma, nm_modem_cdma, NM_TYPE_MODEM)

#define NM_MODEM_CDMA_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_MODEM_CDMA, NMModemCdmaPrivate))

typedef struct {
	DBusGProxyCall *call;
} NMModemCdmaPrivate;


typedef enum {
	NM_CDMA_ERROR_CONNECTION_NOT_CDMA = 0,
	NM_CDMA_ERROR_CONNECTION_INVALID,
	NM_CDMA_ERROR_CONNECTION_INCOMPATIBLE,
} NMCdmaError;

#define NM_CDMA_ERROR (nm_cdma_error_quark ())
#define NM_TYPE_CDMA_ERROR (nm_cdma_error_get_type ())

static GQuark
nm_cdma_error_quark (void)
{
	static GQuark quark = 0;
	if (!quark)
		quark = g_quark_from_static_string ("nm-cdma-error");
	return quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

static GType
nm_cdma_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Connection was not a CDMA connection. */
			ENUM_ENTRY (NM_CDMA_ERROR_CONNECTION_NOT_CDMA, "ConnectionNotCdma"),
			/* Connection was not a valid CDMA connection. */
			ENUM_ENTRY (NM_CDMA_ERROR_CONNECTION_INVALID, "ConnectionInvalid"),
			/* Connection does not apply to this device. */
			ENUM_ENTRY (NM_CDMA_ERROR_CONNECTION_INCOMPATIBLE, "ConnectionIncompatible"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("NMCdmaError", values);
	}
	return etype;
}


NMModem *
nm_modem_cdma_new (const char *path,
                   const char *device,
                   const char *data_device,
                   guint32 ip_method)
{
	g_return_val_if_fail (path != NULL, NULL);
	g_return_val_if_fail (device != NULL, NULL);
	g_return_val_if_fail (data_device != NULL, NULL);

	return (NMModem *) g_object_new (NM_TYPE_MODEM_CDMA,
	                                 NM_MODEM_PATH, path,
	                                 NM_MODEM_DEVICE, device,
	                                 NM_MODEM_IFACE, data_device,
	                                 NM_MODEM_IP_METHOD, ip_method,
	                                 NULL);
}

static void
stage1_prepare_done (DBusGProxy *proxy, DBusGProxyCall *call, gpointer user_data)
{
	NMModemCdma *self = NM_MODEM_CDMA (user_data);
	NMModemCdmaPrivate *priv = NM_MODEM_CDMA_GET_PRIVATE (self);
	GError *error = NULL;

	priv->call = NULL;

	if (dbus_g_proxy_end_call (proxy, call, &error, G_TYPE_INVALID))
		g_signal_emit_by_name (self, NM_MODEM_PREPARE_RESULT, TRUE, NM_DEVICE_STATE_REASON_NONE);
	else {
		nm_warning ("CDMA connection failed: (%d) %s",
		            error ? error->code : -1,
		            error && error->message ? error->message : "(unknown)");
		g_error_free (error);
		g_signal_emit_by_name (self, NM_MODEM_PREPARE_RESULT, FALSE, NM_DEVICE_STATE_REASON_NONE);
	}
}

static GHashTable *
create_connect_properties (NMConnection *connection)
{
	NMSettingCdma *setting;
	GHashTable *properties;
	const char *str;

	setting = NM_SETTING_CDMA (nm_connection_get_setting (connection, NM_TYPE_SETTING_CDMA));
	properties = value_hash_create ();

	str = nm_setting_cdma_get_number (setting);
	if (str)
		value_hash_add_str (properties, "number", str);

	return properties;
}

static NMActStageReturn
real_act_stage1_prepare (NMModem *modem,
                         NMActRequest *req,
                         GPtrArray **out_hints,
                         const char **out_setting_name,
                         NMDeviceStateReason *reason)
{
	NMModemCdma *self = NM_MODEM_CDMA (modem);
	NMModemCdmaPrivate *priv = NM_MODEM_CDMA_GET_PRIVATE (self);
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

		if (strcmp (nm_setting_connection_get_connection_type (s_con), NM_SETTING_CDMA_SETTING_NAME))
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
	NMSettingCdma *s_cdma;

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	g_assert (s_con);

	if (strcmp (nm_setting_connection_get_connection_type (s_con), NM_SETTING_CDMA_SETTING_NAME)) {
		g_set_error (error,
		             NM_CDMA_ERROR, NM_CDMA_ERROR_CONNECTION_NOT_CDMA,
		             "The connection was not a CDMA connection.");
		return FALSE;
	}

	s_cdma = NM_SETTING_CDMA (nm_connection_get_setting (connection, NM_TYPE_SETTING_CDMA));
	if (!s_cdma) {
		g_set_error (error,
		             NM_CDMA_ERROR, NM_CDMA_ERROR_CONNECTION_INVALID,
		             "The connection was not a valid CDMA connection.");
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
	NMSettingCdma *s_cdma;

	s_cdma = (NMSettingCdma *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CDMA);
	if (!s_cdma)
		return FALSE;

	if (user)
		*user = nm_setting_cdma_get_username (s_cdma);
	if (pass)
		*pass = nm_setting_cdma_get_password (s_cdma);

	return TRUE;
}

static const char *
real_get_setting_name (NMModem *modem)
{
	return NM_SETTING_CDMA_SETTING_NAME;
}

static void
real_deactivate_quickly (NMModem *modem, NMDevice *device)
{
	NMModemCdmaPrivate *priv = NM_MODEM_CDMA_GET_PRIVATE (modem);

	if (priv->call) {
		DBusGProxy *proxy;

		proxy = nm_modem_get_proxy (modem, MM_DBUS_INTERFACE_MODEM_SIMPLE);
		dbus_g_proxy_cancel_call (proxy, priv->call);
		priv->call = NULL;
	}

	NM_MODEM_CLASS (nm_modem_cdma_parent_class)->deactivate_quickly (modem, device);	
}

/*****************************************************************************/

static void
nm_modem_cdma_init (NMModemCdma *self)
{
}

static void
nm_modem_cdma_class_init (NMModemCdmaClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMModemClass *modem_class = NM_MODEM_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMModemCdmaPrivate));

	/* Virtual methods */
	modem_class->get_user_pass = real_get_user_pass;
	modem_class->get_setting_name = real_get_setting_name;
	modem_class->get_best_auto_connection = real_get_best_auto_connection;
	modem_class->check_connection_compatible = real_check_connection_compatible;
	modem_class->act_stage1_prepare = real_act_stage1_prepare;
	modem_class->deactivate_quickly = real_deactivate_quickly;

	dbus_g_error_domain_register (NM_CDMA_ERROR, NULL, NM_TYPE_CDMA_ERROR);
}
