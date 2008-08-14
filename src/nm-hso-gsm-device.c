/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <dbus/dbus-glib.h>

#include "nm-device.h"
#include "nm-hso-gsm-device.h"
#include "nm-gsm-device.h"
#include "nm-device-interface.h"
#include "nm-device-private.h"
#include "nm-setting-gsm.h"
#include "nm-utils.h"
#include "nm-properties-changed-signal.h"
#include "nm-setting-connection.h"
#include "NetworkManagerSystem.h"

G_DEFINE_TYPE (NMHsoGsmDevice, nm_hso_gsm_device, NM_TYPE_GSM_DEVICE)

#define NM_HSO_GSM_DEVICE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_HSO_GSM_DEVICE, NMHsoGsmDevicePrivate))

extern const DBusGObjectInfo dbus_glib_nm_gsm_device_object_info;

#define GSM_CID "gsm-cid"
#define HSO_SECRETS_TRIES "gsm-secrets-tries"

typedef struct {
	char *netdev_iface;
	NMIP4Config *pending_ip4_config;
} NMHsoGsmDevicePrivate;

enum {
	PROP_0,
	PROP_NETDEV_IFACE,

	LAST_PROP
};

NMHsoGsmDevice *
nm_hso_gsm_device_new (const char *udi,
                       const char *data_iface,
                       const char *monitor_iface,
                       const char *netdev_iface,
                       const char *driver,
                       gboolean managed)
{
	g_return_val_if_fail (udi != NULL, NULL);
	g_return_val_if_fail (data_iface != NULL, NULL);
	g_return_val_if_fail (driver != NULL, NULL);
	g_return_val_if_fail (netdev_iface != NULL, NULL);

	return (NMHsoGsmDevice *) g_object_new (NM_TYPE_HSO_GSM_DEVICE,
								  NM_DEVICE_INTERFACE_UDI, udi,
								  NM_DEVICE_INTERFACE_IFACE, data_iface,
								  NM_DEVICE_INTERFACE_DRIVER, driver,
								  NM_GSM_DEVICE_MONITOR_IFACE, monitor_iface,
								  NM_HSO_GSM_DEVICE_NETDEV_IFACE, netdev_iface,
								  NM_DEVICE_INTERFACE_MANAGED, managed,
								  NULL);
}

static void
modem_wait_for_reply (NMGsmDevice *self,
				  const char *command,
				  guint timeout,
				  char **responses,
				  char **terminators,
				  NMSerialWaitForReplyFn callback,
				  gpointer user_data)
{
	NMSerialDevice *serial = NM_SERIAL_DEVICE (self);
	guint id = 0;

	if (nm_serial_device_send_command_string (serial, command))
		id = nm_serial_device_wait_for_reply (serial, timeout, responses, terminators, callback, user_data);

	if (id == 0)
		nm_device_state_changed (NM_DEVICE (self), NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_UNKNOWN);
}

static void
modem_get_reply (NMGsmDevice *self,
			  const char *command,
			  guint timeout,
			  const char *terminators,
			  NMSerialGetReplyFn callback)
{
	NMSerialDevice *serial = NM_SERIAL_DEVICE (self);
	guint id = 0;

	if (nm_serial_device_send_command_string (serial, command))
		id = nm_serial_device_get_reply (serial, timeout, terminators, callback, NULL);

	if (id == 0)
		nm_device_state_changed (NM_DEVICE (self), NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_UNKNOWN);
}

static NMSetting *
gsm_device_get_setting (NMGsmDevice *device, GType setting_type)
{
	NMActRequest *req;
	NMSetting *setting = NULL;

	req = nm_device_get_act_request (NM_DEVICE (device));
	if (req) {
		NMConnection *connection;

		connection = nm_act_request_get_connection (req);
		if (connection)
			setting = nm_connection_get_setting (connection, setting_type);
	}

	return setting;
}

static void
hso_call_done (NMSerialDevice *device,
               int reply_index,
               gpointer user_data)
{
	gboolean success = FALSE;

	switch (reply_index) {
	case 0:
		nm_info ("Connected, Woo!");
		success = TRUE;
		break;
	default:
		nm_warning ("Connect request failed");
		break;
	}

	if (success)
		nm_device_activate_schedule_stage3_ip_config_start (NM_DEVICE (device));
	else
		nm_device_state_changed (NM_DEVICE (device), NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_MODEM_DIAL_FAILED);
}

static void
hso_clear_done (NMSerialDevice *device,
               int reply_index,
               gpointer user_data)
{
	char *responses[] = { "_OWANCALL: ", "ERROR", NULL };
	guint cid = GPOINTER_TO_UINT (user_data);
	char *command;

	/* Try to connect */
	command = g_strdup_printf ("AT_OWANCALL=%d,1,1", cid);
	modem_wait_for_reply (NM_GSM_DEVICE (device), command, 10, responses, responses, hso_call_done, NULL);
	g_free (command);
}

static void
hso_auth_done (NMSerialDevice *device,
               int reply_index,
               gpointer user_data)
{
	gboolean success = FALSE;
	char *responses[] = { "_OWANCALL: ", "ERROR", "NO CARRIER", NULL };
	guint cid = GPOINTER_TO_UINT (user_data);
	char *command;

	switch (reply_index) {
	case 0:
		nm_info ("Authentication successful!");
		success = TRUE;
		break;
	default:
		nm_warning ("Authentication failed");
		break;
	}

	if (!success) {
		nm_device_state_changed (NM_DEVICE (device), NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_MODEM_DIAL_FAILED);
		return;
	}

	/* Kill any existing connection */
	command = g_strdup_printf ("AT_OWANCALL=%d,0,1", cid);
	modem_wait_for_reply (NM_GSM_DEVICE (device), command, 5, responses, responses, hso_clear_done, GUINT_TO_POINTER (cid));
	g_free (command);
}

static void
do_hso_auth (NMHsoGsmDevice *device)
{
	NMSettingGsm *s_gsm;
	NMActRequest *req;
	char *responses[] = { "OK", "ERROR", NULL };
	char *command;
	guint cid;

	req = nm_device_get_act_request (NM_DEVICE (device));
	g_assert (req);

	cid = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (req), GSM_CID));

	s_gsm = NM_SETTING_GSM (gsm_device_get_setting (NM_GSM_DEVICE (device), NM_TYPE_SETTING_GSM));

	command = g_strdup_printf ("AT$QCPDPP=%d,1,\"%s\",\"%s\"",
	                           cid,
	                           s_gsm->password ? s_gsm->password : "",
	                           s_gsm->username ? s_gsm->username : "");
	modem_wait_for_reply (NM_GSM_DEVICE (device), command, 5, responses, responses, hso_auth_done, GUINT_TO_POINTER (cid));
	g_free (command);
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
		do_hso_auth (NM_HSO_GSM_DEVICE (device));
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
real_do_dial (NMGsmDevice *device, guint cid)
{
	NMActRequest *req;

	req = nm_device_get_act_request (NM_DEVICE (device));
	g_assert (req);
	g_object_set_data (G_OBJECT (req), GSM_CID, GUINT_TO_POINTER (cid));

	nm_device_activate_schedule_stage2_device_config (NM_DEVICE (device));
}

#define OWANDATA_TAG "_OWANDATA: "

static void
hso_ip4_config_done (NMSerialDevice *device,
                     const char *response,
                     gpointer user_data)
{
	NMHsoGsmDevicePrivate *priv = NM_HSO_GSM_DEVICE_GET_PRIVATE (device);
	NMActRequest *req;
	char **items, **iter;
	guint cid, i;
	NMSettingIP4Address addr = { 0, 32, 0 };
	guint32 dns1 = 0, dns2 = 0;

	if (!response || strncmp (response, OWANDATA_TAG, strlen (OWANDATA_TAG))) {
		nm_device_activate_schedule_stage4_ip_config_timeout (NM_DEVICE (device));
		return;
	}

	req = nm_device_get_act_request (NM_DEVICE (device));
	g_assert (req);
	cid = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (req), GSM_CID));

	items = g_strsplit (response + strlen (OWANDATA_TAG), ", ", 0);
	for (iter = items, i = 0; *iter; iter++, i++) {
		if (i == 0) { /* CID */
			long int tmp;

			errno = 0;
			tmp = strtol (*iter, NULL, 10);
			if (errno != 0 || tmp < 0 || (guint) tmp != cid) {
				nm_warning ("%s: unknown CID in OWANDATA response (got %d, expected %d)",
				            nm_device_get_iface (NM_DEVICE (device)),
				            (guint) tmp, cid);
				goto out;
			}
		} else if (i == 1) { /* IP address */
			if (inet_pton (AF_INET, *iter, &(addr.address)) <= 0)
				addr.address = 0;
		} else if (i == 3) { /* DNS 1 */
			if (inet_pton (AF_INET, *iter, &dns1) <= 0)
				dns1 = 0;
		} else if (i == 4) { /* DNS 2 */
			if (inet_pton (AF_INET, *iter, &dns2) <= 0)
				dns2 = 0;
		}
	}

out:
	g_strfreev (items);

	if (addr.address) {
		priv->pending_ip4_config = nm_ip4_config_new ();

		nm_ip4_config_add_address (priv->pending_ip4_config, &addr);

		if (dns1)
			nm_ip4_config_add_nameserver (priv->pending_ip4_config, dns1);
		if (dns2)
			nm_ip4_config_add_nameserver (priv->pending_ip4_config, dns2);

		nm_device_activate_schedule_stage4_ip_config_get (NM_DEVICE (device));
	} else {
		nm_device_state_changed (NM_DEVICE (device),
		                         NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE);
	}
}

static NMActStageReturn
real_act_stage3_ip_config_start (NMDevice *device, NMDeviceStateReason *reason)
{
	const char terminators[] = { '\r', '\n', '\0' };
	NMActRequest *req;
	char *command;
	gint cid;

	req = nm_device_get_act_request (device);
	g_assert (req);

	cid = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (req), GSM_CID));
	command = g_strdup_printf ("AT_OWANDATA=%d", cid);
	modem_get_reply (NM_GSM_DEVICE (device), command, 5, terminators, hso_ip4_config_done);
	g_free (command);

	return NM_ACT_STAGE_RETURN_POSTPONE;
}

static NMActStageReturn
real_act_stage4_get_ip4_config (NMDevice *device,
                                NMIP4Config **config,
                                NMDeviceStateReason *reason)
{
	NMHsoGsmDevice *self = NM_HSO_GSM_DEVICE (device);
	NMHsoGsmDevicePrivate *priv = NM_HSO_GSM_DEVICE_GET_PRIVATE (self);

	g_return_val_if_fail (config != NULL, NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (*config == NULL, NM_ACT_STAGE_RETURN_FAILURE);

	nm_device_set_ip_iface (device, priv->netdev_iface);
	if (!nm_device_hw_bring_up (device, TRUE))
		return NM_ACT_STAGE_RETURN_FAILURE;

	*config = priv->pending_ip4_config;
	priv->pending_ip4_config = NULL;
	return NM_ACT_STAGE_RETURN_SUCCESS;
}

static void
real_connection_secrets_updated (NMDevice *device,
                                 NMConnection *connection,
                                 GSList *updated_settings,
                                 RequestSecretsCaller caller)
{
	g_return_if_fail (caller == SECRETS_CALLER_HSO_GSM);
	g_return_if_fail (nm_device_get_state (device) == NM_DEVICE_STATE_NEED_AUTH);

	nm_device_activate_schedule_stage2_device_config (device);
}

static void
real_deactivate_quickly (NMDevice *device)
{
	NMHsoGsmDevicePrivate *priv = NM_HSO_GSM_DEVICE_GET_PRIVATE (device);
	NMActRequest *req;
	guint cid;
	char *command;

	if (priv->pending_ip4_config) {
		g_object_unref (priv->pending_ip4_config);
		priv->pending_ip4_config = NULL;
	}

	/* Don't leave the modem connected */
	req = nm_device_get_act_request (device);
	if (req) {
		cid = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (req), GSM_CID));
		if (cid) {
			command = g_strdup_printf ("AT_OWANCALL=%d,0,1", cid);
			nm_serial_device_send_command_string (NM_SERIAL_DEVICE (device), command);
			g_free (command);

			/* FIXME: doesn't seem to take the command otherwise, perhaps since
			 * the serial port gets closed right away
			 */
			g_usleep (G_USEC_PER_SEC / 3);
		}
	}


	if (NM_DEVICE_CLASS (nm_hso_gsm_device_parent_class)->deactivate_quickly)
		NM_DEVICE_CLASS (nm_hso_gsm_device_parent_class)->deactivate_quickly (device);
}

static void
real_deactivate (NMDevice *device)
{
	NMHsoGsmDevicePrivate *priv = NM_HSO_GSM_DEVICE_GET_PRIVATE (device);

	if (priv->netdev_iface) {
		nm_system_device_flush_ip4_routes_with_iface (priv->netdev_iface);
		nm_system_device_flush_ip4_addresses_with_iface (priv->netdev_iface);
		nm_system_device_set_up_down_with_iface (priv->netdev_iface, FALSE);
	}
	nm_device_set_ip_iface (device, NULL);

	if (NM_DEVICE_CLASS (nm_hso_gsm_device_parent_class)->deactivate)
		NM_DEVICE_CLASS (nm_hso_gsm_device_parent_class)->deactivate (device);
}

static gboolean
real_hw_is_up (NMDevice *device)
{
	NMHsoGsmDevicePrivate *priv = NM_HSO_GSM_DEVICE_GET_PRIVATE (device);
	NMDeviceState state;

	state = nm_device_interface_get_state (NM_DEVICE_INTERFACE (device));

	if (   priv->pending_ip4_config
	    || (state == NM_DEVICE_STATE_IP_CONFIG)
	    || (state == NM_DEVICE_STATE_ACTIVATED))
		return nm_system_device_is_up_with_iface (priv->netdev_iface);

	return TRUE;
}

static gboolean
real_hw_bring_up (NMDevice *device)
{
	NMHsoGsmDevicePrivate *priv = NM_HSO_GSM_DEVICE_GET_PRIVATE (device);
	NMDeviceState state;

	state = nm_device_interface_get_state (NM_DEVICE_INTERFACE (device));

	if (   priv->pending_ip4_config
	    || (state == NM_DEVICE_STATE_IP_CONFIG)
	    || (state == NM_DEVICE_STATE_ACTIVATED))
		return nm_system_device_set_up_down_with_iface (priv->netdev_iface, TRUE);

	return TRUE;
}

static void
nm_hso_gsm_device_init (NMHsoGsmDevice *self)
{
}

static GObject*
constructor (GType type,
             guint n_params,
             GObjectConstructParam *params)
{
	return G_OBJECT_CLASS (nm_hso_gsm_device_parent_class)->constructor (type, n_params, params);
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	NMHsoGsmDevicePrivate *priv = NM_HSO_GSM_DEVICE_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_NETDEV_IFACE:
		/* Construct only */
		priv->netdev_iface = g_value_dup_string (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
		    GValue *value, GParamSpec *pspec)
{
	NMHsoGsmDevicePrivate *priv = NM_HSO_GSM_DEVICE_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_NETDEV_IFACE:
		g_value_set_string (value, priv->netdev_iface);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
finalize (GObject *object)
{
	NMHsoGsmDevicePrivate *priv = NM_HSO_GSM_DEVICE_GET_PRIVATE (object);

	g_free (priv->netdev_iface);

	G_OBJECT_CLASS (nm_hso_gsm_device_parent_class)->finalize (object);
}

static void
nm_hso_gsm_device_class_init (NMHsoGsmDeviceClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);
	NMGsmDeviceClass *gsm_class = NM_GSM_DEVICE_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMHsoGsmDevicePrivate));

	object_class->constructor = constructor;
	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->finalize = finalize;

	device_class->act_stage2_config = real_act_stage2_config;
	device_class->act_stage3_ip_config_start = real_act_stage3_ip_config_start;
	device_class->act_stage4_get_ip4_config = real_act_stage4_get_ip4_config;
	device_class->connection_secrets_updated = real_connection_secrets_updated;
	device_class->deactivate_quickly = real_deactivate_quickly;
	device_class->deactivate = real_deactivate;
	device_class->hw_is_up = real_hw_is_up;
	device_class->hw_bring_up = real_hw_bring_up;

	gsm_class->do_dial = real_do_dial;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_NETDEV_IFACE,
		 g_param_spec_string (NM_HSO_GSM_DEVICE_NETDEV_IFACE,
						  "Network interface",
						  "Network interface",
						  NULL,
						  G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | NM_PROPERTY_PARAM_NO_EXPORT));

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (klass),
									 &dbus_glib_nm_gsm_device_object_info);
}
