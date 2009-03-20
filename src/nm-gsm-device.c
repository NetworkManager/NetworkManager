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
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2008 Red Hat, Inc.
 */

#include <stdio.h>
#include <string.h>
#include "nm-glib-compat.h"
#include "nm-gsm-device.h"
#include "nm-device-interface.h"
#include "nm-device-private.h"
#include "nm-setting-gsm.h"
#include "nm-utils.h"
#include "nm-properties-changed-signal.h"
#include "nm-gsm-device-glue.h"
#include "nm-setting-connection.h"

G_DEFINE_TYPE (NMGsmDevice, nm_gsm_device, NM_TYPE_SERIAL_DEVICE)

#define NM_GSM_DEVICE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_GSM_DEVICE, NMGsmDevicePrivate))

typedef enum {
	NM_GSM_SECRET_NONE = 0,
	NM_GSM_SECRET_PIN,
	NM_GSM_SECRET_PUK
} NMGsmSecret;

typedef struct {
	char *monitor_iface;
	NMSerialDevice *monitor_device;

	guint pending_id;
	guint state_to_disconnected_id;

	guint reg_tries;
	guint init_tries;
	gboolean init_ok;
	guint pin_tries;

	gboolean needs_cgreg;
	gboolean checked_cgmm;
} NMGsmDevicePrivate;

enum {
	PROP_0,
	PROP_MONITOR_IFACE,

	LAST_PROP
};

enum {
	PROPERTIES_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

/* Various possible init sequences */
const gchar *modem_init_sequences[] = {
	"ATZ E0 V1 X4 &C1 +FCLASS=0",
	"ATZ E0 V1 &C1",
	"AT&F E0 V1 X4 &C1 +FCLASS=0",
	"AT&F E0 V1 &C1",
	"AT&F E0 V1",
	"\rAT&F E0 V1 X4 &C1 +CREG=0 +FCLASS=0",  /* USBModem by MobileStream for Palm */
	NULL
};

static void enter_pin (NMGsmDevice *device, NMGsmSecret secret_type, gboolean retry);
static void manual_registration (NMGsmDevice *device);
static void automatic_registration (NMGsmDevice *device);
static void init_modem_full (NMGsmDevice *device);
static void init_modem (NMSerialDevice *device);
static void check_pin (NMGsmDevice *self);

NMGsmDevice *
nm_gsm_device_new (const char *udi,
			    const char *data_iface,
			    const char *monitor_iface,
			    const char *driver,
			    gboolean managed)
{
	g_return_val_if_fail (udi != NULL, NULL);
	g_return_val_if_fail (data_iface != NULL, NULL);
	g_return_val_if_fail (driver != NULL, NULL);

	return (NMGsmDevice *) g_object_new (NM_TYPE_GSM_DEVICE,
								  NM_DEVICE_INTERFACE_UDI, udi,
								  NM_DEVICE_INTERFACE_IFACE, data_iface,
								  NM_DEVICE_INTERFACE_DRIVER, driver,
								  NM_GSM_DEVICE_MONITOR_IFACE, monitor_iface,
								  NM_DEVICE_INTERFACE_MANAGED, managed,
								  NULL);
}

static void
modem_wait_for_reply (NMGsmDevice *self,
                      const char *command,
                      guint timeout,
                      const char **responses,
                      const char **terminators,
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
dial_done (NMSerialDevice *device,
           int reply_index,
           const char *reply,
           gpointer user_data)
{
	gboolean success = FALSE;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_UNKNOWN;

	switch (reply_index) {
	case 0:
		nm_info ("Connected, Woo!");
		success = TRUE;
		break;
	case 1:
		nm_info ("Busy");
		reason = NM_DEVICE_STATE_REASON_MODEM_BUSY;
		break;
	case 2:
		nm_warning ("No dial tone");
		reason = NM_DEVICE_STATE_REASON_MODEM_NO_DIAL_TONE;
		break;
	case 3:
		nm_warning ("No carrier");
		reason = NM_DEVICE_STATE_REASON_MODEM_NO_CARRIER;
		break;
	case -1:
		nm_warning ("Dialing timed out");
		reason = NM_DEVICE_STATE_REASON_MODEM_DIAL_TIMEOUT;
		break;
	default:
		nm_warning ("Dialing failed");
		reason = NM_DEVICE_STATE_REASON_MODEM_DIAL_FAILED;
		break;
	}

	if (success)
		nm_device_activate_schedule_stage2_device_config (NM_DEVICE (device));
	else
		nm_device_state_changed (NM_DEVICE (device), NM_DEVICE_STATE_FAILED, reason);
}

static void
real_do_dial (NMGsmDevice *device, guint cid)
{
	NMSettingGsm *setting;
	char *command;
	const char *number;
	const char *responses[] = { "CONNECT", "BUSY", "NO DIAL TONE", "NO CARRIER", NULL };

	setting = NM_SETTING_GSM (gsm_device_get_setting (NM_GSM_DEVICE (device), NM_TYPE_SETTING_GSM));
	number = nm_setting_gsm_get_number (setting);

	if (cid) {
		GString *str;

		str = g_string_new ("ATD");
		if (g_str_has_suffix (number, "#"))
			str = g_string_append_len (str, number, strlen (number) - 1);
		else
			str = g_string_append (str, number);

		g_string_append_printf (str, "***%d#", cid);
		command = g_string_free (str, FALSE);
	} else
		command = g_strconcat ("ATDT", number, NULL);

	modem_wait_for_reply (device, command, 60, responses, responses, dial_done, NULL);
	g_free (command);
}

static void
set_apn_done (NMSerialDevice *device,
              int reply_index,
              const char *reply,
              gpointer user_data)
{
	switch (reply_index) {
	case 0:
		NM_GSM_DEVICE_GET_CLASS (device)->do_dial (NM_GSM_DEVICE (device), GPOINTER_TO_UINT (user_data));
		break;
	default:
		nm_warning ("Setting APN failed");
		nm_device_state_changed (NM_DEVICE (device),
		                         NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_GSM_APN_FAILED);
		break;
	}
}

static void
set_apn (NMGsmDevice *device)
{
	NMGsmDevicePrivate *priv = NM_GSM_DEVICE_GET_PRIVATE (device);
	NMSettingGsm *setting;
	char *command;
	const char *apn;
	const char *responses[] = { "OK", "ERROR", NULL };
	guint cid = 1;

	priv->reg_tries = 0;

	setting = NM_SETTING_GSM (gsm_device_get_setting (NM_GSM_DEVICE (device), NM_TYPE_SETTING_GSM));

	apn = nm_setting_gsm_get_apn (setting);
	if (!apn) {
		/* APN not set, nothing to do */
		NM_GSM_DEVICE_GET_CLASS (device)->do_dial (NM_GSM_DEVICE (device), 0);
		return;
	}

	command = g_strdup_printf ("AT+CGDCONT=%d,\"IP\",\"%s\"", cid, apn);
	modem_wait_for_reply (device, command, 7, responses, responses, set_apn_done, GUINT_TO_POINTER (cid));
	g_free (command);
}

static gboolean
manual_registration_again (gpointer data)
{
	manual_registration (NM_GSM_DEVICE (data));
	return FALSE;
}

static void
schedule_manual_registration_again (NMGsmDevice *self)
{
	NMGsmDevicePrivate *priv = NM_GSM_DEVICE_GET_PRIVATE (self);

	if (priv->pending_id)
		g_source_remove (priv->pending_id);

	priv->pending_id = g_idle_add (manual_registration_again, self);
}

static void
manual_registration_response (NMSerialDevice *device,
                              int reply_index,
                              const char *reply,
                              gpointer user_data)
{
	NMGsmDevicePrivate *priv = NM_GSM_DEVICE_GET_PRIVATE (device);

	switch (reply_index) {
	case 0:
		set_apn (NM_GSM_DEVICE (device));
		break;
	case -1:
		/* Some cards (ex. Sierra AC860) don't immediately respond to commands
		 * after they are powered up with CFUN=1, but take a few seconds to come
		 * back to life.  So try registration a few times.
		 */
		if (priv->reg_tries++ < 6) {
			schedule_manual_registration_again (NM_GSM_DEVICE (device));
		} else {
			nm_warning ("Manual registration timed out");
			priv->reg_tries = 0;
			nm_device_state_changed (NM_DEVICE (device),
			                         NM_DEVICE_STATE_FAILED,
			                         NM_DEVICE_STATE_REASON_GSM_REGISTRATION_TIMEOUT);
		}
		break;
	default:
		nm_warning ("Manual registration failed");
		nm_device_state_changed (NM_DEVICE (device),
		                         NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_GSM_REGISTRATION_FAILED);
		break;
	}
}

static void
manual_registration (NMGsmDevice *device)
{
	NMSettingGsm *setting;
	char *command;
	const char *responses[] = { "OK", "ERROR", "ERR", NULL };

	setting = NM_SETTING_GSM (gsm_device_get_setting (device, NM_TYPE_SETTING_GSM));

	command = g_strdup_printf ("AT+COPS=1,2,\"%s\"", nm_setting_gsm_get_network_id (setting));
	modem_wait_for_reply (device, command, 15, responses, responses, manual_registration_response, NULL);
	g_free (command);
}

static void
get_network_response (NMSerialDevice *device,
                      int reply_index,
                      const char *reply,
                      gpointer user_data)
{
	switch (reply_index) {
	case 0:
		nm_info ("Associated with network: %s", reply);
		break;
	default:
		nm_warning ("Couldn't read active network name");
		break;
	}

	set_apn (NM_GSM_DEVICE (device));
}

static void
automatic_registration_get_network (NMGsmDevice *device)
{
	const char *responses[] = { "+COPS: ", NULL };
	const char *terminators[] = { "OK", "ERROR", "ERR", NULL };

	modem_wait_for_reply (device, "AT+COPS?", 10, responses, terminators, get_network_response, NULL);
}

static gboolean
automatic_registration_again (gpointer data)
{
	automatic_registration (NM_GSM_DEVICE (data));
	return FALSE;
}

static void
schedule_automatic_registration_again (NMGsmDevice *self)
{
	NMGsmDevicePrivate *priv = NM_GSM_DEVICE_GET_PRIVATE (self);

	if (priv->pending_id)
		g_source_remove (priv->pending_id);

	priv->pending_id = g_timeout_add_seconds (1, automatic_registration_again, self);
}

static void
automatic_registration_response (NMSerialDevice *device,
                                 int reply_index,
                                 const char *reply,
                                 gpointer user_data)
{
	NMGsmDevicePrivate *priv = NM_GSM_DEVICE_GET_PRIVATE (device);

	switch (reply_index) {
	case 4:
	case 0:
		/* Try autoregistration a few times here because the card is actually
		 * responding to the query and thus we aren't waiting as long for
		 * each CREG request.  Some cards (ex. Option iCON 225) return OK
		 * immediately from CFUN, but take a bit to start searching for a network.
		 */
		if (priv->reg_tries++ < 15) {
			/* Can happen a few times while the modem is powering up */
			schedule_automatic_registration_again (NM_GSM_DEVICE (device));
		} else {
			priv->reg_tries = 0;
			nm_warning ("Automatic registration failed: not registered and not searching.");
			nm_device_state_changed (NM_DEVICE (device),
			                         NM_DEVICE_STATE_FAILED,
			                         NM_DEVICE_STATE_REASON_GSM_REGISTRATION_NOT_SEARCHING);
		}
		break;
	case 1:
		nm_info ("Registered on Home network");
		automatic_registration_get_network (NM_GSM_DEVICE (device));
		break;
	case 2:
		nm_info ("Searching for a network...");
		schedule_automatic_registration_again (NM_GSM_DEVICE (device));
		break;
	case 3:
		nm_warning ("Automatic registration failed: registration denied.");
		nm_device_state_changed (NM_DEVICE (device),
		                         NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_GSM_REGISTRATION_DENIED);
		break;
	case 5:
		nm_info ("Registered on Roaming network");
		automatic_registration_get_network (NM_GSM_DEVICE (device));
		break;
	case -1:
		/* Some cards (ex. Sierra AC860) don't immediately respond to commands
		 * after they are powered up with CFUN=1, but take a few seconds to come
		 * back to life.  So try registration a few times.
		 */
		nm_warning ("Automatic registration timed out");
		if (priv->reg_tries++ < 6) {
			schedule_automatic_registration_again (NM_GSM_DEVICE (device));
		} else {
			priv->reg_tries = 0;
			nm_device_state_changed (NM_DEVICE (device),
			                         NM_DEVICE_STATE_FAILED,
			                         NM_DEVICE_STATE_REASON_GSM_REGISTRATION_TIMEOUT);
		}
		break;
	default:
		nm_warning ("Automatic registration failed");
		nm_device_state_changed (NM_DEVICE (device),
		                         NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_GSM_REGISTRATION_FAILED);
		break;
	}
}

static void
automatic_registration (NMGsmDevice *device)
{
	NMGsmDevicePrivate *priv = NM_GSM_DEVICE_GET_PRIVATE (device);
	const char *creg_responses[] = { "+CREG: 0,0", "+CREG: 0,1", "+CREG: 0,2", "+CREG: 0,3", "+CREG: 0,4", "+CREG: 0,5", NULL };
	const char *cgreg_responses[] = { "+CGREG: 0,0", "+CGREG: 0,1", "+CGREG: 0,2", "+CGREG: 0,3", "+CGREG: 0,4", "+CGREG: 0,5", NULL };
	const char *terminators[] = { "OK", "ERROR", "ERR", NULL };

	if (priv->needs_cgreg)
		modem_wait_for_reply (device, "AT+CGREG?", 15, cgreg_responses, terminators, automatic_registration_response, NULL);
	else
		modem_wait_for_reply (device, "AT+CREG?", 15, creg_responses, terminators, automatic_registration_response, NULL);
}

static void
do_register (NMGsmDevice *device)
{
	NMGsmDevicePrivate *priv = NM_GSM_DEVICE_GET_PRIVATE (device);
	NMSettingGsm *setting;

	setting = NM_SETTING_GSM (gsm_device_get_setting (device, NM_TYPE_SETTING_GSM));

	priv->reg_tries = 0;
	if (nm_setting_gsm_get_network_id (setting))
		manual_registration (device);
	else
		automatic_registration (device);
}

static void
get_model_done (NMSerialDevice *device,
                int reply_index,
                const char *reply,
                gpointer user_data)
{
	NMGsmDevicePrivate *priv = NM_GSM_DEVICE_GET_PRIVATE (device);

	priv->checked_cgmm = TRUE;

	switch (reply_index) {
	case 0: /* Huawei E160G */
	case 1: /* Ericsson F3507g */
		priv->needs_cgreg = TRUE;
		break;
	default:
		break;
	}

	do_register (NM_GSM_DEVICE (device));
}

static void
power_up_response (NMSerialDevice *device,
                   int reply_index,
                   const char *reply,
                   gpointer user_data)
{
	NMGsmDevice *self = NM_GSM_DEVICE (device);
	NMGsmDevicePrivate *priv = NM_GSM_DEVICE_GET_PRIVATE (self);
	const char *responses[] = { "E160G", "F3507g", "D5530", "MD300", NULL };
	const char *terminators[] = { "OK", "ERROR", "ERR", NULL };

	/* Get the model the first time */
	if (!priv->checked_cgmm)
		modem_wait_for_reply (self, "AT+CGMM", 5, responses, terminators, get_model_done, NULL);
	else
		do_register (NM_GSM_DEVICE (device));
}

static void
power_up (NMGsmDevice *device)
{
	const char *responses[] = { "OK", "ERROR", "ERR", NULL };

	nm_info ("(%s): powering up...", nm_device_get_iface (NM_DEVICE (device)));		
	modem_wait_for_reply (device, "AT+CFUN=1", 10, responses, responses, power_up_response, NULL);
}

static void
init_full_done (NMSerialDevice *device,
                int reply_index,
                const char *reply,
                gpointer user_data)
{
	NMGsmDevice *self = NM_GSM_DEVICE (device);
	NMGsmDevicePrivate *priv = NM_GSM_DEVICE_GET_PRIVATE (self);

	switch (reply_index) {
	case 0:
		priv->init_ok = TRUE;
		power_up (NM_GSM_DEVICE (device));
		break;
	case -1:
		nm_warning ("Modem second stage initialization timed out");
		nm_device_state_changed (NM_DEVICE (device),
		                         NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_MODEM_INIT_FAILED);
		break;
	default:
		if (priv->init_ok) {
			/* If the successful init string from before PIN checking failed for
			 * some reason, try all the init strings again.
			 */
			priv->init_ok = FALSE;

			/* But don't try the first init string twice if it was previously
			 * successful, but has now failed for some reason.
			 */
			priv->init_tries = (priv->init_tries > 0) ? 0 : 1;
		} else
			priv->init_tries++;

		if (modem_init_sequences[priv->init_tries] != NULL) {
			nm_warning ("Trying alternate modem initialization (%d)",
			            priv->init_tries);
			init_modem_full (self);
		} else {
			nm_warning ("Modem second stage initialization failed");
			nm_device_state_changed (NM_DEVICE (device),
			                         NM_DEVICE_STATE_FAILED,
			                         NM_DEVICE_STATE_REASON_MODEM_INIT_FAILED);
		}
		return;
	}
}

static void
init_modem_full (NMGsmDevice *device)
{
	NMGsmDevicePrivate *priv = NM_GSM_DEVICE_GET_PRIVATE (device);
	const char *responses[] = { "OK", "ERROR", "ERR", NULL };

	/* Make sure that E0 gets sent here again, because some devices turn echo
	 * back on after CPIN which just breaks stuff since echo-ed commands are
	 * interpreted as replies. (rh #456770)
	 */
	modem_wait_for_reply (device, modem_init_sequences[priv->init_tries], 10, responses, responses, init_full_done, NULL);
}

static void
enter_pin_done (NMSerialDevice *device,
                int reply_index,
                const char *reply,
                gpointer user_data)
{
	NMSettingGsm *setting;
	NMGsmSecret secret = GPOINTER_TO_UINT (user_data);

	switch (reply_index) {
	case 0:
		init_modem_full (NM_GSM_DEVICE (device));
		break;
	case -1:
		nm_warning ("Did not receive response for secret");
		nm_device_state_changed (NM_DEVICE (device),
		                         NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_NO_SECRETS);
		break;
	default:
		nm_warning ("Invalid secret");
		setting = NM_SETTING_GSM (gsm_device_get_setting (NM_GSM_DEVICE (device), NM_TYPE_SETTING_GSM));

		/* Make sure we don't use the invalid PIN/PUK again
		   as it may lock up the SIM card */

		switch (secret) {
		case NM_GSM_SECRET_PIN:
			g_object_set (setting, NM_SETTING_GSM_PIN, NULL, NULL);
			break;
		case NM_GSM_SECRET_PUK:
			g_object_set (setting, NM_SETTING_GSM_PUK, NULL, NULL);
			break;
		default:
			break;
		}

		enter_pin (NM_GSM_DEVICE (device), secret, TRUE);
		break;
	}
}

static void
enter_pin (NMGsmDevice *device, NMGsmSecret secret_type, gboolean retry)
{
	NMSettingGsm *setting;
	NMActRequest *req;
	NMConnection *connection;
	const char *secret;
	char *secret_name = NULL;

	req = nm_device_get_act_request (NM_DEVICE (device));
	g_assert (req);
	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	setting = NM_SETTING_GSM (nm_connection_get_setting (connection, NM_TYPE_SETTING_GSM));

	switch (secret_type) {
	case NM_GSM_SECRET_PIN:
		secret_name = NM_SETTING_GSM_PIN;
		break;
	case NM_GSM_SECRET_PUK:
		secret_name = NM_SETTING_GSM_PUK;
		break;
	default:
		power_up (device);
		return;
	}

	g_object_get (setting, secret_name, &secret, NULL);
	if (secret) {
		char *command;
		const char *responses[] = { "OK", "ERROR", "ERR", NULL };

		command = g_strdup_printf ("AT+CPIN=\"%s\"", secret);
		modem_wait_for_reply (device, command, 3, responses, responses, enter_pin_done, GUINT_TO_POINTER (secret_type));
		g_free (command);
	} else {
		nm_info ("(%s): GSM %s secret required", nm_device_get_iface (NM_DEVICE (device)), secret_name);
		nm_device_state_changed (NM_DEVICE (device),
		                         NM_DEVICE_STATE_NEED_AUTH,
		                         NM_DEVICE_STATE_REASON_NONE);
		nm_act_request_request_connection_secrets (req,
		                                           NM_SETTING_GSM_SETTING_NAME,
		                                           retry,
		                                           SECRETS_CALLER_GSM,
		                                           secret_name,
		                                           NULL);
	}
}

static gboolean
check_pin_again (gpointer data)
{
	check_pin (NM_GSM_DEVICE (data));
	return FALSE;
}

static void
schedule_check_pin_again (NMGsmDevice *self)
{
	NMGsmDevicePrivate *priv = NM_GSM_DEVICE_GET_PRIVATE (self);

	if (priv->pending_id)
		g_source_remove (priv->pending_id);

	priv->pending_id = g_timeout_add_seconds (1, check_pin_again, self);
}

static void
check_pin_done (NMSerialDevice *device,
                int reply_index,
                const char *reply,
                gpointer user_data)
{
	NMGsmDevicePrivate *priv = NM_GSM_DEVICE_GET_PRIVATE (device);

	switch (reply_index) {
	case 0:
		priv->pin_tries = 0;
		init_modem_full (NM_GSM_DEVICE (device));
		break;
	case 1:
		priv->pin_tries = 0;
		enter_pin (NM_GSM_DEVICE (device), NM_GSM_SECRET_PIN, FALSE);
		break;
	case 2:
		priv->pin_tries = 0;
		enter_pin (NM_GSM_DEVICE (device), NM_GSM_SECRET_PUK, FALSE);
		break;
	case 3:
	case 4:
	case -1: /* timeout */
		/* Try the pin a few times; sometimes the error is transient */
		if (priv->pin_tries++ < 4) {
			schedule_check_pin_again (NM_GSM_DEVICE (device));
		} else {
			priv->pin_tries = 0;
			nm_warning ("PIN checking failed to many times");
			nm_device_state_changed (NM_DEVICE (device),
			                         NM_DEVICE_STATE_FAILED,
			                         NM_DEVICE_STATE_REASON_GSM_PIN_CHECK_FAILED);
		}
		break;
	default:
		nm_warning ("PIN checking failed");
		nm_device_state_changed (NM_DEVICE (device),
		                         NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_GSM_PIN_CHECK_FAILED);
		return;
	}
}

static void
check_pin (NMGsmDevice *self)
{
	const char *responses[] = { "READY", "SIM PIN", "SIM PUK", "ERROR", "ERR", NULL };
	const char *terminators[] = { "OK", "ERROR", "ERR", NULL };

	modem_wait_for_reply (self, "AT+CPIN?", 3, responses, terminators, check_pin_done, NULL);
}

static gboolean
init_modem_again (gpointer data)
{
	init_modem (NM_SERIAL_DEVICE (data));
	return FALSE;
}

static void
schedule_init_modem_again (NMGsmDevice *self)
{
	NMGsmDevicePrivate *priv = NM_GSM_DEVICE_GET_PRIVATE (self);

	if (priv->pending_id)
		g_source_remove (priv->pending_id);

	priv->pending_id = g_timeout_add_seconds (1, init_modem_again, self);
}

static void
init_done (NMSerialDevice *device,
           int reply_index,
           const char *reply,
           gpointer user_data)
{
	NMGsmDevicePrivate *priv = NM_GSM_DEVICE_GET_PRIVATE (device);

	switch (reply_index) {
	case 0:
		priv->init_ok = TRUE;
		check_pin (NM_GSM_DEVICE (device));
		break;
	case 1:
		/* Ignore a NO CARRIER message from previous connection termination */
		schedule_init_modem_again (NM_GSM_DEVICE (device));
		break;
	case -1:
		nm_warning ("Modem initialization timed out");
		nm_device_state_changed (NM_DEVICE (device),
		                         NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_MODEM_INIT_FAILED);
		break;
	default:
		priv->init_tries++;
		if (modem_init_sequences[priv->init_tries] != NULL) {
			nm_warning ("Trying alternate modem initialization (%d)",
			            priv->init_tries);
			schedule_init_modem_again (NM_GSM_DEVICE (device));
		} else {
			nm_warning ("Modem initialization failed");
			nm_device_state_changed (NM_DEVICE (device),
			                         NM_DEVICE_STATE_FAILED,
			                         NM_DEVICE_STATE_REASON_MODEM_INIT_FAILED);
		}
		break;
	}
}

static void
init_modem (NMSerialDevice *device)
{
	NMGsmDevicePrivate *priv = NM_GSM_DEVICE_GET_PRIVATE (device);
	const char *responses[] = { "OK", "NO CARRIER", "ERROR", "ERR", NULL };
	const char *init_string = modem_init_sequences[priv->init_tries];

	modem_wait_for_reply (NM_GSM_DEVICE (device), init_string, 10, responses, responses, init_done, NULL);
}

static NMActStageReturn
real_act_stage1_prepare (NMDevice *device, NMDeviceStateReason *reason)
{
	NMSerialDevice *serial_device = NM_SERIAL_DEVICE (device);
	NMSettingSerial *setting;
	guint id;

	setting = NM_SETTING_SERIAL (gsm_device_get_setting (NM_GSM_DEVICE (device), NM_TYPE_SETTING_SERIAL));

	if (!nm_serial_device_open (serial_device, setting)) {
		*reason = NM_DEVICE_STATE_REASON_CONFIG_FAILED;
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	NM_GSM_DEVICE_GET_PRIVATE (device)->init_tries = 0;
	NM_GSM_DEVICE_GET_PRIVATE (device)->init_ok = FALSE;
	NM_GSM_DEVICE_GET_PRIVATE (device)->pin_tries = 0;
	NM_GSM_DEVICE_GET_PRIVATE (device)->reg_tries = 0;

	id = nm_serial_device_flash (serial_device, 100, (NMSerialFlashFn) init_modem, NULL);
	if (!id)
		*reason = NM_DEVICE_STATE_REASON_UNKNOWN;

	return id ? NM_ACT_STAGE_RETURN_POSTPONE : NM_ACT_STAGE_RETURN_FAILURE;
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

static guint32
real_get_generic_capabilities (NMDevice *dev)
{
	return NM_DEVICE_CAP_NM_SUPPORTED;
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

		ppp_manager = nm_serial_device_get_ppp_manager (NM_SERIAL_DEVICE (dev));
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
			const char *gsm_username = nm_setting_gsm_get_username (s_gsm);
			const char *gsm_password = nm_setting_gsm_get_password (s_gsm);

			nm_ppp_manager_update_secrets (ppp_manager,
			                               nm_device_get_iface (dev),
			                               gsm_username ? gsm_username : "",
			                               gsm_password ? gsm_password : "",
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

static void
real_deactivate_quickly (NMDevice *device)
{
	NMGsmDevicePrivate *priv = NM_GSM_DEVICE_GET_PRIVATE (device);

	priv->reg_tries = 0;

	if (priv->pending_id) {
		g_source_remove (priv->pending_id);
		priv->pending_id = 0;
	}

	if (NM_DEVICE_CLASS (nm_gsm_device_parent_class)->deactivate_quickly)
		NM_DEVICE_CLASS (nm_gsm_device_parent_class)->deactivate_quickly (device);
}

static const char *
real_get_ppp_name (NMSerialDevice *device, NMActRequest *req)
{
	NMConnection *connection;
	NMSettingGsm *s_gsm;

	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	s_gsm = (NMSettingGsm *) nm_connection_get_setting (connection, NM_TYPE_SETTING_GSM);
	g_assert (s_gsm);

	return nm_setting_gsm_get_username (s_gsm);
}

/*****************************************************************************/
/* Monitor device handling */

static gboolean
monitor_device_got_data (GIOChannel *source,
					GIOCondition condition,
					gpointer data)
{
	gsize bytes_read;
	char buf[4096];
	GIOStatus status;

	if (condition & G_IO_IN) {
		do {
			status = g_io_channel_read_chars (source, buf, 4096, &bytes_read, NULL);

			if (bytes_read) {
				buf[bytes_read] = '\0';
				/* Do nothing with the data for now */
				nm_debug ("Monitor got unhandled data: '%s'", buf);
			}
		} while (bytes_read == 4096 || status == G_IO_STATUS_AGAIN);
	}

	if (condition & G_IO_HUP || condition & G_IO_ERR) {
		return FALSE;
	}

	return TRUE;
}

static gboolean
setup_monitor_device (NMGsmDevice *device)
{
	NMGsmDevicePrivate *priv = NM_GSM_DEVICE_GET_PRIVATE (device);
	GIOChannel *channel;
	NMSettingSerial *setting;

	if (!priv->monitor_iface)
		return FALSE;

	priv->monitor_device = g_object_new (NM_TYPE_SERIAL_DEVICE,
								  NM_DEVICE_INTERFACE_UDI, nm_device_get_udi (NM_DEVICE (device)),
								  NM_DEVICE_INTERFACE_IFACE, priv->monitor_iface,
								  NULL);

	if (!priv->monitor_device) {
		nm_warning ("Creation of the monitoring device failed");
		return FALSE;
	}

	setting = NM_SETTING_SERIAL (nm_setting_serial_new ());
	if (!nm_serial_device_open (priv->monitor_device, setting)) {
		nm_warning ("Monitoring device open failed");
		g_object_unref (setting);
		g_object_unref (priv->monitor_device);
		return FALSE;
	}

	g_object_unref (setting);

	channel = nm_serial_device_get_io_channel (priv->monitor_device);
	g_io_add_watch (channel, G_IO_IN | G_IO_ERR | G_IO_HUP,
				 monitor_device_got_data, device);

	g_io_channel_unref (channel);

	return TRUE;
}

/*****************************************************************************/

static void
nm_gsm_device_init (NMGsmDevice *self)
{
	nm_device_set_device_type (NM_DEVICE (self), NM_DEVICE_TYPE_GSM);
}

static gboolean
unavailable_to_disconnected (gpointer user_data)
{
	nm_device_state_changed (NM_DEVICE (user_data),
	                         NM_DEVICE_STATE_DISCONNECTED,
	                         NM_DEVICE_STATE_REASON_NONE);
	return FALSE;
}

static void
device_state_changed (NMDeviceInterface *device,
                      NMDeviceState new_state,
                      NMDeviceState old_state,
                      NMDeviceStateReason reason,
                      gpointer user_data)
{
	NMGsmDevice *self = NM_GSM_DEVICE (user_data);
	NMGsmDevicePrivate *priv = NM_GSM_DEVICE_GET_PRIVATE (self);

	/* Remove any previous delayed transition to disconnected */
	if (priv->state_to_disconnected_id) {
		g_source_remove (priv->state_to_disconnected_id);
		priv->state_to_disconnected_id = 0;
	}

	/* Transition to DISCONNECTED from an idle handler */
	if (new_state == NM_DEVICE_STATE_UNAVAILABLE)
		priv->state_to_disconnected_id = g_idle_add (unavailable_to_disconnected, self);

	/* Make sure we don't leave the serial device open */
	switch (new_state) {
	case NM_DEVICE_STATE_UNMANAGED:
	case NM_DEVICE_STATE_UNAVAILABLE:
	case NM_DEVICE_STATE_FAILED:
	case NM_DEVICE_STATE_DISCONNECTED:
		nm_serial_device_close (NM_SERIAL_DEVICE (self));
		break;
	default:
		break;
	}
}

static GObject*
constructor (GType type,
		   guint n_construct_params,
		   GObjectConstructParam *construct_params)
{
	GObject *object;

	object = G_OBJECT_CLASS (nm_gsm_device_parent_class)->constructor (type,
														  n_construct_params,
														  construct_params);
	if (!object)
		return NULL;

	/* FIXME: Make the monitor device not required for now */
	setup_monitor_device (NM_GSM_DEVICE (object));
#if 0
	if (!setup_monitor_device (NM_GSM_DEVICE (object))) {
		g_object_unref (object);
		object = NULL;
	}
#endif

	g_signal_connect (NM_DEVICE (object), "state-changed",
	                  G_CALLBACK (device_state_changed), NM_GSM_DEVICE (object));

	return object;
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	NMGsmDevicePrivate *priv = NM_GSM_DEVICE_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_MONITOR_IFACE:
		/* Construct only */
		priv->monitor_iface = g_value_dup_string (value);
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
	NMGsmDevicePrivate *priv = NM_GSM_DEVICE_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_MONITOR_IFACE:
		g_value_set_string (value, priv->monitor_iface);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
finalize (GObject *object)
{
	NMGsmDevicePrivate *priv = NM_GSM_DEVICE_GET_PRIVATE (object);

	if (priv->monitor_device)
		g_object_unref (priv->monitor_device);

	g_free (priv->monitor_iface);

	if (priv->state_to_disconnected_id) {
		g_source_remove (priv->state_to_disconnected_id);
		priv->state_to_disconnected_id = 0;
	}

	G_OBJECT_CLASS (nm_gsm_device_parent_class)->finalize (object);
}

static void
nm_gsm_device_class_init (NMGsmDeviceClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);
	NMSerialDeviceClass *serial_class = NM_SERIAL_DEVICE_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMGsmDevicePrivate));

	object_class->constructor = constructor;
	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->finalize = finalize;

	device_class->get_best_auto_connection = real_get_best_auto_connection;
	device_class->get_generic_capabilities = real_get_generic_capabilities;
	device_class->act_stage1_prepare = real_act_stage1_prepare;
	device_class->connection_secrets_updated = real_connection_secrets_updated;
	device_class->deactivate_quickly = real_deactivate_quickly;

	klass->do_dial = real_do_dial;

	serial_class->get_ppp_name = real_get_ppp_name;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_MONITOR_IFACE,
		 g_param_spec_string (NM_GSM_DEVICE_MONITOR_IFACE,
						  "Monitoring interface",
						  "Monitoring interface",
						  NULL,
						  G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | NM_PROPERTY_PARAM_NO_EXPORT));

	/* Signals */
	signals[PROPERTIES_CHANGED] = 
		nm_properties_changed_signal_new (object_class,
								    G_STRUCT_OFFSET (NMGsmDeviceClass, properties_changed));

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (klass),
									 &dbus_glib_nm_gsm_device_object_info);
}
