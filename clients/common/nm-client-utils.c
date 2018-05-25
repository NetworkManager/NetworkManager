/* nmcli - command-line tool to control NetworkManager
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
 * Copyright 2010 - 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-client-utils.h"
#include "nm-utils.h"

#include "nm-device-bond.h"
#include "nm-device-bridge.h"
#include "nm-device-team.h"

/*****************************************************************************/

static int
_nmc_objects_sort_by_path_cmp (gconstpointer pa, gconstpointer pb, gpointer user_data)
{
	NMObject *a = *((NMObject **) pa);
	NMObject *b = *((NMObject **) pb);

	NM_CMP_SELF (a, b);
	NM_CMP_RETURN (nm_utils_dbus_path_cmp (nm_object_get_path (a),
	                                       nm_object_get_path (b)));
	return 0;
}

const NMObject **
nmc_objects_sort_by_path (const NMObject *const* objs, gssize len)
{
	const NMObject **arr;
	gsize i, l;

	if (len < 0)
		l = NM_PTRARRAY_LEN (objs);
	else
		l = len;

	arr = g_new (const NMObject *, l + 1);
	for (i = 0; i < l; i++)
		arr[i] = objs[i];
	arr[l] = NULL;

	if (l > 1) {
		g_qsort_with_data (arr,
		                   l,
		                   sizeof (gpointer),
		                   _nmc_objects_sort_by_path_cmp,
		                   NULL);
	}
	return arr;
}

/*****************************************************************************/
/*
 * Convert string to unsigned integer.
 * If required, the resulting number is checked to be in the <min,max> range.
 */
static gboolean
nmc_string_to_uint_base (const char *str,
                         int base,
                         gboolean range_check,
                         unsigned long int min,
                         unsigned long int max,
                         unsigned long int *value)
{
	char *end;
	unsigned long int tmp;

	errno = 0;
	tmp = strtoul (str, &end, base);
	if (errno || *end != '\0' || (range_check && (tmp < min || tmp > max))) {
		return FALSE;
	}
	*value = tmp;
	return TRUE;
}

gboolean
nmc_string_to_uint (const char *str,
                    gboolean range_check,
                    unsigned long int min,
                    unsigned long int max,
                    unsigned long int *value)
{
	return nmc_string_to_uint_base (str, 10, range_check, min, max, value);
}

gboolean
nmc_string_to_bool (const char *str, gboolean *val_bool, GError **error)
{
	const char *s_true[] = { "true", "yes", "on", "1", NULL };
	const char *s_false[] = { "false", "no", "off", "0", NULL };

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (g_strcmp0 (str, "o") == 0) {
		g_set_error (error, 1, 0,
		             /* TRANSLATORS: the first %s is the partial value entered by
		              * the user, the second %s a list of compatible values.
		              */
		             _("'%s' is ambiguous (%s)"), str, "on x off");
		return FALSE;
	}

	if (nmc_string_is_valid (str, s_true, NULL))
		*val_bool = TRUE;
	else if (nmc_string_is_valid (str, s_false, NULL))
		*val_bool = FALSE;
	else {
		g_set_error (error, 1, 0,
		             _("'%s' is not valid; use [%s] or [%s]"),
		             str, "true, yes, on", "false, no, off");
		return FALSE;
	}
	return TRUE;
}

gboolean
nmc_string_to_tristate (const char *str, NMCTriStateValue *val, GError **error)
{
	const char *s_true[] = { "true", "yes", "on", NULL };
	const char *s_false[] = { "false", "no", "off", NULL };
	const char *s_unknown[] = { "unknown", NULL };

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (g_strcmp0 (str, "o") == 0) {
		g_set_error (error, 1, 0,
		             /* TRANSLATORS: the first %s is the partial value entered by
		              * the user, the second %s a list of compatible values.
		              */
		             _("'%s' is ambiguous (%s)"), str, "on x off");
		return FALSE;
	}

	if (nmc_string_is_valid (str, s_true, NULL))
		*val = NMC_TRI_STATE_YES;
	else if (nmc_string_is_valid (str, s_false, NULL))
		*val = NMC_TRI_STATE_NO;
	else if (nmc_string_is_valid (str, s_unknown, NULL))
		*val = NMC_TRI_STATE_UNKNOWN;
	else {
		g_set_error (error, 1, 0,
		             _("'%s' is not valid; use [%s], [%s] or [%s]"),
		             str, "true, yes, on", "false, no, off", "unknown");
		return FALSE;
	}
	return TRUE;
}

/*
 * Check whether 'input' is contained in 'allowed' array. It performs case
 * insensitive comparison and supports shortcut strings if they are unique.
 * Returns: a pointer to found string in allowed array on success or NULL.
 * On failure: error->code : 0 - string not found; 1 - string is ambiguous
 */
const char *
nmc_string_is_valid (const char *input, const char **allowed, GError **error)
{
	const char **p;
	size_t input_ln, p_len;
	const char *partial_match = NULL;
	gboolean ambiguous = FALSE;

	g_return_val_if_fail (!error || !*error, NULL);

	if (!input || !*input)
		goto finish;

	input_ln = strlen (input);
	for (p = allowed; p && *p; p++) {
		p_len = strlen (*p);
		if (g_ascii_strncasecmp (input, *p, input_ln) == 0) {
			if (input_ln == p_len)
				return *p;
			if (!partial_match)
				partial_match = *p;
			else
				ambiguous = TRUE;
		}
	}

	if (ambiguous) {
		GString *candidates = g_string_new ("");

		for (p = allowed; *p; p++) {
			if (g_ascii_strncasecmp (input, *p, input_ln) == 0) {
				if (candidates->len > 0)
					g_string_append (candidates, ", ");
				g_string_append (candidates, *p);
			}
		}
		g_set_error (error, 1, 1, _("'%s' is ambiguous: %s"),
		             input, candidates->str);
		g_string_free (candidates, TRUE);
		return NULL;
	}
finish:
	if (!partial_match) {
		char *valid_vals = g_strjoinv (", ", (char **) allowed);

		if (!input || !*input)
			g_set_error (error, 1, 0, _("missing name, try one of [%s]"), valid_vals);
		else
			g_set_error (error, 1, 0, _("'%s' not among [%s]"), input, valid_vals);

		g_free (valid_vals);
	}

	return partial_match;
}

gboolean
matches (const char *cmd, const char *pattern)
{
	size_t len = strlen (cmd);
	if (!len || len > strlen (pattern))
		return FALSE;
	return memcmp (pattern, cmd, len) == 0;
}

const char *
nmc_bond_validate_mode (const char *mode, GError **error)
{
	unsigned long mode_int;
	static const char *valid_modes[] = { "balance-rr",
	                                     "active-backup",
	                                     "balance-xor",
	                                     "broadcast",
	                                     "802.3ad",
	                                     "balance-tlb",
	                                     "balance-alb",
	                                     NULL };
	if (nmc_string_to_uint (mode, TRUE, 0, 6, &mode_int)) {
		/* Translate bonding mode numbers to mode names:
		 * https://www.kernel.org/doc/Documentation/networking/bonding.txt
		 */
		return valid_modes[mode_int];
	} else
		return nmc_string_is_valid (mode, valid_modes, error);
}

const char *
nmc_device_state_to_string (NMDeviceState state)
{
	switch (state) {
	case NM_DEVICE_STATE_UNMANAGED:
		return _("unmanaged");
	case NM_DEVICE_STATE_UNAVAILABLE:
		return _("unavailable");
	case NM_DEVICE_STATE_DISCONNECTED:
		return _("disconnected");
	case NM_DEVICE_STATE_PREPARE:
		return _("connecting (prepare)");
	case NM_DEVICE_STATE_CONFIG:
		return _("connecting (configuring)");
	case NM_DEVICE_STATE_NEED_AUTH:
		return _("connecting (need authentication)");
	case NM_DEVICE_STATE_IP_CONFIG:
		return _("connecting (getting IP configuration)");
	case NM_DEVICE_STATE_IP_CHECK:
		return _("connecting (checking IP connectivity)");
	case NM_DEVICE_STATE_SECONDARIES:
		return _("connecting (starting secondary connections)");
	case NM_DEVICE_STATE_ACTIVATED:
		return _("connected");
	case NM_DEVICE_STATE_DEACTIVATING:
		return _("deactivating");
	case NM_DEVICE_STATE_FAILED:
		return _("connection failed");
	case NM_DEVICE_STATE_UNKNOWN:
		return _("unknown");
	}

	return _("unknown");
}

const char *
nmc_device_metered_to_string (NMMetered value)
{
	switch (value) {
	case NM_METERED_YES:
		return _("yes");
	case NM_METERED_NO:
		return _("no");
	case NM_METERED_GUESS_YES:
		return _("yes (guessed)");
	case NM_METERED_GUESS_NO:
		return _("no (guessed)");
	case NM_METERED_UNKNOWN:
		return _("unknown");
	}

	return _("unknown");
}

const char *
nmc_device_reason_to_string (NMDeviceStateReason reason)
{
	switch (reason) {
	case NM_DEVICE_STATE_REASON_NONE:
		return _("No reason given");
	case NM_DEVICE_STATE_REASON_UNKNOWN:
		return _("Unknown error");
	case NM_DEVICE_STATE_REASON_NOW_MANAGED:
		return _("Device is now managed");
	case NM_DEVICE_STATE_REASON_NOW_UNMANAGED:
		return _("Device is now unmanaged");
	case NM_DEVICE_STATE_REASON_CONFIG_FAILED:
		return _("The device could not be readied for configuration");
	case NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE:
		return _("IP configuration could not be reserved (no available address, timeout, etc.)");
	case NM_DEVICE_STATE_REASON_IP_CONFIG_EXPIRED:
		return _("The IP configuration is no longer valid");
	case NM_DEVICE_STATE_REASON_NO_SECRETS:
		return _("Secrets were required, but not provided");
	case NM_DEVICE_STATE_REASON_SUPPLICANT_DISCONNECT:
		return _("802.1X supplicant disconnected");
	case NM_DEVICE_STATE_REASON_SUPPLICANT_CONFIG_FAILED:
		return _("802.1X supplicant configuration failed");
	case NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED:
		return _("802.1X supplicant failed");
	case NM_DEVICE_STATE_REASON_SUPPLICANT_TIMEOUT:
		return _("802.1X supplicant took too long to authenticate");
	case NM_DEVICE_STATE_REASON_PPP_START_FAILED:
		return _("PPP service failed to start");
	case NM_DEVICE_STATE_REASON_PPP_DISCONNECT:
		return _("PPP service disconnected");
	case NM_DEVICE_STATE_REASON_PPP_FAILED:
		return _("PPP failed");
	case NM_DEVICE_STATE_REASON_DHCP_START_FAILED:
		return _("DHCP client failed to start");
	case NM_DEVICE_STATE_REASON_DHCP_ERROR:
		return _("DHCP client error");
	case NM_DEVICE_STATE_REASON_DHCP_FAILED:
		return _("DHCP client failed");
	case NM_DEVICE_STATE_REASON_SHARED_START_FAILED:
		return _("Shared connection service failed to start");
	case NM_DEVICE_STATE_REASON_SHARED_FAILED:
		return _("Shared connection service failed");
	case NM_DEVICE_STATE_REASON_AUTOIP_START_FAILED:
		return _("AutoIP service failed to start");
	case NM_DEVICE_STATE_REASON_AUTOIP_ERROR:
		return _("AutoIP service error");
	case NM_DEVICE_STATE_REASON_AUTOIP_FAILED:
		return _("AutoIP service failed");
	case NM_DEVICE_STATE_REASON_MODEM_BUSY:
		return _("The line is busy");
	case NM_DEVICE_STATE_REASON_MODEM_NO_DIAL_TONE:
		return _("No dial tone");
	case NM_DEVICE_STATE_REASON_MODEM_NO_CARRIER:
		return _("No carrier could be established");
	case NM_DEVICE_STATE_REASON_MODEM_DIAL_TIMEOUT:
		return _("The dialing request timed out");
	case NM_DEVICE_STATE_REASON_MODEM_DIAL_FAILED:
		return _("The dialing attempt failed");
	case NM_DEVICE_STATE_REASON_MODEM_INIT_FAILED:
		return _("Modem initialization failed");
	case NM_DEVICE_STATE_REASON_GSM_APN_FAILED:
		return _("Failed to select the specified APN");
	case NM_DEVICE_STATE_REASON_GSM_REGISTRATION_NOT_SEARCHING:
		return _("Not searching for networks");
	case NM_DEVICE_STATE_REASON_GSM_REGISTRATION_DENIED:
		return _("Network registration denied");
	case NM_DEVICE_STATE_REASON_GSM_REGISTRATION_TIMEOUT:
		return _("Network registration timed out");
	case NM_DEVICE_STATE_REASON_GSM_REGISTRATION_FAILED:
		return _("Failed to register with the requested network");
	case NM_DEVICE_STATE_REASON_GSM_PIN_CHECK_FAILED:
		return _("PIN check failed");
	case NM_DEVICE_STATE_REASON_FIRMWARE_MISSING:
		return _("Necessary firmware for the device may be missing");
	case NM_DEVICE_STATE_REASON_REMOVED:
		return _("The device was removed");
	case NM_DEVICE_STATE_REASON_SLEEPING:
		return _("NetworkManager went to sleep");
	case NM_DEVICE_STATE_REASON_CONNECTION_REMOVED:
		return _("The device's active connection disappeared");
	case NM_DEVICE_STATE_REASON_USER_REQUESTED:
		return _("Device disconnected by user or client");
	case NM_DEVICE_STATE_REASON_CARRIER:
		return _("Carrier/link changed");
	case NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED:
		return _("The device's existing connection was assumed");
	case NM_DEVICE_STATE_REASON_SUPPLICANT_AVAILABLE:
		return _("The supplicant is now available");
	case NM_DEVICE_STATE_REASON_MODEM_NOT_FOUND:
		return _("The modem could not be found");
	case NM_DEVICE_STATE_REASON_BT_FAILED:
		return _("The Bluetooth connection failed or timed out");
	case NM_DEVICE_STATE_REASON_GSM_SIM_NOT_INSERTED:
		return _("GSM Modem's SIM card not inserted");
	case NM_DEVICE_STATE_REASON_GSM_SIM_PIN_REQUIRED:
		return _("GSM Modem's SIM PIN required");
	case NM_DEVICE_STATE_REASON_GSM_SIM_PUK_REQUIRED:
		return _("GSM Modem's SIM PUK required");
	case NM_DEVICE_STATE_REASON_GSM_SIM_WRONG:
		return _("GSM Modem's SIM wrong");
	case NM_DEVICE_STATE_REASON_INFINIBAND_MODE:
		return _("InfiniBand device does not support connected mode");
        case NM_DEVICE_STATE_REASON_DEPENDENCY_FAILED:
		return _("A dependency of the connection failed");
	case NM_DEVICE_STATE_REASON_BR2684_FAILED:
		return _("A problem with the RFC 2684 Ethernet over ADSL bridge");
	case NM_DEVICE_STATE_REASON_MODEM_MANAGER_UNAVAILABLE:
		return _("ModemManager is unavailable");
	case NM_DEVICE_STATE_REASON_SSID_NOT_FOUND:
		return _("The Wi-Fi network could not be found");
	case NM_DEVICE_STATE_REASON_SECONDARY_CONNECTION_FAILED:
		return _("A secondary connection of the base connection failed");
	case NM_DEVICE_STATE_REASON_DCB_FCOE_FAILED:
		return _("DCB or FCoE setup failed");
	case NM_DEVICE_STATE_REASON_TEAMD_CONTROL_FAILED:
		return _("teamd control failed");
	case NM_DEVICE_STATE_REASON_MODEM_FAILED:
		return _("Modem failed or no longer available");
	case NM_DEVICE_STATE_REASON_MODEM_AVAILABLE:
		return _("Modem now ready and available");
	case NM_DEVICE_STATE_REASON_SIM_PIN_INCORRECT:
		return _("SIM PIN was incorrect");
	case NM_DEVICE_STATE_REASON_NEW_ACTIVATION:
		return _("New connection activation was enqueued");
	case NM_DEVICE_STATE_REASON_PARENT_CHANGED:
		return _("The device's parent changed");
	case NM_DEVICE_STATE_REASON_PARENT_MANAGED_CHANGED:
		return _("The device parent's management changed");
	case NM_DEVICE_STATE_REASON_OVSDB_FAILED:
		return _("OpenVSwitch database connection failed");
	case NM_DEVICE_STATE_REASON_IP_ADDRESS_DUPLICATE:
		return _("A duplicate IP address was detected");
	case NM_DEVICE_STATE_REASON_IP_METHOD_UNSUPPORTED:
		return _("The selected IP method is not supported");
	}

	/* TRANSLATORS: Unknown reason for a device state change (NMDeviceStateReason) */
	return _("Unknown");
}

const char *
nm_active_connection_state_reason_to_string (NMActiveConnectionStateReason reason)
{
	switch (reason) {
	case NM_ACTIVE_CONNECTION_STATE_REASON_UNKNOWN:
		return _("Unknown reason");
	case NM_ACTIVE_CONNECTION_STATE_REASON_NONE:
		return _("The connection was disconnected");
	case NM_ACTIVE_CONNECTION_STATE_REASON_USER_DISCONNECTED:
		return _("Disconnected by user");
	case NM_ACTIVE_CONNECTION_STATE_REASON_DEVICE_DISCONNECTED:
		return _("The base network connection was interrupted");
	case NM_ACTIVE_CONNECTION_STATE_REASON_SERVICE_STOPPED:
		return _("The VPN service stopped unexpectedly");
	case NM_ACTIVE_CONNECTION_STATE_REASON_IP_CONFIG_INVALID:
		return _("The VPN service returned invalid configuration");
	case NM_ACTIVE_CONNECTION_STATE_REASON_CONNECT_TIMEOUT:
		return _("The connection attempt timed out");
	case NM_ACTIVE_CONNECTION_STATE_REASON_SERVICE_START_TIMEOUT:
		return _("The VPN service did not start in time");
	case NM_ACTIVE_CONNECTION_STATE_REASON_SERVICE_START_FAILED:
		return _("The VPN service failed to start");
	case NM_ACTIVE_CONNECTION_STATE_REASON_NO_SECRETS:
		return _("No valid secrets");
	case NM_ACTIVE_CONNECTION_STATE_REASON_LOGIN_FAILED:
		return _("Invalid secrets");
	case NM_ACTIVE_CONNECTION_STATE_REASON_CONNECTION_REMOVED:
		return _("The connection was removed");
	case NM_ACTIVE_CONNECTION_STATE_REASON_DEPENDENCY_FAILED:
		return _("Master connection failed");
	case NM_ACTIVE_CONNECTION_STATE_REASON_DEVICE_REALIZE_FAILED:
		return _("Could not create a software link");
	case NM_ACTIVE_CONNECTION_STATE_REASON_DEVICE_REMOVED:
		return _("The device disappeared");
	default:
		/* TRANSLATORS: Unknown reason for a connection state change (NMActiveConnectionStateReason) */
		return _("Unknown");
	}
}

NMActiveConnectionState
nmc_activation_get_effective_state (NMActiveConnection *active,
                                    NMDevice *device,
                                    const char **reason)
{
	NMActiveConnectionState ac_state;
	NMActiveConnectionStateReason ac_reason;
	NMDeviceState dev_state = NM_DEVICE_STATE_UNKNOWN;
	NMDeviceStateReason dev_reason = NM_DEVICE_STATE_REASON_UNKNOWN;

	g_return_val_if_fail (active, NM_ACTIVE_CONNECTION_STATE_UNKNOWN);
	g_return_val_if_fail (reason, NM_ACTIVE_CONNECTION_STATE_UNKNOWN);

	*reason = NULL;
	ac_reason = nm_active_connection_get_state_reason (active);

	if (device) {
		dev_state = nm_device_get_state (device);
		dev_reason = nm_device_get_state_reason (device);
	}

	ac_state = nm_active_connection_get_state (active);
	switch (ac_state) {
	case NM_ACTIVE_CONNECTION_STATE_DEACTIVATED:
		if (   !device
		    || ac_reason != NM_ACTIVE_CONNECTION_STATE_REASON_DEVICE_DISCONNECTED
		    || nm_device_get_active_connection (device) != active) {
			/* (1)
			 * - we have no device,
			 * - or, @ac_reason is specific
			 * - or, @device no longer references the current @active
			 * >> we complete with @ac_reason. */
			*reason = nm_active_connection_state_reason_to_string (ac_reason);
		} else if (   dev_state <= NM_DEVICE_STATE_DISCONNECTED
		           || dev_state >= NM_DEVICE_STATE_FAILED) {
			/* (2)
			 * - not (1)
			 * - and, the device is no longer in an activated state,
			 * >> we complete with @dev_reason. */
			*reason = nmc_device_reason_to_string (dev_reason);
		} else {
			/* (3)
			 * we wait for the device go disconnect. We will get a better
			 * failure reason from the device (2). */
			return NM_ACTIVE_CONNECTION_STATE_UNKNOWN;
		}
		break;
	case NM_ACTIVE_CONNECTION_STATE_ACTIVATING:
		/* activating master connection does not automatically activate any slaves, so their
		 * active connection state will not progress beyond ACTIVATING state.
		 * Monitor the device instead. */
		if (   device
		    && (   NM_IS_DEVICE_BOND (device)
		        || NM_IS_DEVICE_TEAM (device)
		        || NM_IS_DEVICE_BRIDGE (device))
		    && dev_state >= NM_DEVICE_STATE_IP_CONFIG
		    && dev_state <= NM_DEVICE_STATE_ACTIVATED) {
			*reason = "master waiting for slaves";
			return NM_ACTIVE_CONNECTION_STATE_ACTIVATED;
		}
		break;
	default:
		break;
	}

	return ac_state;
}

static gboolean
can_show_graphics (void)
{
	static gboolean can_show_graphics_set = FALSE;
	gboolean can_show_graphics = TRUE;
	char *locale_str;

	if (G_LIKELY (can_show_graphics_set))
		return can_show_graphics;

	if (!g_get_charset (NULL)) {
		/* Non-UTF-8 locale */
		locale_str = g_locale_from_utf8 ("\342\226\202\342\226\204\342\226\206\342\226\210", -1, NULL, NULL, NULL);
		if (locale_str)
			g_free (locale_str);
		else
			can_show_graphics = FALSE;
	}

	/* The linux console font typically doesn't have characters we need */
	if (g_strcmp0 (g_getenv ("TERM"), "linux") == 0)
		can_show_graphics = FALSE;

	return can_show_graphics;
}

/**
 * nmc_wifi_strength_bars:
 * @strength: the access point strength, from 0 to 100
 *
 * Converts @strength into a 4-character-wide graphical representation of
 * strength suitable for printing to stdout. If the current locale and terminal
 * support it, this will use unicode graphics characters to represent
 * "bars". Otherwise it will use 0 to 4 asterisks.
 *
 * Returns: the graphical representation of the access point strength
 */
const char *
nmc_wifi_strength_bars (guint8 strength)
{
	if (!can_show_graphics ())
		return nm_utils_wifi_strength_bars (strength);

	if (strength > 80)
		return /* ▂▄▆█ */ "\342\226\202\342\226\204\342\226\206\342\226\210";
	else if (strength > 55)
		return /* ▂▄▆_ */ "\342\226\202\342\226\204\342\226\206_";
	else if (strength > 30)
		return /* ▂▄__ */ "\342\226\202\342\226\204__";
	else if (strength > 5)
		return /* ▂___ */ "\342\226\202___";
	else
		return /* ____ */ "____";
}

/**
 * nmc_utils_password_subst_char:
 *
 * Returns: the string substituted when hiding actual password glyphs
 */
const char *
nmc_password_subst_char (void)
{
	if (can_show_graphics ())
		return "\u2022"; /* Bullet */
	else
		return "*";
}
