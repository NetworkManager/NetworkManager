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

#include "nm-device-bond.h"
#include "nm-device-bridge.h"
#include "nm-device-team.h"

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
		             /* Translators: the first %s is the partial value entered by
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
		             /* Translators: the first %s is the partial value entered by
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
	gboolean prev_match = FALSE;
	const char *ret = NULL;

	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	if (!input || !*input)
		goto finish;

	input_ln = strlen (input);
	for (p = allowed; p && *p; p++) {
		p_len = strlen (*p);
		if (g_ascii_strncasecmp (input, *p, input_ln) == 0) {
			if (input_ln == p_len) {
				ret = *p;
				break;
			}
			if (!prev_match)
				ret = *p;
			else {
				g_set_error (error, 1, 1, _("'%s' is ambiguous (%s x %s)"),
				             input, ret, *p);
				return NULL;
			}
			prev_match = TRUE;
		}
	}

finish:
	if (ret == NULL) {
		char *valid_vals = g_strjoinv (", ", (char **) allowed);
		if (!input || !*input)
			g_set_error (error, 1, 0, _("missing name, try one of [%s]"), valid_vals);
		else
			g_set_error (error, 1, 0, _("'%s' not among [%s]"), input, valid_vals);

		g_free (valid_vals);
	}
	return ret;
}

/*
 * Wrapper function for g_strsplit_set() that removes empty strings
 * from the vector as they are not useful in most cases.
 */
char **
nmc_strsplit_set (const char *str, const char *delimiter, int max_tokens)
{
	/* remove empty strings */
	return _nm_utils_strv_cleanup (g_strsplit_set (str, delimiter, max_tokens),
	                               FALSE, TRUE, FALSE);
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
