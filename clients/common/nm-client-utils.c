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

	if (!str || !str[0])
		return FALSE;

	/* FIXME: don't use this function, replace by _nm_utils_ascii_str_to_int64() */
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
nmc_string_to_ternary (const char *str, NMTernary *val, GError **error)
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
		*val = NM_TERNARY_TRUE;
	else if (nmc_string_is_valid (str, s_false, NULL))
		*val = NM_TERNARY_FALSE;
	else if (nmc_string_is_valid (str, s_unknown, NULL))
		*val = NM_TERNARY_DEFAULT;
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

NM_UTILS_LOOKUP_STR_DEFINE (nmc_device_state_to_string, NMDeviceState,
	NM_UTILS_LOOKUP_DEFAULT (N_("unknown")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_UNMANAGED,    N_("unmanaged")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_UNAVAILABLE,  N_("unavailable")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_DISCONNECTED, N_("disconnected")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_PREPARE,      N_("connecting (prepare)")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_CONFIG,       N_("connecting (configuring)")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_NEED_AUTH,    N_("connecting (need authentication)")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_IP_CONFIG,    N_("connecting (getting IP configuration)")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_IP_CHECK,     N_("connecting (checking IP connectivity)")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_SECONDARIES,  N_("connecting (starting secondary connections)")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_ACTIVATED,    N_("connected")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_DEACTIVATING, N_("deactivating")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_FAILED,       N_("connection failed")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_UNKNOWN,      N_("unknown")),
)

NM_UTILS_LOOKUP_STR_DEFINE (nmc_device_metered_to_string, NMMetered,
	NM_UTILS_LOOKUP_DEFAULT (N_("unknown")),
	NM_UTILS_LOOKUP_ITEM (NM_METERED_YES,       N_("yes")),
	NM_UTILS_LOOKUP_ITEM (NM_METERED_NO,        N_("no")),
	NM_UTILS_LOOKUP_ITEM (NM_METERED_GUESS_YES, N_("yes (guessed)")),
	NM_UTILS_LOOKUP_ITEM (NM_METERED_GUESS_NO,  N_("no (guessed)")),
	NM_UTILS_LOOKUP_ITEM (NM_METERED_UNKNOWN,   N_("unknown")),
)

NM_UTILS_LOOKUP_STR_DEFINE (nmc_device_reason_to_string, NMDeviceStateReason,
	/* TRANSLATORS: Unknown reason for a device state change (NMDeviceStateReason) */
	NM_UTILS_LOOKUP_DEFAULT (N_("Unknown")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_NONE,                           N_("No reason given")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_UNKNOWN,                        N_("Unknown error")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_NOW_MANAGED,                    N_("Device is now managed")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_NOW_UNMANAGED,                  N_("Device is now unmanaged")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_CONFIG_FAILED,                  N_("The device could not be readied for configuration")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE,          N_("IP configuration could not be reserved (no available address, timeout, etc.)")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_IP_CONFIG_EXPIRED,              N_("The IP configuration is no longer valid")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_NO_SECRETS,                     N_("Secrets were required, but not provided")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_SUPPLICANT_DISCONNECT,          N_("802.1X supplicant disconnected")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_SUPPLICANT_CONFIG_FAILED,       N_("802.1X supplicant configuration failed")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED,              N_("802.1X supplicant failed")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_SUPPLICANT_TIMEOUT,             N_("802.1X supplicant took too long to authenticate")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_PPP_START_FAILED,               N_("PPP service failed to start")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_PPP_DISCONNECT,                 N_("PPP service disconnected")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_PPP_FAILED,                     N_("PPP failed")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_DHCP_START_FAILED,              N_("DHCP client failed to start")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_DHCP_ERROR,                     N_("DHCP client error")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_DHCP_FAILED,                    N_("DHCP client failed")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_SHARED_START_FAILED,            N_("Shared connection service failed to start")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_SHARED_FAILED,                  N_("Shared connection service failed")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_AUTOIP_START_FAILED,            N_("AutoIP service failed to start")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_AUTOIP_ERROR,                   N_("AutoIP service error")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_AUTOIP_FAILED,                  N_("AutoIP service failed")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_MODEM_BUSY,                     N_("The line is busy")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_MODEM_NO_DIAL_TONE,             N_("No dial tone")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_MODEM_NO_CARRIER,               N_("No carrier could be established")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_MODEM_DIAL_TIMEOUT,             N_("The dialing request timed out")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_MODEM_DIAL_FAILED,              N_("The dialing attempt failed")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_MODEM_INIT_FAILED,              N_("Modem initialization failed")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_GSM_APN_FAILED,                 N_("Failed to select the specified APN")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_GSM_REGISTRATION_NOT_SEARCHING, N_("Not searching for networks")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_GSM_REGISTRATION_DENIED,        N_("Network registration denied")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_GSM_REGISTRATION_TIMEOUT,       N_("Network registration timed out")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_GSM_REGISTRATION_FAILED,        N_("Failed to register with the requested network")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_GSM_PIN_CHECK_FAILED,           N_("PIN check failed")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_FIRMWARE_MISSING,               N_("Necessary firmware for the device may be missing")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_REMOVED,                        N_("The device was removed")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_SLEEPING,                       N_("NetworkManager went to sleep")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_CONNECTION_REMOVED,             N_("The device's active connection disappeared")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_USER_REQUESTED,                 N_("Device disconnected by user or client")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_CARRIER,                        N_("Carrier/link changed")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED,             N_("The device's existing connection was assumed")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_SUPPLICANT_AVAILABLE,           N_("The supplicant is now available")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_MODEM_NOT_FOUND,                N_("The modem could not be found")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_BT_FAILED,                      N_("The Bluetooth connection failed or timed out")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_GSM_SIM_NOT_INSERTED,           N_("GSM Modem's SIM card not inserted")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_GSM_SIM_PIN_REQUIRED,           N_("GSM Modem's SIM PIN required")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_GSM_SIM_PUK_REQUIRED,           N_("GSM Modem's SIM PUK required")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_GSM_SIM_WRONG,                  N_("GSM Modem's SIM wrong")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_INFINIBAND_MODE,                N_("InfiniBand device does not support connected mode")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_DEPENDENCY_FAILED,              N_("A dependency of the connection failed")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_BR2684_FAILED,                  N_("A problem with the RFC 2684 Ethernet over ADSL bridge")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_MODEM_MANAGER_UNAVAILABLE,      N_("ModemManager is unavailable")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_SSID_NOT_FOUND,                 N_("The Wi-Fi network could not be found")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_SECONDARY_CONNECTION_FAILED,    N_("A secondary connection of the base connection failed")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_DCB_FCOE_FAILED,                N_("DCB or FCoE setup failed")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_TEAMD_CONTROL_FAILED,           N_("teamd control failed")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_MODEM_FAILED,                   N_("Modem failed or no longer available")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_MODEM_AVAILABLE,                N_("Modem now ready and available")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_SIM_PIN_INCORRECT,              N_("SIM PIN was incorrect")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_NEW_ACTIVATION,                 N_("New connection activation was enqueued")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_PARENT_CHANGED,                 N_("The device's parent changed")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_PARENT_MANAGED_CHANGED,         N_("The device parent's management changed")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_OVSDB_FAILED,                   N_("Open vSwitch database connection failed")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_IP_ADDRESS_DUPLICATE,           N_("A duplicate IP address was detected")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_IP_METHOD_UNSUPPORTED,          N_("The selected IP method is not supported")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_SRIOV_CONFIGURATION_FAILED,     N_("Failed to configure SR-IOV parameters")),
	NM_UTILS_LOOKUP_ITEM (NM_DEVICE_STATE_REASON_PEER_NOT_FOUND,                 N_("The Wi-Fi P2P peer could not be found")),
)

NM_UTILS_LOOKUP_STR_DEFINE (nm_active_connection_state_reason_to_string, NMActiveConnectionStateReason,
	/* TRANSLATORS: Unknown reason for a connection state change (NMActiveConnectionStateReason) */
	NM_UTILS_LOOKUP_DEFAULT (N_("Unknown")),
	NM_UTILS_LOOKUP_ITEM (NM_ACTIVE_CONNECTION_STATE_REASON_UNKNOWN,               N_("Unknown reason")),
	NM_UTILS_LOOKUP_ITEM (NM_ACTIVE_CONNECTION_STATE_REASON_NONE,                  N_("The connection was disconnected")),
	NM_UTILS_LOOKUP_ITEM (NM_ACTIVE_CONNECTION_STATE_REASON_USER_DISCONNECTED,     N_("Disconnected by user")),
	NM_UTILS_LOOKUP_ITEM (NM_ACTIVE_CONNECTION_STATE_REASON_DEVICE_DISCONNECTED,   N_("The base network connection was interrupted")),
	NM_UTILS_LOOKUP_ITEM (NM_ACTIVE_CONNECTION_STATE_REASON_SERVICE_STOPPED,       N_("The VPN service stopped unexpectedly")),
	NM_UTILS_LOOKUP_ITEM (NM_ACTIVE_CONNECTION_STATE_REASON_IP_CONFIG_INVALID,     N_("The VPN service returned invalid configuration")),
	NM_UTILS_LOOKUP_ITEM (NM_ACTIVE_CONNECTION_STATE_REASON_CONNECT_TIMEOUT,       N_("The connection attempt timed out")),
	NM_UTILS_LOOKUP_ITEM (NM_ACTIVE_CONNECTION_STATE_REASON_SERVICE_START_TIMEOUT, N_("The VPN service did not start in time")),
	NM_UTILS_LOOKUP_ITEM (NM_ACTIVE_CONNECTION_STATE_REASON_SERVICE_START_FAILED,  N_("The VPN service failed to start")),
	NM_UTILS_LOOKUP_ITEM (NM_ACTIVE_CONNECTION_STATE_REASON_NO_SECRETS,            N_("No valid secrets")),
	NM_UTILS_LOOKUP_ITEM (NM_ACTIVE_CONNECTION_STATE_REASON_LOGIN_FAILED,          N_("Invalid secrets")),
	NM_UTILS_LOOKUP_ITEM (NM_ACTIVE_CONNECTION_STATE_REASON_CONNECTION_REMOVED,    N_("The connection was removed")),
	NM_UTILS_LOOKUP_ITEM (NM_ACTIVE_CONNECTION_STATE_REASON_DEPENDENCY_FAILED,     N_("Master connection failed")),
	NM_UTILS_LOOKUP_ITEM (NM_ACTIVE_CONNECTION_STATE_REASON_DEVICE_REALIZE_FAILED, N_("Could not create a software link")),
	NM_UTILS_LOOKUP_ITEM (NM_ACTIVE_CONNECTION_STATE_REASON_DEVICE_REMOVED,        N_("The device disappeared")),
)

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
			*reason = gettext (nm_active_connection_state_reason_to_string (ac_reason));
		} else if (   dev_state <= NM_DEVICE_STATE_DISCONNECTED
		           || dev_state >= NM_DEVICE_STATE_FAILED) {
			/* (2)
			 * - not (1)
			 * - and, the device is no longer in an activated state,
			 * >> we complete with @dev_reason. */
			*reason = gettext (nmc_device_reason_to_string (dev_reason));
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
