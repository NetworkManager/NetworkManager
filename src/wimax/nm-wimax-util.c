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
 * Copyright (C) 2009 Novell, Inc.
 */

#include <WiMaxAPI.h>
#include "nm-wimax-util.h"
#include "nm-utils.h"

void
nm_wimax_util_error (WIMAX_API_DEVICE_ID *device_id,
					 const char *message,
					 WIMAX_API_RET result)
{
	char *warning_msg;
    char str[MAX_SIZE_OF_STRING_BUFFER];
    guint32 str_len = MAX_SIZE_OF_STRING_BUFFER;

    GetErrorString (device_id, result, str, &str_len);
    warning_msg = g_strconcat (message, ": %s (%d)", NULL);
    g_warning (warning_msg, str, result);
    g_free (warning_msg);
}			  

NMWimaxNspNetworkType
nm_wimax_util_convert_network_type (WIMAX_API_NETWORK_TYPE wimax_network_type)
{
	NMWimaxNspNetworkType type;

	switch (wimax_network_type) {
	case WIMAX_API_HOME:
		type = NM_WIMAX_NSP_NETWORK_TYPE_HOME;
		break;
	case WIMAX_API_PARTNER:
		type = NM_WIMAX_NSP_NETWORK_TYPE_PARTNER;
		break;
	case WIMAX_API_ROAMING_PARTNER:
		type = NM_WIMAX_NSP_NETWORK_TYPE_ROAMING_PARTNER;
		break;
	default:
		type = NM_WIMAX_NSP_NETWORK_TYPE_UNKNOWN;
		break;
	}

	return type;
}

/* cinr_to_percentage() and the comment is borrowed from connman */

/*
 * FIXME: pulled it it out of some hole
 *
 * the cinr to percentage computation comes from the L3/L4 doc
 *
 * But some other places (L4 code) have a more complex, seemingly
 * logarithmical computation.
 *
 * Oh well...
 *
 */

int
nm_wimax_util_cinr_to_percentage (int cinr)
{
	int strength;

	if (cinr <= -5)
		strength = 0;
	else if (cinr >= 25)
		strength = 100;
	else	/* Calc percentage on the value from -5 to 25 */
		strength = ((100UL * (cinr - -5)) / (25 - -5));

	return strength;
}

const char *
nm_wimax_util_device_status_to_str (WIMAX_API_DEVICE_STATUS status)
{
	switch (status) {
	case WIMAX_API_DEVICE_STATUS_UnInitialized:
		return "Device is uninitialized";
	case WIMAX_API_DEVICE_STATUS_RF_OFF_HW_SW:
		return "Device RF Off(both H/W and S/W)";
	case WIMAX_API_DEVICE_STATUS_RF_OFF_HW:
		return "Device RF Off(via H/W switch)";
	case WIMAX_API_DEVICE_STATUS_RF_OFF_SW:
		return "Device RF Off(via S/W switch)";
	case WIMAX_API_DEVICE_STATUS_Ready:
		return "Device is ready";
	case WIMAX_API_DEVICE_STATUS_Scanning:
		return "Device is scanning";
	case WIMAX_API_DEVICE_STATUS_Connecting:
		return "Connection in progress";
	case WIMAX_API_DEVICE_STATUS_Data_Connected:
		return "Layer 2 connected";
	}

	return "Unknown device state";
}
