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
#include "iwmxsdk.h"
#include "nm-logging.h"

static guint sdk_refcount = 0;

void
nm_wimax_util_sdk_ref (void)
{
	int ret = 0;

	if (sdk_refcount == 0) {
		ret = iwmx_sdk_api_init ();
		if (ret != 0) {
			nm_log_warn (LOGD_WIMAX, "Failed to initialize WiMAX: %d", ret);
			return;
		}
	}
	sdk_refcount++;
}

gboolean
nm_wimax_util_sdk_is_initialized (void)
{
	return sdk_refcount > 0;
}

void
nm_wimax_util_sdk_unref (void)
{
	g_return_if_fail (sdk_refcount > 0);

	sdk_refcount--;
	if (sdk_refcount == 0)
		iwmx_sdk_api_exit ();
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

