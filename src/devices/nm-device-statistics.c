/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
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
 * Copyright (C) 2016 Canonical Ltd
 *
 */

#include "nm-default.h"

#include <inttypes.h>

#include "nm-device-statistics.h"
#include "nm-device-private.h"
#include "nm-utils.h"
#include "nm-platform.h"

#define _NMLOG_DOMAIN        LOGD_DEVICE
#define _NMLOG(level, ...) \
    nm_log_obj ((level), _NMLOG_DOMAIN, (self->device), "device-stats", \
                "(%s): " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
                nm_device_get_iface (self->device) ?: "(none)" \
                _NM_UTILS_MACRO_REST(__VA_ARGS__))

struct _NMDeviceStatistics {
	NMDevice *device;
	guint stats_update_id;
};

static gboolean
update_stats (gpointer user_data)
{
	NMDeviceStatistics *self = user_data;
	guint64 rx_packets;
	guint64 rx_bytes;
	guint64 tx_packets;
	guint64 tx_bytes;
	int ifindex;

	ifindex = nm_device_get_ip_ifindex (self->device);

	if (nm_platform_link_get_stats (NM_PLATFORM_GET, ifindex,
		                            &rx_packets, &rx_bytes,
		                            &tx_packets, &tx_bytes)) {
		_LOGT ("{RX} %"PRIu64" packets %"PRIu64" bytes {TX} %"PRIu64" packets %"PRIu64" bytes",
		       rx_packets, rx_bytes, tx_packets, tx_bytes);

		nm_device_set_tx_bytes (self->device, tx_bytes);
		nm_device_set_rx_bytes (self->device, rx_bytes);
	} else {
		_LOGE ("error no stats available");
	}

	/* Keep polling */
	nm_platform_link_refresh (NM_PLATFORM_GET, ifindex);

	return TRUE;
}

/********************************************/

NMDeviceStatistics *
nm_device_statistics_new (NMDevice *device, unsigned rate_ms)
{
	NMDeviceStatistics *self;

	self = g_malloc0 (sizeof (*self));
	self->device = device;

	self->stats_update_id = g_timeout_add (rate_ms, update_stats, self);

	return self;
}

void
nm_device_statistics_unref (NMDeviceStatistics *self)
{
	g_source_remove (self->stats_update_id);
	g_free (self);
}

void
nm_device_statistics_change_rate (NMDeviceStatistics *self, unsigned rate_ms)
{
	g_source_remove (self->stats_update_id);

	self->stats_update_id = g_timeout_add (rate_ms, update_stats, self);
}
