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
	int ifindex;
	const NMPlatformLink *pllink;

	ifindex = nm_device_get_ip_ifindex (self->device);

	pllink = nm_platform_link_get (NM_PLATFORM_GET, ifindex);
	if (pllink) {
		_LOGT ("ifindex %d: {RX} %"PRIu64" packets %"PRIu64" bytes {TX} %"PRIu64" packets %"PRIu64" bytes",
		       ifindex, pllink->rx_packets, pllink->rx_bytes, pllink->tx_packets, pllink->tx_bytes);

		nm_device_set_tx_bytes (self->device, pllink->tx_bytes);
		nm_device_set_rx_bytes (self->device, pllink->rx_bytes);
	} else {
		_LOGT ("error no stats available for ifindex %d", ifindex);
		nm_device_set_tx_bytes (self->device, 0);
		nm_device_set_rx_bytes (self->device, 0);
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
