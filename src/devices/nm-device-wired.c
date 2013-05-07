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
 * Copyright (C) 2005 - 2012 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#include "config.h"
#include <glib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_infiniband.h>
#include <netinet/ether.h>
#include <linux/sockios.h>
#include <linux/version.h>
#include <linux/ethtool.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "nm-device-wired.h"
#include "nm-device-private.h"
#include "nm-dhcp-manager.h"
#include "nm-logging.h"
#include "nm-system.h"
#include "nm-utils.h"
#include "NetworkManagerUtils.h"


G_DEFINE_TYPE (NMDeviceWired, nm_device_wired, NM_TYPE_DEVICE)

#define NM_DEVICE_WIRED_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_WIRED, NMDeviceWiredPrivate))

#define NM_DEVICE_WIRED_LOG_LEVEL(dev) ((nm_device_get_device_type (dev) == NM_DEVICE_TYPE_INFINIBAND) ? LOGD_INFINIBAND : LOGD_ETHER)

typedef struct {
	guint32             speed;
} NMDeviceWiredPrivate;


/* Returns speed in Mb/s */
static guint32
ethtool_get_speed (NMDeviceWired *self)
{
	int fd;
	struct ifreq ifr;
	struct ethtool_cmd edata = {
		.cmd = ETHTOOL_GSET,
	};
	guint32 speed = 0;

	g_return_val_if_fail (self != NULL, 0);

	fd = socket (PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		nm_log_warn (LOGD_HW, "couldn't open control socket.");
		return 0;
	}

	memset (&ifr, 0, sizeof (struct ifreq));
	strncpy (ifr.ifr_name, nm_device_get_iface (NM_DEVICE (self)), IFNAMSIZ);
	ifr.ifr_data = (char *) &edata;

	if (ioctl (fd, SIOCETHTOOL, &ifr) < 0)
		goto out;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
	speed = edata.speed;
#else
	speed = ethtool_cmd_speed (&edata);
#endif

	if (speed == G_MAXUINT16 || speed == G_MAXUINT32)
		speed = 0;

out:
	close (fd);
	return speed;
}

static void
set_speed (NMDeviceWired *self, const guint32 speed)
{
	NMDeviceWiredPrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_WIRED_GET_PRIVATE (self);
	if (priv->speed == speed)
		return;

	priv->speed = speed;
	g_object_notify (G_OBJECT (self), "speed");

	nm_log_dbg (LOGD_HW | NM_DEVICE_WIRED_LOG_LEVEL (NM_DEVICE (self)),
	             "(%s): speed is now %d Mb/s",
	             nm_device_get_iface (NM_DEVICE (self)),
	             speed);
}

static void
carrier_changed (NMDevice *device, gboolean carrier)
{
	NMDeviceWired *wired_device = NM_DEVICE_WIRED (device);

	if (carrier)
		set_speed (wired_device, ethtool_get_speed (wired_device));

	G_OBJECT_CLASS (nm_device_wired_parent_class)->carrier_changed (device, carrier);
}

static void
nm_device_wired_init (NMDeviceWired * self)
{
}

static void
nm_device_wired_class_init (NMDeviceWiredClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *parent_class = NM_DEVICE_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMDeviceWiredPrivate));

	/* virtual methods */

	parent_class->carrier_changed = carrier_changed;
}

/**
 * nm_device_wired_get_speed:
 * @dev: an #NMDeviceWired
 *
 * Get @dev's speed
 *
 * Return value: @dev's speed in Mb/s
 */
guint32
nm_device_wired_get_speed (NMDeviceWired *dev)
{
	NMDeviceWiredPrivate *priv;

	g_return_val_if_fail (dev != NULL, 0);

	priv = NM_DEVICE_WIRED_GET_PRIVATE (dev);
	return priv->speed;
}
