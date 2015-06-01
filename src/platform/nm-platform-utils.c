/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-platform.c - Handle runtime kernel networking configuration
 *
 * This program is free software; you can redistribute it and/or modify
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
 * Copyright (C) 2015 Red Hat, Inc.
 */

#include "nm-platform-utils.h"

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <linux/mii.h>
#include <linux/version.h>

#include "gsystem-local-alloc.h"
#include "nm-utils.h"
#include "NetworkManagerUtils.h"
#include "nm-logging.h"


/******************************************************************
 * ethtool
 ******************************************************************/

static gboolean
ethtool_get (const char *name, gpointer edata)
{
	struct ifreq ifr;
	int fd;

	if (!name || !*name)
		return FALSE;

	memset (&ifr, 0, sizeof (ifr));
	strncpy (ifr.ifr_name, name, IFNAMSIZ);
	ifr.ifr_data = edata;

	fd = socket (PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		nm_log_err (LOGD_PLATFORM, "ethtool: Could not open socket.");
		return FALSE;
	}

	if (ioctl (fd, SIOCETHTOOL, &ifr) < 0) {
		nm_log_dbg (LOGD_PLATFORM, "ethtool: Request failed: %s", strerror (errno));
		close (fd);
		return FALSE;
	}

	close (fd);
	return TRUE;
}

static int
ethtool_get_stringset_index (const char *ifname, int stringset_id, const char *string)
{
	gs_free struct ethtool_sset_info *info = NULL;
	gs_free struct ethtool_gstrings *strings = NULL;
	guint32 len, i;

	info = g_malloc0 (sizeof (*info) + sizeof (guint32));
	info->cmd = ETHTOOL_GSSET_INFO;
	info->reserved = 0;
	info->sset_mask = 1ULL << stringset_id;

	if (!ethtool_get (ifname, info))
		return -1;
	if (!info->sset_mask)
		return -1;

	len = info->data[0];

	strings = g_malloc0 (sizeof (*strings) + len * ETH_GSTRING_LEN);
	strings->cmd = ETHTOOL_GSTRINGS;
	strings->string_set = stringset_id;
	strings->len = len;
	if (!ethtool_get (ifname, strings))
		return -1;

	for (i = 0; i < len; i++) {
		if (!strcmp ((char *) &strings->data[i * ETH_GSTRING_LEN], string))
			return i;
	}

	return -1;
}

gboolean
nmp_utils_ethtool_get_driver_info (const char *ifname,
                                   char **out_driver_name,
                                   char **out_driver_version,
                                   char **out_fw_version)
{
	struct ethtool_drvinfo drvinfo = { 0 };

	if (!ifname)
		return FALSE;

	drvinfo.cmd = ETHTOOL_GDRVINFO;
	if (!ethtool_get (ifname, &drvinfo))
		return FALSE;

	if (out_driver_name)
		*out_driver_name = g_strdup (drvinfo.driver);
	if (out_driver_version)
		*out_driver_version = g_strdup (drvinfo.version);
	if (out_fw_version)
		*out_fw_version = g_strdup (drvinfo.fw_version);

	return TRUE;
}

gboolean
nmp_utils_ethtool_get_permanent_address (const char *ifname,
                                         guint8 *buf,
                                         size_t *length)
{
	gs_free struct ethtool_perm_addr *epaddr = NULL;

	if (!ifname)
		return FALSE;

	epaddr = g_malloc0 (sizeof (*epaddr) + NM_UTILS_HWADDR_LEN_MAX);
	epaddr->cmd = ETHTOOL_GPERMADDR;
	epaddr->size = NM_UTILS_HWADDR_LEN_MAX;

	if (!ethtool_get (ifname, epaddr))
		return FALSE;
	if (!nm_ethernet_address_is_valid (epaddr->data, epaddr->size))
		return FALSE;

	g_assert (epaddr->size <= NM_UTILS_HWADDR_LEN_MAX);
	memcpy (buf, epaddr->data, epaddr->size);
	*length = epaddr->size;
	return TRUE;
}

gboolean
nmp_utils_ethtool_supports_carrier_detect (const char *ifname)
{
	struct ethtool_cmd edata = { .cmd = ETHTOOL_GLINK };

	/* We ignore the result. If the ETHTOOL_GLINK call succeeded, then we
	 * assume the device supports carrier-detect, otherwise we assume it
	 * doesn't.
	 */
	return ethtool_get (ifname, &edata);
}

gboolean
nmp_utils_ethtool_supports_vlans (const char *ifname)
{
	gs_free struct ethtool_gfeatures *features = NULL;
	int idx, block, bit, size;

	if (!ifname)
		return FALSE;

	idx = ethtool_get_stringset_index (ifname, ETH_SS_FEATURES, "vlan-challenged");
	if (idx == -1) {
		nm_log_dbg (LOGD_PLATFORM, "ethtool: vlan-challenged ethtool feature does not exist for %s?", ifname);
		return FALSE;
	}

	block = idx /  32;
	bit = idx % 32;
	size = block + 1;

	features = g_malloc0 (sizeof (*features) + size * sizeof (struct ethtool_get_features_block));
	features->cmd = ETHTOOL_GFEATURES;
	features->size = size;

	if (!ethtool_get (ifname, features))
		return FALSE;

	return !(features->features[block].active & (1 << bit));
}

int
nmp_utils_ethtool_get_peer_ifindex (const char *ifname)
{
	gs_free struct ethtool_stats *stats = NULL;
	int peer_ifindex_stat;

	if (!ifname)
		return 0;

	peer_ifindex_stat = ethtool_get_stringset_index (ifname, ETH_SS_STATS, "peer_ifindex");
	if (peer_ifindex_stat == -1) {
		nm_log_dbg (LOGD_PLATFORM, "ethtool: peer_ifindex stat for %s does not exist?", ifname);
		return FALSE;
	}

	stats = g_malloc0 (sizeof (*stats) + (peer_ifindex_stat + 1) * sizeof (guint64));
	stats->cmd = ETHTOOL_GSTATS;
	stats->n_stats = peer_ifindex_stat + 1;
	if (!ethtool_get (ifname, stats))
		return 0;

	return stats->data[peer_ifindex_stat];
}

gboolean
nmp_utils_ethtool_get_wake_on_lan (const char *ifname)
{
	struct ethtool_wolinfo wol;

	if (!ifname)
		return FALSE;

	memset (&wol, 0, sizeof (wol));
	wol.cmd = ETHTOOL_GWOL;
	if (!ethtool_get (ifname, &wol))
		return FALSE;

	return wol.wolopts != 0;
}

gboolean
nmp_utils_ethtool_get_link_speed (const char *ifname, guint32 *out_speed)
{
	struct ethtool_cmd edata = {
		.cmd = ETHTOOL_GSET,
	};
	guint32 speed;

	if (!ethtool_get (ifname, &edata))
		return FALSE;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
	speed = edata.speed;
#else
	speed = ethtool_cmd_speed (&edata);
#endif
	if (speed == G_MAXUINT16 || speed == G_MAXUINT32)
		speed = 0;

	if (out_speed)
		*out_speed = speed;
	return TRUE;
}

/******************************************************************
 * mii
 ******************************************************************/

gboolean
nmp_utils_mii_supports_carrier_detect (const char *ifname)
{
	int fd, errsv;
	struct ifreq ifr;
	struct mii_ioctl_data *mii;
	gboolean supports_mii = FALSE;

	if (!ifname)
		return FALSE;

	fd = socket (PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		nm_log_err (LOGD_PLATFORM, "mii: couldn't open control socket (%s)", ifname);
		return FALSE;
	}

	memset (&ifr, 0, sizeof (struct ifreq));
	strncpy (ifr.ifr_name, ifname, IFNAMSIZ);

	errno = 0;
	if (ioctl (fd, SIOCGMIIPHY, &ifr) < 0) {
		errsv = errno;
		nm_log_dbg (LOGD_PLATFORM, "mii: SIOCGMIIPHY failed: %s (%d) (%s)", strerror (errsv), errsv, ifname);
		goto out;
	}

	/* If we can read the BMSR register, we assume that the card supports MII link detection */
	mii = (struct mii_ioctl_data *) &ifr.ifr_ifru;
	mii->reg_num = MII_BMSR;

	if (ioctl (fd, SIOCGMIIREG, &ifr) == 0) {
		nm_log_dbg (LOGD_PLATFORM, "mii: SIOCGMIIREG result 0x%X (%s)", mii->val_out, ifname);
		supports_mii = TRUE;
	} else {
		errsv = errno;
		nm_log_dbg (LOGD_PLATFORM, "mii: SIOCGMIIREG failed: %s (%d) (%s)", strerror (errsv), errsv, ifname);
	}

out:
	close (fd);
	nm_log_dbg (LOGD_PLATFORM, "mii: MII %s supported (%s)", supports_mii ? "is" : "not", ifname);
	return supports_mii;
}

/******************************************************************
 * udev
 ******************************************************************/

const char *
nmp_utils_udev_get_driver (GUdevDevice *device)
{
	GUdevDevice *parent = NULL, *grandparent = NULL;
	const char *driver, *subsys;

	driver = g_udev_device_get_driver (device);
	if (driver)
		goto out;

	/* Try the parent */
	parent = g_udev_device_get_parent (device);
	if (parent) {
		driver = g_udev_device_get_driver (parent);
		if (!driver) {
			/* Try the grandparent if it's an ibmebus device or if the
			 * subsys is NULL which usually indicates some sort of
			 * platform device like a 'gadget' net interface.
			 */
			subsys = g_udev_device_get_subsystem (parent);
			if (   (g_strcmp0 (subsys, "ibmebus") == 0)
			    || (subsys == NULL)) {
				grandparent = g_udev_device_get_parent (parent);
				if (grandparent)
					driver = g_udev_device_get_driver (grandparent);
			}
		}
	}
	g_clear_object (&parent);
	g_clear_object (&grandparent);

out:
	/* Intern the string so we don't have to worry about memory
	 * management in NMPlatformLink. */
	return g_intern_string (driver);
}


