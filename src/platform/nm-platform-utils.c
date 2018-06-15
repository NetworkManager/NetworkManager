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

#include "nm-default.h"

#include "nm-platform-utils.h"

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <linux/mii.h>
#include <linux/version.h>
#include <linux/rtnetlink.h>
#include <fcntl.h>
#include <libudev.h>

#include "nm-utils.h"
#include "nm-setting-wired.h"

#include "nm-core-utils.h"

/******************************************************************
 * utils
 ******************************************************************/

extern char *if_indextoname (unsigned __ifindex, char *__ifname);
unsigned if_nametoindex (const char *__ifname);

const char *
nmp_utils_if_indextoname (int ifindex, char *out_ifname/*IFNAMSIZ*/)
{
	g_return_val_if_fail (ifindex > 0, NULL);
	g_return_val_if_fail (out_ifname, NULL);

	return if_indextoname (ifindex, out_ifname);
}

int
nmp_utils_if_nametoindex (const char *ifname)
{
	g_return_val_if_fail (ifname, 0);

	return if_nametoindex (ifname);
}

/******************************************************************
 * ethtool
 ******************************************************************/

NM_UTILS_ENUM2STR_DEFINE_STATIC (_ethtool_cmd_to_string, guint32,
	NM_UTILS_ENUM2STR (ETHTOOL_GDRVINFO,   "ETHTOOL_GDRVINFO"),
	NM_UTILS_ENUM2STR (ETHTOOL_GFEATURES,  "ETHTOOL_GFEATURES"),
	NM_UTILS_ENUM2STR (ETHTOOL_GLINK,      "ETHTOOL_GLINK"),
	NM_UTILS_ENUM2STR (ETHTOOL_GPERMADDR,  "ETHTOOL_GPERMADDR"),
	NM_UTILS_ENUM2STR (ETHTOOL_GSET,       "ETHTOOL_GSET"),
	NM_UTILS_ENUM2STR (ETHTOOL_GSSET_INFO, "ETHTOOL_GSSET_INFO"),
	NM_UTILS_ENUM2STR (ETHTOOL_GSTATS,     "ETHTOOL_GSTATS"),
	NM_UTILS_ENUM2STR (ETHTOOL_GSTRINGS,   "ETHTOOL_GSTRINGS"),
	NM_UTILS_ENUM2STR (ETHTOOL_GWOL,       "ETHTOOL_GWOL"),
	NM_UTILS_ENUM2STR (ETHTOOL_SSET,       "ETHTOOL_SSET"),
	NM_UTILS_ENUM2STR (ETHTOOL_SWOL,       "ETHTOOL_SWOL"),
);

static const char *
_ethtool_data_to_string (gconstpointer edata, char *buf, gsize len)
{
	return _ethtool_cmd_to_string (*((guint32 *) edata), buf, len);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
#define ethtool_cmd_speed(pedata) ((pedata)->speed)

#define ethtool_cmd_speed_set(pedata, speed) \
	G_STMT_START { (pedata)->speed = (guint16) (speed); } G_STMT_END
#endif

static gboolean
ethtool_get (int ifindex, gpointer edata)
{
	char ifname[IFNAMSIZ];
	char sbuf[50];

	nm_assert (ifindex > 0);

	/* ethtool ioctl API uses the ifname to refer to an interface. That is racy
	 * as interfaces can be renamed *sigh*.
	 *
	 * Note that we anyway have to verify whether the interface exists, before
	 * calling ioctl for a non-existing ifname. This is to prevent autoloading
	 * of kernel modules *sigh*.
	 * Thus, as we anyway verify the existence of ifname before doing the call,
	 * go one step further and lookup the ifname everytime anew.
	 *
	 * This does not solve the renaming race, but it minimizes the time for
	 * the race to happen as much as possible. */

	if (!nmp_utils_if_indextoname (ifindex, ifname)) {
		nm_log_trace (LOGD_PLATFORM, "ethtool[%d]: %s: request fails resolving ifindex: %s",
		              ifindex,
		              _ethtool_data_to_string (edata, sbuf, sizeof (sbuf)),
		              g_strerror (errno));
		return FALSE;
	}

	{
		nm_auto_close int fd = -1;
		struct ifreq ifr = {
			.ifr_data = edata,
		};

		memcpy (ifr.ifr_name, ifname, sizeof (ifname));

		fd = socket (PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
		if (fd < 0) {
			nm_log_trace (LOGD_PLATFORM, "ethtool[%d]: %s, %s: failed creating socket for ioctl: %s",
			              ifindex,
			              _ethtool_data_to_string (edata, sbuf, sizeof (sbuf)),
			              ifname,
			              g_strerror (errno));
			return FALSE;
		}

		if (ioctl (fd, SIOCETHTOOL, &ifr) < 0) {
			nm_log_trace (LOGD_PLATFORM, "ethtool[%d]: %s, %s: failed: %s",
			              ifindex,
			              _ethtool_data_to_string (edata, sbuf, sizeof (sbuf)),
			              ifname,
			              strerror (errno));
			return FALSE;
		}

		nm_log_trace (LOGD_PLATFORM, "ethtool[%d]: %s, %s: success",
		              ifindex,
		              _ethtool_data_to_string (edata, sbuf, sizeof (sbuf)),
		              ifname);
		return TRUE;
	}
}

static int
ethtool_get_stringset_index (int ifindex, int stringset_id, const char *string)
{
	gs_free struct ethtool_sset_info *info = NULL;
	gs_free struct ethtool_gstrings *strings = NULL;
	guint32 len, i;

	g_return_val_if_fail (ifindex > 0, -1);

	info = g_malloc0 (sizeof (*info) + sizeof (guint32));
	info->cmd = ETHTOOL_GSSET_INFO;
	info->reserved = 0;
	info->sset_mask = 1ULL << stringset_id;

	if (!ethtool_get (ifindex, info))
		return -1;
	if (!info->sset_mask)
		return -1;

	len = info->data[0];

	strings = g_malloc0 (sizeof (*strings) + len * ETH_GSTRING_LEN);
	strings->cmd = ETHTOOL_GSTRINGS;
	strings->string_set = stringset_id;
	strings->len = len;
	if (!ethtool_get (ifindex, strings))
		return -1;

	for (i = 0; i < len; i++) {
		if (!strcmp ((char *) &strings->data[i * ETH_GSTRING_LEN], string))
			return i;
	}

	return -1;
}

gboolean
nmp_utils_ethtool_get_driver_info (int ifindex,
                                   NMPUtilsEthtoolDriverInfo *data)
{
	struct ethtool_drvinfo *drvinfo;
	G_STATIC_ASSERT (sizeof (*data) == sizeof (*drvinfo));
	G_STATIC_ASSERT (offsetof (NMPUtilsEthtoolDriverInfo, driver)     == offsetof (struct ethtool_drvinfo, driver));
	G_STATIC_ASSERT (offsetof (NMPUtilsEthtoolDriverInfo, version)    == offsetof (struct ethtool_drvinfo, version));
	G_STATIC_ASSERT (offsetof (NMPUtilsEthtoolDriverInfo, fw_version) == offsetof (struct ethtool_drvinfo, fw_version));
	G_STATIC_ASSERT (sizeof (data->driver)     == sizeof (drvinfo->driver));
	G_STATIC_ASSERT (sizeof (data->version)    == sizeof (drvinfo->version));
	G_STATIC_ASSERT (sizeof (data->fw_version) == sizeof (drvinfo->fw_version));

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (data, FALSE);

	drvinfo = (struct ethtool_drvinfo *) data;

	memset (drvinfo, 0, sizeof (*drvinfo));
	drvinfo->cmd = ETHTOOL_GDRVINFO;
	return ethtool_get (ifindex, drvinfo);
}

gboolean
nmp_utils_ethtool_get_permanent_address (int ifindex,
                                         guint8 *buf,
                                         size_t *length)
{
	struct {
		struct ethtool_perm_addr e;
		guint8 _extra_data[NM_UTILS_HWADDR_LEN_MAX + 1];
	} edata;
	guint i;

	g_return_val_if_fail (ifindex > 0, FALSE);

	memset (&edata, 0, sizeof (edata));
	edata.e.cmd = ETHTOOL_GPERMADDR;
	edata.e.size = NM_UTILS_HWADDR_LEN_MAX;

	if (!ethtool_get (ifindex, &edata.e))
		return FALSE;

	if (edata.e.size > NM_UTILS_HWADDR_LEN_MAX)
		return FALSE;
	if (edata.e.size < 1)
		return FALSE;

	if (NM_IN_SET (edata.e.data[0], 0, 0xFF)) {
		/* Some drivers might return a permanent address of all zeros.
		 * Reject that (rh#1264024)
		 *
		 * Some drivers return a permanent address of all ones. Reject that too */
		for (i = 1; i < edata.e.size; i++) {
			if (edata.e.data[0] != edata.e.data[i])
				goto not_all_0or1;
		}
		return FALSE;
	}
not_all_0or1:

	memcpy (buf, edata.e.data, edata.e.size);
	*length = edata.e.size;
	return TRUE;
}

gboolean
nmp_utils_ethtool_supports_carrier_detect (int ifindex)
{
	struct ethtool_cmd edata = { .cmd = ETHTOOL_GLINK };

	g_return_val_if_fail (ifindex > 0, FALSE);

	/* We ignore the result. If the ETHTOOL_GLINK call succeeded, then we
	 * assume the device supports carrier-detect, otherwise we assume it
	 * doesn't.
	 */
	return ethtool_get (ifindex, &edata);
}

gboolean
nmp_utils_ethtool_supports_vlans (int ifindex)
{
	gs_free struct ethtool_gfeatures *features = NULL;
	int idx, block, bit, size;

	g_return_val_if_fail (ifindex > 0, FALSE);

	idx = ethtool_get_stringset_index (ifindex, ETH_SS_FEATURES, "vlan-challenged");
	if (idx == -1) {
		nm_log_dbg (LOGD_PLATFORM, "ethtool: vlan-challenged ethtool feature does not exist for %d?", ifindex);
		return FALSE;
	}

	block = idx /  32;
	bit = idx % 32;
	size = block + 1;

	features = g_malloc0 (sizeof (*features) + size * sizeof (struct ethtool_get_features_block));
	features->cmd = ETHTOOL_GFEATURES;
	features->size = size;

	if (!ethtool_get (ifindex, features))
		return FALSE;

	return !(features->features[block].active & (1 << bit));
}

int
nmp_utils_ethtool_get_peer_ifindex (int ifindex)
{
	gs_free struct ethtool_stats *stats = NULL;
	int peer_ifindex_stat;

	g_return_val_if_fail (ifindex > 0, 0);

	peer_ifindex_stat = ethtool_get_stringset_index (ifindex, ETH_SS_STATS, "peer_ifindex");
	if (peer_ifindex_stat == -1) {
		nm_log_dbg (LOGD_PLATFORM, "ethtool: peer_ifindex stat for %d does not exist?", ifindex);
		return FALSE;
	}

	stats = g_malloc0 (sizeof (*stats) + (peer_ifindex_stat + 1) * sizeof (guint64));
	stats->cmd = ETHTOOL_GSTATS;
	stats->n_stats = peer_ifindex_stat + 1;
	if (!ethtool_get (ifindex, stats))
		return 0;

	return stats->data[peer_ifindex_stat];
}

gboolean
nmp_utils_ethtool_get_wake_on_lan (int ifindex)
{
	struct ethtool_wolinfo wol;

	g_return_val_if_fail (ifindex > 0, FALSE);

	memset (&wol, 0, sizeof (wol));
	wol.cmd = ETHTOOL_GWOL;
	if (!ethtool_get (ifindex, &wol))
		return FALSE;

	return wol.wolopts != 0;
}

gboolean
nmp_utils_ethtool_get_link_settings (int ifindex,
                                     gboolean *out_autoneg,
                                     guint32 *out_speed,
                                     NMPlatformLinkDuplexType *out_duplex)
{
	struct ethtool_cmd edata = {
		.cmd = ETHTOOL_GSET,
	};

	g_return_val_if_fail (ifindex > 0, FALSE);

	if (!ethtool_get (ifindex, &edata))
		return FALSE;

	if (out_autoneg)
		*out_autoneg = (edata.autoneg == AUTONEG_ENABLE);

	if (out_speed) {
		guint32 speed;

		speed = ethtool_cmd_speed (&edata);
		if (speed == G_MAXUINT16 || speed == G_MAXUINT32)
			speed = 0;

		*out_speed = speed;
	}

	if (out_duplex) {
		switch (edata.duplex) {
		case DUPLEX_HALF:
			*out_duplex = NM_PLATFORM_LINK_DUPLEX_HALF;
			break;
		case DUPLEX_FULL:
			*out_duplex = NM_PLATFORM_LINK_DUPLEX_FULL;
			break;
		default: /* DUPLEX_UNKNOWN */
			*out_duplex = NM_PLATFORM_LINK_DUPLEX_UNKNOWN;
			break;
		}
	}

	return TRUE;
}


#define ADVERTISED_INVALID 0
#define BASET_ALL_MODES (  ADVERTISED_10baseT_Half \
                         | ADVERTISED_10baseT_Full \
                         | ADVERTISED_100baseT_Half \
                         | ADVERTISED_100baseT_Full \
                         | ADVERTISED_1000baseT_Half \
                         | ADVERTISED_1000baseT_Full \
                         | ADVERTISED_10000baseT_Full )

static inline guint32
get_baset_mode (guint32 speed, NMPlatformLinkDuplexType duplex)
{
	if (duplex == NM_PLATFORM_LINK_DUPLEX_UNKNOWN)
		return ADVERTISED_INVALID;

	if (duplex == NM_PLATFORM_LINK_DUPLEX_HALF) {
		switch (speed) {
		case 10: return ADVERTISED_10baseT_Half;
		case 100: return ADVERTISED_100baseT_Half;
		case 1000: return ADVERTISED_1000baseT_Half;
		default: return ADVERTISED_INVALID;
		}
	} else {
		switch (speed) {
		case 10: return ADVERTISED_10baseT_Full;
		case 100: return ADVERTISED_100baseT_Full;
		case 1000: return ADVERTISED_1000baseT_Full;
		case 10000: return ADVERTISED_10000baseT_Full;
		default: return ADVERTISED_INVALID;
		}
	}
}

gboolean
nmp_utils_ethtool_set_link_settings (int ifindex,
                                     gboolean autoneg,
                                     guint32 speed,
                                     NMPlatformLinkDuplexType duplex)
{
	struct ethtool_cmd edata = {
		.cmd = ETHTOOL_GSET,
	};

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (   (speed && duplex != NM_PLATFORM_LINK_DUPLEX_UNKNOWN)
	                      || (!speed && duplex == NM_PLATFORM_LINK_DUPLEX_UNKNOWN), FALSE);

	/* retrieve first current settings */
	if (!ethtool_get (ifindex, &edata))
		return FALSE;

	/* then change the needed ones */
	edata.cmd = ETHTOOL_SSET;
	if (autoneg) {
		edata.autoneg = AUTONEG_ENABLE;
		if (!speed)
			edata.advertising = edata.supported;
		else {
			guint32 mode;

			mode = get_baset_mode (speed, duplex);

			if (!mode) {
				nm_log_trace (LOGD_PLATFORM,
				              "ethtool[%d]: %uBASE-T %s duplex mode cannot be advertised",
				              ifindex,
				              speed,
				              nm_platform_link_duplex_type_to_string (duplex));
				return FALSE;
			}
			if (!(edata.supported & mode)) {
				nm_log_trace (LOGD_PLATFORM,
				              "ethtool[%d]: device does not support %uBASE-T %s duplex mode",
				              ifindex,
				              speed,
				              nm_platform_link_duplex_type_to_string (duplex));
				return FALSE;
			}
			edata.advertising = (edata.supported & ~BASET_ALL_MODES) | mode;
		}
	} else {
		edata.autoneg = AUTONEG_DISABLE;

		if (speed)
			ethtool_cmd_speed_set (&edata, speed);

		switch (duplex) {
		case NM_PLATFORM_LINK_DUPLEX_HALF:
			edata.duplex = DUPLEX_HALF;
			break;
		case NM_PLATFORM_LINK_DUPLEX_FULL:
			edata.duplex = DUPLEX_FULL;
			break;
		case NM_PLATFORM_LINK_DUPLEX_UNKNOWN:
			break;
		default:
			g_return_val_if_reached (FALSE);
		}
	}

	return ethtool_get (ifindex, &edata);
}

gboolean
nmp_utils_ethtool_set_wake_on_lan (int ifindex,
                                   NMSettingWiredWakeOnLan wol,
                                   const char *wol_password)
{
	struct ethtool_wolinfo wol_info = { };

	g_return_val_if_fail (ifindex > 0, FALSE);

	if (wol == NM_SETTING_WIRED_WAKE_ON_LAN_IGNORE)
		return TRUE;

	nm_log_dbg (LOGD_PLATFORM, "setting Wake-on-LAN options 0x%x, password '%s'",
	            (unsigned) wol, wol_password);

	wol_info.cmd = ETHTOOL_SWOL;
	wol_info.wolopts = 0;

	if (NM_FLAGS_HAS (wol, NM_SETTING_WIRED_WAKE_ON_LAN_PHY))
		wol_info.wolopts |= WAKE_PHY;
	if (NM_FLAGS_HAS (wol, NM_SETTING_WIRED_WAKE_ON_LAN_UNICAST))
		wol_info.wolopts |= WAKE_UCAST;
	if (NM_FLAGS_HAS (wol, NM_SETTING_WIRED_WAKE_ON_LAN_MULTICAST))
		wol_info.wolopts |= WAKE_MCAST;
	if (NM_FLAGS_HAS (wol, NM_SETTING_WIRED_WAKE_ON_LAN_BROADCAST))
		wol_info.wolopts |= WAKE_BCAST;
	if (NM_FLAGS_HAS (wol, NM_SETTING_WIRED_WAKE_ON_LAN_ARP))
		wol_info.wolopts |= WAKE_ARP;
	if (NM_FLAGS_HAS (wol, NM_SETTING_WIRED_WAKE_ON_LAN_MAGIC))
		wol_info.wolopts |= WAKE_MAGIC;

	if (wol_password) {
		if (!nm_utils_hwaddr_aton (wol_password, wol_info.sopass, ETH_ALEN)) {
			nm_log_dbg (LOGD_PLATFORM, "couldn't parse Wake-on-LAN password '%s'", wol_password);
			return FALSE;
		}
		wol_info.wolopts |= WAKE_MAGICSECURE;
	}

	return ethtool_get (ifindex, &wol_info);
}

/******************************************************************
 * mii
 ******************************************************************/

gboolean
nmp_utils_mii_supports_carrier_detect (int ifindex)
{
	char ifname[IFNAMSIZ];
	nm_auto_close int fd = -1;
	struct ifreq ifr;
	struct mii_ioctl_data *mii;

	g_return_val_if_fail (ifindex > 0, FALSE);

	if (!nmp_utils_if_indextoname (ifindex, ifname)) {
		nm_log_trace (LOGD_PLATFORM, "mii[%d]: carrier-detect no: request fails resolving ifindex: %s", ifindex, g_strerror (errno));
		return FALSE;
	}

	fd = socket (PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		nm_log_trace (LOGD_PLATFORM, "mii[%d,%s]: carrier-detect no: couldn't open control socket: %s", ifindex, ifname, g_strerror (errno));
		return FALSE;
	}

	memset (&ifr, 0, sizeof (struct ifreq));
	memcpy (ifr.ifr_name, ifname, IFNAMSIZ);

	if (ioctl (fd, SIOCGMIIPHY, &ifr) < 0) {
		nm_log_trace (LOGD_PLATFORM, "mii[%d,%s]: carrier-detect no: SIOCGMIIPHY failed: %s", ifindex, ifname, strerror (errno));
		return FALSE;
	}

	/* If we can read the BMSR register, we assume that the card supports MII link detection */
	mii = (struct mii_ioctl_data *) &ifr.ifr_ifru;
	mii->reg_num = MII_BMSR;

	if (ioctl (fd, SIOCGMIIREG, &ifr) != 0) {
		nm_log_trace (LOGD_PLATFORM, "mii[%d,%s]: carrier-detect no: SIOCGMIIREG failed: %s", ifindex, ifname, strerror (errno));
		return FALSE;
	}

	nm_log_trace (LOGD_PLATFORM, "mii[%d,%s]: carrier-detect yes: SIOCGMIIREG result 0x%X", ifindex, ifname, mii->val_out);
	return TRUE;
}

/******************************************************************
 * udev
 ******************************************************************/

const char *
nmp_utils_udev_get_driver (struct udev_device *udevice)
{
	struct udev_device *parent = NULL, *grandparent = NULL;
	const char *driver, *subsys;

	driver = udev_device_get_driver (udevice);
	if (driver)
		goto out;

	/* Try the parent */
	parent = udev_device_get_parent (udevice);
	if (parent) {
		driver = udev_device_get_driver (parent);
		if (!driver) {
			/* Try the grandparent if it's an ibmebus device or if the
			 * subsys is NULL which usually indicates some sort of
			 * platform device like a 'gadget' net interface.
			 */
			subsys = udev_device_get_subsystem (parent);
			if (   (g_strcmp0 (subsys, "ibmebus") == 0)
			    || (subsys == NULL)) {
				grandparent = udev_device_get_parent (parent);
				if (grandparent)
					driver = udev_device_get_driver (grandparent);
			}
		}
	}

out:
	/* Intern the string so we don't have to worry about memory
	 * management in NMPlatformLink. */
	return g_intern_string (driver);
}

/******************************************************************************
 * utils
 *****************************************************************************/

NMIPConfigSource
nmp_utils_ip_config_source_from_rtprot (guint8 rtprot)
{
	return ((int) rtprot) + 1;
}

NMIPConfigSource
nmp_utils_ip_config_source_round_trip_rtprot (NMIPConfigSource source)
{
	/* when adding a route to kernel for a give @source, the resulting route
	 * will be put into the cache with a source of NM_IP_CONFIG_SOURCE_RTPROT_*.
	 * This function returns that. */
	return nmp_utils_ip_config_source_from_rtprot (nmp_utils_ip_config_source_coerce_to_rtprot (source));
}

guint8
nmp_utils_ip_config_source_coerce_to_rtprot (NMIPConfigSource source)
{
	/* when adding a route to kernel, we coerce the @source field
	 * to rtm_protocol. This is not lossless as we map different
	 * source values to the same RTPROT uint8 value. */
	if (source <= NM_IP_CONFIG_SOURCE_UNKNOWN)
		return RTPROT_UNSPEC;

	if (source <= _NM_IP_CONFIG_SOURCE_RTPROT_LAST)
		return source - 1;

	switch (source) {
	case NM_IP_CONFIG_SOURCE_KERNEL:
		return RTPROT_KERNEL;
	case NM_IP_CONFIG_SOURCE_IP6LL:
		return RTPROT_KERNEL;
	case NM_IP_CONFIG_SOURCE_DHCP:
		return RTPROT_DHCP;
	case NM_IP_CONFIG_SOURCE_NDISC:
		return RTPROT_RA;

	default:
		return RTPROT_STATIC;
	}
}

NMIPConfigSource
nmp_utils_ip_config_source_coerce_from_rtprot (NMIPConfigSource source)
{
	/* When we receive a route from kernel and put it into the platform cache,
	 * we preserve the protocol field by converting it to a NMIPConfigSource
	 * via nmp_utils_ip_config_source_from_rtprot().
	 *
	 * However, that is not the inverse of nmp_utils_ip_config_source_coerce_to_rtprot().
	 * Instead, to go back to the original value, you need another step:
	 *   nmp_utils_ip_config_source_coerce_from_rtprot (nmp_utils_ip_config_source_from_rtprot (rtprot)).
	 *
	 * This might partly restore the original source value, but of course that
	 * is not really possible because nmp_utils_ip_config_source_coerce_to_rtprot()
	 * is not injective.
	 * */
	switch (source) {
	case NM_IP_CONFIG_SOURCE_RTPROT_UNSPEC:
		return NM_IP_CONFIG_SOURCE_UNKNOWN;

	case NM_IP_CONFIG_SOURCE_RTPROT_KERNEL:
	case NM_IP_CONFIG_SOURCE_RTPROT_REDIRECT:
		return NM_IP_CONFIG_SOURCE_KERNEL;

	case NM_IP_CONFIG_SOURCE_RTPROT_RA:
		return NM_IP_CONFIG_SOURCE_NDISC;

	case NM_IP_CONFIG_SOURCE_RTPROT_DHCP:
		return NM_IP_CONFIG_SOURCE_DHCP;

	default:
		return NM_IP_CONFIG_SOURCE_USER;
	}
}

const char *
nmp_utils_ip_config_source_to_string (NMIPConfigSource source, char *buf, gsize len)
{
	const char *s = NULL;
	nm_utils_to_string_buffer_init (&buf, &len); \

	if (!len)
		return buf;

	switch (source) {
	case NM_IP_CONFIG_SOURCE_UNKNOWN:         s = "unknown"; break;

	case NM_IP_CONFIG_SOURCE_RTPROT_UNSPEC:   s = "rt-unspec"; break;
	case NM_IP_CONFIG_SOURCE_RTPROT_REDIRECT: s = "rt-redirect"; break;
	case NM_IP_CONFIG_SOURCE_RTPROT_KERNEL:   s = "rt-kernel"; break;
	case NM_IP_CONFIG_SOURCE_RTPROT_BOOT:     s = "rt-boot"; break;
	case NM_IP_CONFIG_SOURCE_RTPROT_STATIC:   s = "rt-static"; break;
	case NM_IP_CONFIG_SOURCE_RTPROT_DHCP:     s = "rt-dhcp"; break;
	case NM_IP_CONFIG_SOURCE_RTPROT_RA:       s = "rt-ra"; break;

	case NM_IP_CONFIG_SOURCE_KERNEL:          s = "kernel"; break;
	case NM_IP_CONFIG_SOURCE_SHARED:          s = "shared"; break;
	case NM_IP_CONFIG_SOURCE_IP4LL:           s = "ipv4ll"; break;
	case NM_IP_CONFIG_SOURCE_IP6LL:           s = "ipv6ll"; break;
	case NM_IP_CONFIG_SOURCE_PPP:             s = "ppp"; break;
	case NM_IP_CONFIG_SOURCE_WWAN:            s = "wwan"; break;
	case NM_IP_CONFIG_SOURCE_VPN:             s = "vpn"; break;
	case NM_IP_CONFIG_SOURCE_DHCP:            s = "dhcp"; break;
	case NM_IP_CONFIG_SOURCE_NDISC:           s = "ndisc"; break;
	case NM_IP_CONFIG_SOURCE_USER:            s = "user"; break;
	default:
		break;
	}

	if (source >= 1 && source <= 0x100) {
		if (s)
			g_snprintf (buf, len, "%s", s);
		else
			g_snprintf (buf, len, "rt-%d", ((int) source) - 1);
	} else {
		if (s)
			g_strlcpy (buf, s, len);
		else
			g_snprintf (buf, len, "(%d)", source);
	}
	return buf;
}

/**
 * nmp_utils_sysctl_open_netdir:
 * @ifindex: the ifindex for which to open "/sys/class/net/%s"
 * @ifname_guess: (allow-none): optional argument, if present used as initial
 *   guess as the current name for @ifindex. If guessed right,
 *   it saves an addtional if_indextoname() call.
 * @out_ifname: (allow-none): if present, must be at least IFNAMSIZ
 *   characters. On success, this will contain the actual ifname
 *   found while opening the directory.
 *
 * Returns: a negative value on failure, on success returns the open fd
 *   to the "/sys/class/net/%s" directory for @ifindex.
 */
int
nmp_utils_sysctl_open_netdir (int ifindex,
                              const char *ifname_guess,
                              char *out_ifname)
{
	#define SYS_CLASS_NET "/sys/class/net/"
	const char *ifname = ifname_guess;
	char ifname_buf_last_try[IFNAMSIZ];
	char ifname_buf[IFNAMSIZ];
	guint try_count = 0;
	char sysdir[NM_STRLEN (SYS_CLASS_NET) + IFNAMSIZ] = SYS_CLASS_NET;
	char fd_buf[256];
	ssize_t nn;

	g_return_val_if_fail (ifindex >= 0, -1);

	ifname_buf_last_try[0] = '\0';

	for (try_count = 0; try_count < 10; try_count++, ifname = NULL) {
		nm_auto_close int fd_dir = -1;
		nm_auto_close int fd_ifindex = -1;
		int fd;

		if (!ifname) {
			ifname = nmp_utils_if_indextoname (ifindex, ifname_buf);
			if (!ifname)
				return -1;
		}

		nm_assert (nm_utils_is_valid_iface_name (ifname, NULL));

		if (g_strlcpy (&sysdir[NM_STRLEN (SYS_CLASS_NET)], ifname, IFNAMSIZ) >= IFNAMSIZ)
			g_return_val_if_reached (-1);

		/* we only retry, if the name changed since previous attempt.
		 * Hence, it is extremely unlikely that this loop runes until the
		 * end of the @try_count. */
		if (nm_streq (ifname, ifname_buf_last_try))
			return -1;
		strcpy (ifname_buf_last_try, ifname);

		fd_dir = open (sysdir, O_DIRECTORY | O_CLOEXEC);
		if (fd_dir < 0)
			continue;

		fd_ifindex = openat (fd_dir, "ifindex", O_CLOEXEC);
		if (fd_ifindex < 0)
			continue;

		nn = nm_utils_fd_read_loop (fd_ifindex, fd_buf, sizeof (fd_buf) - 2, FALSE);
		if (nn <= 0)
			continue;
		fd_buf[nn] = '\0';

		if (ifindex != _nm_utils_ascii_str_to_int64 (fd_buf, 10, 1, G_MAXINT, -1))
			continue;

		if (out_ifname)
			strcpy (out_ifname, ifname);

		fd = fd_dir;
		fd_dir = -1;
		return fd;
	}

	return -1;
}
