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
 * Copyright (C) 2005 - 2011 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 * Copyright (C) 2011 Intel Corporation. All rights reserved.
 */

#include "nm-default.h"

#include "wifi-utils-nl80211.h"

#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <unistd.h>
#include <linux/nl80211.h>

#include "platform/nm-netlink.h"
#include "wifi-utils-private.h"
#include "platform/nm-platform.h"
#include "platform/nm-platform-utils.h"
#include "nm-utils.h"

#define _NMLOG_PREFIX_NAME      "wifi-nl80211"
#define _NMLOG(level, domain, ...) \
	G_STMT_START { \
		nm_log ((level), (domain), NULL, NULL, \
		        "%s: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
		        _NMLOG_PREFIX_NAME \
		        _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
	} G_STMT_END

typedef struct {
	WifiData parent;
	struct nl_sock *nl_sock;
	guint32 *freqs;
	int id;
	int num_freqs;
	int phy;
	bool can_wowlan:1;
} WifiDataNl80211;

static int
ack_handler (struct nl_msg *msg, void *arg)
{
	int *done = arg;
	*done = 1;
	return NL_STOP;
}

static int
finish_handler (struct nl_msg *msg, void *arg)
{
	int *done = arg;
	*done = 1;
	return NL_SKIP;
}

static int
error_handler (struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg)
{
	int *done = arg;
	*done = err->error;
	return NL_SKIP;
}

static struct nl_msg *
_nl80211_alloc_msg (int id, int ifindex, int phy, guint32 cmd, guint32 flags)
{
	nm_auto_nlmsg struct nl_msg *msg = NULL;

	msg = nlmsg_alloc ();
	genlmsg_put (msg, 0, 0, id, 0, flags, cmd, 0);
	NLA_PUT_U32 (msg, NL80211_ATTR_IFINDEX, ifindex);
	if (phy != -1)
		NLA_PUT_U32 (msg, NL80211_ATTR_WIPHY, phy);
	return g_steal_pointer (&msg);

nla_put_failure:
	return NULL;
}

static struct nl_msg *
nl80211_alloc_msg (WifiDataNl80211 *nl80211, guint32 cmd, guint32 flags)
{
	return _nl80211_alloc_msg (nl80211->id, nl80211->parent.ifindex, nl80211->phy, cmd, flags);
}

static int
_nl80211_send_and_recv (struct nl_sock *nl_sock,
                        struct nl_msg *msg,
                        int (*valid_handler) (struct nl_msg *, void *),
                        void *valid_data)
{
	int err;
	int done = 0;
	const struct nl_cb cb = {
		.err_cb     = error_handler,
		.err_arg    = &done,
		.finish_cb  = finish_handler,
		.finish_arg = &done,
		.ack_cb     = ack_handler,
		.ack_arg    = &done,
		.valid_cb   = valid_handler,
		.valid_arg  = valid_data,
	};

	g_return_val_if_fail (msg != NULL, -ENOMEM);

	err = nl_send_auto (nl_sock, msg);
	if (err < 0)
		return err;

	/* Loop until one of our NL callbacks says we're done; on success
	 * done will be 1, on error it will be < 0.
	 */
	while (!done) {
		err = nl_recvmsgs (nl_sock, &cb);
		if (err < 0 && err != -EAGAIN) {
			/* Kernel scan list can change while we are dumping it, as new scan
			 * results from H/W can arrive. BSS info is assured to be consistent
			 * and we don't need consistent view of whole scan list. Hence do
			 * not warn on DUMP_INTR error for get scan command.
			 */
			if (err == -NLE_DUMP_INTR &&
			    genlmsg_hdr (nlmsg_hdr (msg))->cmd == NL80211_CMD_GET_SCAN)
				break;

			_LOGW (LOGD_WIFI, "nl_recvmsgs() error: (%d) %s",
			       err, nl_geterror (err));
			break;
		}
	}

	if (err >= 0 && done < 0)
		err = done;
	return err;
}

static int
nl80211_send_and_recv (WifiDataNl80211 *nl80211,
                       struct nl_msg *msg,
                       int (*valid_handler) (struct nl_msg *, void *),
                       void *valid_data)
{
	return _nl80211_send_and_recv (nl80211->nl_sock, msg,
	                               valid_handler, valid_data);
}

static void
wifi_nl80211_deinit (WifiData *parent)
{
	WifiDataNl80211 *nl80211 = (WifiDataNl80211 *) parent;

	if (nl80211->nl_sock)
		nl_socket_free (nl80211->nl_sock);
	g_free (nl80211->freqs);
}

struct nl80211_iface_info {
	NM80211Mode mode;
};

static int
nl80211_iface_info_handler (struct nl_msg *msg, void *arg)
{
	struct nl80211_iface_info *info = arg;
	struct genlmsghdr *gnlh = nlmsg_data (nlmsg_hdr (msg));
	struct nlattr *tb[NL80211_ATTR_MAX + 1];

	if (nla_parse (tb, NL80211_ATTR_MAX, genlmsg_attrdata (gnlh, 0),
	               genlmsg_attrlen (gnlh, 0), NULL) < 0)
		return NL_SKIP;

	if (!tb[NL80211_ATTR_IFTYPE])
		return NL_SKIP;

	switch (nla_get_u32 (tb[NL80211_ATTR_IFTYPE])) {
	case NL80211_IFTYPE_ADHOC:
		info->mode = NM_802_11_MODE_ADHOC;
		break;
	case NL80211_IFTYPE_AP:
		info->mode = NM_802_11_MODE_AP;
		break;
	case NL80211_IFTYPE_STATION:
		info->mode = NM_802_11_MODE_INFRA;
		break;
	}

	return NL_SKIP;
}

static NM80211Mode
wifi_nl80211_get_mode (WifiData *data)
{
	WifiDataNl80211 *nl80211 = (WifiDataNl80211 *) data;
	struct nl80211_iface_info iface_info = {
		.mode = NM_802_11_MODE_UNKNOWN,
	};
	nm_auto_nlmsg struct nl_msg *msg = NULL;

	msg = nl80211_alloc_msg (nl80211, NL80211_CMD_GET_INTERFACE, 0);

	if (nl80211_send_and_recv (nl80211, msg, nl80211_iface_info_handler,
	                           &iface_info) < 0)
		return NM_802_11_MODE_UNKNOWN;

	return iface_info.mode;
}

static gboolean
wifi_nl80211_set_mode (WifiData *data, const NM80211Mode mode)
{
	WifiDataNl80211 *nl80211 = (WifiDataNl80211 *) data;
	nm_auto_nlmsg struct nl_msg *msg = NULL;
	int err;

	msg = nl80211_alloc_msg (nl80211, NL80211_CMD_SET_INTERFACE, 0);

	switch (mode) {
	case NM_802_11_MODE_INFRA:
		NLA_PUT_U32 (msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_STATION);
		break;
	case NM_802_11_MODE_ADHOC:
		NLA_PUT_U32 (msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_ADHOC);
		break;
	case NM_802_11_MODE_AP:
		NLA_PUT_U32 (msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_AP);
		break;
	default:
		g_assert_not_reached ();
	}

	err = nl80211_send_and_recv (nl80211, msg, NULL, NULL);
	return err >= 0;

nla_put_failure:
	return FALSE;
}

static gboolean
wifi_nl80211_set_powersave (WifiData *data, guint32 powersave)
{
	WifiDataNl80211 *nl80211 = (WifiDataNl80211 *) data;
	nm_auto_nlmsg struct nl_msg *msg = NULL;
	int err;

	msg = nl80211_alloc_msg (nl80211, NL80211_CMD_SET_POWER_SAVE, 0);
	NLA_PUT_U32 (msg, NL80211_ATTR_PS_STATE,
	             powersave == 1 ? NL80211_PS_ENABLED : NL80211_PS_DISABLED);
	err = nl80211_send_and_recv (nl80211, msg, NULL, NULL);
	return err >= 0;

nla_put_failure:
	return FALSE;
}

static gboolean
wifi_nl80211_set_wake_on_wlan (WifiData *data, NMSettingWirelessWakeOnWLan wowl)
{
	WifiDataNl80211 *nl80211 = (WifiDataNl80211 *) data;
	nm_auto_nlmsg struct nl_msg *msg = NULL;
	struct nlattr *triggers;
	int err;

	if (wowl == NM_SETTING_WIRELESS_WAKE_ON_WLAN_IGNORE)
		return TRUE;

	msg = nl80211_alloc_msg(nl80211, NL80211_CMD_SET_WOWLAN, 0);
	if (!msg)
		return FALSE;

	triggers = nla_nest_start(msg, NL80211_ATTR_WOWLAN_TRIGGERS);

	if (NM_FLAGS_HAS (wowl, NM_SETTING_WIRELESS_WAKE_ON_WLAN_ANY))
		NLA_PUT_FLAG (msg, NL80211_WOWLAN_TRIG_ANY);
	if (NM_FLAGS_HAS (wowl, NM_SETTING_WIRELESS_WAKE_ON_WLAN_DISCONNECT))
		NLA_PUT_FLAG (msg, NL80211_WOWLAN_TRIG_DISCONNECT);
	if (NM_FLAGS_HAS (wowl, NM_SETTING_WIRELESS_WAKE_ON_WLAN_MAGIC))
		NLA_PUT_FLAG (msg, NL80211_WOWLAN_TRIG_MAGIC_PKT);
	if (NM_FLAGS_HAS (wowl, NM_SETTING_WIRELESS_WAKE_ON_WLAN_GTK_REKEY_FAILURE))
		NLA_PUT_FLAG (msg, NL80211_WOWLAN_TRIG_GTK_REKEY_FAILURE);
	if (NM_FLAGS_HAS (wowl, NM_SETTING_WIRELESS_WAKE_ON_WLAN_EAP_IDENTITY_REQUEST))
		NLA_PUT_FLAG (msg, NL80211_WOWLAN_TRIG_EAP_IDENT_REQUEST);
	if (NM_FLAGS_HAS (wowl, NM_SETTING_WIRELESS_WAKE_ON_WLAN_4WAY_HANDSHAKE))
		NLA_PUT_FLAG (msg, NL80211_WOWLAN_TRIG_4WAY_HANDSHAKE);
	if (NM_FLAGS_HAS (wowl, NM_SETTING_WIRELESS_WAKE_ON_WLAN_RFKILL_RELEASE))
		NLA_PUT_FLAG (msg, NL80211_WOWLAN_TRIG_RFKILL_RELEASE);

	nla_nest_end(msg, triggers);

	err = nl80211_send_and_recv (nl80211, msg, NULL, NULL);
	return err ? FALSE : TRUE;

nla_put_failure:
	return FALSE;
}

/* @divisor: pass what value @xbm should be divided by to get dBm */
static guint32
nl80211_xbm_to_percent (gint32 xbm, guint32 divisor)
{
#define NOISE_FLOOR_DBM  -90
#define SIGNAL_MAX_DBM   -20

	xbm /= divisor;
	xbm = CLAMP (xbm, NOISE_FLOOR_DBM, SIGNAL_MAX_DBM);

	return 100 - 70 * (((float) SIGNAL_MAX_DBM - (float) xbm) /
			   ((float) SIGNAL_MAX_DBM - (float) NOISE_FLOOR_DBM));
}

struct nl80211_bss_info {
	guint32 freq;
	guint8 bssid[ETH_ALEN];
	guint8 ssid[32];
	guint32 ssid_len;
	guint32 beacon_signal;
	gboolean valid;
};

#define WLAN_EID_SSID 0

static void
find_ssid (guint8 *ies, guint32 ies_len,
           guint8 **ssid, guint32 *ssid_len)
{
	*ssid = NULL;
	*ssid_len = 0;

	while (ies_len > 2 && ies[0] != WLAN_EID_SSID) {
		ies_len -= ies[1] + 2;
		ies += ies[1] + 2;
	}
	if (ies_len < 2)
		return;
	if (ies_len < 2 + ies[1])
		return;

	*ssid_len = ies[1];
	*ssid = ies + 2;
}

static int
nl80211_bss_dump_handler (struct nl_msg *msg, void *arg)
{
	struct nl80211_bss_info *info = arg;
	struct genlmsghdr *gnlh = nlmsg_data (nlmsg_hdr (msg));
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct nlattr *bss[NL80211_BSS_MAX + 1];
	static const struct nla_policy bss_policy[NL80211_BSS_MAX + 1] = {
		[NL80211_BSS_TSF] = { .type = NLA_U64 },
		[NL80211_BSS_FREQUENCY] = { .type = NLA_U32 },
		[NL80211_BSS_BSSID] = { },
		[NL80211_BSS_BEACON_INTERVAL] = { .type = NLA_U16 },
		[NL80211_BSS_CAPABILITY] = { .type = NLA_U16 },
		[NL80211_BSS_INFORMATION_ELEMENTS] = { },
		[NL80211_BSS_SIGNAL_MBM] = { .type = NLA_U32 },
		[NL80211_BSS_SIGNAL_UNSPEC] = { .type = NLA_U8 },
		[NL80211_BSS_STATUS] = { .type = NLA_U32 },
	};
	guint32 status;

	if (nla_parse (tb, NL80211_ATTR_MAX, genlmsg_attrdata (gnlh, 0),
	               genlmsg_attrlen (gnlh, 0), NULL) < 0)
		return NL_SKIP;

	if (tb[NL80211_ATTR_BSS] == NULL)
		return NL_SKIP;

	if (nla_parse_nested (bss, NL80211_BSS_MAX,
	                      tb[NL80211_ATTR_BSS],
	                      bss_policy))
		return NL_SKIP;

	if (bss[NL80211_BSS_STATUS] == NULL)
		return NL_SKIP;

	status = nla_get_u32 (bss[NL80211_BSS_STATUS]);

	if (status != NL80211_BSS_STATUS_ASSOCIATED &&
	    status != NL80211_BSS_STATUS_IBSS_JOINED)
		return NL_SKIP;

	if (bss[NL80211_BSS_BSSID] == NULL)
		return NL_SKIP;
	memcpy (info->bssid, nla_data (bss[NL80211_BSS_BSSID]), ETH_ALEN);

	if (bss[NL80211_BSS_FREQUENCY])
		info->freq = nla_get_u32 (bss[NL80211_BSS_FREQUENCY]);

	if (bss[NL80211_BSS_SIGNAL_UNSPEC])
		info->beacon_signal =
			nla_get_u8 (bss[NL80211_BSS_SIGNAL_UNSPEC]);

	if (bss[NL80211_BSS_SIGNAL_MBM])
		info->beacon_signal =
			nl80211_xbm_to_percent (nla_get_u32 (bss[NL80211_BSS_SIGNAL_MBM]), 100);

	if (bss[NL80211_BSS_INFORMATION_ELEMENTS]) {
		guint8 *ssid;
		guint32 ssid_len;

		find_ssid (nla_data (bss[NL80211_BSS_INFORMATION_ELEMENTS]),
			  nla_len (bss[NL80211_BSS_INFORMATION_ELEMENTS]),
			  &ssid, &ssid_len);
		if (ssid && ssid_len && ssid_len <= sizeof (info->ssid)) {
			memcpy (info->ssid, ssid, ssid_len);
			info->ssid_len = ssid_len;
		}
	}

	info->valid = TRUE;

	return NL_SKIP;
}

static void
nl80211_get_bss_info (WifiDataNl80211 *nl80211,
                      struct nl80211_bss_info *bss_info)
{
	nm_auto_nlmsg struct nl_msg *msg = NULL;

	memset (bss_info, 0, sizeof (*bss_info));

	msg = nl80211_alloc_msg (nl80211, NL80211_CMD_GET_SCAN, NLM_F_DUMP);

	nl80211_send_and_recv (nl80211, msg, nl80211_bss_dump_handler, bss_info);
}

static guint32
wifi_nl80211_get_freq (WifiData *data)
{
	WifiDataNl80211 *nl80211 = (WifiDataNl80211 *) data;
	struct nl80211_bss_info bss_info;

	nl80211_get_bss_info (nl80211, &bss_info);

	return bss_info.freq;
}

static guint32
wifi_nl80211_find_freq (WifiData *data, const guint32 *freqs)
{
	WifiDataNl80211 *nl80211 = (WifiDataNl80211 *) data;
	int i;

	for (i = 0; i < nl80211->num_freqs; i++) {
		while (*freqs) {
			if (nl80211->freqs[i] == *freqs)
				return *freqs;
			freqs++;
		}
	}
	return 0;
}

static gboolean
wifi_nl80211_get_bssid (WifiData *data, guint8 *out_bssid)
{
	WifiDataNl80211 *nl80211 = (WifiDataNl80211 *) data;
	struct nl80211_bss_info bss_info;

	nl80211_get_bss_info (nl80211, &bss_info);

	if (bss_info.valid)
		memcpy (out_bssid, bss_info.bssid, ETH_ALEN);

	return bss_info.valid;
}

struct nl80211_station_info {
	guint32 txrate;
	gboolean txrate_valid;
	guint8 signal;
	gboolean signal_valid;
};

static int
nl80211_station_handler (struct nl_msg *msg, void *arg)
{
	struct nl80211_station_info *info = arg;
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data (nlmsg_hdr (msg));
	struct nlattr *sinfo[NL80211_STA_INFO_MAX + 1];
	struct nlattr *rinfo[NL80211_RATE_INFO_MAX + 1];
	static const struct nla_policy stats_policy[NL80211_STA_INFO_MAX + 1] = {
		[NL80211_STA_INFO_INACTIVE_TIME] = { .type = NLA_U32 },
		[NL80211_STA_INFO_RX_BYTES] = { .type = NLA_U32 },
		[NL80211_STA_INFO_TX_BYTES] = { .type = NLA_U32 },
		[NL80211_STA_INFO_RX_PACKETS] = { .type = NLA_U32 },
		[NL80211_STA_INFO_TX_PACKETS] = { .type = NLA_U32 },
		[NL80211_STA_INFO_SIGNAL] = { .type = NLA_U8 },
		[NL80211_STA_INFO_TX_BITRATE] = { .type = NLA_NESTED },
		[NL80211_STA_INFO_LLID] = { .type = NLA_U16 },
		[NL80211_STA_INFO_PLID] = { .type = NLA_U16 },
		[NL80211_STA_INFO_PLINK_STATE] = { .type = NLA_U8 },
	};

	static const struct nla_policy rate_policy[NL80211_RATE_INFO_MAX + 1] = {
		[NL80211_RATE_INFO_BITRATE] = { .type = NLA_U16 },
		[NL80211_RATE_INFO_MCS] = { .type = NLA_U8 },
		[NL80211_RATE_INFO_40_MHZ_WIDTH] = { .type = NLA_FLAG },
		[NL80211_RATE_INFO_SHORT_GI] = { .type = NLA_FLAG },
	};

	if (nla_parse (tb, NL80211_ATTR_MAX, genlmsg_attrdata (gnlh, 0),
	               genlmsg_attrlen (gnlh, 0), NULL) < 0)
		return NL_SKIP;

	if (tb[NL80211_ATTR_STA_INFO] == NULL)
		return NL_SKIP;

	if (nla_parse_nested (sinfo, NL80211_STA_INFO_MAX,
	                      tb[NL80211_ATTR_STA_INFO],
	                      stats_policy))
		return NL_SKIP;

	if (sinfo[NL80211_STA_INFO_TX_BITRATE] == NULL)
		return NL_SKIP;

	if (nla_parse_nested (rinfo, NL80211_RATE_INFO_MAX,
	                      sinfo[NL80211_STA_INFO_TX_BITRATE],
	                      rate_policy))
		return NL_SKIP;

	if (rinfo[NL80211_RATE_INFO_BITRATE] == NULL)
		return NL_SKIP;

	/* convert from nl80211's units of 100kbps to NM's kbps */
	info->txrate = nla_get_u16 (rinfo[NL80211_RATE_INFO_BITRATE]) * 100;
	info->txrate_valid = TRUE;

	if (sinfo[NL80211_STA_INFO_SIGNAL] != NULL) {
		info->signal = nl80211_xbm_to_percent ((gint8) nla_get_u8 (sinfo[NL80211_STA_INFO_SIGNAL]), 1);
		info->signal_valid = TRUE;
	}

	return NL_SKIP;
}

static void
nl80211_get_ap_info (WifiDataNl80211 *nl80211,
                     struct nl80211_station_info *sta_info)
{
	nm_auto_nlmsg struct nl_msg *msg = NULL;
	struct nl80211_bss_info bss_info;

	memset (sta_info, 0, sizeof (*sta_info));

	nl80211_get_bss_info (nl80211, &bss_info);
	if (!bss_info.valid)
		return;

	msg = nl80211_alloc_msg (nl80211, NL80211_CMD_GET_STATION, 0);
	if (msg) {
		NLA_PUT (msg, NL80211_ATTR_MAC, ETH_ALEN, bss_info.bssid);

		nl80211_send_and_recv (nl80211, msg, nl80211_station_handler, sta_info);
		if (!sta_info->signal_valid) {
			/* Fall back to bss_info signal quality (both are in percent) */
			sta_info->signal = bss_info.beacon_signal;
		}
	}

	return;

nla_put_failure:
	return;
}

static guint32
wifi_nl80211_get_rate (WifiData *data)
{
	WifiDataNl80211 *nl80211 = (WifiDataNl80211 *) data;
	struct nl80211_station_info sta_info;

	nl80211_get_ap_info (nl80211, &sta_info);

	return sta_info.txrate;
}

static int
wifi_nl80211_get_qual (WifiData *data)
{
	WifiDataNl80211 *nl80211 = (WifiDataNl80211 *) data;
	struct nl80211_station_info sta_info;

	nl80211_get_ap_info (nl80211, &sta_info);
	return sta_info.signal;
}

static gboolean
wifi_nl80211_indicate_addressing_running (WifiData *data, gboolean running)
{
	WifiDataNl80211 *nl80211 = (WifiDataNl80211 *) data;
	nm_auto_nlmsg struct nl_msg *msg = NULL;
	int err;

	msg = nl80211_alloc_msg (nl80211,
	                         running
	                           ? 98 /* NL80211_CMD_CRIT_PROTOCOL_START */
	                           : 99 /* NL80211_CMD_CRIT_PROTOCOL_STOP */,
	                         0);
	/* Despite the DHCP name, we're using this for any type of IP addressing,
	 * DHCPv4, DHCPv6, and IPv6 SLAAC.
	 */
	NLA_PUT_U16 (msg,
	             179 /* NL80211_ATTR_CRIT_PROT_ID */,
	             1 /* NL80211_CRIT_PROTO_DHCP */);
	if (running) {
		/* Give DHCP 5 seconds to complete */
		NLA_PUT_U16 (msg,
		             180 /* NL80211_ATTR_MAX_CRIT_PROT_DURATION */,
		             5000);
	}

	err = nl80211_send_and_recv (nl80211, msg, NULL, NULL);
	return err >= 0;

nla_put_failure:
	return FALSE;
}

struct nl80211_wowlan_info {
	gboolean enabled;
};

static int
nl80211_wowlan_handler (struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data (nlmsg_hdr (msg));
	struct nl80211_wowlan_info *info = arg;

	info->enabled = FALSE;

	if (nla_parse (tb, NL80211_ATTR_MAX, genlmsg_attrdata (gnlh, 0),
	               genlmsg_attrlen (gnlh, 0), NULL) < 0)
		return NL_SKIP;

	if (tb[NL80211_ATTR_WOWLAN_TRIGGERS])
		info->enabled = TRUE;

	return NL_SKIP;
}

static gboolean
wifi_nl80211_get_wowlan (WifiData *data)
{
	WifiDataNl80211 *nl80211 = (WifiDataNl80211 *) data;
	nm_auto_nlmsg struct nl_msg *msg = NULL;
	struct nl80211_wowlan_info info;

	if (!nl80211->can_wowlan)
		return FALSE;

	msg = nl80211_alloc_msg (nl80211, NL80211_CMD_GET_WOWLAN, 0);
	nl80211_send_and_recv (nl80211, msg, nl80211_wowlan_handler, &info);
	return info.enabled;
}

struct nl80211_device_info {
	int phy;
	guint32 *freqs;
	int num_freqs;
	guint32 caps;
	gboolean can_scan;
	gboolean can_scan_ssid;
	gboolean supported;
	gboolean success;
	gboolean can_wowlan;
};

#define WLAN_CIPHER_SUITE_USE_GROUP 0x000FAC00
#define WLAN_CIPHER_SUITE_WEP40     0x000FAC01
#define WLAN_CIPHER_SUITE_TKIP      0x000FAC02
#define WLAN_CIPHER_SUITE_CCMP      0x000FAC04
#define WLAN_CIPHER_SUITE_WEP104    0x000FAC05
#define WLAN_CIPHER_SUITE_AES_CMAC  0x000FAC06
#define WLAN_CIPHER_SUITE_GCMP      0x000FAC08
#define WLAN_CIPHER_SUITE_SMS4      0x00147201

static int nl80211_wiphy_info_handler (struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data (nlmsg_hdr (msg));
	struct nl80211_device_info *info = arg;
	struct nlattr *tb_band[NL80211_BAND_ATTR_MAX + 1];
	struct nlattr *tb_freq[NL80211_FREQUENCY_ATTR_MAX + 1];
	struct nlattr *nl_band;
	struct nlattr *nl_freq;
	int rem_freq;
	int rem_band;
	int freq_idx;
	static const struct nla_policy freq_policy[NL80211_FREQUENCY_ATTR_MAX + 1] = {
		[NL80211_FREQUENCY_ATTR_FREQ] = { .type = NLA_U32 },
		[NL80211_FREQUENCY_ATTR_DISABLED] = { .type = NLA_FLAG },
#ifdef NL80211_FREQUENCY_ATTR_NO_IR
		[NL80211_FREQUENCY_ATTR_NO_IR] = { .type = NLA_FLAG },
#else
		[NL80211_FREQUENCY_ATTR_PASSIVE_SCAN] = { .type = NLA_FLAG },
		[NL80211_FREQUENCY_ATTR_NO_IBSS] = { .type = NLA_FLAG },
#endif
		[NL80211_FREQUENCY_ATTR_RADAR] = { .type = NLA_FLAG },
		[NL80211_FREQUENCY_ATTR_MAX_TX_POWER] = { .type = NLA_U32 },
	};
#ifdef NL80211_FREQUENCY_ATTR_NO_IR
	G_STATIC_ASSERT (NL80211_FREQUENCY_ATTR_PASSIVE_SCAN == NL80211_FREQUENCY_ATTR_NO_IR && NL80211_FREQUENCY_ATTR_NO_IBSS == NL80211_FREQUENCY_ATTR_NO_IR);
#else
	G_STATIC_ASSERT (NL80211_FREQUENCY_ATTR_PASSIVE_SCAN != NL80211_FREQUENCY_ATTR_NO_IBSS);
#endif

	if (nla_parse (tb, NL80211_ATTR_MAX, genlmsg_attrdata (gnlh, 0),
	               genlmsg_attrlen (gnlh, 0), NULL) < 0)
		return NL_SKIP;

	if (   tb[NL80211_ATTR_WIPHY] == NULL
	    || tb[NL80211_ATTR_WIPHY_BANDS] == NULL)
		return NL_SKIP;

	info->phy = nla_get_u32 (tb[NL80211_ATTR_WIPHY]);

	if (tb[NL80211_ATTR_MAX_NUM_SCAN_SSIDS]) {
		info->can_scan_ssid =
			nla_get_u8 (tb[NL80211_ATTR_MAX_NUM_SCAN_SSIDS]) > 0;
	} else {
		/* old kernel that only had mac80211, so assume it can */
		info->can_scan_ssid = TRUE;
	}

	if (tb[NL80211_ATTR_SUPPORTED_COMMANDS]) {
		struct nlattr *nl_cmd;
		int i;

		nla_for_each_nested (nl_cmd, tb[NL80211_ATTR_SUPPORTED_COMMANDS], i) {
			switch (nla_get_u32 (nl_cmd)) {
			case NL80211_CMD_TRIGGER_SCAN:
				info->can_scan = TRUE;
				break;
			case NL80211_CMD_CONNECT:
			case NL80211_CMD_AUTHENTICATE:
				/* Only devices that support CONNECT or AUTH actually support
				 * 802.11, unlike say ipw2x00 (up to at least kernel 3.4) which
				 * has minimal info support, but no actual command support.
				 * This check mirrors what wpa_supplicant does to determine
				 * whether or not to use the nl80211 driver.
				 */
				info->supported = TRUE;
				break;
			default:
				break;
			}
		}
	}

	/* Find number of supported frequencies */
	info->num_freqs = 0;

	nla_for_each_nested (nl_band, tb[NL80211_ATTR_WIPHY_BANDS], rem_band) {
		if (nla_parse_nested (tb_band, NL80211_BAND_ATTR_MAX, nl_band,
		                      NULL) < 0)
			return NL_SKIP;

		nla_for_each_nested (nl_freq, tb_band[NL80211_BAND_ATTR_FREQS],
		                     rem_freq) {
			if (nla_parse_nested (tb_freq, NL80211_FREQUENCY_ATTR_MAX,
			                      nl_freq, freq_policy) < 0)
				continue;

			if (!tb_freq[NL80211_FREQUENCY_ATTR_FREQ])
				continue;

			info->num_freqs++;
		}
	}

	/* Read supported frequencies */
	info->freqs = g_malloc0 (sizeof (guint32) * info->num_freqs);

	freq_idx = 0;
	nla_for_each_nested (nl_band, tb[NL80211_ATTR_WIPHY_BANDS], rem_band) {
		if (nla_parse_nested (tb_band, NL80211_BAND_ATTR_MAX, nl_band,
		                      NULL) < 0)
			return NL_SKIP;

		nla_for_each_nested (nl_freq, tb_band[NL80211_BAND_ATTR_FREQS],
		                    rem_freq) {
			if (nla_parse_nested (tb_freq, NL80211_FREQUENCY_ATTR_MAX,
			                      nl_freq, freq_policy) < 0)
				continue;

			if (!tb_freq[NL80211_FREQUENCY_ATTR_FREQ])
				continue;

			info->freqs[freq_idx] =
				nla_get_u32 (tb_freq[NL80211_FREQUENCY_ATTR_FREQ]);

			info->caps |= NM_WIFI_DEVICE_CAP_FREQ_VALID;

			if (info->freqs[freq_idx] > 2400 && info->freqs[freq_idx] < 2500)
				info->caps |= NM_WIFI_DEVICE_CAP_FREQ_2GHZ;
			if (info->freqs[freq_idx] > 4900 && info->freqs[freq_idx] < 6000)
				info->caps |= NM_WIFI_DEVICE_CAP_FREQ_5GHZ;

			freq_idx++;
		}
	}

	/* Read security/encryption support */
	if (tb[NL80211_ATTR_CIPHER_SUITES]) {
		int num;
		int i;
		__u32 *ciphers = nla_data (tb[NL80211_ATTR_CIPHER_SUITES]);

		num = nla_len (tb[NL80211_ATTR_CIPHER_SUITES]) / sizeof (__u32);
		for (i = 0; i < num; i++) {
			switch (ciphers[i]) {
			case WLAN_CIPHER_SUITE_WEP40:
				info->caps |= NM_WIFI_DEVICE_CAP_CIPHER_WEP40;
				break;
			case WLAN_CIPHER_SUITE_WEP104:
				info->caps |= NM_WIFI_DEVICE_CAP_CIPHER_WEP104;
				break;
			case WLAN_CIPHER_SUITE_TKIP:
				info->caps |= (NM_WIFI_DEVICE_CAP_CIPHER_TKIP |
				               NM_WIFI_DEVICE_CAP_WPA);
				break;
			case WLAN_CIPHER_SUITE_CCMP:
				info->caps |= (NM_WIFI_DEVICE_CAP_CIPHER_CCMP |
				               NM_WIFI_DEVICE_CAP_RSN);
				break;
			case WLAN_CIPHER_SUITE_AES_CMAC:
			case WLAN_CIPHER_SUITE_GCMP:
			case WLAN_CIPHER_SUITE_SMS4:
				break;
			default:
				_LOGD (LOGD_PLATFORM | LOGD_WIFI,
				       "don't know the meaning of NL80211_ATTR_CIPHER_SUITE %#8.8x.",
				       ciphers[i]);
				break;
			}
		}
	}

	if (tb[NL80211_ATTR_SUPPORTED_IFTYPES]) {
		struct nlattr *nl_mode;
		int i;

		nla_for_each_nested (nl_mode, tb[NL80211_ATTR_SUPPORTED_IFTYPES], i) {
			if (nla_type (nl_mode) == NL80211_IFTYPE_AP)
				info->caps |= NM_WIFI_DEVICE_CAP_AP;
			else if (nla_type (nl_mode) == NL80211_IFTYPE_ADHOC)
				info->caps |= NM_WIFI_DEVICE_CAP_ADHOC;
		}
	}

	if (tb[NL80211_ATTR_WOWLAN_TRIGGERS_SUPPORTED])
		info->can_wowlan = TRUE;

	info->success = TRUE;

	return NL_SKIP;
}

WifiData *
wifi_nl80211_init (int ifindex)
{
	static const WifiDataClass klass = {
		.struct_size = sizeof (WifiDataNl80211),
		.get_mode = wifi_nl80211_get_mode,
		.set_mode = wifi_nl80211_set_mode,
		.set_powersave = wifi_nl80211_set_powersave,
		.set_wake_on_wlan = wifi_nl80211_set_wake_on_wlan,
		.get_freq = wifi_nl80211_get_freq,
		.find_freq = wifi_nl80211_find_freq,
		.get_bssid = wifi_nl80211_get_bssid,
		.get_rate = wifi_nl80211_get_rate,
		.get_qual = wifi_nl80211_get_qual,
		.get_wowlan = wifi_nl80211_get_wowlan,
		.indicate_addressing_running = wifi_nl80211_indicate_addressing_running,
		.deinit = wifi_nl80211_deinit,
	};
	WifiDataNl80211 *nl80211;
	nm_auto_nlmsg struct nl_msg *msg = NULL;
	struct nl80211_device_info device_info = {};
	char ifname[IFNAMSIZ];

	if (!nmp_utils_if_indextoname (ifindex, ifname)) {
		_LOGW (LOGD_PLATFORM | LOGD_WIFI,
		       "can't determine interface name for ifindex %d", ifindex);
		nm_sprintf_buf (ifname, "if %d", ifindex);
	}

	nl80211 = wifi_data_new (&klass, ifindex);

	nl80211->nl_sock = nl_socket_alloc ();
	if (nl80211->nl_sock == NULL)
		goto error;

	if (nl_connect (nl80211->nl_sock, NETLINK_GENERIC))
		goto error;

	nl80211->id = genl_ctrl_resolve (nl80211->nl_sock, "nl80211");
	if (nl80211->id < 0) {
		_LOGD (LOGD_WIFI, "genl_ctrl_resolve: failed to resolve \"nl80211\"");
		goto error;
	}

	nl80211->phy = -1;

	msg = nl80211_alloc_msg (nl80211, NL80211_CMD_GET_WIPHY, 0);

	if (nl80211_send_and_recv (nl80211, msg, nl80211_wiphy_info_handler,
	                           &device_info) < 0) {
		_LOGD (LOGD_PLATFORM | LOGD_WIFI,
		       "(%s): NL80211_CMD_GET_WIPHY request failed",
		       ifname);
		goto error;
	}

	if (!device_info.success) {
		_LOGD (LOGD_PLATFORM | LOGD_WIFI,
		       "(%s): NL80211_CMD_GET_WIPHY request indicated failure",
		       ifname);
		goto error;
	}

	if (!device_info.supported) {
		_LOGD (LOGD_PLATFORM | LOGD_WIFI,
		       "(%s): driver does not fully support nl80211, falling back to WEXT",
		       ifname);
		goto error;
	}

	if (!device_info.can_scan_ssid) {
		_LOGE (LOGD_PLATFORM | LOGD_WIFI,
		       "(%s): driver does not support SSID scans",
		       ifname);
		goto error;
	}

	if (device_info.num_freqs == 0 || device_info.freqs == NULL) {
		nm_log_err (LOGD_PLATFORM | LOGD_WIFI,
		            "(%s): driver reports no supported frequencies",
		            ifname);
		goto error;
	}

	if (device_info.caps == 0) {
		_LOGE (LOGD_PLATFORM | LOGD_WIFI,
		       "(%s): driver doesn't report support of any encryption",
		       ifname);
		goto error;
	}

	nl80211->phy = device_info.phy;
	nl80211->freqs = device_info.freqs;
	nl80211->num_freqs = device_info.num_freqs;
	nl80211->parent.caps = device_info.caps;
	nl80211->can_wowlan = device_info.can_wowlan;

	_LOGI (LOGD_PLATFORM | LOGD_WIFI,
	       "(%s): using nl80211 for WiFi device control",
	       ifname);
	return (WifiData *) nl80211;

error:
	wifi_utils_unref ((WifiData *) nl80211);
	return NULL;
}

