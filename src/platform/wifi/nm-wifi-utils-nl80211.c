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
 * Copyright (C) 2005 - 2018 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 * Copyright (C) 2011 Intel Corporation. All rights reserved.
 */

#include "nm-default.h"

#include "nm-wifi-utils-nl80211.h"

#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <unistd.h>
#include <linux/nl80211.h>
#include <linux/if.h>

#include "platform/nm-netlink.h"
#include "nm-wifi-utils-private.h"
#include "platform/nm-platform.h"
#include "platform/nm-platform-utils.h"
#include "nm-utils.h"

#define _NMLOG_PREFIX_NAME      "wifi-nl80211"
#define _NMLOG_DOMAIN           LOGD_PLATFORM | LOGD_WIFI
#define _NMLOG(level, ...) \
	G_STMT_START { \
		char _ifname_buf[IFNAMSIZ]; \
		const char *_ifname = self ? nmp_utils_if_indextoname (self->parent.ifindex, _ifname_buf) : NULL; \
		\
		nm_log ((level), _NMLOG_DOMAIN, _ifname ?: NULL, NULL, \
		        "%s%s%s%s: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
		        _NMLOG_PREFIX_NAME, \
		        NM_PRINT_FMT_QUOTED (_ifname, " (", _ifname, ")", "") \
		        _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
	} G_STMT_END

typedef struct {
	NMWifiUtils parent;
	struct nl_sock *nl_sock;
	guint32 *freqs;
	int id;
	int num_freqs;
	int phy;
	bool can_wowlan:1;
} NMWifiUtilsNl80211;

typedef struct {
	NMWifiUtilsClass parent;
} NMWifiUtilsNl80211Class;

G_DEFINE_TYPE (NMWifiUtilsNl80211, nm_wifi_utils_nl80211, NM_TYPE_WIFI_UTILS)

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
	g_return_val_if_reached (NULL);
}

static struct nl_msg *
nl80211_alloc_msg (NMWifiUtilsNl80211 *self, guint32 cmd, guint32 flags)
{
	return _nl80211_alloc_msg (self->id, self->parent.ifindex, self->phy, cmd, flags);
}

static int
nl80211_send_and_recv (NMWifiUtilsNl80211 *self,
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

	err = nl_send_auto (self->nl_sock, msg);
	if (err < 0)
		return err;

	/* Loop until one of our NL callbacks says we're done; on success
	 * done will be 1, on error it will be < 0.
	 */
	while (!done) {
		err = nl_recvmsgs (self->nl_sock, &cb);
		if (err < 0 && err != -EAGAIN) {
			/* Kernel scan list can change while we are dumping it, as new scan
			 * results from H/W can arrive. BSS info is assured to be consistent
			 * and we don't need consistent view of whole scan list. Hence do
			 * not warn on DUMP_INTR error for get scan command.
			 */
			if (err == -NME_NL_DUMP_INTR &&
			    genlmsg_hdr (nlmsg_hdr (msg))->cmd == NL80211_CMD_GET_SCAN)
				break;

			_LOGW ("nl_recvmsgs() error: (%d) %s", err, nm_strerror (err));
			break;
		}
	}

	if (err >= 0 && done < 0)
		err = done;
	return err;
}

static void
dispose (GObject *object)
{
	NMWifiUtilsNl80211 *self = NM_WIFI_UTILS_NL80211 (object);

	g_clear_pointer (&self->freqs, g_free);
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

	if (nla_parse_arr (tb,
	                   genlmsg_attrdata (gnlh, 0),
	                   genlmsg_attrlen (gnlh, 0),
	                   NULL) < 0)
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
	case NL80211_IFTYPE_MESH_POINT:
		info->mode = NM_802_11_MODE_MESH;
		break;
	}

	return NL_SKIP;
}

static NM80211Mode
wifi_nl80211_get_mode (NMWifiUtils *data)
{
	NMWifiUtilsNl80211 *self = (NMWifiUtilsNl80211 *) data;
	struct nl80211_iface_info iface_info = {
		.mode = NM_802_11_MODE_UNKNOWN,
	};
	nm_auto_nlmsg struct nl_msg *msg = NULL;

	msg = nl80211_alloc_msg (self, NL80211_CMD_GET_INTERFACE, 0);

	if (nl80211_send_and_recv (self, msg, nl80211_iface_info_handler,
	                           &iface_info) < 0)
		return NM_802_11_MODE_UNKNOWN;

	return iface_info.mode;
}

static gboolean
wifi_nl80211_set_mode (NMWifiUtils *data, const NM80211Mode mode)
{
	NMWifiUtilsNl80211 *self = (NMWifiUtilsNl80211 *) data;
	nm_auto_nlmsg struct nl_msg *msg = NULL;
	int err;

	msg = nl80211_alloc_msg (self, NL80211_CMD_SET_INTERFACE, 0);

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
	case NM_802_11_MODE_MESH:
		NLA_PUT_U32 (msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_MESH_POINT);
		break;
	default:
		g_assert_not_reached ();
	}

	err = nl80211_send_and_recv (self, msg, NULL, NULL);
	return err >= 0;

nla_put_failure:
	g_return_val_if_reached (FALSE);
}

static gboolean
wifi_nl80211_set_powersave (NMWifiUtils *data, guint32 powersave)
{
	NMWifiUtilsNl80211 *self = (NMWifiUtilsNl80211 *) data;
	nm_auto_nlmsg struct nl_msg *msg = NULL;
	int err;

	msg = nl80211_alloc_msg (self, NL80211_CMD_SET_POWER_SAVE, 0);
	NLA_PUT_U32 (msg, NL80211_ATTR_PS_STATE,
	             powersave == 1 ? NL80211_PS_ENABLED : NL80211_PS_DISABLED);
	err = nl80211_send_and_recv (self, msg, NULL, NULL);
	return err >= 0;

nla_put_failure:
	g_return_val_if_reached (FALSE);
}

static int
nl80211_get_wake_on_wlan_handler (struct nl_msg *msg, void *arg)
{
	NMSettingWirelessWakeOnWLan *wowl = arg;
	struct nlattr *attrs[NL80211_ATTR_MAX + 1];
	struct nlattr *trig[NUM_NL80211_WOWLAN_TRIG];
	struct genlmsghdr *gnlh = nlmsg_data (nlmsg_hdr (msg));

	nla_parse_arr (attrs,
	               genlmsg_attrdata (gnlh, 0),
	               genlmsg_attrlen (gnlh, 0),
	               NULL);

	if (!attrs[NL80211_ATTR_WOWLAN_TRIGGERS])
		return NL_SKIP;

	nla_parse_arr (trig,
	               nla_data (attrs[NL80211_ATTR_WOWLAN_TRIGGERS]),
	               nla_len (attrs[NL80211_ATTR_WOWLAN_TRIGGERS]),
	               NULL);

	*wowl = NM_SETTING_WIRELESS_WAKE_ON_WLAN_NONE;
	if (trig[NL80211_WOWLAN_TRIG_ANY])
		*wowl |= NM_SETTING_WIRELESS_WAKE_ON_WLAN_ANY;
	if (trig[NL80211_WOWLAN_TRIG_DISCONNECT])
		*wowl |= NM_SETTING_WIRELESS_WAKE_ON_WLAN_DISCONNECT;
	if (trig[NL80211_WOWLAN_TRIG_MAGIC_PKT])
		*wowl |= NM_SETTING_WIRELESS_WAKE_ON_WLAN_MAGIC;
	if (trig[NL80211_WOWLAN_TRIG_GTK_REKEY_FAILURE])
		*wowl |= NM_SETTING_WIRELESS_WAKE_ON_WLAN_GTK_REKEY_FAILURE;
	if (trig[NL80211_WOWLAN_TRIG_EAP_IDENT_REQUEST])
		*wowl |= NM_SETTING_WIRELESS_WAKE_ON_WLAN_EAP_IDENTITY_REQUEST;
	if (trig[NL80211_WOWLAN_TRIG_4WAY_HANDSHAKE])
		*wowl |= NM_SETTING_WIRELESS_WAKE_ON_WLAN_4WAY_HANDSHAKE;
	if (trig[NL80211_WOWLAN_TRIG_RFKILL_RELEASE])
		*wowl |= NM_SETTING_WIRELESS_WAKE_ON_WLAN_RFKILL_RELEASE;
	if (trig[NL80211_WOWLAN_TRIG_TCP_CONNECTION])
		*wowl |= NM_SETTING_WIRELESS_WAKE_ON_WLAN_TCP;

	return NL_SKIP;
}

static NMSettingWirelessWakeOnWLan
wifi_nl80211_get_wake_on_wlan (NMWifiUtils *data)
{
	NMWifiUtilsNl80211 *self = (NMWifiUtilsNl80211 *) data;
	NMSettingWirelessWakeOnWLan wowl = NM_SETTING_WIRELESS_WAKE_ON_WLAN_IGNORE;
	nm_auto_nlmsg struct nl_msg *msg = NULL;

	msg = nl80211_alloc_msg (self, NL80211_CMD_GET_WOWLAN, 0);

	nl80211_send_and_recv (self, msg, nl80211_get_wake_on_wlan_handler, &wowl);

	return wowl;
}

static gboolean
wifi_nl80211_set_wake_on_wlan (NMWifiUtils *data, NMSettingWirelessWakeOnWLan wowl)
{
	NMWifiUtilsNl80211 *self = (NMWifiUtilsNl80211 *) data;
	nm_auto_nlmsg struct nl_msg *msg = NULL;
	struct nlattr *triggers;
	int err;

	if (wowl == NM_SETTING_WIRELESS_WAKE_ON_WLAN_IGNORE)
		return TRUE;

	msg = nl80211_alloc_msg (self, NL80211_CMD_SET_WOWLAN, 0);

	triggers = nla_nest_start (msg, NL80211_ATTR_WOWLAN_TRIGGERS);
	if (!triggers)
		goto nla_put_failure;

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

	nla_nest_end (msg, triggers);

	err = nl80211_send_and_recv (self, msg, NULL, NULL);

	return err >= 0;

nla_put_failure:
	g_return_val_if_reached (FALSE);
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
	static const struct nla_policy bss_policy[] = {
		[NL80211_BSS_TSF]                  = { .type = NLA_U64 },
		[NL80211_BSS_FREQUENCY]            = { .type = NLA_U32 },
		[NL80211_BSS_BSSID]                = { .minlen = ETH_ALEN },
		[NL80211_BSS_BEACON_INTERVAL]      = { .type = NLA_U16 },
		[NL80211_BSS_CAPABILITY]           = { .type = NLA_U16 },
		[NL80211_BSS_INFORMATION_ELEMENTS] = { },
		[NL80211_BSS_SIGNAL_MBM]           = { .type = NLA_U32 },
		[NL80211_BSS_SIGNAL_UNSPEC]        = { .type = NLA_U8 },
		[NL80211_BSS_STATUS]               = { .type = NLA_U32 },
	};
	struct nl80211_bss_info *info = arg;
	struct genlmsghdr *gnlh = nlmsg_data (nlmsg_hdr (msg));
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct nlattr *bss[G_N_ELEMENTS (bss_policy)];
	guint32 status;

	if (nla_parse_arr (tb,
	                   genlmsg_attrdata (gnlh, 0),
	                   genlmsg_attrlen (gnlh, 0),
	                   NULL) < 0)
		return NL_SKIP;

	if (tb[NL80211_ATTR_BSS] == NULL)
		return NL_SKIP;

	if (nla_parse_nested_arr (bss,
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
		info->beacon_signal = nla_get_u8 (bss[NL80211_BSS_SIGNAL_UNSPEC]);

	if (bss[NL80211_BSS_SIGNAL_MBM])
		info->beacon_signal = nl80211_xbm_to_percent (nla_get_u32 (bss[NL80211_BSS_SIGNAL_MBM]), 100);

	if (bss[NL80211_BSS_INFORMATION_ELEMENTS]) {
		guint8 *ssid;
		guint32 ssid_len;

		find_ssid (nla_data (bss[NL80211_BSS_INFORMATION_ELEMENTS]),
		           nla_len (bss[NL80211_BSS_INFORMATION_ELEMENTS]),
		           &ssid,
		           &ssid_len);
		if (   ssid
		    && ssid_len
		    && ssid_len <= sizeof (info->ssid)) {
			memcpy (info->ssid, ssid, ssid_len);
			info->ssid_len = ssid_len;
		}
	}

	info->valid = TRUE;

	return NL_SKIP;
}

static void
nl80211_get_bss_info (NMWifiUtilsNl80211 *self,
                      struct nl80211_bss_info *bss_info)
{
	nm_auto_nlmsg struct nl_msg *msg = NULL;

	memset (bss_info, 0, sizeof (*bss_info));

	msg = nl80211_alloc_msg (self, NL80211_CMD_GET_SCAN, NLM_F_DUMP);

	nl80211_send_and_recv (self, msg, nl80211_bss_dump_handler, bss_info);
}

static guint32
wifi_nl80211_get_freq (NMWifiUtils *data)
{
	NMWifiUtilsNl80211 *self = (NMWifiUtilsNl80211 *) data;
	struct nl80211_bss_info bss_info;

	nl80211_get_bss_info (self, &bss_info);

	return bss_info.freq;
}

static guint32
wifi_nl80211_find_freq (NMWifiUtils *data, const guint32 *freqs)
{
	NMWifiUtilsNl80211 *self = (NMWifiUtilsNl80211 *) data;
	int i;

	for (i = 0; i < self->num_freqs; i++) {
		while (*freqs) {
			if (self->freqs[i] == *freqs)
				return *freqs;
			freqs++;
		}
	}
	return 0;
}

static gboolean
wifi_nl80211_get_bssid (NMWifiUtils *data, guint8 *out_bssid)
{
	NMWifiUtilsNl80211 *self = (NMWifiUtilsNl80211 *) data;
	struct nl80211_bss_info bss_info;

	nl80211_get_bss_info (self, &bss_info);

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
	static const struct nla_policy stats_policy[] = {
		[NL80211_STA_INFO_INACTIVE_TIME] = { .type = NLA_U32 },
		[NL80211_STA_INFO_RX_BYTES]      = { .type = NLA_U32 },
		[NL80211_STA_INFO_TX_BYTES]      = { .type = NLA_U32 },
		[NL80211_STA_INFO_RX_PACKETS]    = { .type = NLA_U32 },
		[NL80211_STA_INFO_TX_PACKETS]    = { .type = NLA_U32 },
		[NL80211_STA_INFO_SIGNAL]        = { .type = NLA_U8 },
		[NL80211_STA_INFO_TX_BITRATE]    = { .type = NLA_NESTED },
		[NL80211_STA_INFO_LLID]          = { .type = NLA_U16 },
		[NL80211_STA_INFO_PLID]          = { .type = NLA_U16 },
		[NL80211_STA_INFO_PLINK_STATE]   = { .type = NLA_U8 },
	};
	static const struct nla_policy rate_policy[] = {
		[NL80211_RATE_INFO_BITRATE]      = { .type = NLA_U16 },
		[NL80211_RATE_INFO_MCS]          = { .type = NLA_U8 },
		[NL80211_RATE_INFO_40_MHZ_WIDTH] = { .type = NLA_FLAG },
		[NL80211_RATE_INFO_SHORT_GI]     = { .type = NLA_FLAG },
	};
	struct nlattr *rinfo[G_N_ELEMENTS (rate_policy)];
	struct nlattr *sinfo[G_N_ELEMENTS (stats_policy)];
	struct nl80211_station_info *info = arg;
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data (nlmsg_hdr (msg));

	if (nla_parse_arr (tb,
	                   genlmsg_attrdata (gnlh, 0),
	                   genlmsg_attrlen (gnlh, 0),
	                   NULL) < 0)
		return NL_SKIP;

	if (tb[NL80211_ATTR_STA_INFO] == NULL)
		return NL_SKIP;

	if (nla_parse_nested_arr (sinfo,
	                          tb[NL80211_ATTR_STA_INFO],
	                          stats_policy))
		return NL_SKIP;

	if (sinfo[NL80211_STA_INFO_TX_BITRATE] == NULL)
		return NL_SKIP;

	if (nla_parse_nested_arr (rinfo,
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
nl80211_get_ap_info (NMWifiUtilsNl80211 *self,
                     struct nl80211_station_info *sta_info)
{
	nm_auto_nlmsg struct nl_msg *msg = NULL;
	struct nl80211_bss_info bss_info;

	memset (sta_info, 0, sizeof (*sta_info));

	nl80211_get_bss_info (self, &bss_info);
	if (!bss_info.valid)
		return;

	msg = nl80211_alloc_msg (self, NL80211_CMD_GET_STATION, 0);
	NLA_PUT (msg, NL80211_ATTR_MAC, ETH_ALEN, bss_info.bssid);

	nl80211_send_and_recv (self, msg, nl80211_station_handler, sta_info);
	if (!sta_info->signal_valid) {
		/* Fall back to bss_info signal quality (both are in percent) */
		sta_info->signal = bss_info.beacon_signal;
	}

	return;

nla_put_failure:
	g_return_if_reached ();
}

static guint32
wifi_nl80211_get_rate (NMWifiUtils *data)
{
	NMWifiUtilsNl80211 *self = (NMWifiUtilsNl80211 *) data;
	struct nl80211_station_info sta_info;

	nl80211_get_ap_info (self, &sta_info);

	return sta_info.txrate;
}

static int
wifi_nl80211_get_qual (NMWifiUtils *data)
{
	NMWifiUtilsNl80211 *self = (NMWifiUtilsNl80211 *) data;
	struct nl80211_station_info sta_info;

	nl80211_get_ap_info (self, &sta_info);
	return sta_info.signal;
}

static gboolean
wifi_nl80211_indicate_addressing_running (NMWifiUtils *data, gboolean running)
{
	NMWifiUtilsNl80211 *self = (NMWifiUtilsNl80211 *) data;
	nm_auto_nlmsg struct nl_msg *msg = NULL;
	int err;

	msg = nl80211_alloc_msg (self,
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

	err = nl80211_send_and_recv (self, msg, NULL, NULL);
	return err >= 0;

nla_put_failure:
	g_return_val_if_reached (FALSE);
}

struct nl80211_device_info {
	NMWifiUtilsNl80211 *self;
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
	static const struct nla_policy freq_policy[] = {
		[NL80211_FREQUENCY_ATTR_FREQ]         = { .type = NLA_U32 },
		[NL80211_FREQUENCY_ATTR_DISABLED]     = { .type = NLA_FLAG },
#ifdef NL80211_FREQUENCY_ATTR_NO_IR
		[NL80211_FREQUENCY_ATTR_NO_IR]        = { .type = NLA_FLAG },
#else
		[NL80211_FREQUENCY_ATTR_PASSIVE_SCAN] = { .type = NLA_FLAG },
		[NL80211_FREQUENCY_ATTR_NO_IBSS]      = { .type = NLA_FLAG },
#endif
		[NL80211_FREQUENCY_ATTR_RADAR]        = { .type = NLA_FLAG },
		[NL80211_FREQUENCY_ATTR_MAX_TX_POWER] = { .type = NLA_U32 },
	};
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data (nlmsg_hdr (msg));
	struct nl80211_device_info *info = arg;
	NMWifiUtilsNl80211 *self = info->self;
	struct nlattr *tb_band[NL80211_BAND_ATTR_MAX + 1];
	struct nlattr *tb_freq[G_N_ELEMENTS (freq_policy)];
	struct nlattr *nl_band;
	struct nlattr *nl_freq;
	int rem_freq;
	int rem_band;
	int freq_idx;

#ifdef NL80211_FREQUENCY_ATTR_NO_IR
	G_STATIC_ASSERT_EXPR (NL80211_FREQUENCY_ATTR_PASSIVE_SCAN == NL80211_FREQUENCY_ATTR_NO_IR && NL80211_FREQUENCY_ATTR_NO_IBSS == NL80211_FREQUENCY_ATTR_NO_IR);
#else
	G_STATIC_ASSERT_EXPR (NL80211_FREQUENCY_ATTR_PASSIVE_SCAN != NL80211_FREQUENCY_ATTR_NO_IBSS);
#endif

	if (nla_parse_arr (tb,
	                   genlmsg_attrdata (gnlh, 0),
	                   genlmsg_attrlen (gnlh, 0),
	                   NULL) < 0)
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
		if (nla_parse_nested_arr (tb_band,
		                          nl_band,
		                          NULL) < 0)
			return NL_SKIP;

		nla_for_each_nested (nl_freq,
		                     tb_band[NL80211_BAND_ATTR_FREQS],
		                     rem_freq) {
			if (nla_parse_nested_arr (tb_freq,
			                          nl_freq,
			                          freq_policy) < 0)
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
		if (nla_parse_nested_arr (tb_band,
		                          nl_band,
		                          NULL) < 0)
			return NL_SKIP;

		nla_for_each_nested (nl_freq, tb_band[NL80211_BAND_ATTR_FREQS],
		                    rem_freq) {
			if (nla_parse_nested_arr (tb_freq,
			                          nl_freq,
			                          freq_policy) < 0)
				continue;

			if (!tb_freq[NL80211_FREQUENCY_ATTR_FREQ])
				continue;

			info->freqs[freq_idx] = nla_get_u32 (tb_freq[NL80211_FREQUENCY_ATTR_FREQ]);

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
		guint32 *ciphers = nla_data (tb[NL80211_ATTR_CIPHER_SUITES]);
		guint i, num;

		num = nla_len (tb[NL80211_ATTR_CIPHER_SUITES]) / sizeof (guint32);
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
				_LOGD ("don't know the meaning of NL80211_ATTR_CIPHER_SUITE %#8.8x.",
				       ciphers[i]);
				break;
			}
		}
	}

	if (tb[NL80211_ATTR_SUPPORTED_IFTYPES]) {
		struct nlattr *nl_mode;
		int i;

		nla_for_each_nested (nl_mode, tb[NL80211_ATTR_SUPPORTED_IFTYPES], i) {
			switch (nla_type (nl_mode)) {
			case NL80211_IFTYPE_AP:         info->caps |= NM_WIFI_DEVICE_CAP_AP;    break;
			case NL80211_IFTYPE_ADHOC:      info->caps |= NM_WIFI_DEVICE_CAP_ADHOC; break;
			case NL80211_IFTYPE_MESH_POINT: info->caps |= NM_WIFI_DEVICE_CAP_MESH;  break;
			}
		}
	}

	if (tb[NL80211_ATTR_WOWLAN_TRIGGERS_SUPPORTED])
		info->can_wowlan = TRUE;

	if (tb[NL80211_ATTR_SUPPORT_IBSS_RSN])
		info->caps |= NM_WIFI_DEVICE_CAP_IBSS_RSN;

	info->success = TRUE;

	return NL_SKIP;
}

static void
nm_wifi_utils_nl80211_init (NMWifiUtilsNl80211 *self)
{
}

static void
nm_wifi_utils_nl80211_class_init (NMWifiUtilsNl80211Class *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMWifiUtilsClass *wifi_utils_class = NM_WIFI_UTILS_CLASS (klass);

	object_class->dispose = dispose;

	wifi_utils_class->get_mode = wifi_nl80211_get_mode;
	wifi_utils_class->set_mode = wifi_nl80211_set_mode;
	wifi_utils_class->set_powersave = wifi_nl80211_set_powersave;
	wifi_utils_class->get_wake_on_wlan = wifi_nl80211_get_wake_on_wlan,
	wifi_utils_class->set_wake_on_wlan = wifi_nl80211_set_wake_on_wlan,
	wifi_utils_class->get_freq = wifi_nl80211_get_freq;
	wifi_utils_class->find_freq = wifi_nl80211_find_freq;
	wifi_utils_class->get_bssid = wifi_nl80211_get_bssid;
	wifi_utils_class->get_rate = wifi_nl80211_get_rate;
	wifi_utils_class->get_qual = wifi_nl80211_get_qual;
	wifi_utils_class->indicate_addressing_running = wifi_nl80211_indicate_addressing_running;
}

NMWifiUtils *
nm_wifi_utils_nl80211_new (int ifindex, struct nl_sock *genl)
{
	gs_unref_object NMWifiUtilsNl80211 *self = NULL;
	nm_auto_nlmsg struct nl_msg *msg = NULL;
	struct nl80211_device_info device_info = { };

	if (!genl)
		return NULL;

	self = g_object_new (NM_TYPE_WIFI_UTILS_NL80211, NULL);

	self->parent.ifindex = ifindex;
	self->nl_sock = genl;

	self->id = genl_ctrl_resolve (self->nl_sock, "nl80211");
	if (self->id < 0) {
		_LOGD ("genl_ctrl_resolve: failed to resolve \"nl80211\"");
		return NULL;
	}

	self->phy = -1;

	msg = nl80211_alloc_msg (self, NL80211_CMD_GET_WIPHY, 0);

	device_info.self = self;
	if (nl80211_send_and_recv (self, msg, nl80211_wiphy_info_handler,
	                           &device_info) < 0) {
		_LOGD ("NL80211_CMD_GET_WIPHY request failed");
		return NULL;
	}

	if (!device_info.success) {
		_LOGD ("NL80211_CMD_GET_WIPHY request indicated failure");
		return NULL;
	}

	if (!device_info.supported) {
		_LOGD ("driver does not fully support nl80211, falling back to WEXT");
		return NULL;
	}

	if (!device_info.can_scan_ssid) {
		_LOGE ("driver does not support SSID scans");
		return NULL;
	}

	if (device_info.num_freqs == 0 || device_info.freqs == NULL) {
		_LOGE ("driver reports no supported frequencies");
		return NULL;
	}

	if (device_info.caps == 0) {
		_LOGE ("driver doesn't report support of any encryption");
		return NULL;
	}

	self->phy = device_info.phy;
	self->freqs = device_info.freqs;
	self->num_freqs = device_info.num_freqs;
	self->parent.caps = device_info.caps;
	self->can_wowlan = device_info.can_wowlan;

	_LOGD ("using nl80211 for Wi-Fi device control");
	return (NMWifiUtils *) g_steal_pointer (&self);
}
