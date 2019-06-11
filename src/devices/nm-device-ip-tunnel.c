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
 * Copyright 2015 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-device-ip-tunnel.h"

#include <netinet/in.h>
#include <linux/if.h>
#include <linux/ip.h>
#include <linux/if_tunnel.h>
#include <linux/ip6_tunnel.h>

#include "nm-device-private.h"
#include "nm-manager.h"
#include "platform/nm-platform.h"
#include "nm-device-factory.h"
#include "nm-core-internal.h"
#include "settings/nm-settings.h"
#include "nm-act-request.h"
#include "nm-ip4-config.h"

#include "nm-device-logging.h"
_LOG_DECLARE_SELF(NMDeviceIPTunnel);

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NMDeviceIPTunnel,
	PROP_MODE,
	PROP_LOCAL,
	PROP_REMOTE,
	PROP_TTL,
	PROP_TOS,
	PROP_PATH_MTU_DISCOVERY,
	PROP_INPUT_KEY,
	PROP_OUTPUT_KEY,
	PROP_ENCAPSULATION_LIMIT,
	PROP_FLOW_LABEL,
	PROP_FLAGS,
);

typedef struct {
	NMIPTunnelMode mode;
	char *local;
	char *remote;
	guint8 ttl;
	guint8 tos;
	gboolean path_mtu_discovery;
	int addr_family;
	char *input_key;
	char *output_key;
	guint8 encap_limit;
	guint32 flow_label;
	NMIPTunnelFlags flags;
} NMDeviceIPTunnelPrivate;

struct _NMDeviceIPTunnel {
	NMDevice parent;
	NMDeviceIPTunnelPrivate _priv;
};

struct _NMDeviceIPTunnelClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDeviceIPTunnel, nm_device_ip_tunnel, NM_TYPE_DEVICE)

#define NM_DEVICE_IP_TUNNEL_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMDeviceIPTunnel, NM_IS_DEVICE_IP_TUNNEL)

/*****************************************************************************/

static guint32
ip6tnl_flags_setting_to_plat (NMIPTunnelFlags flags)
{
	G_STATIC_ASSERT (NM_IP_TUNNEL_FLAG_IP6_IGN_ENCAP_LIMIT    == IP6_TNL_F_IGN_ENCAP_LIMIT);
	G_STATIC_ASSERT (NM_IP_TUNNEL_FLAG_IP6_USE_ORIG_TCLASS    == IP6_TNL_F_USE_ORIG_TCLASS);
	G_STATIC_ASSERT (NM_IP_TUNNEL_FLAG_IP6_USE_ORIG_FLOWLABEL == IP6_TNL_F_USE_ORIG_FLOWLABEL);
	G_STATIC_ASSERT (NM_IP_TUNNEL_FLAG_IP6_MIP6_DEV           == IP6_TNL_F_MIP6_DEV);
	G_STATIC_ASSERT (NM_IP_TUNNEL_FLAG_IP6_RCV_DSCP_COPY      == IP6_TNL_F_RCV_DSCP_COPY);
	G_STATIC_ASSERT (NM_IP_TUNNEL_FLAG_IP6_USE_ORIG_FWMARK    == IP6_TNL_F_USE_ORIG_FWMARK);

	/* NOTE: "accidentally", the numeric values correspond.
	 *       For flags added in the future, that might no longer
	 *       be the case. */
	return flags & _NM_IP_TUNNEL_FLAG_ALL_IP6TNL;
}

static NMIPTunnelFlags
ip6tnl_flags_plat_to_setting (guint32 flags)
{
	return flags & ((guint32) _NM_IP_TUNNEL_FLAG_ALL_IP6TNL);
}

/*****************************************************************************/

static gboolean
address_equal_pp (int family, const char *a, const char *b)
{
	char buffer1[sizeof (struct in6_addr)] = { };
	char buffer2[sizeof (struct in6_addr)] = { };

	g_return_val_if_fail (family == AF_INET || family == AF_INET6, FALSE);

	if (a)
		inet_pton (family, a, buffer1);
	if (b)
		inet_pton (family, b, buffer2);

	return !memcmp (buffer1, buffer2,
	                family == AF_INET ? sizeof (in_addr_t) : sizeof (struct in6_addr));
}

static gboolean
address_equal_pn (int family, const char *a, const void *b)
{
	char buffer1[sizeof (struct in6_addr)] = { };

	g_return_val_if_fail (family == AF_INET || family == AF_INET6, FALSE);

	if (a)
		inet_pton (family, a, buffer1);

	return !memcmp (buffer1, b,
	                family == AF_INET ? sizeof (in_addr_t) : sizeof (struct in6_addr));

}

static void
update_properties_from_ifindex (NMDevice *device, int ifindex)
{
	NMDeviceIPTunnel *self = NM_DEVICE_IP_TUNNEL (device);
	NMDeviceIPTunnelPrivate *priv = NM_DEVICE_IP_TUNNEL_GET_PRIVATE (self);
	int parent_ifindex = 0;
	in_addr_t local4 = 0;
	in_addr_t remote4 = 0;
	struct in6_addr local6 = IN6ADDR_ANY_INIT;
	struct in6_addr remote6 = IN6ADDR_ANY_INIT;
	guint8 ttl = 0;
	guint8 tos = 0;
	guint8 encap_limit = 0;
	gboolean pmtud = FALSE;
	guint32 flow_label = 0;
	NMIPTunnelFlags flags = NM_IP_TUNNEL_FLAG_NONE;
	char *key;

	if (ifindex <= 0) {
clear:
		nm_device_parent_set_ifindex (device, 0);
		if (priv->local) {
			g_clear_pointer (&priv->local, g_free);
			_notify (self, PROP_LOCAL);
		}
		if (priv->remote) {
			g_clear_pointer (&priv->remote, g_free);
			_notify (self, PROP_REMOTE);
		}
		if (priv->input_key) {
			g_clear_pointer (&priv->input_key, g_free);
			_notify (self, PROP_INPUT_KEY);
		}
		if (priv->output_key) {
			g_clear_pointer (&priv->output_key, g_free);
			_notify (self, PROP_OUTPUT_KEY);
		}

		goto out;
	}

	if (NM_IN_SET (priv->mode, NM_IP_TUNNEL_MODE_GRE, NM_IP_TUNNEL_MODE_GRETAP)) {
		const NMPlatformLnkGre *lnk;

		if (priv->mode == NM_IP_TUNNEL_MODE_GRE)
			lnk = nm_platform_link_get_lnk_gre (nm_device_get_platform (device), ifindex, NULL);
		else
			lnk = nm_platform_link_get_lnk_gretap (nm_device_get_platform (device), ifindex, NULL);
		if (!lnk) {
			_LOGW (LOGD_PLATFORM, "could not read %s properties", "gre");
			goto clear;
		}

		parent_ifindex = lnk->parent_ifindex;
		local4 = lnk->local;
		remote4 = lnk->remote;
		ttl = lnk->ttl;
		tos = lnk->tos;
		pmtud = lnk->path_mtu_discovery;

		if (NM_FLAGS_HAS (lnk->input_flags, NM_GRE_KEY)) {
			key = g_strdup_printf ("%u", lnk->input_key);
			if (g_strcmp0 (priv->input_key, key)) {
				g_free (priv->input_key);
				priv->input_key = key;
				_notify (self, PROP_INPUT_KEY);
			} else
				g_free (key);
		} else {
			if (priv->input_key) {
				g_clear_pointer (&priv->input_key, g_free);
				_notify (self, PROP_INPUT_KEY);
			}
		}

		if (NM_FLAGS_HAS (lnk->output_flags, NM_GRE_KEY)) {
			key = g_strdup_printf ("%u", lnk->output_key);
			if (g_strcmp0 (priv->output_key, key)) {
				g_free (priv->output_key);
				priv->output_key = key;
				_notify (self, PROP_OUTPUT_KEY);
			} else
				g_free (key);
		} else {
			if (priv->output_key) {
				g_clear_pointer (&priv->output_key, g_free);
				_notify (self, PROP_OUTPUT_KEY);
			}
		}
	} else if (priv->mode == NM_IP_TUNNEL_MODE_SIT) {
		const NMPlatformLnkSit *lnk;

		lnk = nm_platform_link_get_lnk_sit (nm_device_get_platform (device), ifindex, NULL);
		if (!lnk) {
			_LOGW (LOGD_PLATFORM, "could not read %s properties", "sit");
			goto clear;
		}

		parent_ifindex = lnk->parent_ifindex;
		local4 = lnk->local;
		remote4 = lnk->remote;
		ttl = lnk->ttl;
		tos = lnk->tos;
		pmtud = lnk->path_mtu_discovery;
	} else if (priv->mode == NM_IP_TUNNEL_MODE_IPIP) {
		const NMPlatformLnkIpIp *lnk;

		lnk = nm_platform_link_get_lnk_ipip (nm_device_get_platform (device), ifindex, NULL);
		if (!lnk) {
			_LOGW (LOGD_PLATFORM, "could not read %s properties", "ipip");
			goto clear;
		}

		parent_ifindex = lnk->parent_ifindex;
		local4 = lnk->local;
		remote4 = lnk->remote;
		ttl = lnk->ttl;
		tos = lnk->tos;
		pmtud = lnk->path_mtu_discovery;
	} else if (NM_IN_SET (priv->mode,
	                      NM_IP_TUNNEL_MODE_IPIP6,
	                      NM_IP_TUNNEL_MODE_IP6IP6,
	                      NM_IP_TUNNEL_MODE_IP6GRE,
	                      NM_IP_TUNNEL_MODE_IP6GRETAP)) {
		const NMPlatformLnkIp6Tnl *lnk;
		NMPlatform *plat = nm_device_get_platform (device);

		if (priv->mode == NM_IP_TUNNEL_MODE_IP6GRE)
			lnk = nm_platform_link_get_lnk_ip6gre (plat, ifindex, NULL);
		else if (priv->mode == NM_IP_TUNNEL_MODE_IP6GRETAP)
			lnk = nm_platform_link_get_lnk_ip6gretap (plat, ifindex, NULL);
		else
			lnk = nm_platform_link_get_lnk_ip6tnl (plat, ifindex, NULL);

		if (!lnk) {
			_LOGW (LOGD_PLATFORM, "could not read %s properties", "ip6tnl");
			goto clear;
		}

		parent_ifindex = lnk->parent_ifindex;
		local6 = lnk->local;
		remote6 = lnk->remote;
		ttl = lnk->ttl;
		tos = lnk->tclass;
		encap_limit = lnk->encap_limit;
		flow_label = lnk->flow_label;
		flags = ip6tnl_flags_plat_to_setting (lnk->flags);

		if (NM_IN_SET (priv->mode,
		               NM_IP_TUNNEL_MODE_IP6GRE,
		               NM_IP_TUNNEL_MODE_IP6GRETAP)) {
			if (NM_FLAGS_HAS (lnk->input_flags, NM_GRE_KEY)) {
				key = g_strdup_printf ("%u", lnk->input_key);
				if (g_strcmp0 (priv->input_key, key)) {
					g_free (priv->input_key);
					priv->input_key = key;
					_notify (self, PROP_INPUT_KEY);
				} else
					g_free (key);
			} else {
				if (priv->input_key) {
					g_clear_pointer (&priv->input_key, g_free);
					_notify (self, PROP_INPUT_KEY);
				}
			}

			if (NM_FLAGS_HAS (lnk->output_flags, NM_GRE_KEY)) {
				key = g_strdup_printf ("%u", lnk->output_key);
				if (g_strcmp0 (priv->output_key, key)) {
					g_free (priv->output_key);
					priv->output_key = key;
					_notify (self, PROP_OUTPUT_KEY);
				} else
					g_free (key);
			} else {
				if (priv->output_key) {
					g_clear_pointer (&priv->output_key, g_free);
					_notify (self, PROP_OUTPUT_KEY);
				}
			}
		}
	} else
		g_return_if_reached ();

	nm_device_parent_set_ifindex (device, parent_ifindex);

	if (priv->addr_family == AF_INET) {
		if (!address_equal_pn (AF_INET, priv->local, &local4)) {
			g_clear_pointer (&priv->local, g_free);
			if (local4)
				priv->local = nm_utils_inet4_ntop_dup (local4);
			_notify (self, PROP_LOCAL);
		}

		if (!address_equal_pn (AF_INET, priv->remote, &remote4)) {
			g_clear_pointer (&priv->remote, g_free);
			if (remote4)
				priv->remote = nm_utils_inet4_ntop_dup (remote4);
			_notify (self, PROP_REMOTE);
		}
	} else {
		if (!address_equal_pn (AF_INET6, priv->local, &local6)) {
			g_clear_pointer (&priv->local, g_free);
			if (memcmp (&local6, &in6addr_any, sizeof (in6addr_any)))
				priv->local = nm_utils_inet6_ntop_dup (&local6);
			_notify (self, PROP_LOCAL);
		}

		if (!address_equal_pn (AF_INET6, priv->remote, &remote6)) {
			g_clear_pointer (&priv->remote, g_free);
			if (memcmp (&remote6, &in6addr_any, sizeof (in6addr_any)))
				priv->remote = nm_utils_inet6_ntop_dup (&remote6);
			_notify (self, PROP_REMOTE);
		}
	}

out:

	if (priv->ttl != ttl) {
		priv->ttl = ttl;
		_notify (self, PROP_TTL);
	}

	if (priv->tos != tos) {
		priv->tos = tos;
		_notify (self, PROP_TOS);
	}

	if (priv->path_mtu_discovery != pmtud) {
		priv->path_mtu_discovery = pmtud;
		_notify (self, PROP_PATH_MTU_DISCOVERY);
	}

	if (priv->encap_limit != encap_limit) {
		priv->encap_limit = encap_limit;
		_notify (self, PROP_ENCAPSULATION_LIMIT);
	}

	if (priv->flow_label != flow_label) {
		priv->flow_label = flow_label;
		_notify (self, PROP_FLOW_LABEL);
	}

	if (priv->flags != flags) {
		priv->flags = flags;
		_notify (self, PROP_FLAGS);
	}
}

static void
update_properties (NMDevice *device)
{
	update_properties_from_ifindex (device, nm_device_get_ifindex (device));
}

static void
link_changed (NMDevice *device,
              const NMPlatformLink *pllink)
{
	NM_DEVICE_CLASS (nm_device_ip_tunnel_parent_class)->link_changed (device, pllink);
	update_properties (device);
}

static gboolean
complete_connection (NMDevice *device,
                     NMConnection *connection,
                     const char *specific_object,
                     NMConnection *const*existing_connections,
                     GError **error)
{
	NMSettingIPTunnel *s_ip_tunnel;

	nm_utils_complete_generic (nm_device_get_platform (device),
	                           connection,
	                           NM_SETTING_IP_TUNNEL_SETTING_NAME,
	                           existing_connections,
	                           NULL,
	                           _("IP tunnel connection"),
	                           NULL,
	                           NULL,
	                           TRUE);

	s_ip_tunnel = nm_connection_get_setting_ip_tunnel (connection);
	if (!s_ip_tunnel) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INVALID_CONNECTION,
		                     "A 'tunnel' setting is required.");
		return FALSE;
	}

	return TRUE;
}

static void
update_connection (NMDevice *device, NMConnection *connection)
{
	NMDeviceIPTunnel *self = NM_DEVICE_IP_TUNNEL (device);
	NMDeviceIPTunnelPrivate *priv = NM_DEVICE_IP_TUNNEL_GET_PRIVATE (self);
	NMSettingIPTunnel *s_ip_tunnel = nm_connection_get_setting_ip_tunnel (connection);

	if (!s_ip_tunnel) {
		s_ip_tunnel = (NMSettingIPTunnel *) nm_setting_ip_tunnel_new ();
		nm_connection_add_setting (connection, (NMSetting *) s_ip_tunnel);
	}

	if (nm_setting_ip_tunnel_get_mode (s_ip_tunnel) != priv->mode)
		g_object_set (G_OBJECT (s_ip_tunnel), NM_SETTING_IP_TUNNEL_MODE, priv->mode, NULL);

	g_object_set (s_ip_tunnel,
	              NM_SETTING_IP_TUNNEL_PARENT,
	              nm_device_parent_find_for_connection (device,
	                                                    nm_setting_ip_tunnel_get_parent (s_ip_tunnel)),
	              NULL);

	if (!address_equal_pp (priv->addr_family,
	                       nm_setting_ip_tunnel_get_local (s_ip_tunnel),
	                       priv->local))
		g_object_set (G_OBJECT (s_ip_tunnel), NM_SETTING_IP_TUNNEL_LOCAL, priv->local, NULL);

	if (!address_equal_pp (priv->addr_family,
	                       nm_setting_ip_tunnel_get_remote (s_ip_tunnel),
	                       priv->remote))
		g_object_set (G_OBJECT (s_ip_tunnel), NM_SETTING_IP_TUNNEL_REMOTE, priv->remote, NULL);

	if (nm_setting_ip_tunnel_get_ttl (s_ip_tunnel) != priv->ttl)
		g_object_set (G_OBJECT (s_ip_tunnel), NM_SETTING_IP_TUNNEL_TTL, priv->ttl, NULL);

	if (nm_setting_ip_tunnel_get_tos (s_ip_tunnel) != priv->tos)
		g_object_set (G_OBJECT (s_ip_tunnel), NM_SETTING_IP_TUNNEL_TOS, priv->tos, NULL);

	if (nm_setting_ip_tunnel_get_path_mtu_discovery (s_ip_tunnel) != priv->path_mtu_discovery) {
		g_object_set (G_OBJECT (s_ip_tunnel),
		              NM_SETTING_IP_TUNNEL_PATH_MTU_DISCOVERY,
		              priv->path_mtu_discovery,
		              NULL);
	}

	if (nm_setting_ip_tunnel_get_encapsulation_limit (s_ip_tunnel) != priv->encap_limit) {
		g_object_set (G_OBJECT (s_ip_tunnel),
		                        NM_SETTING_IP_TUNNEL_ENCAPSULATION_LIMIT,
		                        priv->encap_limit,
		                        NULL);
	}

	if (nm_setting_ip_tunnel_get_flow_label (s_ip_tunnel) != priv->flow_label) {
		g_object_set (G_OBJECT (s_ip_tunnel),
		                        NM_SETTING_IP_TUNNEL_FLOW_LABEL,
		                        priv->flow_label,
		                        NULL);
	}

	if (NM_IN_SET (priv->mode,
	               NM_IP_TUNNEL_MODE_GRE,
	               NM_IP_TUNNEL_MODE_GRETAP,
	               NM_IP_TUNNEL_MODE_IP6GRE,
	               NM_IP_TUNNEL_MODE_IP6GRETAP)) {
		if (g_strcmp0 (nm_setting_ip_tunnel_get_input_key (s_ip_tunnel), priv->input_key)) {
			g_object_set (G_OBJECT (s_ip_tunnel),
			              NM_SETTING_IP_TUNNEL_INPUT_KEY,
			              priv->input_key,
			              NULL);
		}
		if (g_strcmp0 (nm_setting_ip_tunnel_get_output_key (s_ip_tunnel), priv->output_key)) {
			g_object_set (G_OBJECT (s_ip_tunnel),
			              NM_SETTING_IP_TUNNEL_OUTPUT_KEY,
			              priv->output_key,
			              NULL);
		}
	}
}

static gboolean
check_connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	NMDeviceIPTunnel *self = NM_DEVICE_IP_TUNNEL (device);
	NMDeviceIPTunnelPrivate *priv = NM_DEVICE_IP_TUNNEL_GET_PRIVATE (self);
	NMSettingIPTunnel *s_ip_tunnel;
	const char *parent;

	if (!NM_DEVICE_CLASS (nm_device_ip_tunnel_parent_class)->check_connection_compatible (device, connection, error))
		return FALSE;

	s_ip_tunnel = nm_connection_get_setting_ip_tunnel (connection);

	if (nm_setting_ip_tunnel_get_mode (s_ip_tunnel) != priv->mode) {
		nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
		                            "incompatible IP tunnel mode");
		return FALSE;
	}

	if (nm_device_is_real (device)) {
		/* Check parent interface; could be an interface name or a UUID */
		parent = nm_setting_ip_tunnel_get_parent (s_ip_tunnel);
		if (parent && !nm_device_match_parent (device, parent)) {
			nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
			                            "IP tunnel parent mismatches");
			return FALSE;
		}

		if (!address_equal_pp (priv->addr_family,
		                       nm_setting_ip_tunnel_get_local (s_ip_tunnel),
		                       priv->local)) {
			nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
			                            "local IP tunnel address mismatches");
			return FALSE;
		}

		if (!address_equal_pp (priv->addr_family,
		                       nm_setting_ip_tunnel_get_remote (s_ip_tunnel),
		                       priv->remote)) {
			nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
			                            "remote IP tunnel address mismatches");
			return FALSE;
		}

		if (nm_setting_ip_tunnel_get_ttl (s_ip_tunnel) != priv->ttl) {
			nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
			                            "TTL of IP tunnel mismatches");
			return FALSE;
		}

		if (nm_setting_ip_tunnel_get_tos (s_ip_tunnel) != priv->tos) {
			nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
			                            "TOS of IP tunnel mismatches");
			return FALSE;
		}

		if (priv->addr_family == AF_INET) {
			if (nm_setting_ip_tunnel_get_path_mtu_discovery (s_ip_tunnel) != priv->path_mtu_discovery) {
				nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
				                            "MTU discovery setting of IP tunnel mismatches");
				return FALSE;
			}
		} else {
			if (nm_setting_ip_tunnel_get_encapsulation_limit (s_ip_tunnel) != priv->encap_limit) {
				nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
				                            "encapsulation limit of IP tunnel mismatches");
				return FALSE;
			}

			if (nm_setting_ip_tunnel_get_flow_label (s_ip_tunnel) != priv->flow_label) {
				nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
				                            "flow-label of IP tunnel mismatches");
				return FALSE;
			}
		}
	}

	return TRUE;
}

static NMIPTunnelMode
platform_link_to_tunnel_mode (const NMPlatformLink *link)
{
	const NMPlatformLnkIp6Tnl *lnk;

	switch (link->type) {
	case NM_LINK_TYPE_GRE:
		return NM_IP_TUNNEL_MODE_GRE;
	case NM_LINK_TYPE_GRETAP:
		return NM_IP_TUNNEL_MODE_GRETAP;
	case NM_LINK_TYPE_IP6TNL:
		lnk = nm_platform_link_get_lnk_ip6tnl (NM_PLATFORM_GET, link->ifindex, NULL);
		if (lnk) {
			if (lnk->proto == IPPROTO_IPIP)
				return NM_IP_TUNNEL_MODE_IPIP6;
			if (lnk->proto == IPPROTO_IPV6)
				return NM_IP_TUNNEL_MODE_IP6IP6;
		}
		return NM_IP_TUNNEL_MODE_UNKNOWN;
	case NM_LINK_TYPE_IP6GRE:
		return NM_IP_TUNNEL_MODE_IP6GRE;
	case NM_LINK_TYPE_IP6GRETAP:
		return NM_IP_TUNNEL_MODE_IP6GRETAP;
	case NM_LINK_TYPE_IPIP:
		return NM_IP_TUNNEL_MODE_IPIP;
	case NM_LINK_TYPE_SIT:
		return NM_IP_TUNNEL_MODE_SIT;
	default:
		g_return_val_if_reached (NM_IP_TUNNEL_MODE_UNKNOWN);
	}
}

static NMLinkType
tunnel_mode_to_link_type (NMIPTunnelMode tunnel_mode)
{
	switch (tunnel_mode) {
	case NM_IP_TUNNEL_MODE_GRE:
		return NM_LINK_TYPE_GRE;
	case NM_IP_TUNNEL_MODE_GRETAP:
		return NM_LINK_TYPE_GRETAP;
	case NM_IP_TUNNEL_MODE_IPIP6:
	case NM_IP_TUNNEL_MODE_IP6IP6:
		return NM_LINK_TYPE_IP6TNL;
	case NM_IP_TUNNEL_MODE_IP6GRE:
		return NM_LINK_TYPE_IP6GRE;
	case NM_IP_TUNNEL_MODE_IP6GRETAP:
		return NM_LINK_TYPE_IP6GRETAP;
	case NM_IP_TUNNEL_MODE_IPIP:
		return NM_LINK_TYPE_IPIP;
	case NM_IP_TUNNEL_MODE_SIT:
		return NM_LINK_TYPE_SIT;
	case NM_IP_TUNNEL_MODE_VTI:
	case NM_IP_TUNNEL_MODE_VTI6:
	case NM_IP_TUNNEL_MODE_ISATAP:
		return NM_LINK_TYPE_UNKNOWN;
	case NM_IP_TUNNEL_MODE_UNKNOWN:
		break;
	}
	g_return_val_if_reached (NM_LINK_TYPE_UNKNOWN);
}

/*****************************************************************************/

static gboolean
create_and_realize (NMDevice *device,
                    NMConnection *connection,
                    NMDevice *parent,
                    const NMPlatformLink **out_plink,
                    GError **error)
{
	const char *iface = nm_device_get_iface (device);
	NMSettingIPTunnel *s_ip_tunnel;
	NMPlatformLnkGre lnk_gre = { };
	NMPlatformLnkSit lnk_sit = { };
	NMPlatformLnkIpIp lnk_ipip = { };
	NMPlatformLnkIp6Tnl lnk_ip6tnl = { };
	const char *str;
	gint64 val;
	NMIPTunnelMode mode;
	int r;

	s_ip_tunnel = nm_connection_get_setting_ip_tunnel (connection);
	g_assert (s_ip_tunnel);

	mode = nm_setting_ip_tunnel_get_mode (s_ip_tunnel);
	switch (mode) {
	case NM_IP_TUNNEL_MODE_GRETAP:
		lnk_gre.is_tap = TRUE;
		/* fall-through */
	case NM_IP_TUNNEL_MODE_GRE:
		if (parent)
			lnk_gre.parent_ifindex = nm_device_get_ifindex (parent);

		str = nm_setting_ip_tunnel_get_local (s_ip_tunnel);
		if (str)
			inet_pton (AF_INET, str, &lnk_gre.local);

		str = nm_setting_ip_tunnel_get_remote (s_ip_tunnel);
		g_assert (str);
		inet_pton (AF_INET, str, &lnk_gre.remote);

		lnk_gre.ttl = nm_setting_ip_tunnel_get_ttl (s_ip_tunnel);
		lnk_gre.tos = nm_setting_ip_tunnel_get_tos (s_ip_tunnel);
		lnk_gre.path_mtu_discovery = nm_setting_ip_tunnel_get_path_mtu_discovery (s_ip_tunnel);

		val = _nm_utils_ascii_str_to_int64 (nm_setting_ip_tunnel_get_input_key (s_ip_tunnel),
		                                    10,
		                                    0,
		                                    G_MAXUINT32,
		                                    -1);
		if (val != -1) {
			lnk_gre.input_key = val;
			lnk_gre.input_flags = NM_GRE_KEY;
		}

		val = _nm_utils_ascii_str_to_int64 (nm_setting_ip_tunnel_get_output_key (s_ip_tunnel),
		                                    10,
		                                    0,
		                                    G_MAXUINT32,
		                                    -1);
		if (val != -1) {
			lnk_gre.output_key = val;
			lnk_gre.output_flags = NM_GRE_KEY;
		}

		r = nm_platform_link_gre_add (nm_device_get_platform (device), iface, &lnk_gre, out_plink);
		if (r < 0) {
			g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_CREATION_FAILED,
			             "Failed to create GRE interface '%s' for '%s': %s",
			             iface,
			             nm_connection_get_id (connection),
			             nm_strerror (r));
			return FALSE;
		}
		break;
	case NM_IP_TUNNEL_MODE_SIT:
		if (parent)
			lnk_sit.parent_ifindex = nm_device_get_ifindex (parent);

		str = nm_setting_ip_tunnel_get_local (s_ip_tunnel);
		if (str)
			inet_pton (AF_INET, str, &lnk_sit.local);

		str = nm_setting_ip_tunnel_get_remote (s_ip_tunnel);
		g_assert (str);
		inet_pton (AF_INET, str, &lnk_sit.remote);

		lnk_sit.ttl = nm_setting_ip_tunnel_get_ttl (s_ip_tunnel);
		lnk_sit.tos = nm_setting_ip_tunnel_get_tos (s_ip_tunnel);
		lnk_sit.path_mtu_discovery = nm_setting_ip_tunnel_get_path_mtu_discovery (s_ip_tunnel);

		r = nm_platform_link_sit_add (nm_device_get_platform (device), iface, &lnk_sit, out_plink);
		if (r < 0) {
			g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_CREATION_FAILED,
			             "Failed to create SIT interface '%s' for '%s': %s",
			             iface,
			             nm_connection_get_id (connection),
			             nm_strerror (r));
			return FALSE;
		}
		break;
	case NM_IP_TUNNEL_MODE_IPIP:
		if (parent)
			lnk_ipip.parent_ifindex = nm_device_get_ifindex (parent);

		str = nm_setting_ip_tunnel_get_local (s_ip_tunnel);
		if (str)
			inet_pton (AF_INET, str, &lnk_ipip.local);

		str = nm_setting_ip_tunnel_get_remote (s_ip_tunnel);
		g_assert (str);
		inet_pton (AF_INET, str, &lnk_ipip.remote);

		lnk_ipip.ttl = nm_setting_ip_tunnel_get_ttl (s_ip_tunnel);
		lnk_ipip.tos = nm_setting_ip_tunnel_get_tos (s_ip_tunnel);
		lnk_ipip.path_mtu_discovery = nm_setting_ip_tunnel_get_path_mtu_discovery (s_ip_tunnel);

		r = nm_platform_link_ipip_add (nm_device_get_platform (device), iface, &lnk_ipip, out_plink);
		if (r < 0) {
			g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_CREATION_FAILED,
			             "Failed to create IPIP interface '%s' for '%s': %s",
			             iface,
			             nm_connection_get_id (connection),
			             nm_strerror (r));
			return FALSE;
		}
		break;
	case NM_IP_TUNNEL_MODE_IPIP6:
	case NM_IP_TUNNEL_MODE_IP6IP6:
	case NM_IP_TUNNEL_MODE_IP6GRE:
	case NM_IP_TUNNEL_MODE_IP6GRETAP:
		if (parent)
			lnk_ip6tnl.parent_ifindex = nm_device_get_ifindex (parent);

		str = nm_setting_ip_tunnel_get_local (s_ip_tunnel);
		if (str)
			inet_pton (AF_INET6, str, &lnk_ip6tnl.local);

		str = nm_setting_ip_tunnel_get_remote (s_ip_tunnel);
		g_assert (str);
		inet_pton (AF_INET6, str, &lnk_ip6tnl.remote);

		lnk_ip6tnl.ttl = nm_setting_ip_tunnel_get_ttl (s_ip_tunnel);
		lnk_ip6tnl.tclass = nm_setting_ip_tunnel_get_tos (s_ip_tunnel);
		lnk_ip6tnl.encap_limit = nm_setting_ip_tunnel_get_encapsulation_limit (s_ip_tunnel);
		lnk_ip6tnl.flow_label = nm_setting_ip_tunnel_get_flow_label (s_ip_tunnel);
		lnk_ip6tnl.flags = ip6tnl_flags_setting_to_plat (nm_setting_ip_tunnel_get_flags (s_ip_tunnel));

		if (NM_IN_SET (mode, NM_IP_TUNNEL_MODE_IP6GRE, NM_IP_TUNNEL_MODE_IP6GRETAP)) {
			val = _nm_utils_ascii_str_to_int64 (nm_setting_ip_tunnel_get_input_key (s_ip_tunnel),
			                                    10,
			                                    0,
			                                    G_MAXUINT32,
			                                    -1);
			if (val != -1) {
				lnk_ip6tnl.input_key = val;
				lnk_ip6tnl.input_flags = NM_GRE_KEY;
			}

			val = _nm_utils_ascii_str_to_int64 (nm_setting_ip_tunnel_get_output_key (s_ip_tunnel),
			                                    10,
			                                    0,
			                                    G_MAXUINT32,
			                                    -1);
			if (val != -1) {
				lnk_ip6tnl.output_key = val;
				lnk_ip6tnl.output_flags = NM_GRE_KEY;
			}

			lnk_ip6tnl.is_gre = TRUE;
			lnk_ip6tnl.is_tap = (mode == NM_IP_TUNNEL_MODE_IP6GRETAP);

			r = nm_platform_link_ip6gre_add (nm_device_get_platform (device),
			                                 iface, &lnk_ip6tnl, out_plink);
		} else {
			lnk_ip6tnl.proto = nm_setting_ip_tunnel_get_mode (s_ip_tunnel) == NM_IP_TUNNEL_MODE_IPIP6
			                       ? IPPROTO_IPIP
			                       : IPPROTO_IPV6;
			r = nm_platform_link_ip6tnl_add (nm_device_get_platform (device),
			                                 iface, &lnk_ip6tnl, out_plink);
		}
		if (r < 0) {
			g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_CREATION_FAILED,
			             "Failed to create IPv6 tunnel interface '%s' for '%s': %s",
			             iface,
			             nm_connection_get_id (connection),
			             nm_strerror (r));
			return FALSE;
		}
		break;
	default:
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_CREATION_FAILED,
		             "Failed to create IP tunnel interface '%s' for '%s': mode %d not supported",
		             iface,
		             nm_connection_get_id (connection),
		             (int) nm_setting_ip_tunnel_get_mode (s_ip_tunnel));
		return FALSE;
	}

	return TRUE;
}

static guint32
get_configured_mtu (NMDevice *device, NMDeviceMtuSource *out_source)
{
	return nm_device_get_configured_mtu_from_connection (device,
	                                                     NM_TYPE_SETTING_IP_TUNNEL,
	                                                     out_source);
}

static NMDeviceCapabilities
get_generic_capabilities (NMDevice *device)
{
	return NM_DEVICE_CAP_IS_SOFTWARE;
}

static void
unrealize_notify (NMDevice *device)
{
	NM_DEVICE_CLASS (nm_device_ip_tunnel_parent_class)->unrealize_notify (device);

	update_properties_from_ifindex (device, 0);
}

static gboolean
can_reapply_change (NMDevice *device,
                    const char *setting_name,
                    NMSetting *s_old,
                    NMSetting *s_new,
                    GHashTable *diffs,
                    GError **error)
{
	NMDeviceClass *device_class;

	/* Only handle ip-tunnel setting here, delegate other settings to parent class */
	if (nm_streq (setting_name, NM_SETTING_IP_TUNNEL_SETTING_NAME)) {
		return nm_device_hash_check_invalid_keys (diffs,
		                                          NM_SETTING_IP_TUNNEL_SETTING_NAME,
		                                          error,
		                                          NM_SETTING_IP_TUNNEL_MTU); /* reapplied with IP config */
	}

	device_class = NM_DEVICE_CLASS (nm_device_ip_tunnel_parent_class);
	return device_class->can_reapply_change (device,
	                                         setting_name,
	                                         s_old,
	                                         s_new,
	                                         diffs,
	                                         error);
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMDeviceIPTunnelPrivate *priv = NM_DEVICE_IP_TUNNEL_GET_PRIVATE ((NMDeviceIPTunnel *) object);

	switch (prop_id) {
	case PROP_MODE:
		g_value_set_uint (value, priv->mode);
		break;
	case PROP_LOCAL:
		g_value_set_string (value, priv->local);
		break;
	case PROP_REMOTE:
		g_value_set_string (value, priv->remote);
		break;
	case PROP_TTL:
		g_value_set_uchar (value, priv->ttl);
		break;
	case PROP_TOS:
		g_value_set_uchar (value, priv->tos);
		break;
	case PROP_PATH_MTU_DISCOVERY:
		g_value_set_boolean (value, priv->path_mtu_discovery);
		break;
	case PROP_INPUT_KEY:
		g_value_set_string (value, priv->input_key);
		break;
	case PROP_OUTPUT_KEY:
		g_value_set_string (value, priv->output_key);
		break;
	case PROP_ENCAPSULATION_LIMIT:
		g_value_set_uchar (value, priv->encap_limit);
		break;
	case PROP_FLOW_LABEL:
		g_value_set_uint (value, priv->flow_label);
		break;
	case PROP_FLAGS:
		g_value_set_uint (value, priv->flags);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMDeviceIPTunnelPrivate *priv = NM_DEVICE_IP_TUNNEL_GET_PRIVATE ((NMDeviceIPTunnel *) object);

	switch (prop_id) {
	case PROP_MODE:
		priv->mode = g_value_get_uint (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
	}
}

static NMActStageReturn
act_stage1_prepare (NMDevice *device, NMDeviceStateReason *out_failure_reason)
{
	NMActStageReturn ret;

	ret = NM_DEVICE_CLASS (nm_device_ip_tunnel_parent_class)->act_stage1_prepare (device, out_failure_reason);
	if (ret != NM_ACT_STAGE_RETURN_SUCCESS)
		return ret;

	if (!nm_device_hw_addr_set_cloned (device, nm_device_get_applied_connection (device), FALSE))
		return NM_ACT_STAGE_RETURN_FAILURE;

	return NM_ACT_STAGE_RETURN_SUCCESS;
}

/*****************************************************************************/

static void
nm_device_ip_tunnel_init (NMDeviceIPTunnel *self)
{
}

static void
constructed (GObject *object)
{
	NMDeviceIPTunnelPrivate *priv = NM_DEVICE_IP_TUNNEL_GET_PRIVATE ((NMDeviceIPTunnel *) object);

	if (NM_IN_SET (priv->mode,
	               NM_IP_TUNNEL_MODE_IPIP6,
	               NM_IP_TUNNEL_MODE_IP6IP6,
	               NM_IP_TUNNEL_MODE_IP6GRE,
	               NM_IP_TUNNEL_MODE_IP6GRETAP))
		priv->addr_family = AF_INET6;
	else
		priv->addr_family = AF_INET;

	G_OBJECT_CLASS (nm_device_ip_tunnel_parent_class)->constructed (object);
}

static void
dispose (GObject *object)
{
	NMDeviceIPTunnel *self = NM_DEVICE_IP_TUNNEL (object);
	NMDeviceIPTunnelPrivate *priv = NM_DEVICE_IP_TUNNEL_GET_PRIVATE (self);

	g_clear_pointer (&priv->local, g_free);
	g_clear_pointer (&priv->remote, g_free);
	g_clear_pointer (&priv->input_key, g_free);
	g_clear_pointer (&priv->output_key, g_free);

	G_OBJECT_CLASS (nm_device_ip_tunnel_parent_class)->dispose (object);
}

static const NMDBusInterfaceInfoExtended interface_info_device_ip_tunnel = {
	.parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT (
		NM_DBUS_INTERFACE_DEVICE_IP_TUNNEL,
		.signals = NM_DEFINE_GDBUS_SIGNAL_INFOS (
			&nm_signal_info_property_changed_legacy,
		),
		.properties = NM_DEFINE_GDBUS_PROPERTY_INFOS (
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Mode",               "u",  NM_DEVICE_IP_TUNNEL_MODE),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Parent",             "o",  NM_DEVICE_PARENT),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Local",              "s",  NM_DEVICE_IP_TUNNEL_LOCAL),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Remote",             "s",  NM_DEVICE_IP_TUNNEL_REMOTE),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Ttl",                "y",  NM_DEVICE_IP_TUNNEL_TTL),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Tos",                "y",  NM_DEVICE_IP_TUNNEL_TOS),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("PathMtuDiscovery",   "b",  NM_DEVICE_IP_TUNNEL_PATH_MTU_DISCOVERY),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("InputKey",           "s",  NM_DEVICE_IP_TUNNEL_INPUT_KEY),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("OutputKey",          "s",  NM_DEVICE_IP_TUNNEL_OUTPUT_KEY),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("EncapsulationLimit", "y",  NM_DEVICE_IP_TUNNEL_ENCAPSULATION_LIMIT),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("FlowLabel",          "u",  NM_DEVICE_IP_TUNNEL_FLOW_LABEL),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Flags",              "u",  NM_DEVICE_IP_TUNNEL_FLAGS),
		),
	),
	.legacy_property_changed = TRUE,
};

static void
nm_device_ip_tunnel_class_init (NMDeviceIPTunnelClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	object_class->constructed = constructed;
	object_class->dispose = dispose;
	object_class->get_property = get_property;
	object_class->set_property = set_property;

	dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS (&interface_info_device_ip_tunnel);

	device_class->connection_type_supported = NM_SETTING_IP_TUNNEL_SETTING_NAME;
	device_class->connection_type_check_compatible = NM_SETTING_IP_TUNNEL_SETTING_NAME;
	device_class->link_types = NM_DEVICE_DEFINE_LINK_TYPES (NM_LINK_TYPE_GRE,
	                                                        NM_LINK_TYPE_GRETAP,
	                                                        NM_LINK_TYPE_IP6TNL,
	                                                        NM_LINK_TYPE_IP6GRE,
	                                                        NM_LINK_TYPE_IP6GRETAP,
	                                                        NM_LINK_TYPE_IPIP,
	                                                        NM_LINK_TYPE_SIT);

	device_class->act_stage1_prepare = act_stage1_prepare;
	device_class->link_changed = link_changed;
	device_class->can_reapply_change = can_reapply_change;
	device_class->complete_connection = complete_connection;
	device_class->update_connection = update_connection;
	device_class->check_connection_compatible = check_connection_compatible;
	device_class->create_and_realize = create_and_realize;
	device_class->get_generic_capabilities = get_generic_capabilities;
	device_class->get_configured_mtu = get_configured_mtu;
	device_class->unrealize_notify = unrealize_notify;

	obj_properties[PROP_MODE] =
	     g_param_spec_uint (NM_DEVICE_IP_TUNNEL_MODE, "", "",
	                        0, G_MAXUINT, 0,
	                        G_PARAM_READWRITE |
	                        G_PARAM_CONSTRUCT_ONLY |
	                        G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_LOCAL] =
	     g_param_spec_string (NM_DEVICE_IP_TUNNEL_LOCAL, "", "",
	                          NULL,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_REMOTE] =
	     g_param_spec_string (NM_DEVICE_IP_TUNNEL_REMOTE, "", "",
	                          NULL,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_TTL] =
	     g_param_spec_uchar (NM_DEVICE_IP_TUNNEL_TTL, "", "",
	                         0, 255, 0,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_TOS] =
	     g_param_spec_uchar (NM_DEVICE_IP_TUNNEL_TOS, "", "",
	                         0, 255, 0,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_PATH_MTU_DISCOVERY] =
	     g_param_spec_boolean (NM_DEVICE_IP_TUNNEL_PATH_MTU_DISCOVERY, "", "",
	                           FALSE,
	                           G_PARAM_READABLE |
	                           G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_INPUT_KEY] =
	     g_param_spec_string (NM_DEVICE_IP_TUNNEL_INPUT_KEY, "", "",
	                          NULL,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_OUTPUT_KEY] =
	     g_param_spec_string (NM_DEVICE_IP_TUNNEL_OUTPUT_KEY, "", "",
	                          NULL,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_ENCAPSULATION_LIMIT] =
	      g_param_spec_uchar (NM_DEVICE_IP_TUNNEL_ENCAPSULATION_LIMIT, "", "",
	                          0, 255, 0,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_FLOW_LABEL] =
	     g_param_spec_uint (NM_DEVICE_IP_TUNNEL_FLOW_LABEL, "", "",
	                        0, (1 << 20) - 1, 0,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_FLAGS] =
	     g_param_spec_uint (NM_DEVICE_IP_TUNNEL_FLAGS, "", "",
	                        0, G_MAXUINT32, 0,
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}

/*****************************************************************************/

#define NM_TYPE_IP_TUNNEL_DEVICE_FACTORY (nm_ip_tunnel_device_factory_get_type ())
#define NM_IP_TUNNEL_DEVICE_FACTORY(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_IP_TUNNEL_DEVICE_FACTORY, NMIPTunnelDeviceFactory))

static NMDevice *
create_device (NMDeviceFactory *factory,
               const char *iface,
               const NMPlatformLink *plink,
               NMConnection *connection,
               gboolean *out_ignore)
{
	NMSettingIPTunnel *s_ip_tunnel;
	NMIPTunnelMode mode;
	NMLinkType link_type;

	if (connection) {
		s_ip_tunnel = nm_connection_get_setting_ip_tunnel (connection);
		mode = nm_setting_ip_tunnel_get_mode (s_ip_tunnel);
		link_type = tunnel_mode_to_link_type (mode);
	} else {
		link_type = plink->type;
		mode = platform_link_to_tunnel_mode (plink);
	}

	if (mode == NM_IP_TUNNEL_MODE_UNKNOWN || link_type == NM_LINK_TYPE_UNKNOWN)
		return NULL;

	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_IP_TUNNEL,
	                                  NM_DEVICE_IFACE, iface,
	                                  NM_DEVICE_TYPE_DESC, "IPTunnel",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_IP_TUNNEL,
	                                  NM_DEVICE_LINK_TYPE, link_type,
	                                  NM_DEVICE_IP_TUNNEL_MODE, mode,
	                                  NULL);
}

static const char *
get_connection_parent (NMDeviceFactory *factory, NMConnection *connection)
{
	NMSettingIPTunnel *s_ip_tunnel;

	g_return_val_if_fail (nm_connection_is_type (connection, NM_SETTING_IP_TUNNEL_SETTING_NAME), NULL);

	s_ip_tunnel = nm_connection_get_setting_ip_tunnel (connection);
	g_assert (s_ip_tunnel);

	return nm_setting_ip_tunnel_get_parent (s_ip_tunnel);
}

static char *
get_connection_iface (NMDeviceFactory *factory,
                      NMConnection *connection,
                      const char *parent_iface)
{
	const char *ifname;
	NMSettingIPTunnel *s_ip_tunnel;

	g_return_val_if_fail (nm_connection_is_type (connection, NM_SETTING_IP_TUNNEL_SETTING_NAME), NULL);

	s_ip_tunnel = nm_connection_get_setting_ip_tunnel (connection);
	g_assert (s_ip_tunnel);

	if (nm_setting_ip_tunnel_get_parent (s_ip_tunnel) && !parent_iface)
		return NULL;

	ifname = nm_connection_get_interface_name (connection);

	return g_strdup (ifname);
}

NM_DEVICE_FACTORY_DEFINE_INTERNAL (IP_TUNNEL, IPTunnel, ip_tunnel,
	NM_DEVICE_FACTORY_DECLARE_LINK_TYPES (NM_LINK_TYPE_GRE,
	                                      NM_LINK_TYPE_GRETAP,
	                                      NM_LINK_TYPE_SIT,
	                                      NM_LINK_TYPE_IPIP,
	                                      NM_LINK_TYPE_IP6TNL,
	                                      NM_LINK_TYPE_IP6GRE,
	                                      NM_LINK_TYPE_IP6GRETAP)
	NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES (NM_SETTING_IP_TUNNEL_SETTING_NAME),
	factory_class->create_device = create_device;
	factory_class->get_connection_parent = get_connection_parent;
	factory_class->get_connection_iface = get_connection_iface;
);
