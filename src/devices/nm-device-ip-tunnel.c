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
 * Copyright 2015 Red Hat, Inc.
 */

#include "nm-default.h"

#include <string.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/ip.h>
#include <linux/if_tunnel.h>

#include "nm-device-ip-tunnel.h"
#include "nm-device-private.h"
#include "nm-manager.h"
#include "nm-platform.h"
#include "nm-device-factory.h"
#include "nm-core-internal.h"
#include "nm-connection-provider.h"
#include "nm-activation-request.h"
#include "nm-ip4-config.h"

#include "nmdbus-device-ip-tunnel.h"

#include "nm-device-logging.h"
_LOG_DECLARE_SELF(NMDeviceIPTunnel);

G_DEFINE_TYPE (NMDeviceIPTunnel, nm_device_ip_tunnel, NM_TYPE_DEVICE)

#define NM_DEVICE_IP_TUNNEL_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_IP_TUNNEL, NMDeviceIPTunnelPrivate))

typedef struct {
	NMIPTunnelMode mode;
	NMDevice *parent;
	int parent_ifindex;
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
} NMDeviceIPTunnelPrivate;

enum {
	PROP_0,
	PROP_MODE,
	PROP_PARENT,
	PROP_LOCAL,
	PROP_REMOTE,
	PROP_TTL,
	PROP_TOS,
	PROP_PATH_MTU_DISCOVERY,
	PROP_INPUT_KEY,
	PROP_OUTPUT_KEY,
	PROP_ENCAPSULATION_LIMIT,
	PROP_FLOW_LABEL,

	LAST_PROP
};

/**************************************************************/

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
	GObject *object = G_OBJECT (device);
	NMDevice *parent;
	int parent_ifindex;
	in_addr_t local4, remote4;
	struct in6_addr local6, remote6;
	guint8 ttl = 0, tos = 0, encap_limit = 0;
	gboolean pmtud = FALSE;
	guint32 flow_label = 0;
	char *key;

	if (ifindex <= 0) {
clear:
		if (priv->parent || priv->parent_ifindex) {
			g_clear_object (&priv->parent);
			priv->parent_ifindex = 0;
			g_object_notify (object, NM_DEVICE_IP_TUNNEL_PARENT);
		}
		if (priv->local) {
			g_clear_pointer (&priv->local, g_free);
			g_object_notify (object, NM_DEVICE_IP_TUNNEL_LOCAL);
		}
		if (priv->remote) {
			g_clear_pointer (&priv->remote, g_free);
			g_object_notify (object, NM_DEVICE_IP_TUNNEL_REMOTE);
		}
		if (priv->input_key) {
			g_clear_pointer (&priv->input_key, g_free);
			g_object_notify (object, NM_DEVICE_IP_TUNNEL_INPUT_KEY);
		}
		if (priv->output_key) {
			g_clear_pointer (&priv->output_key, g_free);
			g_object_notify (object, NM_DEVICE_IP_TUNNEL_OUTPUT_KEY);
		}

		goto out;
	}

	if (priv->mode == NM_IP_TUNNEL_MODE_GRE) {
		const NMPlatformLnkGre *lnk;

		lnk = nm_platform_link_get_lnk_gre (NM_PLATFORM_GET, ifindex, NULL);
		if (!lnk) {
			_LOGW (LOGD_HW, "could not read %s properties", "gre");
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
				g_object_notify (object, NM_DEVICE_IP_TUNNEL_INPUT_KEY);
			} else
				g_free (key);
		} else {
			if (priv->input_key) {
				g_clear_pointer (&priv->input_key, g_free);
				g_object_notify (object, NM_DEVICE_IP_TUNNEL_INPUT_KEY);
			}
		}

		if (NM_FLAGS_HAS (lnk->output_flags, NM_GRE_KEY)) {
			key = g_strdup_printf ("%u", lnk->output_key);
			if (g_strcmp0 (priv->output_key, key)) {
				g_free (priv->output_key);
				priv->output_key = key;
				g_object_notify (object, NM_DEVICE_IP_TUNNEL_OUTPUT_KEY);
			} else
				g_free (key);
		} else {
			if (priv->output_key) {
				g_clear_pointer (&priv->output_key, g_free);
				g_object_notify (object, NM_DEVICE_IP_TUNNEL_OUTPUT_KEY);
			}
		}
	} else if (priv->mode == NM_IP_TUNNEL_MODE_SIT) {
		const NMPlatformLnkSit *lnk;

		lnk = nm_platform_link_get_lnk_sit (NM_PLATFORM_GET, ifindex, NULL);
		if (!lnk) {
			_LOGW (LOGD_HW, "could not read %s properties", "sit");
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

		lnk = nm_platform_link_get_lnk_ipip (NM_PLATFORM_GET, ifindex, NULL);
		if (!lnk) {
			_LOGW (LOGD_HW, "could not read %s properties", "ipip");
			goto clear;
		}

		parent_ifindex = lnk->parent_ifindex;
		local4 = lnk->local;
		remote4 = lnk->remote;
		ttl = lnk->ttl;
		tos = lnk->tos;
		pmtud = lnk->path_mtu_discovery;
	} else if (   priv->mode == NM_IP_TUNNEL_MODE_IPIP6
	           || priv->mode == NM_IP_TUNNEL_MODE_IP6IP6) {
		const NMPlatformLnkIp6Tnl *lnk;

		lnk = nm_platform_link_get_lnk_ip6tnl (NM_PLATFORM_GET, ifindex, NULL);
		if (!lnk) {
			_LOGW (LOGD_HW, "could not read %s properties", "ip6tnl");
			goto clear;
		}

		parent_ifindex = lnk->parent_ifindex;
		local6 = lnk->local;
		remote6 = lnk->remote;
		ttl = lnk->ttl;
		tos = lnk->tclass;
		encap_limit = lnk->encap_limit;
		flow_label = lnk->flow_label;
	} else
		g_return_if_reached ();

	if (priv->parent_ifindex != parent_ifindex) {
		g_clear_object (&priv->parent);
		priv->parent_ifindex = parent_ifindex;
		parent = nm_manager_get_device_by_ifindex (nm_manager_get (), parent_ifindex);
		if (parent)
			priv->parent = g_object_ref (parent);
		g_object_notify (object, NM_DEVICE_IP_TUNNEL_PARENT);
	}

	if (priv->addr_family == AF_INET) {
		if (!address_equal_pn (AF_INET, priv->local, &local4)) {
			g_clear_pointer (&priv->local, g_free);
			if (local4)
				priv->local = g_strdup (nm_utils_inet4_ntop (local4, NULL));
			g_object_notify (object, NM_DEVICE_IP_TUNNEL_LOCAL);
		}

		if (!address_equal_pn (AF_INET, priv->remote, &remote4)) {
			g_clear_pointer (&priv->remote, g_free);
			if (remote4)
				priv->remote = g_strdup (nm_utils_inet4_ntop (remote4, NULL));
			g_object_notify (object, NM_DEVICE_IP_TUNNEL_REMOTE);
		}
	} else {
		if (!address_equal_pn (AF_INET6, priv->local, &local6)) {
			g_clear_pointer (&priv->local, g_free);
			if (memcmp (&local6, &in6addr_any, sizeof (in6addr_any)))
				priv->local = g_strdup (nm_utils_inet6_ntop (&local6, NULL));
			g_object_notify (object, NM_DEVICE_IP_TUNNEL_LOCAL);
		}

		if (!address_equal_pn (AF_INET6, priv->remote, &remote6)) {
			g_clear_pointer (&priv->remote, g_free);
			if (memcmp (&remote6, &in6addr_any, sizeof (in6addr_any)))
				priv->remote = g_strdup (nm_utils_inet6_ntop (&remote6, NULL));
			g_object_notify (object, NM_DEVICE_IP_TUNNEL_REMOTE);
		}
	}

out:

	if (priv->ttl != ttl) {
		priv->ttl = ttl;
		g_object_notify (object, NM_DEVICE_IP_TUNNEL_TTL);
	}

	if (priv->tos != tos) {
		priv->tos = tos;
		g_object_notify (object, NM_DEVICE_IP_TUNNEL_TOS);
	}

	if (priv->path_mtu_discovery != pmtud) {
		priv->path_mtu_discovery = pmtud;
		g_object_notify (object, NM_DEVICE_IP_TUNNEL_PATH_MTU_DISCOVERY);
	}

	if (priv->encap_limit != encap_limit) {
		priv->encap_limit = encap_limit;
		g_object_notify (object, NM_DEVICE_IP_TUNNEL_ENCAPSULATION_LIMIT);
	}

	if (priv->flow_label != flow_label) {
		priv->flow_label = flow_label;
		g_object_notify (object, NM_DEVICE_IP_TUNNEL_FLOW_LABEL);
	}
}

static void
update_properties (NMDevice *device)
{
	update_properties_from_ifindex (device, nm_device_get_ifindex (device));
}

static void
link_changed (NMDevice *device, NMPlatformLink *info)
{
	NM_DEVICE_CLASS (nm_device_ip_tunnel_parent_class)->link_changed (device, info);
	update_properties (device);
}

static gboolean
complete_connection (NMDevice *device,
                     NMConnection *connection,
                     const char *specific_object,
                     const GSList *existing_connections,
                     GError **error)
{
	NMSettingIPTunnel *s_ip_tunnel;

	nm_utils_complete_generic (NM_PLATFORM_GET,
	                           connection,
	                           NM_SETTING_IP_TUNNEL_SETTING_NAME,
	                           existing_connections,
	                           NULL,
	                           _("IP tunnel connection"),
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
	NMDevice *parent = NULL;
	const char *setting_parent, *new_parent;

	if (!s_ip_tunnel) {
		s_ip_tunnel = (NMSettingIPTunnel *) nm_setting_ip_tunnel_new ();
		nm_connection_add_setting (connection, (NMSetting *) s_ip_tunnel);
	}

	if (nm_setting_ip_tunnel_get_mode (s_ip_tunnel) != priv->mode)
		g_object_set (G_OBJECT (s_ip_tunnel), NM_SETTING_IP_TUNNEL_MODE, priv->mode, NULL);

	if (priv->parent_ifindex > 0)
		parent = nm_manager_get_device_by_ifindex (nm_manager_get (), priv->parent_ifindex);

	/* Update parent in the connection; default to parent's interface name */
	if (parent) {
		new_parent = nm_device_get_iface (parent);
		setting_parent = nm_setting_ip_tunnel_get_parent (s_ip_tunnel);
		if (setting_parent && nm_utils_is_uuid (setting_parent)) {
			NMConnection *parent_connection;

			/* Don't change a parent specified by UUID if it's still valid */
			parent_connection = nm_connection_provider_get_connection_by_uuid (nm_connection_provider_get (),
			                                                                   setting_parent);
			if (parent_connection && nm_device_check_connection_compatible (parent, parent_connection))
				new_parent = NULL;
		}
		if (new_parent)
			g_object_set (s_ip_tunnel, NM_SETTING_IP_TUNNEL_PARENT, new_parent, NULL);
	} else
		g_object_set (s_ip_tunnel, NM_SETTING_IP_TUNNEL_PARENT, NULL, NULL);

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

	if (priv->mode == NM_IP_TUNNEL_MODE_GRE || priv->mode == NM_IP_TUNNEL_MODE_IP6GRE) {
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
match_parent (NMDevice *dev_parent, const char *setting_parent)
{
	g_return_val_if_fail (setting_parent, FALSE);

	if (!dev_parent)
		return FALSE;

	if (nm_utils_is_uuid (setting_parent)) {
		NMActRequest *parent_req;
		NMConnection *parent_connection;

		/* If the parent is a UUID, the connection matches if our parent
		 * device has that connection activated.
		 */
		parent_req = nm_device_get_act_request (dev_parent);
		if (!parent_req)
			return FALSE;

		parent_connection = nm_active_connection_get_applied_connection (NM_ACTIVE_CONNECTION (parent_req));
		if (!parent_connection)
			return FALSE;

		if (g_strcmp0 (setting_parent, nm_connection_get_uuid (parent_connection)) != 0)
			return FALSE;
	} else {
		/* interface name */
		if (g_strcmp0 (setting_parent, nm_device_get_ip_iface (dev_parent)) != 0)
			return FALSE;
	}

	return TRUE;
}

static gboolean
check_connection_compatible (NMDevice *device, NMConnection *connection)
{
	NMDeviceIPTunnel *self = NM_DEVICE_IP_TUNNEL (device);
	NMDeviceIPTunnelPrivate *priv = NM_DEVICE_IP_TUNNEL_GET_PRIVATE (self);
	NMSettingIPTunnel *s_ip_tunnel;
	const char *parent;

	if (!NM_DEVICE_CLASS (nm_device_ip_tunnel_parent_class)->check_connection_compatible (device, connection))
		return FALSE;

	s_ip_tunnel = nm_connection_get_setting_ip_tunnel (connection);
	if (!s_ip_tunnel)
		return FALSE;

	if (nm_setting_ip_tunnel_get_mode (s_ip_tunnel) != priv->mode)
		return FALSE;

	if (nm_device_is_real (device)) {
		/* Check parent interface; could be an interface name or a UUID */
		parent = nm_setting_ip_tunnel_get_parent (s_ip_tunnel);
		if (parent) {
			if (!match_parent (priv->parent, parent))
				return FALSE;
		}

		if (!address_equal_pp (priv->addr_family,
		                       nm_setting_ip_tunnel_get_local (s_ip_tunnel),
		                       priv->local))
			return FALSE;

		if (!address_equal_pp (priv->addr_family,
		                       nm_setting_ip_tunnel_get_remote (s_ip_tunnel),
		                       priv->remote))
			return FALSE;

		if (nm_setting_ip_tunnel_get_ttl (s_ip_tunnel) != priv->ttl)
			return FALSE;

		if (nm_setting_ip_tunnel_get_tos (s_ip_tunnel) != priv->tos)
			return FALSE;

		if (priv->addr_family == AF_INET) {
			if (nm_setting_ip_tunnel_get_path_mtu_discovery (s_ip_tunnel) != priv->path_mtu_discovery)
				return FALSE;
		} else {
			if (nm_setting_ip_tunnel_get_encapsulation_limit (s_ip_tunnel) != priv->encap_limit)
				return FALSE;

			if (nm_setting_ip_tunnel_get_flow_label (s_ip_tunnel) != priv->flow_label)
				return FALSE;
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
	case NM_LINK_TYPE_IP6TNL:
		lnk = nm_platform_link_get_lnk_ip6tnl (NM_PLATFORM_GET, link->ifindex, NULL);
		if (lnk->proto == IPPROTO_IPIP)
			return NM_IP_TUNNEL_MODE_IPIP6;
		else if (lnk->proto == IPPROTO_IPV6)
			return NM_IP_TUNNEL_MODE_IP6IP6;
		else
			return NM_IP_TUNNEL_MODE_UNKNOWN;
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
	case NM_IP_TUNNEL_MODE_IPIP6:
	case NM_IP_TUNNEL_MODE_IP6IP6:
		return NM_LINK_TYPE_IP6TNL;
	case NM_IP_TUNNEL_MODE_IPIP:
		return NM_LINK_TYPE_IPIP;
	case NM_IP_TUNNEL_MODE_SIT:
		return NM_LINK_TYPE_SIT;
	default:
		g_return_val_if_reached (NM_LINK_TYPE_UNKNOWN);
	}
}

/**************************************************************/

static void
nm_device_ip_tunnel_init (NMDeviceIPTunnel *self)
{
}

static void
constructed (GObject *object)
{
	NMDeviceIPTunnelPrivate *priv = NM_DEVICE_IP_TUNNEL_GET_PRIVATE (object);

	if (   priv->mode == NM_IP_TUNNEL_MODE_IPIP6
	    || priv->mode == NM_IP_TUNNEL_MODE_IP6IP6)
		priv->addr_family = AF_INET6;
	else
		priv->addr_family = AF_INET;

	G_OBJECT_CLASS (nm_device_ip_tunnel_parent_class)->constructed (object);
}

static gboolean
create_and_realize (NMDevice *device,
                    NMConnection *connection,
                    NMDevice *parent,
                    const NMPlatformLink **out_plink,
                    GError **error)
{
	const char *iface = nm_device_get_iface (device);
	NMSettingIPTunnel *s_ip_tunnel;
	NMPlatformError plerr;
	NMPlatformLnkGre lnk_gre = { };
	NMPlatformLnkSit lnk_sit = { };
	NMPlatformLnkIpIp lnk_ipip = { };
	NMPlatformLnkIp6Tnl lnk_ip6tnl = { };
	const char *str;
	gint64 val;

	s_ip_tunnel = nm_connection_get_setting_ip_tunnel (connection);
	g_assert (s_ip_tunnel);

	switch (nm_setting_ip_tunnel_get_mode (s_ip_tunnel)) {
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

		plerr = nm_platform_link_gre_add (NM_PLATFORM_GET, iface, &lnk_gre, out_plink);
		if (plerr != NM_PLATFORM_ERROR_SUCCESS) {
			g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_CREATION_FAILED,
			             "Failed to create GRE interface '%s' for '%s': %s",
			             iface,
			             nm_connection_get_id (connection),
			             nm_platform_error_to_string (plerr));
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

		plerr = nm_platform_link_sit_add (NM_PLATFORM_GET, iface, &lnk_sit, out_plink);
		if (plerr != NM_PLATFORM_ERROR_SUCCESS) {
			g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_CREATION_FAILED,
					"Failed to create SIT interface '%s' for '%s': %s",
					iface,
					nm_connection_get_id (connection),
					nm_platform_error_to_string (plerr));
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

		plerr = nm_platform_link_ipip_add (NM_PLATFORM_GET, iface, &lnk_ipip, out_plink);
		if (plerr != NM_PLATFORM_ERROR_SUCCESS) {
			g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_CREATION_FAILED,
					"Failed to create IPIP interface '%s' for '%s': %s",
					iface,
					nm_connection_get_id (connection),
					nm_platform_error_to_string (plerr));
			return FALSE;
		}
		break;
	case NM_IP_TUNNEL_MODE_IPIP6:
	case NM_IP_TUNNEL_MODE_IP6IP6:
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
		lnk_ip6tnl.proto = nm_setting_ip_tunnel_get_mode (s_ip_tunnel) == NM_IP_TUNNEL_MODE_IPIP6 ? IPPROTO_IPIP : IPPROTO_IPV6;

		plerr = nm_platform_link_ip6tnl_add (NM_PLATFORM_GET, iface, &lnk_ip6tnl, out_plink);
		if (plerr != NM_PLATFORM_ERROR_SUCCESS) {
			g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_CREATION_FAILED,
			             "Failed to create IPIP interface '%s' for '%s': %s",
			             iface,
			             nm_connection_get_id (connection),
			             nm_platform_error_to_string (plerr));
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

static void
realize_start_notify (NMDevice *device, const NMPlatformLink *plink)
{
	NM_DEVICE_CLASS (nm_device_ip_tunnel_parent_class)->realize_start_notify (device, plink);

	update_properties (device);
}

static void
ip4_config_pre_commit (NMDevice *device, NMIP4Config *config)
{
	NMConnection *connection;
	NMSettingIPTunnel *s_ip_tunnel;
	guint32 mtu;

	connection = nm_device_get_applied_connection (device);
	g_assert (connection);
	s_ip_tunnel = nm_connection_get_setting_ip_tunnel (connection);
	g_assert (s_ip_tunnel);

	/* MTU override */
	mtu = nm_setting_ip_tunnel_get_mtu (s_ip_tunnel);
	if (mtu)
		nm_ip4_config_set_mtu (config, mtu, NM_IP_CONFIG_SOURCE_USER);
}

static NMDeviceCapabilities
get_generic_capabilities (NMDevice *dev)
{
	return NM_DEVICE_CAP_IS_SOFTWARE;
}

static void
unrealize_notify (NMDevice *device)
{
	NM_DEVICE_CLASS (nm_device_ip_tunnel_parent_class)->unrealize_notify (device);

	update_properties_from_ifindex (device, 0);
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMDeviceIPTunnelPrivate *priv = NM_DEVICE_IP_TUNNEL_GET_PRIVATE (object);
	NMDevice *parent;

	switch (prop_id) {
	case PROP_MODE:
		g_value_set_uint (value, priv->mode);
		break;
	case PROP_PARENT:
		parent = nm_manager_get_device_by_ifindex (nm_manager_get (), priv->parent_ifindex);
		nm_utils_g_value_set_object_path (value, parent);
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
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object, guint prop_id,
			  const GValue *value, GParamSpec *pspec)
{
	NMDeviceIPTunnelPrivate *priv = NM_DEVICE_IP_TUNNEL_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_MODE:
		priv->mode = g_value_get_uint (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
	}
}

static void
nm_device_ip_tunnel_class_init (NMDeviceIPTunnelClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMDeviceIPTunnelPrivate));

	object_class->constructed = constructed;
	object_class->get_property = get_property;
	object_class->set_property = set_property;

	device_class->link_changed = link_changed;
	device_class->complete_connection = complete_connection;
	device_class->update_connection = update_connection;
	device_class->check_connection_compatible = check_connection_compatible;
	device_class->create_and_realize = create_and_realize;
	device_class->get_generic_capabilities = get_generic_capabilities;
	device_class->ip4_config_pre_commit = ip4_config_pre_commit;
	device_class->realize_start_notify = realize_start_notify;
	device_class->unrealize_notify = unrealize_notify;

	NM_DEVICE_CLASS_DECLARE_TYPES (klass,
	                               NM_SETTING_IP_TUNNEL_SETTING_NAME,
	                               NM_LINK_TYPE_GRE,
	                               NM_LINK_TYPE_IP6TNL,
	                               NM_LINK_TYPE_IPIP,
	                               NM_LINK_TYPE_SIT);

	/* properties */
	g_object_class_install_property
		(object_class, PROP_MODE,
		 g_param_spec_uint (NM_DEVICE_IP_TUNNEL_MODE, "", "",
		                    0, G_MAXUINT, 0,
		                    G_PARAM_READWRITE |
		                    G_PARAM_CONSTRUCT_ONLY |
		                    G_PARAM_STATIC_STRINGS));

	/* properties */
	g_object_class_install_property
		(object_class, PROP_PARENT,
		 g_param_spec_string (NM_DEVICE_IP_TUNNEL_PARENT, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_LOCAL,
		 g_param_spec_string (NM_DEVICE_IP_TUNNEL_LOCAL, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_REMOTE,
		 g_param_spec_string (NM_DEVICE_IP_TUNNEL_REMOTE, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_TTL,
		 g_param_spec_uchar (NM_DEVICE_IP_TUNNEL_TTL, "", "",
		                     0, 255, 0,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_TOS,
		 g_param_spec_uchar (NM_DEVICE_IP_TUNNEL_TOS, "", "",
		                     0, 255, 0,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_PATH_MTU_DISCOVERY,
		 g_param_spec_boolean (NM_DEVICE_IP_TUNNEL_PATH_MTU_DISCOVERY, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_INPUT_KEY,
		 g_param_spec_string (NM_DEVICE_IP_TUNNEL_INPUT_KEY, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_OUTPUT_KEY,
		 g_param_spec_string (NM_DEVICE_IP_TUNNEL_OUTPUT_KEY, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_ENCAPSULATION_LIMIT,
		  g_param_spec_uchar (NM_DEVICE_IP_TUNNEL_ENCAPSULATION_LIMIT, "", "",
		                      0, 255, 0,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_FLOW_LABEL,
		 g_param_spec_uint (NM_DEVICE_IP_TUNNEL_FLOW_LABEL, "", "",
		                    0, (1 << 20) - 1, 0,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (klass),
	                                        NMDBUS_TYPE_DEVICE_IPTUNNEL_SKELETON,
	                                        NULL);
}
/*************************************************************/

#define NM_TYPE_IP_TUNNEL_FACTORY (nm_ip_tunnel_factory_get_type ())
#define NM_IP_TUNNEL_FACTORY(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_IP_TUNNEL_FACTORY, NMIPTunnelFactory))

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

	if (mode == NM_IP_TUNNEL_MODE_UNKNOWN)
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
	NM_DEVICE_FACTORY_DECLARE_LINK_TYPES (NM_LINK_TYPE_GRE, NM_LINK_TYPE_SIT, NM_LINK_TYPE_IPIP)
	NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES (NM_SETTING_IP_TUNNEL_SETTING_NAME),
	factory_iface->create_device = create_device;
	factory_iface->get_connection_parent = get_connection_parent;
	factory_iface->get_connection_iface = get_connection_iface;
)
