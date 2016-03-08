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
 * Copyright 2013 - 2015 Red Hat, Inc.
 */

#include "nm-default.h"

#include <string.h>

#include "nm-device-vxlan.h"
#include "nm-device-private.h"
#include "nm-manager.h"
#include "nm-platform.h"
#include "nm-utils.h"
#include "nm-device-factory.h"
#include "nm-setting-vxlan.h"
#include "nm-setting-wired.h"
#include "nm-connection-provider.h"
#include "nm-activation-request.h"
#include "nm-ip4-config.h"

#include "nmdbus-device-vxlan.h"

#include "nm-device-logging.h"
_LOG_DECLARE_SELF(NMDeviceVxlan);

G_DEFINE_TYPE (NMDeviceVxlan, nm_device_vxlan, NM_TYPE_DEVICE)

#define NM_DEVICE_VXLAN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_VXLAN, NMDeviceVxlanPrivate))

typedef struct {
	NMDevice *parent;
	NMPlatformLnkVxlan props;
} NMDeviceVxlanPrivate;

enum {
	PROP_0,
	PROP_PARENT,
	PROP_ID,
	PROP_LOCAL,
	PROP_GROUP,
	PROP_TOS,
	PROP_TTL,
	PROP_LEARNING,
	PROP_AGEING,
	PROP_LIMIT,
	PROP_SRC_PORT_MIN,
	PROP_SRC_PORT_MAX,
	PROP_DST_PORT,
	PROP_PROXY,
	PROP_RSC,
	PROP_L2MISS,
	PROP_L3MISS,

	LAST_PROP
};

/**************************************************************/

static void
update_properties (NMDevice *device)
{
	NMDeviceVxlan *self = NM_DEVICE_VXLAN (device);
	NMDeviceVxlanPrivate *priv = NM_DEVICE_VXLAN_GET_PRIVATE (device);
	GObject *object = G_OBJECT (device);
	const NMPlatformLnkVxlan *props;
	NMDevice *parent;

	props = nm_platform_link_get_lnk_vxlan (NM_PLATFORM_GET, nm_device_get_ifindex (device), NULL);
	if (!props) {
		_LOGW (LOGD_HW, "could not get vxlan properties");
		return;
	}

	g_object_freeze_notify (object);

	if (priv->props.parent_ifindex != props->parent_ifindex) {
		g_clear_object (&priv->parent);
		parent = nm_manager_get_device_by_ifindex (nm_manager_get (), props->parent_ifindex);
		if (parent)
			priv->parent = g_object_ref (parent);
		g_object_notify (object, NM_DEVICE_VXLAN_PARENT);
	}
	if (priv->props.id != props->id)
		g_object_notify (object, NM_DEVICE_VXLAN_ID);
	if (priv->props.local != props->local)
		g_object_notify (object, NM_DEVICE_VXLAN_LOCAL);
	if (memcmp (&priv->props.local6, &props->local6, sizeof (props->local6)) != 0)
		g_object_notify (object, NM_DEVICE_VXLAN_LOCAL);
	if (priv->props.group != props->group)
		g_object_notify (object, NM_DEVICE_VXLAN_GROUP);
	if (memcmp (&priv->props.group6, &props->group6, sizeof (props->group6)) != 0)
		g_object_notify (object, NM_DEVICE_VXLAN_GROUP);
	if (priv->props.tos != props->tos)
		g_object_notify (object, NM_DEVICE_VXLAN_TOS);
	if (priv->props.ttl != props->ttl)
		g_object_notify (object, NM_DEVICE_VXLAN_TTL);
	if (priv->props.learning != props->learning)
		g_object_notify (object, NM_DEVICE_VXLAN_LEARNING);
	if (priv->props.ageing != props->ageing)
		g_object_notify (object, NM_DEVICE_VXLAN_AGEING);
	if (priv->props.limit != props->limit)
		g_object_notify (object, NM_DEVICE_VXLAN_LIMIT);
	if (priv->props.src_port_min != props->src_port_min)
		g_object_notify (object, NM_DEVICE_VXLAN_SRC_PORT_MIN);
	if (priv->props.src_port_max != props->src_port_max)
		g_object_notify (object, NM_DEVICE_VXLAN_SRC_PORT_MAX);
	if (priv->props.dst_port != props->dst_port)
		g_object_notify (object, NM_DEVICE_VXLAN_DST_PORT);
	if (priv->props.proxy != props->proxy)
		g_object_notify (object, NM_DEVICE_VXLAN_PROXY);
	if (priv->props.rsc != props->rsc)
		g_object_notify (object, NM_DEVICE_VXLAN_RSC);
	if (priv->props.l2miss != props->l2miss)
		g_object_notify (object, NM_DEVICE_VXLAN_L2MISS);
	if (priv->props.l3miss != props->l3miss)
		g_object_notify (object, NM_DEVICE_VXLAN_L3MISS);

	priv->props = *props;

	g_object_thaw_notify (object);
}

static void
link_changed (NMDevice *device, NMPlatformLink *info)
{
	NM_DEVICE_CLASS (nm_device_vxlan_parent_class)->link_changed (device, info);
	update_properties (device);
}

static void
realize_start_notify (NMDevice *device, const NMPlatformLink *plink)
{
	g_assert (plink->type == NM_LINK_TYPE_VXLAN);

	NM_DEVICE_CLASS (nm_device_vxlan_parent_class)->realize_start_notify (device, plink);

	update_properties (device);
}

static void
unrealize_notify (NMDevice *device)
{
	NMDeviceVxlan *self = NM_DEVICE_VXLAN (device);
	NMDeviceVxlanPrivate *priv = NM_DEVICE_VXLAN_GET_PRIVATE (self);
	GParamSpec **properties;
	guint n_properties, i;

	NM_DEVICE_CLASS (nm_device_vxlan_parent_class)->unrealize_notify (device);

	memset (&priv->props, 0, sizeof (NMPlatformLnkVxlan));

	properties = g_object_class_list_properties (G_OBJECT_GET_CLASS (self), &n_properties);
	for (i = 0; i < n_properties; i++)
		g_object_notify_by_pspec (G_OBJECT (self), properties[i]);
	g_free (properties);
}

static gboolean
create_and_realize (NMDevice *device,
                    NMConnection *connection,
                    NMDevice *parent,
                    const NMPlatformLink **out_plink,
                    GError **error)
{
	const char *iface = nm_device_get_iface (device);
	NMPlatformError plerr;
	NMPlatformLnkVxlan props = { };
	NMSettingVxlan *s_vxlan;
	const char *str;
	int ret;

	s_vxlan = nm_connection_get_setting_vxlan (connection);
	g_assert (s_vxlan);

	if (parent)
		props.parent_ifindex = nm_device_get_ifindex (parent);

	props.id = nm_setting_vxlan_get_id (s_vxlan);

	str = nm_setting_vxlan_get_local (s_vxlan);
	if (str) {
		ret = inet_pton (AF_INET, str, &props.local);
		if (ret != 1)
			ret = inet_pton (AF_INET6, str, &props.local6);
		if (ret != 1)
			return FALSE;
	}

	str = nm_setting_vxlan_get_remote (s_vxlan);
	ret = inet_pton (AF_INET, str, &props.group);
	if (ret != 1)
		ret = inet_pton (AF_INET6, str, &props.group6);
	if (ret != 1)
		return FALSE;

	props.tos = nm_setting_vxlan_get_tos (s_vxlan);
	props.ttl = nm_setting_vxlan_get_ttl (s_vxlan);
	props.learning = nm_setting_vxlan_get_learning (s_vxlan);
	props.ageing = nm_setting_vxlan_get_ageing (s_vxlan);
	props.limit = nm_setting_vxlan_get_limit (s_vxlan);
	props.src_port_min = nm_setting_vxlan_get_source_port_min (s_vxlan);
	props.src_port_max = nm_setting_vxlan_get_source_port_max (s_vxlan);
	props.dst_port = nm_setting_vxlan_get_destination_port (s_vxlan);
	props.proxy = nm_setting_vxlan_get_proxy (s_vxlan);
	props.rsc = nm_setting_vxlan_get_rsc (s_vxlan);
	props.l2miss = nm_setting_vxlan_get_l2_miss (s_vxlan);
	props.l3miss = nm_setting_vxlan_get_l3_miss (s_vxlan);

	plerr = nm_platform_link_vxlan_add (NM_PLATFORM_GET, iface, &props, out_plink);
	if (plerr != NM_PLATFORM_ERROR_SUCCESS) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_CREATION_FAILED,
		             "Failed to create VXLAN interface '%s' for '%s': %s",
		             iface,
		             nm_connection_get_id (connection),
		             nm_platform_error_to_string (plerr));
		return FALSE;
	}

	return TRUE;
}

static gboolean
match_parent (NMDeviceVxlan *self, const char *parent)
{
	NMDeviceVxlanPrivate *priv = NM_DEVICE_VXLAN_GET_PRIVATE (self);

	g_return_val_if_fail (parent != NULL, FALSE);

	if (!priv->parent)
		return FALSE;

	if (nm_utils_is_uuid (parent)) {
		NMActRequest *parent_req;
		NMConnection *parent_connection;

		/* If the parent is a UUID, the connection matches if our parent
		 * device has that connection activated.
		 */
		parent_req = nm_device_get_act_request (priv->parent);
		if (!parent_req)
			return FALSE;

		parent_connection = nm_active_connection_get_applied_connection (NM_ACTIVE_CONNECTION (parent_req));
		if (!parent_connection)
			return FALSE;

		if (g_strcmp0 (parent, nm_connection_get_uuid (parent_connection)) != 0)
			return FALSE;
	} else {
		/* interface name */
		if (g_strcmp0 (parent, nm_device_get_ip_iface (priv->parent)) != 0)
			return FALSE;
	}

	return TRUE;
}

static gboolean
address_matches (const char *str, in_addr_t addr4, struct in6_addr *addr6)
{
	in_addr_t new_addr4 = 0;
	struct in6_addr new_addr6 = { };

	if (!str) {
		return    addr4 == 0
		       && !memcmp (addr6, &in6addr_any, sizeof (in6addr_any));
	}

	if (inet_pton (AF_INET, str, &new_addr4) == 1)
		return new_addr4 == addr4;
	else if (inet_pton (AF_INET6, str, &new_addr6) == 1)
		return !memcmp (&new_addr6, addr6, sizeof (new_addr6));
	else
		return FALSE;
}

static gboolean
check_connection_compatible (NMDevice *device, NMConnection *connection)
{
	NMDeviceVxlanPrivate *priv = NM_DEVICE_VXLAN_GET_PRIVATE (device);
	NMSettingVxlan *s_vxlan;
	const char *parent;

	if (!NM_DEVICE_CLASS (nm_device_vxlan_parent_class)->check_connection_compatible (device, connection))
		return FALSE;

	s_vxlan = nm_connection_get_setting_vxlan (connection);
	if (!s_vxlan)
		return FALSE;

	if (nm_device_is_real (device)) {
		parent = nm_setting_vxlan_get_parent (s_vxlan);
		if (   parent
		    && !match_parent (NM_DEVICE_VXLAN (device), parent))
			return FALSE;

		if (priv->props.id != nm_setting_vxlan_get_id (s_vxlan))
			return FALSE;

		if (!address_matches (nm_setting_vxlan_get_local (s_vxlan), priv->props.local, &priv->props.local6))
			return FALSE;

		if (!address_matches (nm_setting_vxlan_get_remote (s_vxlan), priv->props.group, &priv->props.group6))
			return FALSE;

		if (priv->props.src_port_min != nm_setting_vxlan_get_source_port_min (s_vxlan))
			return FALSE;

		if (priv->props.src_port_max != nm_setting_vxlan_get_source_port_max (s_vxlan))
			return FALSE;

		if (priv->props.dst_port != nm_setting_vxlan_get_destination_port (s_vxlan))
			return FALSE;

		if (priv->props.tos != nm_setting_vxlan_get_tos (s_vxlan))
			return FALSE;

		if (priv->props.ttl != nm_setting_vxlan_get_ttl (s_vxlan))
			return FALSE;

		if (priv->props.learning != nm_setting_vxlan_get_learning (s_vxlan))
			return FALSE;

		if (priv->props.ageing != nm_setting_vxlan_get_ageing (s_vxlan))
			return FALSE;

		if (priv->props.proxy != nm_setting_vxlan_get_proxy (s_vxlan))
			return FALSE;

		if (priv->props.rsc != nm_setting_vxlan_get_rsc (s_vxlan))
			return FALSE;

		if (priv->props.l2miss != nm_setting_vxlan_get_l2_miss (s_vxlan))
			return FALSE;

		if (priv->props.l3miss != nm_setting_vxlan_get_l3_miss (s_vxlan))
			return FALSE;
	}

	return TRUE;
}

static gboolean
complete_connection (NMDevice *device,
                     NMConnection *connection,
                     const char *specific_object,
                     const GSList *existing_connections,
                     GError **error)
{
	NMSettingVxlan *s_vxlan;

	nm_utils_complete_generic (NM_PLATFORM_GET,
	                           connection,
	                           NM_SETTING_VXLAN_SETTING_NAME,
	                           existing_connections,
	                           NULL,
	                           _("VXLAN connection"),
	                           NULL,
	                           TRUE);

	s_vxlan = nm_connection_get_setting_vxlan (connection);
	if (!s_vxlan) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INVALID_CONNECTION,
		                     "A 'vxlan' setting is required.");
		return FALSE;
	}

	return TRUE;
}

static void
update_connection (NMDevice *device, NMConnection *connection)
{
	NMDeviceVxlanPrivate *priv = NM_DEVICE_VXLAN_GET_PRIVATE (device);
	NMSettingVxlan *s_vxlan = nm_connection_get_setting_vxlan (connection);
	NMDevice *parent = NULL;
	const char *setting_parent, *new_parent;

	if (!s_vxlan) {
		s_vxlan = (NMSettingVxlan *) nm_setting_vxlan_new ();
		nm_connection_add_setting (connection, (NMSetting *) s_vxlan);
	}

	if (priv->props.id != nm_setting_vxlan_get_id (s_vxlan))
		g_object_set (G_OBJECT (s_vxlan), NM_SETTING_VXLAN_ID, priv->props.id, NULL);

	if (priv->props.parent_ifindex != NM_PLATFORM_LINK_OTHER_NETNS)
		parent = nm_manager_get_device_by_ifindex (nm_manager_get (), priv->props.parent_ifindex);

	/* Update parent in the connection; default to parent's interface name */
	if (parent) {
		new_parent = nm_device_get_iface (parent);
		setting_parent = nm_setting_vxlan_get_parent (s_vxlan);
		if (setting_parent && nm_utils_is_uuid (setting_parent)) {
			NMConnection *parent_connection;

			/* Don't change a parent specified by UUID if it's still valid */
			parent_connection = nm_connection_provider_get_connection_by_uuid (nm_connection_provider_get (),
			                                                                   setting_parent);
			if (parent_connection && nm_device_check_connection_compatible (parent, parent_connection))
				new_parent = NULL;
		}
		if (new_parent)
			g_object_set (s_vxlan, NM_SETTING_VXLAN_PARENT, new_parent, NULL);
	} else
		g_object_set (s_vxlan, NM_SETTING_VXLAN_PARENT, NULL, NULL);

	if (!address_matches (nm_setting_vxlan_get_remote (s_vxlan), priv->props.group, &priv->props.group6)) {
		if (priv->props.group) {
			g_object_set (s_vxlan, NM_SETTING_VXLAN_REMOTE,
			              nm_utils_inet4_ntop (priv->props.group, NULL),
			              NULL);
		} else {
			g_object_set (s_vxlan, NM_SETTING_VXLAN_REMOTE,
			              nm_utils_inet6_ntop (&priv->props.group6, NULL),
			              NULL);
		}
	}

	if (!address_matches (nm_setting_vxlan_get_local (s_vxlan), priv->props.local, &priv->props.local6)) {
		if (priv->props.local) {
			g_object_set (s_vxlan, NM_SETTING_VXLAN_LOCAL,
			              nm_utils_inet4_ntop (priv->props.local, NULL),
			              NULL);
		} else if (memcmp (&priv->props.local6, &in6addr_any, sizeof (in6addr_any))) {
			g_object_set (s_vxlan, NM_SETTING_VXLAN_LOCAL,
			              nm_utils_inet6_ntop (&priv->props.local6, NULL),
			              NULL);
		}
	}

	if (priv->props.src_port_min != nm_setting_vxlan_get_source_port_min (s_vxlan)) {
		g_object_set (G_OBJECT (s_vxlan), NM_SETTING_VXLAN_SOURCE_PORT_MIN,
		              priv->props.src_port_min, NULL);
	}

	if (priv->props.src_port_max != nm_setting_vxlan_get_source_port_max (s_vxlan)) {
		g_object_set (G_OBJECT (s_vxlan), NM_SETTING_VXLAN_SOURCE_PORT_MAX,
		              priv->props.src_port_max, NULL);
	}

	if (priv->props.dst_port != nm_setting_vxlan_get_destination_port (s_vxlan)) {
		g_object_set (G_OBJECT (s_vxlan), NM_SETTING_VXLAN_DESTINATION_PORT,
		              priv->props.dst_port, NULL);
	}

	if (priv->props.tos != nm_setting_vxlan_get_tos (s_vxlan)) {
		g_object_set (G_OBJECT (s_vxlan), NM_SETTING_VXLAN_TOS,
		              priv->props.tos, NULL);
	}

	if (priv->props.ttl != nm_setting_vxlan_get_ttl (s_vxlan)) {
		g_object_set (G_OBJECT (s_vxlan), NM_SETTING_VXLAN_TTL,
		              priv->props.ttl, NULL);
	}

	if (priv->props.learning != nm_setting_vxlan_get_learning (s_vxlan)) {
		g_object_set (G_OBJECT (s_vxlan), NM_SETTING_VXLAN_LEARNING,
		              priv->props.learning, NULL);
	}

	if (priv->props.ageing != nm_setting_vxlan_get_ageing (s_vxlan)) {
		g_object_set (G_OBJECT (s_vxlan), NM_SETTING_VXLAN_AGEING,
		              priv->props.ageing, NULL);
	}

	if (priv->props.proxy != nm_setting_vxlan_get_proxy (s_vxlan)) {
		g_object_set (G_OBJECT (s_vxlan), NM_SETTING_VXLAN_PROXY,
		              priv->props.proxy, NULL);
	}

	if (priv->props.rsc != nm_setting_vxlan_get_rsc (s_vxlan)) {
		g_object_set (G_OBJECT (s_vxlan), NM_SETTING_VXLAN_RSC,
		              priv->props.rsc, NULL);
	}

	if (priv->props.l2miss != nm_setting_vxlan_get_l2_miss (s_vxlan)) {
		g_object_set (G_OBJECT (s_vxlan), NM_SETTING_VXLAN_L2_MISS,
		              priv->props.l2miss, NULL);
	}

	if (priv->props.l3miss != nm_setting_vxlan_get_l3_miss (s_vxlan)) {
		g_object_set (G_OBJECT (s_vxlan), NM_SETTING_VXLAN_L3_MISS,
		              priv->props.l3miss, NULL);
	}
}

static NMActStageReturn
act_stage1_prepare (NMDevice *device, NMDeviceStateReason *reason)
{
	NMSettingWired *s_wired;
	const char *cloned_mac;
	NMActStageReturn ret;

	g_return_val_if_fail (reason != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	ret = NM_DEVICE_CLASS (nm_device_vxlan_parent_class)->act_stage1_prepare (device, reason);
	if (ret != NM_ACT_STAGE_RETURN_SUCCESS)
		return ret;

	s_wired = (NMSettingWired *) nm_device_get_applied_setting (device, NM_TYPE_SETTING_WIRED);
	if (s_wired) {
		/* Set device MAC address if the connection wants to change it */
		cloned_mac = nm_setting_wired_get_cloned_mac_address (s_wired);
		nm_device_set_hw_addr (device, cloned_mac, "set", LOGD_DEVICE);
	}

	return NM_ACT_STAGE_RETURN_SUCCESS;
}

static void
ip4_config_pre_commit (NMDevice *device, NMIP4Config *config)
{
	NMConnection *connection;
	NMSettingWired *s_wired;
	guint32 mtu;

	connection = nm_device_get_applied_connection (device);
	g_assert (connection);

	s_wired = nm_connection_get_setting_wired (connection);
	if (s_wired) {
		mtu = nm_setting_wired_get_mtu (s_wired);
		if (mtu)
			nm_ip4_config_set_mtu (config, mtu, NM_IP_CONFIG_SOURCE_USER);
	}
}

/**************************************************************/

static void
nm_device_vxlan_init (NMDeviceVxlan *self)
{
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMDeviceVxlanPrivate *priv = NM_DEVICE_VXLAN_GET_PRIVATE (object);
	NMDevice *parent;

	switch (prop_id) {
	case PROP_PARENT:
		parent = nm_manager_get_device_by_ifindex (nm_manager_get (), priv->props.parent_ifindex);
		nm_utils_g_value_set_object_path (value, parent);
		break;
	case PROP_ID:
		g_value_set_uint (value, priv->props.id);
		break;
	case PROP_GROUP:
		if (priv->props.group)
			g_value_set_string (value, nm_utils_inet4_ntop (priv->props.group, NULL));
		else if (!IN6_IS_ADDR_UNSPECIFIED (&priv->props.group6))
			g_value_set_string (value, nm_utils_inet6_ntop (&priv->props.group6, NULL));
		break;
	case PROP_LOCAL:
		if (priv->props.local)
			g_value_set_string (value, nm_utils_inet4_ntop (priv->props.local, NULL));
		else if (!IN6_IS_ADDR_UNSPECIFIED (&priv->props.local6))
			g_value_set_string (value, nm_utils_inet6_ntop (&priv->props.local6, NULL));
		break;
	case PROP_TOS:
		g_value_set_uchar (value, priv->props.tos);
		break;
	case PROP_TTL:
		g_value_set_uchar (value, priv->props.ttl);
		break;
	case PROP_LEARNING:
		g_value_set_boolean (value, priv->props.learning);
		break;
	case PROP_AGEING:
		g_value_set_uint (value, priv->props.ageing);
		break;
	case PROP_LIMIT:
		g_value_set_uint (value, priv->props.limit);
		break;
	case PROP_DST_PORT:
		g_value_set_uint (value, priv->props.dst_port);
		break;
	case PROP_SRC_PORT_MIN:
		g_value_set_uint (value, priv->props.src_port_min);
		break;
	case PROP_SRC_PORT_MAX:
		g_value_set_uint (value, priv->props.src_port_max);
		break;
	case PROP_PROXY:
		g_value_set_boolean (value, priv->props.proxy);
		break;
	case PROP_RSC:
		g_value_set_boolean (value, priv->props.rsc);
		break;
	case PROP_L2MISS:
		g_value_set_boolean (value, priv->props.l2miss);
		break;
	case PROP_L3MISS:
		g_value_set_boolean (value, priv->props.l3miss);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
dispose (GObject *object)
{
	NMDeviceVxlanPrivate *priv = NM_DEVICE_VXLAN_GET_PRIVATE (object);

	g_clear_object (&priv->parent);
	G_OBJECT_CLASS (nm_device_vxlan_parent_class)->dispose (object);
}

static void
nm_device_vxlan_class_init (NMDeviceVxlanClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMDeviceVxlanPrivate));

	NM_DEVICE_CLASS_DECLARE_TYPES (klass, NULL, NM_LINK_TYPE_VXLAN)

	object_class->get_property = get_property;
	object_class->dispose = dispose;

	device_class->link_changed = link_changed;
	device_class->realize_start_notify = realize_start_notify;
	device_class->unrealize_notify = unrealize_notify;
	device_class->connection_type = NM_SETTING_VXLAN_SETTING_NAME;
	device_class->create_and_realize = create_and_realize;
	device_class->check_connection_compatible = check_connection_compatible;
	device_class->complete_connection = complete_connection;
	device_class->update_connection = update_connection;
	device_class->act_stage1_prepare = act_stage1_prepare;
	device_class->ip4_config_pre_commit = ip4_config_pre_commit;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_PARENT,
		 g_param_spec_string (NM_DEVICE_VXLAN_PARENT, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_ID,
		 g_param_spec_uint (NM_DEVICE_VXLAN_ID, "", "",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_LOCAL,
		 g_param_spec_string (NM_DEVICE_VXLAN_LOCAL, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_GROUP,
		 g_param_spec_string (NM_DEVICE_VXLAN_GROUP, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_TOS,
		 g_param_spec_uchar (NM_DEVICE_VXLAN_TOS, "", "",
		                     0, 255, 0,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_TTL,
		 g_param_spec_uchar (NM_DEVICE_VXLAN_TTL, "", "",
		                     0, 255, 0,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_LEARNING,
		 g_param_spec_boolean (NM_DEVICE_VXLAN_LEARNING, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_AGEING,
		 g_param_spec_uint (NM_DEVICE_VXLAN_AGEING, "", "",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_LIMIT,
		 g_param_spec_uint (NM_DEVICE_VXLAN_LIMIT, "", "",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_SRC_PORT_MIN,
		 g_param_spec_uint (NM_DEVICE_VXLAN_SRC_PORT_MIN, "", "",
		                    0, 65535, 0,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_SRC_PORT_MAX,
		 g_param_spec_uint (NM_DEVICE_VXLAN_SRC_PORT_MAX, "", "",
		                    0, 65535, 0,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_DST_PORT,
		 g_param_spec_uint (NM_DEVICE_VXLAN_DST_PORT, "", "",
		                    0, 65535, 0,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_PROXY,
		 g_param_spec_boolean (NM_DEVICE_VXLAN_PROXY, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_RSC,
		 g_param_spec_boolean (NM_DEVICE_VXLAN_RSC, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_L2MISS,
		 g_param_spec_boolean (NM_DEVICE_VXLAN_L2MISS, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_L3MISS,
		 g_param_spec_boolean (NM_DEVICE_VXLAN_L3MISS, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (klass),
	                                        NMDBUS_TYPE_DEVICE_VXLAN_SKELETON,
	                                        NULL);
}

/*************************************************************/

#define NM_TYPE_VXLAN_FACTORY (nm_vxlan_factory_get_type ())
#define NM_VXLAN_FACTORY(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_VXLAN_FACTORY, NMVxlanFactory))

static NMDevice *
create_device (NMDeviceFactory *factory,
               const char *iface,
               const NMPlatformLink *plink,
               NMConnection *connection,
               gboolean *out_ignore)
{
	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_VXLAN,
	                                  NM_DEVICE_IFACE, iface,
	                                  NM_DEVICE_TYPE_DESC, "Vxlan",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_VXLAN,
	                                  NM_DEVICE_LINK_TYPE, NM_LINK_TYPE_VXLAN,
	                                  NULL);
}

static const char *
get_connection_parent (NMDeviceFactory *factory, NMConnection *connection)
{
	NMSettingVxlan *s_vxlan;

	g_return_val_if_fail (nm_connection_is_type (connection, NM_SETTING_VXLAN_SETTING_NAME), NULL);

	s_vxlan = nm_connection_get_setting_vxlan (connection);
	g_assert (s_vxlan);

	return nm_setting_vxlan_get_parent (s_vxlan);
}

static char *
get_connection_iface (NMDeviceFactory *factory,
                      NMConnection *connection,
                      const char *parent_iface)
{
	const char *ifname;
	NMSettingVxlan *s_vxlan;

	g_return_val_if_fail (nm_connection_is_type (connection, NM_SETTING_VXLAN_SETTING_NAME), NULL);

	s_vxlan = nm_connection_get_setting_vxlan (connection);
	g_assert (s_vxlan);

	if (nm_setting_vxlan_get_parent (s_vxlan) && !parent_iface)
		return NULL;

	ifname = nm_connection_get_interface_name (connection);
	return g_strdup (ifname);
}

NM_DEVICE_FACTORY_DEFINE_INTERNAL (VXLAN, Vxlan, vxlan,
	NM_DEVICE_FACTORY_DECLARE_LINK_TYPES (NM_LINK_TYPE_VXLAN)
	NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES (NM_SETTING_VXLAN_SETTING_NAME),
	factory_iface->create_device = create_device;
	factory_iface->get_connection_parent = get_connection_parent;
	factory_iface->get_connection_iface = get_connection_iface;
	)

