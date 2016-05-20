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
 * Copyright 2011 - 2012 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-device-vlan.h"

#include <sys/socket.h>

#include "nm-manager.h"
#include "nm-utils.h"
#include "NetworkManagerUtils.h"
#include "nm-device-private.h"
#include "nm-enum-types.h"
#include "nm-settings.h"
#include "nm-activation-request.h"
#include "nm-ip4-config.h"
#include "nm-platform.h"
#include "nm-device-factory.h"
#include "nm-manager.h"
#include "nm-core-internal.h"
#include "nmp-object.h"

#include "nmdbus-device-vlan.h"

#include "nm-device-logging.h"
_LOG_DECLARE_SELF(NMDeviceVlan);

G_DEFINE_TYPE (NMDeviceVlan, nm_device_vlan, NM_TYPE_DEVICE)

#define NM_DEVICE_VLAN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_VLAN, NMDeviceVlanPrivate))

typedef struct {
	NMDevice *parent;
	gulong parent_state_id;
	gulong parent_hwaddr_id;
	guint vlan_id;
} NMDeviceVlanPrivate;

enum {
	PROP_0,
	PROP_PARENT,
	PROP_VLAN_ID,

	LAST_PROP
};

/******************************************************************/

static void
parent_state_changed (NMDevice *parent,
                      NMDeviceState new_state,
                      NMDeviceState old_state,
                      NMDeviceStateReason reason,
                      gpointer user_data)
{
	NMDeviceVlan *self = NM_DEVICE_VLAN (user_data);

	/* We'll react to our own carrier state notifications. Ignore the parent's. */
	if (reason == NM_DEVICE_STATE_REASON_CARRIER)
		return;

	nm_device_set_unmanaged_by_flags (NM_DEVICE (self), NM_UNMANAGED_PARENT, !nm_device_get_managed (parent, FALSE), reason);
}

static void
parent_hwaddr_maybe_changed (NMDevice *parent,
                             GParamSpec *pspec,
                             gpointer user_data)
{
	NMDeviceVlan *self = NM_DEVICE_VLAN (user_data);
	NMConnection *connection;
	NMSettingWired *s_wired;
	const char *new_mac, *old_mac;
	NMSettingIPConfig *s_ip6;

	/* Never touch assumed devices */
	if (nm_device_uses_assumed_connection (self))
		return;

	connection = nm_device_get_applied_connection (self);
	if (!connection)
		return;

	/* Update the VLAN MAC only if configuration does not specify one */
	s_wired = nm_connection_get_setting_wired (connection);
	if (s_wired) {
		if (nm_setting_wired_get_cloned_mac_address (s_wired))
			return;
	}

	old_mac = nm_device_get_hw_address (self);
	new_mac = nm_device_get_hw_address (parent);
	if (nm_streq0 (old_mac, new_mac))
		return;

	_LOGD (LOGD_VLAN, "parent hardware address changed to %s%s%s",
	       NM_PRINT_FMT_QUOTE_STRING (new_mac));
	if (new_mac) {
		nm_device_hw_addr_set (self, new_mac);
		/* When changing the hw address the interface is taken down,
		 * removing the IPv6 configuration; reapply it.
		 */
		s_ip6 = nm_connection_get_setting_ip6_config (connection);
		if (s_ip6)
			nm_device_reactivate_ip6_config (NM_DEVICE (self), s_ip6, s_ip6);
	}
}

static void
nm_device_vlan_set_parent (NMDeviceVlan *self, NMDevice *parent)
{
	NMDeviceVlanPrivate *priv = NM_DEVICE_VLAN_GET_PRIVATE (self);
	NMDevice *device = NM_DEVICE (self);

	if (parent == priv->parent)
		return;

	nm_clear_g_signal_handler (priv->parent, &priv->parent_state_id);
	nm_clear_g_signal_handler (priv->parent, &priv->parent_hwaddr_id);
	g_clear_object (&priv->parent);

	if (parent) {
		priv->parent = g_object_ref (parent);
		priv->parent_state_id = g_signal_connect (priv->parent,
		                                          NM_DEVICE_STATE_CHANGED,
		                                          G_CALLBACK (parent_state_changed),
		                                          device);

		priv->parent_hwaddr_id = g_signal_connect (priv->parent, "notify::" NM_DEVICE_HW_ADDRESS,
		                                           G_CALLBACK (parent_hwaddr_maybe_changed), device);
		parent_hwaddr_maybe_changed (parent, NULL, self);

		/* Set parent-dependent unmanaged flag */
		nm_device_set_unmanaged_by_flags (device,
		                                  NM_UNMANAGED_PARENT,
		                                  !nm_device_get_managed (parent, FALSE),
		                                  NM_DEVICE_STATE_REASON_PARENT_MANAGED_CHANGED);
	}

	/* Recheck availability now that the parent has changed */
	nm_device_queue_recheck_available (self,
	                                   NM_DEVICE_STATE_REASON_PARENT_CHANGED,
	                                   NM_DEVICE_STATE_REASON_PARENT_CHANGED);
	g_object_notify (G_OBJECT (device), NM_DEVICE_VLAN_PARENT);
}

static void
update_properties (NMDevice *device)
{
	NMDeviceVlanPrivate *priv;
	const NMPlatformLink *plink = NULL;
	const NMPlatformLnkVlan *plnk = NULL;
	NMDevice *parent = NULL;
	int ifindex;
	guint vlan_id;

	g_return_if_fail (NM_IS_DEVICE_VLAN (device));

	priv = NM_DEVICE_VLAN_GET_PRIVATE (device);

	ifindex = nm_device_get_ifindex (device);

	if (ifindex > 0)
		plnk = nm_platform_link_get_lnk_vlan (NM_PLATFORM_GET, ifindex, &plink);
	if (   plnk
	    && plink->parent
	    && plink->parent != NM_PLATFORM_LINK_OTHER_NETNS)
		parent = nm_manager_get_device_by_ifindex (nm_manager_get (), plink->parent);

	g_object_freeze_notify ((GObject *) device);

	nm_device_vlan_set_parent ((NMDeviceVlan *) device, parent);

	vlan_id = plnk ? plnk->id : 0;
	if (vlan_id != priv->vlan_id) {
		priv->vlan_id = vlan_id;
		g_object_notify ((GObject *) device, NM_DEVICE_VLAN_ID);
	}

	g_object_thaw_notify ((GObject *) device);
}

static void
realize_start_notify (NMDevice *device, const NMPlatformLink *plink)
{
	NM_DEVICE_CLASS (nm_device_vlan_parent_class)->realize_start_notify (device, plink);

	update_properties (device);
}

static gboolean
create_and_realize (NMDevice *device,
                    NMConnection *connection,
                    NMDevice *parent,
                    const NMPlatformLink **out_plink,
                    GError **error)
{
	NMDeviceVlanPrivate *priv = NM_DEVICE_VLAN_GET_PRIVATE (device);
	const char *iface = nm_device_get_iface (device);
	NMSettingVlan *s_vlan;
	int parent_ifindex;
	guint vlan_id;
	NMPlatformError plerr;

	s_vlan = nm_connection_get_setting_vlan (connection);
	g_assert (s_vlan);

	if (!parent) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
		             "VLAN devices can not be created without a parent interface");
		return FALSE;
	}

	if (!nm_device_supports_vlans (parent)) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
		             "no support for VLANs on interface %s of type %s",
		             nm_device_get_iface (parent),
		             nm_device_get_type_desc (parent));
		return FALSE;
	}

	parent_ifindex = nm_device_get_ifindex (parent);
	g_warn_if_fail (parent_ifindex > 0);

	vlan_id = nm_setting_vlan_get_id (s_vlan);

	plerr = nm_platform_link_vlan_add (NM_PLATFORM_GET,
	                                   iface,
	                                   parent_ifindex,
	                                   vlan_id,
	                                   nm_setting_vlan_get_flags (s_vlan),
	                                   out_plink);
	if (plerr != NM_PLATFORM_ERROR_SUCCESS) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_CREATION_FAILED,
		             "Failed to create VLAN interface '%s' for '%s': %s",
		             iface,
		             nm_connection_get_id (connection),
		             nm_platform_error_to_string (plerr));
		return FALSE;
	}

	g_warn_if_fail (priv->parent == NULL);
	nm_device_vlan_set_parent (NM_DEVICE_VLAN (device), parent);
	if (vlan_id != priv->vlan_id) {
		priv->vlan_id = vlan_id;
		g_object_notify ((GObject *) device, NM_DEVICE_VLAN_ID);
	}

	return TRUE;
}

static void
unrealize_notify (NMDevice *device)
{
	NM_DEVICE_CLASS (nm_device_vlan_parent_class)->unrealize_notify (device);

	NM_DEVICE_VLAN_GET_PRIVATE (device)->vlan_id = 0;
	g_object_notify (G_OBJECT (device), NM_DEVICE_VLAN_ID);
	nm_device_vlan_set_parent (NM_DEVICE_VLAN (device), NULL);
}

/******************************************************************/

static NMDeviceCapabilities
get_generic_capabilities (NMDevice *dev)
{
	/* We assume VLAN interfaces always support carrier detect */
	return NM_DEVICE_CAP_CARRIER_DETECT | NM_DEVICE_CAP_IS_SOFTWARE;
}

static gboolean
bring_up (NMDevice *dev, gboolean *no_firmware)
{
	gboolean success = FALSE;
	guint i = 20;

	while (i-- > 0 && !success) {
		success = NM_DEVICE_CLASS (nm_device_vlan_parent_class)->bring_up (dev, no_firmware);
		g_usleep (50);
	}

	return success;
}

/******************************************************************/

static gboolean
is_available (NMDevice *device, NMDeviceCheckDevAvailableFlags flags)
{
	if (!NM_DEVICE_VLAN_GET_PRIVATE (device)->parent)
		return FALSE;

	return NM_DEVICE_CLASS (nm_device_vlan_parent_class)->is_available (device, flags);
}

static void
notify_new_device_added (NMDevice *device, NMDevice *new_device)
{
	NMDeviceVlan *self = NM_DEVICE_VLAN (device);
	NMDeviceVlanPrivate *priv = NM_DEVICE_VLAN_GET_PRIVATE (self);
	const NMPlatformLink *plink;
	const NMPlatformLnkVlan *plnk;

	if (priv->parent)
		return;

	if (!nm_device_is_real (device))
		return;

	plnk = nm_platform_link_get_lnk_vlan (NM_PLATFORM_GET, nm_device_get_ifindex (device), &plink);
	if (!plnk)
		return;

	if (   plink->parent <= 0
	    || nm_device_get_ifindex (new_device) != plink->parent)
		return;

	nm_device_vlan_set_parent (self, new_device);
}

/******************************************************************/

static gboolean
match_parent (NMDeviceVlan *self, const char *parent)
{
	NMDeviceVlanPrivate *priv = NM_DEVICE_VLAN_GET_PRIVATE (self);

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
match_hwaddr (NMDevice *device, NMConnection *connection, gboolean fail_if_no_hwaddr)
{
	  NMSettingWired *s_wired;
	  const char *setting_mac;
	  const char *device_mac;

	  s_wired = nm_connection_get_setting_wired (connection);
	  if (!s_wired)
		  return !fail_if_no_hwaddr;

	  setting_mac = nm_setting_wired_get_mac_address (s_wired);
	  if (!setting_mac)
		  return !fail_if_no_hwaddr;

	  device_mac = nm_device_get_hw_address (device);

	  return nm_utils_hwaddr_matches (setting_mac, -1, device_mac, -1);
}

static gboolean
check_connection_compatible (NMDevice *device, NMConnection *connection)
{
	NMDeviceVlanPrivate *priv = NM_DEVICE_VLAN_GET_PRIVATE (device);
	NMSettingVlan *s_vlan;
	const char *parent = NULL;

	if (!NM_DEVICE_CLASS (nm_device_vlan_parent_class)->check_connection_compatible (device, connection))
		return FALSE;

	s_vlan = nm_connection_get_setting_vlan (connection);
	if (!s_vlan)
		return FALSE;

	/* Before the device is realized some properties will not be set */
	if (nm_device_is_real (device)) {
		if (nm_setting_vlan_get_id (s_vlan) != priv->vlan_id)
			return FALSE;

		/* Check parent interface; could be an interface name or a UUID */
		parent = nm_setting_vlan_get_parent (s_vlan);
		if (parent) {
			if (!match_parent (NM_DEVICE_VLAN (device), parent))
				return FALSE;
		} else {
			/* Parent could be a MAC address in an NMSettingWired */
			if (!match_hwaddr (device, connection, TRUE))
				return FALSE;
		}
	}

	return TRUE;
}

static gboolean
check_connection_available (NMDevice *device,
                            NMConnection *connection,
                            NMDeviceCheckConAvailableFlags flags,
                            const char *specific_object)
{
	if (!nm_device_is_real (device))
		return TRUE;

	return NM_DEVICE_CLASS (nm_device_vlan_parent_class)->check_connection_available (device, connection, flags, specific_object);
}

static gboolean
complete_connection (NMDevice *device,
                     NMConnection *connection,
                     const char *specific_object,
                     const GSList *existing_connections,
                     GError **error)
{
	NMSettingVlan *s_vlan;

	nm_utils_complete_generic (NM_PLATFORM_GET,
	                           connection,
	                           NM_SETTING_VLAN_SETTING_NAME,
	                           existing_connections,
	                           NULL,
	                           _("VLAN connection"),
	                           NULL,
	                           TRUE);

	s_vlan = nm_connection_get_setting_vlan (connection);
	if (!s_vlan) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INVALID_CONNECTION,
		                     "A 'vlan' setting is required.");
		return FALSE;
	}

	/* If there's no VLAN interface, no parent, and no hardware address in the
	 * settings, then there's not enough information to complete the setting.
	 */
	if (   !nm_setting_vlan_get_parent (s_vlan)
	    && !match_hwaddr (device, connection, TRUE)) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INVALID_CONNECTION,
		                     "The 'vlan' setting had no interface name, parent, or hardware address.");
		return FALSE;
	}

	return TRUE;
}

static void
update_connection (NMDevice *device, NMConnection *connection)
{
	NMDeviceVlanPrivate *priv = NM_DEVICE_VLAN_GET_PRIVATE (device);
	NMSettingVlan *s_vlan = nm_connection_get_setting_vlan (connection);
	int ifindex = nm_device_get_ifindex (device);
	const char *setting_parent, *new_parent;
	const NMPlatformLink *plink;
	const NMPObject *polnk;
	guint vlan_id;
	guint vlan_flags;

	if (!s_vlan) {
		s_vlan = (NMSettingVlan *) nm_setting_vlan_new ();
		nm_connection_add_setting (connection, (NMSetting *) s_vlan);
	}

	polnk = nm_platform_link_get_lnk (NM_PLATFORM_GET, ifindex, NM_LINK_TYPE_VLAN, &plink);

	if (polnk)
		vlan_id = polnk->lnk_vlan.id;
	else
		vlan_id = priv->vlan_id;
	if (vlan_id != nm_setting_vlan_get_id (s_vlan))
		g_object_set (s_vlan, NM_SETTING_VLAN_ID, vlan_id, NULL);

	/* Update parent in the connection; default to parent's interface name */
	if (   priv->parent
	    && polnk
	    && plink->parent > 0
	    && nm_device_get_ifindex (priv->parent) == plink->parent) {
		new_parent = nm_device_get_iface (priv->parent);
		setting_parent = nm_setting_vlan_get_parent (s_vlan);
		if (setting_parent && nm_utils_is_uuid (setting_parent)) {
			NMConnection *parent_connection;

			/* Don't change a parent specified by UUID if it's still valid */
			parent_connection = (NMConnection *) nm_settings_get_connection_by_uuid (nm_device_get_settings (device), setting_parent);
			if (parent_connection && nm_device_check_connection_compatible (priv->parent, parent_connection))
				new_parent = NULL;
		}
		if (new_parent)
			g_object_set (s_vlan, NM_SETTING_VLAN_PARENT, new_parent, NULL);
	} else
		g_object_set (s_vlan, NM_SETTING_VLAN_PARENT, NULL, NULL);

	if (polnk)
		vlan_flags = polnk->lnk_vlan.flags;
	else
		vlan_flags = NM_VLAN_FLAG_REORDER_HEADERS;
	if (vlan_flags != nm_setting_vlan_get_flags (s_vlan))
		g_object_set (s_vlan, NM_SETTING_VLAN_FLAGS, (NMVlanFlags) vlan_flags, NULL);

	if (polnk) {
		_nm_setting_vlan_set_priorities (s_vlan, NM_VLAN_INGRESS_MAP,
		                                 polnk->_lnk_vlan.ingress_qos_map,
		                                 polnk->_lnk_vlan.n_ingress_qos_map);
		_nm_setting_vlan_set_priorities (s_vlan, NM_VLAN_EGRESS_MAP,
		                                 polnk->_lnk_vlan.egress_qos_map,
		                                 polnk->_lnk_vlan.n_egress_qos_map);
	} else {
		_nm_setting_vlan_set_priorities (s_vlan, NM_VLAN_INGRESS_MAP, NULL, 0);
		_nm_setting_vlan_set_priorities (s_vlan, NM_VLAN_EGRESS_MAP, NULL, 0);
	}
}

static NMActStageReturn
act_stage1_prepare (NMDevice *dev, NMDeviceStateReason *reason)
{
	NMDeviceVlanPrivate *priv = NM_DEVICE_VLAN_GET_PRIVATE (dev);
	NMSettingVlan *s_vlan;
	NMSettingWired *s_wired;
	const char *cloned_mac = NULL;
	NMActStageReturn ret;

	g_return_val_if_fail (reason != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	ret = NM_DEVICE_CLASS (nm_device_vlan_parent_class)->act_stage1_prepare (dev, reason);
	if (ret != NM_ACT_STAGE_RETURN_SUCCESS)
		return ret;

	s_wired = (NMSettingWired *) nm_device_get_applied_setting (dev, NM_TYPE_SETTING_WIRED);
	if (s_wired)
		cloned_mac = nm_setting_wired_get_cloned_mac_address (s_wired);
	nm_device_hw_addr_set (dev, cloned_mac);

	/* Change MAC address to parent's one if needed */
	if (priv->parent)
		parent_hwaddr_maybe_changed (priv->parent, NULL, dev);

	s_vlan = (NMSettingVlan *) nm_device_get_applied_setting (dev, NM_TYPE_SETTING_VLAN);
	if (s_vlan) {
		gs_free NMVlanQosMapping *ingress_map = NULL;
		gs_free NMVlanQosMapping *egress_map = NULL;
		guint n_ingress_map = 0, n_egress_map = 0;

		_nm_setting_vlan_get_priorities (s_vlan,
		                                 NM_VLAN_INGRESS_MAP,
		                                 &ingress_map,
		                                 &n_ingress_map);
		_nm_setting_vlan_get_priorities (s_vlan,
		                                 NM_VLAN_EGRESS_MAP,
		                                 &egress_map,
		                                 &n_egress_map);

		nm_platform_link_vlan_change (NM_PLATFORM_GET,
		                              nm_device_get_ifindex (dev),
		                              NM_VLAN_FLAGS_ALL,
		                              nm_setting_vlan_get_flags (s_vlan),
		                              TRUE,
		                              ingress_map,
		                              n_ingress_map,
		                              TRUE,
		                              egress_map,
		                              n_egress_map);
	}

	return ret;
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

static void
deactivate (NMDevice *device)
{
	nm_device_hw_addr_reset (device);
}

/******************************************************************/

static void
nm_device_vlan_init (NMDeviceVlan * self)
{
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMDeviceVlanPrivate *priv = NM_DEVICE_VLAN_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_PARENT:
		nm_utils_g_value_set_object_path (value, priv->parent);
		break;
	case PROP_VLAN_ID:
		g_value_set_uint (value, priv->vlan_id);
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
	G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
}

static void
dispose (GObject *object)
{
	nm_device_vlan_set_parent (NM_DEVICE_VLAN (object), NULL);

	G_OBJECT_CLASS (nm_device_vlan_parent_class)->dispose (object);
}

static void
nm_device_vlan_class_init (NMDeviceVlanClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *parent_class = NM_DEVICE_CLASS (klass);

	NM_DEVICE_CLASS_DECLARE_TYPES (klass, NM_SETTING_VLAN_SETTING_NAME, NM_LINK_TYPE_VLAN)

	g_type_class_add_private (object_class, sizeof (NMDeviceVlanPrivate));

	/* virtual methods */
	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->dispose = dispose;

	parent_class->create_and_realize = create_and_realize;
	parent_class->realize_start_notify = realize_start_notify;
	parent_class->unrealize_notify = unrealize_notify;
	parent_class->get_generic_capabilities = get_generic_capabilities;
	parent_class->bring_up = bring_up;
	parent_class->act_stage1_prepare = act_stage1_prepare;
	parent_class->ip4_config_pre_commit = ip4_config_pre_commit;
	parent_class->deactivate = deactivate;
	parent_class->is_available = is_available;
	parent_class->notify_new_device_added = notify_new_device_added;

	parent_class->check_connection_compatible = check_connection_compatible;
	parent_class->check_connection_available = check_connection_available;
	parent_class->complete_connection = complete_connection;
	parent_class->update_connection = update_connection;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_PARENT,
		 g_param_spec_string (NM_DEVICE_VLAN_PARENT, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));
	g_object_class_install_property
		(object_class, PROP_VLAN_ID,
		 g_param_spec_uint (NM_DEVICE_VLAN_ID, "", "",
		                    0, 4095, 0,
		                    G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (klass),
	                                        NMDBUS_TYPE_DEVICE_VLAN_SKELETON,
	                                        NULL);
}

/*************************************************************/

#define NM_TYPE_VLAN_FACTORY (nm_vlan_factory_get_type ())
#define NM_VLAN_FACTORY(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_VLAN_FACTORY, NMVlanFactory))

static NMDevice *
create_device (NMDeviceFactory *factory,
               const char *iface,
               const NMPlatformLink *plink,
               NMConnection *connection,
               gboolean *out_ignore)
{
	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_VLAN,
	                                  NM_DEVICE_IFACE, iface,
	                                  NM_DEVICE_DRIVER, "8021q",
	                                  NM_DEVICE_TYPE_DESC, "VLAN",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_VLAN,
	                                  NM_DEVICE_LINK_TYPE, NM_LINK_TYPE_VLAN,
	                                  NULL);
}

static const char *
get_connection_parent (NMDeviceFactory *factory, NMConnection *connection)
{
	NMSettingVlan *s_vlan;
	NMSettingWired *s_wired;
	const char *parent = NULL;

	g_return_val_if_fail (nm_connection_is_type (connection, NM_SETTING_VLAN_SETTING_NAME), NULL);

	s_vlan = nm_connection_get_setting_vlan (connection);
	g_assert (s_vlan);

	parent = nm_setting_vlan_get_parent (s_vlan);
	if (parent)
		return parent;

	/* Try the hardware address from the VLAN connection's hardware setting */
	s_wired = nm_connection_get_setting_wired (connection);
	if (s_wired)
		return nm_setting_wired_get_mac_address (s_wired);

	return NULL;
}

static char *
get_connection_iface (NMDeviceFactory *factory,
                      NMConnection *connection,
                      const char *parent_iface)
{
	const char *ifname;
	NMSettingVlan *s_vlan;

	g_return_val_if_fail (nm_connection_is_type (connection, NM_SETTING_VLAN_SETTING_NAME), NULL);

	s_vlan = nm_connection_get_setting_vlan (connection);
	g_assert (s_vlan);

	if (!parent_iface)
		return NULL;

	ifname = nm_connection_get_interface_name (connection);
	if (ifname)
		return g_strdup (ifname);

	/* If the connection doesn't specify the interface name for the VLAN
	 * device, we create one for it using the VLAN ID and the parent
	 * interface's name.
	 */
	return nm_utils_new_vlan_name (parent_iface, nm_setting_vlan_get_id (s_vlan));
}

NM_DEVICE_FACTORY_DEFINE_INTERNAL (VLAN, Vlan, vlan,
	NM_DEVICE_FACTORY_DECLARE_LINK_TYPES    (NM_LINK_TYPE_VLAN)
	NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES (NM_SETTING_VLAN_SETTING_NAME),
	factory_iface->create_device = create_device;
	factory_iface->get_connection_parent = get_connection_parent;
	factory_iface->get_connection_iface = get_connection_iface;
	)

