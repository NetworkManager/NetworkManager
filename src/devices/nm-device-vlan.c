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
#include "settings/nm-settings.h"
#include "nm-act-request.h"
#include "nm-ip4-config.h"
#include "platform/nm-platform.h"
#include "nm-device-factory.h"
#include "nm-manager.h"
#include "nm-core-internal.h"
#include "platform/nmp-object.h"

#include "nm-device-logging.h"
_LOG_DECLARE_SELF(NMDeviceVlan);

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NMDeviceVlan,
	PROP_VLAN_ID,
);

typedef struct {
	gulong parent_state_id;
	gulong parent_hwaddr_id;
	gulong parent_mtu_id;
	guint vlan_id;
} NMDeviceVlanPrivate;

struct _NMDeviceVlan {
	NMDevice parent;
	NMDeviceVlanPrivate _priv;
};

struct _NMDeviceVlanClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDeviceVlan, nm_device_vlan, NM_TYPE_DEVICE)

#define NM_DEVICE_VLAN_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMDeviceVlan, NM_IS_DEVICE_VLAN, NMDevice)

/*****************************************************************************/

static void
parent_state_changed (NMDevice *parent,
                      NMDeviceState new_state,
                      NMDeviceState old_state,
                      NMDeviceStateReason reason,
                      gpointer user_data)
{
	NMDeviceVlan *self = NM_DEVICE_VLAN (user_data);

	/* We'll react to our own carrier state notifications. Ignore the parent's. */
	if (nm_device_state_reason_check (reason) == NM_DEVICE_STATE_REASON_CARRIER)
		return;

	nm_device_set_unmanaged_by_flags (NM_DEVICE (self), NM_UNMANAGED_PARENT, !nm_device_get_managed (parent, FALSE), reason);
}

static void
parent_mtu_maybe_changed (NMDevice *parent,
                          GParamSpec *pspec,
                          gpointer user_data)
{
	/* the MTU of a VLAN device is limited by the parent's MTU.
	 *
	 * When the parent's MTU changes, try to re-set the MTU. */
	nm_device_commit_mtu (user_data);
}

static void
parent_hwaddr_maybe_changed (NMDevice *parent,
                             GParamSpec *pspec,
                             gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);
	NMDeviceVlan *self = NM_DEVICE_VLAN (device);
	NMConnection *connection;
	const char *new_mac, *old_mac;
	NMSettingIPConfig *s_ip6;

	/* Never touch assumed devices */
	if (nm_device_sys_iface_state_is_external_or_assume (device))
		return;

	connection = nm_device_get_applied_connection (device);
	if (!connection)
		return;

	/* Update the VLAN MAC only if configuration does not specify one */
	if (nm_device_hw_addr_is_explict (device))
		return;

	old_mac = nm_device_get_hw_address (device);
	new_mac = nm_device_get_hw_address (parent);
	if (nm_streq0 (old_mac, new_mac))
		return;

	_LOGD (LOGD_VLAN, "parent hardware address changed to %s%s%s",
	       NM_PRINT_FMT_QUOTE_STRING (new_mac));
	if (new_mac) {
		nm_device_hw_addr_set (device, new_mac, "vlan-parent", TRUE);
		nm_device_arp_announce (device);
		/* When changing the hw address the interface is taken down,
		 * removing the IPv6 configuration; reapply it.
		 */
		s_ip6 = nm_connection_get_setting_ip6_config (connection);
		if (s_ip6)
			nm_device_reactivate_ip6_config (device, s_ip6, s_ip6);
	}
}

static void
parent_changed_notify (NMDevice *device,
                       int old_ifindex,
                       NMDevice *old_parent,
                       int new_ifindex,
                       NMDevice *new_parent)
{
	NMDeviceVlan *self = NM_DEVICE_VLAN (device);
	NMDeviceVlanPrivate *priv = NM_DEVICE_VLAN_GET_PRIVATE (self);

	NM_DEVICE_CLASS (nm_device_vlan_parent_class)->parent_changed_notify (device, old_ifindex, old_parent, new_ifindex, new_parent);

	/*  note that @self doesn't have to clear @parent_state_id on dispose,
	 *  because NMDevice's dispose() will unset the parent, which in turn calls
	 *  parent_changed_notify(). */
	nm_clear_g_signal_handler (old_parent, &priv->parent_state_id);
	nm_clear_g_signal_handler (old_parent, &priv->parent_hwaddr_id);
	nm_clear_g_signal_handler (old_parent, &priv->parent_mtu_id);

	if (new_parent) {
		priv->parent_state_id = g_signal_connect (new_parent,
		                                          NM_DEVICE_STATE_CHANGED,
		                                          G_CALLBACK (parent_state_changed),
		                                          device);

		priv->parent_hwaddr_id = g_signal_connect (new_parent, "notify::" NM_DEVICE_HW_ADDRESS,
		                                           G_CALLBACK (parent_hwaddr_maybe_changed), device);
		parent_hwaddr_maybe_changed (new_parent, NULL, self);

		priv->parent_mtu_id = g_signal_connect (new_parent, "notify::" NM_DEVICE_MTU,
		                                        G_CALLBACK (parent_mtu_maybe_changed), device);
		parent_mtu_maybe_changed (new_parent, NULL, self);

		/* Set parent-dependent unmanaged flag */
		nm_device_set_unmanaged_by_flags (device,
		                                  NM_UNMANAGED_PARENT,
		                                  !nm_device_get_managed (new_parent, FALSE),
		                                  NM_DEVICE_STATE_REASON_PARENT_MANAGED_CHANGED);
	}

	/* Recheck availability now that the parent has changed */
	if (new_ifindex > 0) {
		nm_device_queue_recheck_available (device,
		                                   NM_DEVICE_STATE_REASON_PARENT_CHANGED,
		                                   NM_DEVICE_STATE_REASON_PARENT_CHANGED);
	}
}

static void
update_properties (NMDevice *device)
{
	NMDeviceVlanPrivate *priv;
	const NMPlatformLink *plink = NULL;
	const NMPlatformLnkVlan *plnk = NULL;
	int ifindex;
	int parent_ifindex = 0;
	guint vlan_id;

	g_return_if_fail (NM_IS_DEVICE_VLAN (device));

	priv = NM_DEVICE_VLAN_GET_PRIVATE ((NMDeviceVlan *) device);

	ifindex = nm_device_get_ifindex (device);

	if (ifindex > 0)
		plnk = nm_platform_link_get_lnk_vlan (nm_device_get_platform (device), ifindex, &plink);

	if (   plnk
	    && plink->parent > 0)
		parent_ifindex = plink->parent;

	g_object_freeze_notify ((GObject *) device);

	nm_device_parent_set_ifindex (device, parent_ifindex);

	vlan_id = plnk ? plnk->id : 0;
	if (vlan_id != priv->vlan_id) {
		priv->vlan_id = vlan_id;
		_notify ((NMDeviceVlan *) device, PROP_VLAN_ID);
	}

	g_object_thaw_notify ((GObject *) device);
}

static void
link_changed (NMDevice *device,
              const NMPlatformLink *pllink)
{
	NM_DEVICE_CLASS (nm_device_vlan_parent_class)->link_changed (device, pllink);
	update_properties (device);
}

static gboolean
create_and_realize (NMDevice *device,
                    NMConnection *connection,
                    NMDevice *parent,
                    const NMPlatformLink **out_plink,
                    GError **error)
{
	NMDeviceVlanPrivate *priv = NM_DEVICE_VLAN_GET_PRIVATE ((NMDeviceVlan *) device);
	const char *iface = nm_device_get_iface (device);
	NMSettingVlan *s_vlan;
	int parent_ifindex;
	guint vlan_id;
	int r;

	s_vlan = nm_connection_get_setting_vlan (connection);
	g_assert (s_vlan);

	if (!parent) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_MISSING_DEPENDENCIES,
		             "VLAN devices can not be created without a parent interface");
		return FALSE;
	}

	parent_ifindex = nm_device_get_ifindex (parent);
	if (parent_ifindex <= 0) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_MISSING_DEPENDENCIES,
		             "cannot retrieve ifindex of interface %s (%s)",
		             nm_device_get_iface (parent),
		             nm_device_get_type_desc (parent));
		return FALSE;
	}

	if (!nm_device_supports_vlans (parent)) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
		             "no support for VLANs on interface %s of type %s",
		             nm_device_get_iface (parent),
		             nm_device_get_type_desc (parent));
		return FALSE;
	}

	vlan_id = nm_setting_vlan_get_id (s_vlan);

	r = nm_platform_link_vlan_add (nm_device_get_platform (device),
	                               iface,
	                               parent_ifindex,
	                               vlan_id,
	                               nm_setting_vlan_get_flags (s_vlan),
	                               out_plink);
	if (r < 0) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_CREATION_FAILED,
		             "Failed to create VLAN interface '%s' for '%s': %s",
		             iface,
		             nm_connection_get_id (connection),
		             nm_strerror (r));
		return FALSE;
	}

	nm_device_parent_set_ifindex (device, parent_ifindex);
	if (vlan_id != priv->vlan_id) {
		priv->vlan_id = vlan_id;
		_notify ((NMDeviceVlan *) device, PROP_VLAN_ID);
	}

	return TRUE;
}

static void
unrealize_notify (NMDevice *device)
{
	NMDeviceVlan *self = NM_DEVICE_VLAN (device);
	NMDeviceVlanPrivate *priv = NM_DEVICE_VLAN_GET_PRIVATE (self);

	NM_DEVICE_CLASS (nm_device_vlan_parent_class)->unrealize_notify (device);

	if (priv->vlan_id != 0) {
		priv->vlan_id = 0;
		_notify (self, PROP_VLAN_ID);
	}
}

/*****************************************************************************/

static NMDeviceCapabilities
get_generic_capabilities (NMDevice *device)
{
	/* We assume VLAN interfaces always support carrier detect */
	return NM_DEVICE_CAP_CARRIER_DETECT | NM_DEVICE_CAP_IS_SOFTWARE;
}

/*****************************************************************************/

static gboolean
is_available (NMDevice *device, NMDeviceCheckDevAvailableFlags flags)
{
	if (!nm_device_parent_get_device (device))
		return FALSE;
	return NM_DEVICE_CLASS (nm_device_vlan_parent_class)->is_available (device, flags);
}

/*****************************************************************************/

static gboolean
check_connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	NMDeviceVlanPrivate *priv = NM_DEVICE_VLAN_GET_PRIVATE ((NMDeviceVlan *) device);
	NMSettingVlan *s_vlan;
	const char *parent;

	if (!NM_DEVICE_CLASS (nm_device_vlan_parent_class)->check_connection_compatible (device, connection, error))
		return FALSE;

	if (nm_device_is_real (device)) {
		s_vlan = nm_connection_get_setting_vlan (connection);

		if (nm_setting_vlan_get_id (s_vlan) != priv->vlan_id) {
			nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
			                            "vlan id setting mismatches");
			return FALSE;
		}

		/* Check parent interface; could be an interface name or a UUID */
		parent = nm_setting_vlan_get_parent (s_vlan);
		if (parent) {
			if (!nm_device_match_parent (device, parent)) {
				nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
				                            "vlan parent setting differs");
				return FALSE;
			}
		} else {
			/* Parent could be a MAC address in an NMSettingWired */
			if (!nm_device_match_parent_hwaddr (device, connection, TRUE)) {
				nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
				                            "vlan parent mac setting differs");
				return FALSE;
			}
		}
	}

	return TRUE;
}

static gboolean
check_connection_available (NMDevice *device,
                            NMConnection *connection,
                            NMDeviceCheckConAvailableFlags flags,
                            const char *specific_object,
                            GError **error)
{
	if (!nm_device_is_real (device))
		return TRUE;

	return NM_DEVICE_CLASS (nm_device_vlan_parent_class)->check_connection_available (device, connection, flags, specific_object, error);
}

static gboolean
complete_connection (NMDevice *device,
                     NMConnection *connection,
                     const char *specific_object,
                     NMConnection *const*existing_connections,
                     GError **error)
{
	NMSettingVlan *s_vlan;

	nm_utils_complete_generic (nm_device_get_platform (device),
	                           connection,
	                           NM_SETTING_VLAN_SETTING_NAME,
	                           existing_connections,
	                           NULL,
	                           _("VLAN connection"),
	                           NULL,
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
	    && !nm_device_match_parent_hwaddr (device, connection, TRUE)) {
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
	const NMPlatformLink *plink;
	const NMPObject *polnk;
	guint vlan_id;
	guint vlan_flags;

	if (!s_vlan) {
		s_vlan = (NMSettingVlan *) nm_setting_vlan_new ();
		nm_connection_add_setting (connection, (NMSetting *) s_vlan);
	}

	polnk = nm_platform_link_get_lnk (nm_device_get_platform (device), ifindex, NM_LINK_TYPE_VLAN, &plink);

	if (polnk)
		vlan_id = polnk->lnk_vlan.id;
	else
		vlan_id = priv->vlan_id;
	if (vlan_id != nm_setting_vlan_get_id (s_vlan))
		g_object_set (s_vlan, NM_SETTING_VLAN_ID, vlan_id, NULL);

	g_object_set (s_vlan,
	              NM_SETTING_VLAN_PARENT,
	              nm_device_parent_find_for_connection (device,
	                                                    nm_setting_vlan_get_parent (s_vlan)),
	              NULL);

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
act_stage1_prepare (NMDevice *device, NMDeviceStateReason *out_failure_reason)
{
	NMDevice *parent_device;
	NMSettingVlan *s_vlan;
	NMActStageReturn ret;

	ret = NM_DEVICE_CLASS (nm_device_vlan_parent_class)->act_stage1_prepare (device, out_failure_reason);
	if (ret != NM_ACT_STAGE_RETURN_SUCCESS)
		return ret;

	if (!nm_device_hw_addr_set_cloned (device, nm_device_get_applied_connection (device), FALSE))
		return NM_ACT_STAGE_RETURN_FAILURE;

	/* Change MAC address to parent's one if needed */
	parent_device = nm_device_parent_get_device (device);
	if (parent_device) {
		parent_hwaddr_maybe_changed (parent_device, NULL, device);
		parent_mtu_maybe_changed (parent_device, NULL, device);
	}

	s_vlan = nm_device_get_applied_setting (device, NM_TYPE_SETTING_VLAN);
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

		nm_platform_link_vlan_change (nm_device_get_platform (device),
		                              nm_device_get_ifindex (device),
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

static guint32
get_configured_mtu (NMDevice *self, NMDeviceMtuSource *out_source)
{
	guint32 mtu = 0;
	int ifindex;

	mtu = nm_device_get_configured_mtu_for_wired (self, out_source);
	if (*out_source != NM_DEVICE_MTU_SOURCE_NONE)
		return mtu;

	/* Inherit the MTU from parent device, if any */
	ifindex = nm_device_parent_get_ifindex (self);
	if (ifindex > 0) {
		mtu = nm_platform_link_get_mtu (nm_device_get_platform (NM_DEVICE (self)), ifindex);
		*out_source = NM_DEVICE_MTU_SOURCE_PARENT;
	}

	return mtu;
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMDeviceVlanPrivate *priv = NM_DEVICE_VLAN_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_VLAN_ID:
		g_value_set_uint (value, priv->vlan_id);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_device_vlan_init (NMDeviceVlan * self)
{
}

static const NMDBusInterfaceInfoExtended interface_info_device_vlan = {
	.parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT (
		NM_DBUS_INTERFACE_DEVICE_VLAN,
		.signals = NM_DEFINE_GDBUS_SIGNAL_INFOS (
			&nm_signal_info_property_changed_legacy,
		),
		.properties = NM_DEFINE_GDBUS_PROPERTY_INFOS (
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("HwAddress", "s", NM_DEVICE_HW_ADDRESS),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Carrier",   "b", NM_DEVICE_CARRIER),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Parent",    "o", NM_DEVICE_PARENT),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("VlanId",    "u", NM_DEVICE_VLAN_ID),
		),
	),
	.legacy_property_changed = TRUE,
};

static void
nm_device_vlan_class_init (NMDeviceVlanClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	object_class->get_property = get_property;

	dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS (&interface_info_device_vlan);

	device_class->connection_type_supported = NM_SETTING_VLAN_SETTING_NAME;
	device_class->connection_type_check_compatible = NM_SETTING_VLAN_SETTING_NAME;
	device_class->link_types = NM_DEVICE_DEFINE_LINK_TYPES (NM_LINK_TYPE_VLAN);

	device_class->create_and_realize = create_and_realize;
	device_class->link_changed = link_changed;
	device_class->unrealize_notify = unrealize_notify;
	device_class->get_generic_capabilities = get_generic_capabilities;
	device_class->act_stage1_prepare = act_stage1_prepare;
	device_class->get_configured_mtu = get_configured_mtu;
	device_class->is_available = is_available;
	device_class->parent_changed_notify = parent_changed_notify;

	device_class->check_connection_compatible = check_connection_compatible;
	device_class->check_connection_available = check_connection_available;
	device_class->complete_connection = complete_connection;
	device_class->update_connection = update_connection;

	obj_properties[PROP_VLAN_ID] =
	     g_param_spec_uint (NM_DEVICE_VLAN_ID, "", "",
	                        0, 4095, 0,
	                        G_PARAM_READABLE
	                        | G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}

/*****************************************************************************/

#define NM_TYPE_VLAN_DEVICE_FACTORY (nm_vlan_device_factory_get_type ())
#define NM_VLAN_DEVICE_FACTORY(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_VLAN_DEVICE_FACTORY, NMVlanDeviceFactory))

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
	factory_class->create_device = create_device;
	factory_class->get_connection_parent = get_connection_parent;
	factory_class->get_connection_iface = get_connection_iface;
);
