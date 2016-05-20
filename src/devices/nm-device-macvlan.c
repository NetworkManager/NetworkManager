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

#include "nm-device-macvlan.h"

#include <string.h>

#include "nm-device-private.h"
#include "nm-settings.h"
#include "nm-activation-request.h"
#include "nm-manager.h"
#include "nm-platform.h"
#include "nm-device-factory.h"
#include "nm-setting-macvlan.h"
#include "nm-setting-wired.h"
#include "nm-active-connection.h"
#include "nm-ip4-config.h"
#include "nm-utils.h"

#include "nmdbus-device-macvlan.h"

#include "nm-device-logging.h"
_LOG_DECLARE_SELF(NMDeviceMacvlan);

G_DEFINE_TYPE (NMDeviceMacvlan, nm_device_macvlan, NM_TYPE_DEVICE)

#define NM_DEVICE_MACVLAN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_MACVLAN, NMDeviceMacvlanPrivate))

typedef struct {
	int parent_ifindex;
	gulong parent_state_id;
	NMDevice *parent;
	NMPlatformLnkMacvlan props;
} NMDeviceMacvlanPrivate;

enum {
	PROP_0,
	PROP_PARENT,
	PROP_MODE,
	PROP_NO_PROMISC,
	PROP_TAP,

	LAST_PROP
};

static int modes[][2] = {
	{ NM_SETTING_MACVLAN_MODE_VEPA,      MACVLAN_MODE_VEPA     },
	{ NM_SETTING_MACVLAN_MODE_BRIDGE,    MACVLAN_MODE_BRIDGE   },
	{ NM_SETTING_MACVLAN_MODE_PRIVATE,   MACVLAN_MODE_PRIVATE  },
	{ NM_SETTING_MACVLAN_MODE_PASSTHRU,  MACVLAN_MODE_PASSTHRU },
};

static int
setting_mode_to_platform (int mode)
{
	guint i;

	for (i = 0; i < G_N_ELEMENTS (modes); i++) {
		if (modes[i][0] == mode)
			return modes[i][1];
	}

	return 0;
}

static int
platform_mode_to_setting (int mode)
{
	guint i;

	for (i = 0; i < G_N_ELEMENTS (modes); i++) {
		if (modes[i][1] == mode)
			return modes[i][0];
	}

	return 0;
}

static const char *
platform_mode_to_string (guint mode)
{
	switch (mode) {
	case MACVLAN_MODE_PRIVATE:
		return "private";
	case MACVLAN_MODE_VEPA:
		return "vepa";
	case MACVLAN_MODE_BRIDGE:
		return "bridge";
	case MACVLAN_MODE_PASSTHRU:
		return "passthru";
	default:
		return "unknown";
	}
}

/**************************************************************/

static void
parent_state_changed (NMDevice *parent,
                      NMDeviceState new_state,
                      NMDeviceState old_state,
                      NMDeviceStateReason reason,
                      gpointer user_data)
{
	NMDeviceMacvlan *self = NM_DEVICE_MACVLAN (user_data);

	/* We'll react to our own carrier state notifications. Ignore the parent's. */
	if (reason == NM_DEVICE_STATE_REASON_CARRIER)
		return;

	nm_device_set_unmanaged_by_flags (NM_DEVICE (self), NM_UNMANAGED_PARENT, !nm_device_get_managed (parent, FALSE), reason);
}

static void
nm_device_macvlan_set_parent (NMDeviceMacvlan *self, NMDevice *parent)
	{
	NMDeviceMacvlanPrivate *priv = NM_DEVICE_MACVLAN_GET_PRIVATE (self);
	NMDevice *device = NM_DEVICE (self);

	if (parent == priv->parent)
		return;

	nm_clear_g_signal_handler (priv->parent, &priv->parent_state_id);

	g_clear_object (&priv->parent);

	if (parent) {
		priv->parent = g_object_ref (parent);
		priv->parent_state_id = g_signal_connect (priv->parent,
		                                          "state-changed",
		                                          G_CALLBACK (parent_state_changed),
		                                          device);

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
	g_object_notify (G_OBJECT (device), NM_DEVICE_MACVLAN_PARENT);
}

static void
update_properties (NMDevice *device)
{
	NMDeviceMacvlan *self = NM_DEVICE_MACVLAN (device);
	NMDeviceMacvlanPrivate *priv = NM_DEVICE_MACVLAN_GET_PRIVATE (device);
	GObject *object = G_OBJECT (device);
	const NMPlatformLnkMacvlan *props;
	const NMPlatformLink *plink;
	NMDevice *parent = NULL;

	if (priv->props.tap)
		props = nm_platform_link_get_lnk_macvtap (NM_PLATFORM_GET, nm_device_get_ifindex (device), &plink);
	else
		props = nm_platform_link_get_lnk_macvlan (NM_PLATFORM_GET, nm_device_get_ifindex (device), &plink);

	if (!props) {
		_LOGW (LOGD_HW, "could not get %s properties", priv->props.tap ? "macvtap" : "macvlan");
		return;
	}

	g_object_freeze_notify (object);

	if (priv->parent_ifindex != plink->parent) {
		parent = nm_manager_get_device_by_ifindex (nm_manager_get (), plink->parent);
		nm_device_macvlan_set_parent (self, parent);
	}
	if (priv->props.mode != props->mode)
		g_object_notify (object, NM_DEVICE_MACVLAN_MODE);
	if (priv->props.no_promisc != props->no_promisc)
		g_object_notify (object, NM_DEVICE_MACVLAN_NO_PROMISC);

	priv->parent_ifindex = plink->parent;
	priv->props = *props;

	g_object_thaw_notify (object);
}

static void
link_changed (NMDevice *device, NMPlatformLink *info)
{
	NM_DEVICE_CLASS (nm_device_macvlan_parent_class)->link_changed (device, info);
	update_properties (device);
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
	NMSettingMacvlan *s_macvlan;
	NMPlatformLnkMacvlan lnk = { };
	int parent_ifindex;

	s_macvlan = nm_connection_get_setting_macvlan (connection);
	g_assert (s_macvlan);

	if (!parent) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
		             "MACVLAN devices can not be created without a parent interface");
		return FALSE;
	}

	parent_ifindex = nm_device_get_ifindex (parent);
	g_warn_if_fail (parent_ifindex > 0);

	lnk.mode = setting_mode_to_platform (nm_setting_macvlan_get_mode (s_macvlan));
	if (!lnk.mode) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
		             "unsupported MACVLAN mode %u in connection %s",
		             nm_setting_macvlan_get_mode (s_macvlan),
		             nm_connection_get_uuid (connection));
		return FALSE;
	}
	lnk.no_promisc = !nm_setting_macvlan_get_promiscuous (s_macvlan);
	lnk.tap = nm_setting_macvlan_get_tap (s_macvlan);

	plerr = nm_platform_link_macvlan_add (NM_PLATFORM_GET, iface, parent_ifindex, &lnk, out_plink);
	if (plerr != NM_PLATFORM_ERROR_SUCCESS) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_CREATION_FAILED,
		             "Failed to create %s interface '%s' for '%s': %s",
		             lnk.tap ? "macvtap" : "macvlan",
		             iface,
		             nm_connection_get_id (connection),
		             nm_platform_error_to_string (plerr));
		return FALSE;
	}

	return TRUE;
}

/******************************************************************/

static NMDeviceCapabilities
get_generic_capabilities (NMDevice *dev)
{
	/* We assume MACVLAN interfaces always support carrier detect */
	return NM_DEVICE_CAP_CARRIER_DETECT | NM_DEVICE_CAP_IS_SOFTWARE;
}

static gboolean
bring_up (NMDevice *dev, gboolean *no_firmware)
{
	gboolean success = FALSE;
	guint i = 20;

	while (i-- > 0 && !success) {
		success = NM_DEVICE_CLASS (nm_device_macvlan_parent_class)->bring_up (dev, no_firmware);
		g_usleep (50);
	}

	return success;
}

/******************************************************************/

static gboolean
is_available (NMDevice *device, NMDeviceCheckDevAvailableFlags flags)
{
	if (!NM_DEVICE_MACVLAN_GET_PRIVATE (device)->parent)
		return FALSE;

	return NM_DEVICE_CLASS (nm_device_macvlan_parent_class)->is_available (device, flags);
}

static void
notify_new_device_added (NMDevice *device, NMDevice *new_device)
{
	NMDeviceMacvlan *self = NM_DEVICE_MACVLAN (device);
	NMDeviceMacvlanPrivate *priv = NM_DEVICE_MACVLAN_GET_PRIVATE (self);

	if (priv->parent)
		return;

	if (!nm_device_is_real (device))
		return;

	update_properties (device);

	if (   priv->parent_ifindex <= 0
	    || nm_device_get_ifindex (new_device) != priv->parent_ifindex)
		return;

	priv->parent_ifindex = nm_device_get_ifindex (new_device);
	nm_device_macvlan_set_parent (self, new_device);
}

/**************************************************************/


static gboolean
match_parent (NMDeviceMacvlan *self, const char *parent)
{
	NMDeviceMacvlanPrivate *priv = NM_DEVICE_MACVLAN_GET_PRIVATE (self);

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
	NMDeviceMacvlanPrivate *priv = NM_DEVICE_MACVLAN_GET_PRIVATE (device);
	NMSettingWired *s_wired;
	const char *setting_mac;
	const char *parent_mac;

	s_wired = nm_connection_get_setting_wired (connection);
	if (!s_wired)
		return !fail_if_no_hwaddr;

	setting_mac = nm_setting_wired_get_mac_address (s_wired);
	if (!setting_mac)
		return !fail_if_no_hwaddr;

	if (!priv->parent)
		return !fail_if_no_hwaddr;

	parent_mac = nm_device_get_hw_address (priv->parent);

	return nm_utils_hwaddr_matches (setting_mac, -1, parent_mac, -1);
}

static gboolean
check_connection_compatible (NMDevice *device, NMConnection *connection)
{
	NMDeviceMacvlanPrivate *priv = NM_DEVICE_MACVLAN_GET_PRIVATE (device);
	NMSettingMacvlan *s_macvlan;
	const char *parent = NULL;

	if (!NM_DEVICE_CLASS (nm_device_macvlan_parent_class)->check_connection_compatible (device, connection))
		return FALSE;

	s_macvlan = nm_connection_get_setting_macvlan (connection);
	if (!s_macvlan)
		return FALSE;

	if (nm_setting_macvlan_get_tap (s_macvlan) != priv->props.tap)
		return FALSE;

	/* Before the device is realized some properties will not be set */
	if (nm_device_is_real (device)) {

		if (setting_mode_to_platform (nm_setting_macvlan_get_mode (s_macvlan)) != priv->props.mode)
			return FALSE;

		if (nm_setting_macvlan_get_promiscuous (s_macvlan) ==  priv->props.no_promisc)
			return FALSE;

		/* Check parent interface; could be an interface name or a UUID */
		parent = nm_setting_macvlan_get_parent (s_macvlan);
		if (parent) {
			if (!match_parent (NM_DEVICE_MACVLAN (device), parent))
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
complete_connection (NMDevice *device,
                     NMConnection *connection,
                     const char *specific_object,
                     const GSList *existing_connections,
                     GError **error)
{
	NMSettingMacvlan *s_macvlan;

	nm_utils_complete_generic (NM_PLATFORM_GET,
	                           connection,
	                           NM_SETTING_MACVLAN_SETTING_NAME,
	                           existing_connections,
	                           NULL,
	                           _("MACVLAN connection"),
	                           NULL,
	                           TRUE);

	s_macvlan = nm_connection_get_setting_macvlan (connection);
	if (!s_macvlan) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INVALID_CONNECTION,
		                     "A 'macvlan' setting is required.");
		return FALSE;
	}

	/* If there's no MACVLAN interface, no parent, and no hardware address in the
	 * settings, then there's not enough information to complete the setting.
	 */
	if (   !nm_setting_macvlan_get_parent (s_macvlan)
	    && !match_hwaddr (device, connection, TRUE)) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INVALID_CONNECTION,
		                     "The 'macvlan' setting had no interface name, parent, or hardware address.");
		return FALSE;
	}

	return TRUE;
}

static void
update_connection (NMDevice *device, NMConnection *connection)
{
	NMDeviceMacvlanPrivate *priv = NM_DEVICE_MACVLAN_GET_PRIVATE (device);
	NMSettingMacvlan *s_macvlan = nm_connection_get_setting_macvlan (connection);
	const char *setting_parent, *new_parent;
	int new_mode;

	if (!s_macvlan) {
		s_macvlan = (NMSettingMacvlan *) nm_setting_macvlan_new ();
		nm_connection_add_setting (connection, (NMSetting *) s_macvlan);
	}

	new_mode = platform_mode_to_setting (priv->props.mode);
	if (new_mode != nm_setting_macvlan_get_mode (s_macvlan))
		g_object_set (s_macvlan, NM_SETTING_MACVLAN_MODE, new_mode, NULL);

	if (priv->props.no_promisc == nm_setting_macvlan_get_promiscuous (s_macvlan))
		g_object_set (s_macvlan, NM_SETTING_MACVLAN_PROMISCUOUS, !priv->props.no_promisc, NULL);


	if (priv->props.tap != nm_setting_macvlan_get_tap (s_macvlan))
		g_object_set (s_macvlan, NM_SETTING_MACVLAN_TAP, !!priv->props.tap, NULL);

	/* Update parent in the connection; default to parent's interface name */
	if (priv->parent) {
		new_parent = nm_device_get_iface (priv->parent);
		setting_parent = nm_setting_macvlan_get_parent (s_macvlan);
		if (setting_parent && nm_utils_is_uuid (setting_parent)) {
			NMConnection *parent_connection;

			/* Don't change a parent specified by UUID if it's still valid */
			parent_connection = (NMConnection *) nm_settings_get_connection_by_uuid (nm_device_get_settings (device), setting_parent);
			if (parent_connection && nm_device_check_connection_compatible (priv->parent, parent_connection))
				new_parent = NULL;
		}
		if (new_parent)
			g_object_set (s_macvlan, NM_SETTING_MACVLAN_PARENT, new_parent, NULL);
	} else
		g_object_set (s_macvlan, NM_SETTING_MACVLAN_PARENT, NULL, NULL);

}

static NMActStageReturn
act_stage1_prepare (NMDevice *dev, NMDeviceStateReason *reason)
{
	NMSettingWired *s_wired;
	const char *cloned_mac = NULL;
	NMActStageReturn ret;

	g_return_val_if_fail (reason != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	ret = NM_DEVICE_CLASS (nm_device_macvlan_parent_class)->act_stage1_prepare (dev, reason);
	if (ret != NM_ACT_STAGE_RETURN_SUCCESS)
		return ret;

	s_wired = (NMSettingWired *) nm_device_get_applied_setting (dev, NM_TYPE_SETTING_WIRED);
	if (s_wired)
		cloned_mac = nm_setting_wired_get_cloned_mac_address (s_wired);
	nm_device_hw_addr_set (dev, cloned_mac);

	return TRUE;
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
realize_start_notify (NMDevice *device, const NMPlatformLink *plink)
{
	NM_DEVICE_CLASS (nm_device_macvlan_parent_class)->realize_start_notify (device, plink);

	update_properties (device);
}

static void
deactivate (NMDevice *device)
{
	nm_device_hw_addr_reset (device);
}

/******************************************************************/

static void
nm_device_macvlan_init (NMDeviceMacvlan *self)
{
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMDeviceMacvlanPrivate *priv = NM_DEVICE_MACVLAN_GET_PRIVATE (object);
	NMDevice *parent;

	switch (prop_id) {
	case PROP_PARENT:
		if (priv->parent_ifindex > 0)
			parent = nm_manager_get_device_by_ifindex (nm_manager_get (), priv->parent_ifindex);
		else
			parent = NULL;
		nm_utils_g_value_set_object_path (value, parent);
		break;
	case PROP_MODE:
		g_value_set_string (value, platform_mode_to_string (priv->props.mode));
		break;
	case PROP_NO_PROMISC:
		g_value_set_boolean (value, priv->props.no_promisc);
		break;
	case PROP_TAP:
		g_value_set_boolean (value, priv->props.tap);
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
	NMDeviceMacvlanPrivate *priv = NM_DEVICE_MACVLAN_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_TAP:
		priv->props.tap = g_value_get_boolean (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
	}
}

static void
dispose (GObject *object)
{
	nm_device_macvlan_set_parent (NM_DEVICE_MACVLAN (object), NULL);

	G_OBJECT_CLASS (nm_device_macvlan_parent_class)->dispose (object);
}

static void
nm_device_macvlan_class_init (NMDeviceMacvlanClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMDeviceMacvlanPrivate));

	NM_DEVICE_CLASS_DECLARE_TYPES (klass, NULL, NM_LINK_TYPE_MACVLAN, NM_LINK_TYPE_MACVTAP)

	object_class->dispose = dispose;
	object_class->get_property = get_property;
	object_class->set_property = set_property;

	device_class->act_stage1_prepare = act_stage1_prepare;
	device_class->bring_up = bring_up;
	device_class->check_connection_compatible = check_connection_compatible;
	device_class->complete_connection = complete_connection;
	device_class->connection_type = NM_SETTING_MACVLAN_SETTING_NAME;
	device_class->create_and_realize = create_and_realize;
	device_class->deactivate = deactivate;
	device_class->get_generic_capabilities = get_generic_capabilities;
	device_class->ip4_config_pre_commit = ip4_config_pre_commit;
	device_class->is_available = is_available;
	device_class->link_changed = link_changed;
	device_class->notify_new_device_added = notify_new_device_added;
	device_class->realize_start_notify = realize_start_notify;
	device_class->update_connection = update_connection;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_PARENT,
		 g_param_spec_string (NM_DEVICE_MACVLAN_PARENT, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_MODE,
		 g_param_spec_string (NM_DEVICE_MACVLAN_MODE, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_NO_PROMISC,
		 g_param_spec_boolean (NM_DEVICE_MACVLAN_NO_PROMISC, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_TAP,
		 g_param_spec_boolean (NM_DEVICE_MACVLAN_TAP, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT_ONLY |
		                       G_PARAM_STATIC_STRINGS));

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (klass),
	                                        NMDBUS_TYPE_DEVICE_MACVLAN_SKELETON,
	                                        NULL);
}

/*************************************************************/

#define NM_TYPE_MACVLAN_FACTORY (nm_macvlan_factory_get_type ())
#define NM_MACVLAN_FACTORY(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_MACVLAN_FACTORY, NMMacvlanFactory))

static NMDevice *
create_device (NMDeviceFactory *factory,
               const char *iface,
               const NMPlatformLink *plink,
               NMConnection *connection,
               gboolean *out_ignore)
{
	NMSettingMacvlan *s_macvlan;
	NMLinkType link_type;
	gboolean tap;

	if (connection) {
		s_macvlan = nm_connection_get_setting_macvlan (connection);
		g_assert (s_macvlan);
		tap = nm_setting_macvlan_get_tap (s_macvlan);
	} else {
		g_assert (plink);
		tap = plink->type == NM_LINK_TYPE_MACVTAP;
	}

	link_type = tap ? NM_LINK_TYPE_MACVTAP : NM_LINK_TYPE_MACVLAN;

	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_MACVLAN,
	                                  NM_DEVICE_IFACE, iface,
	                                  NM_DEVICE_TYPE_DESC, "Macvlan",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_MACVLAN,
	                                  NM_DEVICE_LINK_TYPE, link_type,
	                                  NM_DEVICE_MACVLAN_TAP, tap,
	                                  NULL);
}

static const char *
get_connection_parent (NMDeviceFactory *factory, NMConnection *connection)
{
	NMSettingMacvlan *s_macvlan;
	NMSettingWired *s_wired;
	const char *parent = NULL;

	g_return_val_if_fail (nm_connection_is_type (connection, NM_SETTING_MACVLAN_SETTING_NAME), NULL);

	s_macvlan = nm_connection_get_setting_macvlan (connection);
	g_assert (s_macvlan);

	parent = nm_setting_macvlan_get_parent (s_macvlan);
	if (parent)
		return parent;

	/* Try the hardware address from the MACVLAN connection's hardware setting */
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
	NMSettingMacvlan *s_macvlan;
	const char *ifname;

	g_return_val_if_fail (nm_connection_is_type (connection, NM_SETTING_MACVLAN_SETTING_NAME), NULL);

	s_macvlan = nm_connection_get_setting_macvlan (connection);
	g_assert (s_macvlan);

	if (!parent_iface)
		return NULL;

	ifname = nm_connection_get_interface_name (connection);
	return g_strdup (ifname);
}

NM_DEVICE_FACTORY_DEFINE_INTERNAL (MACVLAN, Macvlan, macvlan,
	NM_DEVICE_FACTORY_DECLARE_LINK_TYPES (NM_LINK_TYPE_MACVLAN, NM_LINK_TYPE_MACVTAP)
	NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES (NM_SETTING_MACVLAN_SETTING_NAME),
	factory_iface->create_device = create_device;
	factory_iface->get_connection_parent = get_connection_parent;
	factory_iface->get_connection_iface = get_connection_iface;
	)

