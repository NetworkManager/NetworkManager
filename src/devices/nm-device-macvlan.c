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
#include "settings/nm-settings.h"
#include "nm-act-request.h"
#include "nm-manager.h"
#include "platform/nm-platform.h"
#include "nm-device-factory.h"
#include "nm-setting-macvlan.h"
#include "nm-setting-wired.h"
#include "nm-active-connection.h"
#include "nm-ip4-config.h"
#include "nm-utils.h"

#include "nm-device-logging.h"
_LOG_DECLARE_SELF(NMDeviceMacvlan);

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NMDeviceMacvlan,
	PROP_MODE,
	PROP_NO_PROMISC,
	PROP_TAP,
);

typedef struct {
	gulong parent_state_id;
	NMPlatformLnkMacvlan props;
} NMDeviceMacvlanPrivate;

struct _NMDeviceMacvlan {
	NMDevice parent;
	NMDeviceMacvlanPrivate _priv;
};

struct _NMDeviceMacvlanClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDeviceMacvlan, nm_device_macvlan, NM_TYPE_DEVICE)

#define NM_DEVICE_MACVLAN_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMDeviceMacvlan, NM_IS_DEVICE_MACVLAN)

/*****************************************************************************/

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

/*****************************************************************************/

static void
parent_state_changed (NMDevice *parent,
                      NMDeviceState new_state,
                      NMDeviceState old_state,
                      NMDeviceStateReason reason,
                      gpointer user_data)
{
	NMDeviceMacvlan *self = NM_DEVICE_MACVLAN (user_data);

	/* We'll react to our own carrier state notifications. Ignore the parent's. */
	if (nm_device_state_reason_check (reason) == NM_DEVICE_STATE_REASON_CARRIER)
		return;

	nm_device_set_unmanaged_by_flags (NM_DEVICE (self), NM_UNMANAGED_PARENT, !nm_device_get_managed (parent, FALSE), reason);
}

static void
parent_changed_notify (NMDevice *device,
                       int old_ifindex,
                       NMDevice *old_parent,
                       int new_ifindex,
                       NMDevice *new_parent)
{
	NMDeviceMacvlan *self = NM_DEVICE_MACVLAN (device);
	NMDeviceMacvlanPrivate *priv = NM_DEVICE_MACVLAN_GET_PRIVATE (self);

	NM_DEVICE_CLASS (nm_device_macvlan_parent_class)->parent_changed_notify (device, old_ifindex, old_parent, new_ifindex, new_parent);

	/*  note that @self doesn't have to clear @parent_state_id on dispose,
	 *  because NMDevice's dispose() will unset the parent, which in turn calls
	 *  parent_changed_notify(). */
	nm_clear_g_signal_handler (old_parent, &priv->parent_state_id);

	if (new_parent) {
		priv->parent_state_id = g_signal_connect (new_parent,
		                                          NM_DEVICE_STATE_CHANGED,
		                                          G_CALLBACK (parent_state_changed),
		                                          device);

		/* Set parent-dependent unmanaged flag */
		nm_device_set_unmanaged_by_flags (device,
		                                  NM_UNMANAGED_PARENT,
		                                  !nm_device_get_managed (new_parent, FALSE),
		                                  NM_DEVICE_STATE_REASON_PARENT_MANAGED_CHANGED);
	}

	if (new_ifindex > 0) {
		/* Recheck availability now that the parent has changed */
		nm_device_queue_recheck_available (device,
		                                   NM_DEVICE_STATE_REASON_PARENT_CHANGED,
		                                   NM_DEVICE_STATE_REASON_PARENT_CHANGED);
	}
}

static void
update_properties (NMDevice *device)
{
	NMDeviceMacvlan *self = NM_DEVICE_MACVLAN (device);
	NMDeviceMacvlanPrivate *priv = NM_DEVICE_MACVLAN_GET_PRIVATE (self);
	GObject *object = G_OBJECT (device);
	const NMPlatformLnkMacvlan *props;
	const NMPlatformLink *plink;

	if (priv->props.tap)
		props = nm_platform_link_get_lnk_macvtap (nm_device_get_platform (device), nm_device_get_ifindex (device), &plink);
	else
		props = nm_platform_link_get_lnk_macvlan (nm_device_get_platform (device), nm_device_get_ifindex (device), &plink);

	if (!props) {
		_LOGW (LOGD_PLATFORM, "could not get %s properties", priv->props.tap ? "macvtap" : "macvlan");
		return;
	}

	g_object_freeze_notify (object);

	nm_device_parent_set_ifindex (device, plink->parent);

#define CHECK_PROPERTY_CHANGED(field, prop) \
	G_STMT_START { \
		if (priv->props.field != props->field) { \
			priv->props.field = props->field; \
			_notify (self, prop); \
		} \
	} G_STMT_END

	CHECK_PROPERTY_CHANGED (mode, PROP_MODE);
	CHECK_PROPERTY_CHANGED (no_promisc, PROP_NO_PROMISC);

	g_object_thaw_notify (object);
}

static void
link_changed (NMDevice *device,
              const NMPlatformLink *pllink)
{
	NM_DEVICE_CLASS (nm_device_macvlan_parent_class)->link_changed (device, pllink);
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
	g_return_val_if_fail (s_macvlan, FALSE);

	parent_ifindex = parent ? nm_device_get_ifindex (parent) : 0;

	if (parent_ifindex <= 0) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_MISSING_DEPENDENCIES,
		             "MACVLAN devices can not be created without a parent interface");
		g_return_val_if_fail (!parent, FALSE);
		return FALSE;
	}

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

	plerr = nm_platform_link_macvlan_add (nm_device_get_platform (device), iface, parent_ifindex, &lnk, out_plink);
	if (plerr != NM_PLATFORM_ERROR_SUCCESS) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_CREATION_FAILED,
		             "Failed to create %s interface '%s' for '%s': %s",
		             lnk.tap ? "macvtap" : "macvlan",
		             iface,
		             nm_connection_get_id (connection),
		             nm_platform_error_to_string_a (plerr));
		return FALSE;
	}

	return TRUE;
}

/*****************************************************************************/

static NMDeviceCapabilities
get_generic_capabilities (NMDevice *dev)
{
	/* We assume MACVLAN interfaces always support carrier detect */
	return NM_DEVICE_CAP_CARRIER_DETECT | NM_DEVICE_CAP_IS_SOFTWARE;
}

/*****************************************************************************/

static gboolean
is_available (NMDevice *device, NMDeviceCheckDevAvailableFlags flags)
{
	if (!nm_device_parent_get_device (device))
		return FALSE;
	return NM_DEVICE_CLASS (nm_device_macvlan_parent_class)->is_available (device, flags);
}

/*****************************************************************************/

static gboolean
check_connection_compatible (NMDevice *device, NMConnection *connection)
{
	NMDeviceMacvlanPrivate *priv = NM_DEVICE_MACVLAN_GET_PRIVATE ((NMDeviceMacvlan *) device);
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
			if (!nm_device_match_parent (device, parent))
				return FALSE;
		} else {
			/* Parent could be a MAC address in an NMSettingWired */
			if (!nm_device_match_hwaddr (device, connection, TRUE))
				return FALSE;
		}
	}

	return TRUE;
}

static gboolean
complete_connection (NMDevice *device,
                     NMConnection *connection,
                     const char *specific_object,
                     NMConnection *const*existing_connections,
                     GError **error)
{
	NMSettingMacvlan *s_macvlan;

	nm_utils_complete_generic (nm_device_get_platform (device),
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
	    && !nm_device_match_hwaddr (device, connection, TRUE)) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INVALID_CONNECTION,
		                     "The 'macvlan' setting had no interface name, parent, or hardware address.");
		return FALSE;
	}

	return TRUE;
}

static void
update_connection (NMDevice *device, NMConnection *connection)
{
	NMDeviceMacvlanPrivate *priv = NM_DEVICE_MACVLAN_GET_PRIVATE ((NMDeviceMacvlan *) device);
	NMSettingMacvlan *s_macvlan = nm_connection_get_setting_macvlan (connection);
	NMDevice *parent_device;
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
	parent_device = nm_device_parent_get_device (device);
	if (parent_device) {
		new_parent = nm_device_get_iface (parent_device);
		setting_parent = nm_setting_macvlan_get_parent (s_macvlan);
		if (setting_parent && nm_utils_is_uuid (setting_parent)) {
			NMConnection *parent_connection;

			/* Don't change a parent specified by UUID if it's still valid */
			parent_connection = (NMConnection *) nm_settings_get_connection_by_uuid (nm_device_get_settings (device), setting_parent);
			if (parent_connection && nm_device_check_connection_compatible (parent_device, parent_connection))
				new_parent = NULL;
		}
		if (new_parent)
			g_object_set (s_macvlan, NM_SETTING_MACVLAN_PARENT, new_parent, NULL);
	} else
		g_object_set (s_macvlan, NM_SETTING_MACVLAN_PARENT, NULL, NULL);

}

static NMActStageReturn
act_stage1_prepare (NMDevice *dev, NMDeviceStateReason *out_failure_reason)
{
	NMActStageReturn ret;

	ret = NM_DEVICE_CLASS (nm_device_macvlan_parent_class)->act_stage1_prepare (dev, out_failure_reason);
	if (ret != NM_ACT_STAGE_RETURN_SUCCESS)
		return ret;

	if (!nm_device_hw_addr_set_cloned (dev, nm_device_get_applied_connection (dev), FALSE))
		return NM_ACT_STAGE_RETURN_FAILURE;
	return NM_ACT_STAGE_RETURN_SUCCESS;
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMDeviceMacvlanPrivate *priv = NM_DEVICE_MACVLAN_GET_PRIVATE ((NMDeviceMacvlan *) object);

	switch (prop_id) {
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
	NMDeviceMacvlanPrivate *priv = NM_DEVICE_MACVLAN_GET_PRIVATE ((NMDeviceMacvlan *) object);

	switch (prop_id) {
	case PROP_TAP:
		priv->props.tap = g_value_get_boolean (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
	}
}

/*****************************************************************************/

static void
nm_device_macvlan_init (NMDeviceMacvlan *self)
{
}

static const NMDBusInterfaceInfoExtended interface_info_device_macvlan = {
	.parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT (
		NM_DBUS_INTERFACE_DEVICE_MACVLAN,
		.signals = NM_DEFINE_GDBUS_SIGNAL_INFOS (
			&nm_signal_info_property_changed_legacy,
		),
		.properties = NM_DEFINE_GDBUS_PROPERTY_INFOS (
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Parent",    "o", NM_DEVICE_PARENT),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Mode",      "s", NM_DEVICE_MACVLAN_MODE),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("NoPromisc", "b", NM_DEVICE_MACVLAN_NO_PROMISC),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Tab",       "b", NM_DEVICE_MACVLAN_TAP),
		),
	),
	.legacy_property_changed = TRUE,
};

static void
nm_device_macvlan_class_init (NMDeviceMacvlanClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	NM_DEVICE_CLASS_DECLARE_TYPES (klass, NULL, NM_LINK_TYPE_MACVLAN, NM_LINK_TYPE_MACVTAP)

	object_class->get_property = get_property;
	object_class->set_property = set_property;

	dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS (&interface_info_device_macvlan);

	device_class->act_stage1_prepare = act_stage1_prepare;
	device_class->check_connection_compatible = check_connection_compatible;
	device_class->complete_connection = complete_connection;
	device_class->connection_type = NM_SETTING_MACVLAN_SETTING_NAME;
	device_class->create_and_realize = create_and_realize;
	device_class->get_generic_capabilities = get_generic_capabilities;
	device_class->get_configured_mtu = nm_device_get_configured_mtu_for_wired;
	device_class->is_available = is_available;
	device_class->link_changed = link_changed;
	device_class->parent_changed_notify = parent_changed_notify;
	device_class->update_connection = update_connection;

	obj_properties[PROP_MODE] =
	     g_param_spec_string (NM_DEVICE_MACVLAN_MODE, "", "",
	                          NULL,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_NO_PROMISC] =
	     g_param_spec_boolean (NM_DEVICE_MACVLAN_NO_PROMISC, "", "",
	                           FALSE,
	                           G_PARAM_READABLE |
	                           G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_TAP] =
	     g_param_spec_boolean (NM_DEVICE_MACVLAN_TAP, "", "",
	                           FALSE,
	                           G_PARAM_READWRITE |
	                           G_PARAM_CONSTRUCT_ONLY |
	                           G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}

/*****************************************************************************/

#define NM_TYPE_MACVLAN_DEVICE_FACTORY (nm_macvlan_device_factory_get_type ())
#define NM_MACVLAN_DEVICE_FACTORY(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_MACVLAN_DEVICE_FACTORY, NMMacvlanDeviceFactory))

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
	factory_class->create_device = create_device;
	factory_class->get_connection_parent = get_connection_parent;
	factory_class->get_connection_iface = get_connection_iface;
);
