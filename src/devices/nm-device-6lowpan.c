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
 * Copyright 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-device-6lowpan.h"

#include "nm-device-private.h"
#include "settings/nm-settings.h"
#include "platform/nm-platform.h"
#include "nm-device-factory.h"
#include "nm-setting-6lowpan.h"
#include "nm-utils.h"

#include "nm-device-logging.h"
_LOG_DECLARE_SELF(NMDevice6Lowpan);

/*****************************************************************************/

typedef struct {
	gulong parent_state_id;
} NMDevice6LowpanPrivate;

struct _NMDevice6Lowpan {
	NMDevice parent;
	NMDevice6LowpanPrivate _priv;
};

struct _NMDevice6LowpanClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDevice6Lowpan, nm_device_6lowpan, NM_TYPE_DEVICE)

#define NM_DEVICE_6LOWPAN_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMDevice6Lowpan, NM_IS_DEVICE_6LOWPAN)

/*****************************************************************************/

static void
parent_state_changed (NMDevice *parent,
                      NMDeviceState new_state,
                      NMDeviceState old_state,
                      NMDeviceStateReason reason,
                      gpointer user_data)
{
	NMDevice6Lowpan *self = NM_DEVICE_6LOWPAN (user_data);

	nm_device_set_unmanaged_by_flags (NM_DEVICE (self), NM_UNMANAGED_PARENT, !nm_device_get_managed (parent, FALSE), reason);
}

static void
parent_changed_notify (NMDevice *device,
                       int old_ifindex,
                       NMDevice *old_parent,
                       int new_ifindex,
                       NMDevice *new_parent)
{
	NMDevice6Lowpan *self = NM_DEVICE_6LOWPAN (device);
	NMDevice6LowpanPrivate *priv = NM_DEVICE_6LOWPAN_GET_PRIVATE (self);

	NM_DEVICE_CLASS (nm_device_6lowpan_parent_class)->parent_changed_notify (device, old_ifindex, old_parent, new_ifindex, new_parent);

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

static gboolean
create_and_realize (NMDevice *device,
                    NMConnection *connection,
                    NMDevice *parent,
                    const NMPlatformLink **out_plink,
                    GError **error)
{
	const char *iface = nm_device_get_iface (device);
	NMSetting6Lowpan *s_6lowpan;
	int parent_ifindex;
	int r;

	s_6lowpan = NM_SETTING_6LOWPAN (nm_connection_get_setting (connection, NM_TYPE_SETTING_6LOWPAN));
	g_return_val_if_fail (s_6lowpan, FALSE);

	parent_ifindex = parent ? nm_device_get_ifindex (parent) : 0;

	if (parent_ifindex <= 0) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_MISSING_DEPENDENCIES,
		             "6LoWPAN devices can not be created without a parent interface");
		g_return_val_if_fail (!parent, FALSE);
		return FALSE;
	}

	r = nm_platform_link_6lowpan_add (nm_device_get_platform (device), iface, parent_ifindex, out_plink);
	if (r < 0) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_CREATION_FAILED,
		             "Failed to create 6lowpan interface '%s' for '%s': %s",
		             iface,
		             nm_connection_get_id (connection),
		             nm_strerror (r));
		return FALSE;
	}

	nm_device_parent_set_ifindex (device, parent_ifindex);

	return TRUE;
}

static NMDeviceCapabilities
get_generic_capabilities (NMDevice *dev)
{
	return NM_DEVICE_CAP_CARRIER_DETECT | NM_DEVICE_CAP_IS_SOFTWARE;
}

static void
link_changed (NMDevice *device,
	      const NMPlatformLink *pllink)
{
	NMDevice6Lowpan *self = NM_DEVICE_6LOWPAN (device);
	int parent = 0;
	int ifindex;

	NM_DEVICE_CLASS (nm_device_6lowpan_parent_class)->link_changed (device, pllink);

	ifindex = nm_device_get_ifindex (device);
	if (!nm_platform_link_6lowpan_get_properties (nm_device_get_platform (device), ifindex, &parent)) {
		_LOGW (LOGD_DEVICE, "could not get 6lowpan properties");
		return;
	}

	nm_device_parent_set_ifindex (device, parent);
}

static gboolean
is_available (NMDevice *device, NMDeviceCheckDevAvailableFlags flags)
{
	if (!nm_device_parent_get_device (device))
		return FALSE;
	return NM_DEVICE_CLASS (nm_device_6lowpan_parent_class)->is_available (device, flags);
}

static gboolean
complete_connection (NMDevice *device,
                     NMConnection *connection,
                     const char *specific_object,
                     NMConnection *const*existing_connections,
                     GError **error)
{
	NMSetting6Lowpan *s_6lowpan;

	nm_utils_complete_generic (nm_device_get_platform (device),
	                           connection,
	                           NM_SETTING_6LOWPAN_SETTING_NAME,
	                           existing_connections,
	                           NULL,
	                           _("6LOWPAN connection"),
	                           NULL,
	                           TRUE);

	s_6lowpan = NM_SETTING_6LOWPAN (nm_connection_get_setting (connection, NM_TYPE_SETTING_6LOWPAN));
	if (!s_6lowpan) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INVALID_CONNECTION,
		                     "A '6lowpan' setting is required.");
		return FALSE;
	}

	/* If there's no 6LoWPAN interface, no parent, and no hardware address in the
	 * settings, then there's not enough information to complete the setting.
	 */
	if (   !nm_setting_6lowpan_get_parent (s_6lowpan)
	    && !nm_device_match_parent_hwaddr (device, connection, TRUE)) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INVALID_CONNECTION,
		                     "The '6lowpan' setting had no interface name, parent, or hardware address.");
		return FALSE;
	}

	return TRUE;
}

static void
update_connection (NMDevice *device, NMConnection *connection)
{
	NMSetting6Lowpan *s_6lowpan = NM_SETTING_6LOWPAN (nm_connection_get_setting (connection, NM_TYPE_SETTING_6LOWPAN));

	if (!s_6lowpan) {
		s_6lowpan = (NMSetting6Lowpan *) nm_setting_6lowpan_new ();
		nm_connection_add_setting (connection, (NMSetting *) s_6lowpan);
	}

	g_object_set (s_6lowpan,
	              NM_SETTING_6LOWPAN_PARENT,
	              nm_device_parent_find_for_connection (device,
	                                                    nm_setting_6lowpan_get_parent (s_6lowpan)),
	              NULL);
}

static NMActStageReturn
act_stage1_prepare (NMDevice *dev, NMDeviceStateReason *out_failure_reason)
{
	NMActStageReturn ret;

	ret = NM_DEVICE_CLASS (nm_device_6lowpan_parent_class)->act_stage1_prepare (dev, out_failure_reason);
	if (ret != NM_ACT_STAGE_RETURN_SUCCESS)
		return ret;

	if (!nm_device_hw_addr_set_cloned (dev, nm_device_get_applied_connection (dev), FALSE))
		return NM_ACT_STAGE_RETURN_FAILURE;
	return NM_ACT_STAGE_RETURN_SUCCESS;
}

/*****************************************************************************/

static void
nm_device_6lowpan_init (NMDevice6Lowpan *self)
{
}

static const NMDBusInterfaceInfoExtended interface_info_device_6lowpan = {
	.parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT (
		NM_DBUS_INTERFACE_DEVICE_6LOWPAN,
		.properties = NM_DEFINE_GDBUS_PROPERTY_INFOS (
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE ("HwAddress", "s", NM_DEVICE_HW_ADDRESS),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE ("Parent", "o", NM_DEVICE_PARENT),
		),
	),
};

static void
nm_device_6lowpan_class_init (NMDevice6LowpanClass *klass)
{
	NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS (&interface_info_device_6lowpan);

	device_class->connection_type_supported = NM_SETTING_6LOWPAN_SETTING_NAME;
	device_class->connection_type_check_compatible = NM_SETTING_6LOWPAN_SETTING_NAME;
	device_class->link_types = NM_DEVICE_DEFINE_LINK_TYPES (NM_LINK_TYPE_6LOWPAN);

	device_class->act_stage1_prepare = act_stage1_prepare;
	device_class->complete_connection = complete_connection;
	device_class->create_and_realize = create_and_realize;
	device_class->get_generic_capabilities = get_generic_capabilities;
	device_class->get_configured_mtu = nm_device_get_configured_mtu_for_wired;
	device_class->link_changed = link_changed;
	device_class->is_available = is_available;
	device_class->parent_changed_notify = parent_changed_notify;
	device_class->update_connection = update_connection;
}

/*****************************************************************************/

#define NM_TYPE_6LOWPAN_DEVICE_FACTORY (nm_6lowpan_device_factory_get_type ())
#define NM_6LOWPAN_DEVICE_FACTORY(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_6LOWPAN_DEVICE_FACTORY, NM6LowpanDeviceFactory))

static NMDevice *
create_device (NMDeviceFactory *factory,
               const char *iface,
               const NMPlatformLink *plink,
               NMConnection *connection,
               gboolean *out_ignore)
{
	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_6LOWPAN,
	                                  NM_DEVICE_IFACE, iface,
	                                  NM_DEVICE_TYPE_DESC, "6LoWPAN",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_6LOWPAN,
	                                  NM_DEVICE_LINK_TYPE, NM_LINK_TYPE_6LOWPAN,
	                                  NULL);
}

static const char *
get_connection_parent (NMDeviceFactory *factory, NMConnection *connection)
{
	NMSetting6Lowpan *s_6lowpan;

	g_return_val_if_fail (nm_connection_is_type (connection, NM_SETTING_6LOWPAN_SETTING_NAME), NULL);

	s_6lowpan = NM_SETTING_6LOWPAN (nm_connection_get_setting (connection, NM_TYPE_SETTING_6LOWPAN));
	g_assert (s_6lowpan);

	return nm_setting_6lowpan_get_parent (s_6lowpan);
}

static char *
get_connection_iface (NMDeviceFactory *factory,
                      NMConnection *connection,
                      const char *parent_iface)
{
	NMSetting6Lowpan *s_6lowpan;
	const char *ifname;

	g_return_val_if_fail (nm_connection_is_type (connection, NM_SETTING_6LOWPAN_SETTING_NAME), NULL);

	s_6lowpan = NM_SETTING_6LOWPAN (nm_connection_get_setting (connection, NM_TYPE_SETTING_6LOWPAN));
	g_assert (s_6lowpan);

	if (!parent_iface)
		return NULL;

	ifname = nm_connection_get_interface_name (connection);
	return g_strdup (ifname);
}

NM_DEVICE_FACTORY_DEFINE_INTERNAL (6LOWPAN, 6Lowpan, 6lowpan,
	NM_DEVICE_FACTORY_DECLARE_LINK_TYPES (NM_LINK_TYPE_6LOWPAN)
	NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES (NM_SETTING_6LOWPAN_SETTING_NAME),
	factory_class->create_device = create_device;
	factory_class->get_connection_parent = get_connection_parent;
	factory_class->get_connection_iface = get_connection_iface;
);
