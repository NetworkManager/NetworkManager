/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-device-dummy.h"

#include <stdlib.h>
#include <sys/types.h>

#include "nm-act-request.h"
#include "nm-device-private.h"
#include "nm-ip4-config.h"
#include "platform/nm-platform.h"
#include "nm-device-factory.h"
#include "nm-setting-dummy.h"
#include "nm-core-internal.h"

#include "nm-device-logging.h"
_LOG_DECLARE_SELF(NMDeviceDummy);

/*****************************************************************************/

struct _NMDeviceDummy {
	NMDevice parent;
};

struct _NMDeviceDummyClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDeviceDummy, nm_device_dummy, NM_TYPE_DEVICE)

/*****************************************************************************/

static NMDeviceCapabilities
get_generic_capabilities (NMDevice *dev)
{
	return NM_DEVICE_CAP_IS_SOFTWARE;
}

static gboolean
complete_connection (NMDevice *device,
                     NMConnection *connection,
                     const char *specific_object,
                     NMConnection *const*existing_connections,
                     GError **error)
{
	NMSettingDummy *s_dummy;

	nm_utils_complete_generic (nm_device_get_platform (device),
	                           connection,
	                           NM_SETTING_DUMMY_SETTING_NAME,
	                           existing_connections,
	                           NULL,
	                           _("Dummy connection"),
	                           NULL,
	                           NULL,
	                           TRUE);

	s_dummy = nm_connection_get_setting_dummy (connection);
	if (!s_dummy) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INVALID_CONNECTION,
		                     "A 'dummy' setting is required.");
		return FALSE;
	}

	return TRUE;
}

static void
update_connection (NMDevice *device, NMConnection *connection)
{
	NMSettingDummy *s_dummy = nm_connection_get_setting_dummy (connection);

	if (!s_dummy) {
		s_dummy = (NMSettingDummy *) nm_setting_dummy_new ();
		nm_connection_add_setting (connection, (NMSetting *) s_dummy);
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
	NMSettingDummy *s_dummy;
	int r;

	s_dummy = nm_connection_get_setting_dummy (connection);
	g_assert (s_dummy);

	r = nm_platform_link_dummy_add (nm_device_get_platform (device), iface, out_plink);
	if (r < 0) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_CREATION_FAILED,
		             "Failed to create dummy interface '%s' for '%s': %s",
		             iface,
		             nm_connection_get_id (connection),
		             nm_strerror (r));
		return FALSE;
	}

	return TRUE;
}

static NMActStageReturn
act_stage1_prepare (NMDevice *device, NMDeviceStateReason *out_failure_reason)
{
	NMActStageReturn ret;

	ret = NM_DEVICE_CLASS (nm_device_dummy_parent_class)->act_stage1_prepare (device, out_failure_reason);
	if (ret != NM_ACT_STAGE_RETURN_SUCCESS)
		return ret;

	if (!nm_device_hw_addr_set_cloned (device, nm_device_get_applied_connection (device), FALSE))
		return NM_ACT_STAGE_RETURN_FAILURE;

	return NM_ACT_STAGE_RETURN_SUCCESS;
}

/*****************************************************************************/

static void
nm_device_dummy_init (NMDeviceDummy *self)
{
}

static const NMDBusInterfaceInfoExtended interface_info_device_dummy = {
	.parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT (
		NM_DBUS_INTERFACE_DEVICE_DUMMY,
		.signals = NM_DEFINE_GDBUS_SIGNAL_INFOS (
			&nm_signal_info_property_changed_legacy,
		),
		.properties = NM_DEFINE_GDBUS_PROPERTY_INFOS (
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("HwAddress", "s",  NM_DEVICE_HW_ADDRESS),
		),
	),
	.legacy_property_changed = TRUE,
};

static void
nm_device_dummy_class_init (NMDeviceDummyClass *klass)
{
	NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS (&interface_info_device_dummy);

	device_class->connection_type_supported = NM_SETTING_DUMMY_SETTING_NAME;
	device_class->connection_type_check_compatible = NM_SETTING_DUMMY_SETTING_NAME;
	device_class->link_types = NM_DEVICE_DEFINE_LINK_TYPES (NM_LINK_TYPE_DUMMY);

	device_class->complete_connection = complete_connection;
	device_class->create_and_realize = create_and_realize;
	device_class->get_generic_capabilities = get_generic_capabilities;
	device_class->update_connection = update_connection;
	device_class->act_stage1_prepare = act_stage1_prepare;
	device_class->get_configured_mtu = nm_device_get_configured_mtu_for_wired;
}

/*****************************************************************************/

#define NM_TYPE_DUMMY_DEVICE_FACTORY (nm_dummy_device_factory_get_type ())
#define NM_DUMMY_DEVICE_FACTORY(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DUMMY_DEVICE_FACTORY, NMDummyDeviceFactory))

static NMDevice *
create_device (NMDeviceFactory *factory,
               const char *iface,
               const NMPlatformLink *plink,
               NMConnection *connection,
               gboolean *out_ignore)
{
	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_DUMMY,
	                                  NM_DEVICE_IFACE, iface,
	                                  NM_DEVICE_TYPE_DESC, "Dummy",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_DUMMY,
	                                  NM_DEVICE_LINK_TYPE, NM_LINK_TYPE_DUMMY,
	                                  NULL);
}

NM_DEVICE_FACTORY_DEFINE_INTERNAL (DUMMY, Dummy, dummy,
	NM_DEVICE_FACTORY_DECLARE_LINK_TYPES (NM_LINK_TYPE_DUMMY)
	NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES (NM_SETTING_DUMMY_SETTING_NAME),
	factory_class->create_device = create_device;
);
