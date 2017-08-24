/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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
#include <string.h>
#include <sys/types.h>

#include "nm-act-request.h"
#include "nm-device-private.h"
#include "nm-ip4-config.h"
#include "platform/nm-platform.h"
#include "nm-device-factory.h"
#include "nm-setting-dummy.h"
#include "nm-core-internal.h"

#include "introspection/org.freedesktop.NetworkManager.Device.Dummy.h"

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
                     const GSList *existing_connections,
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
	NMPlatformError plerr;
	NMSettingDummy *s_dummy;

	s_dummy = nm_connection_get_setting_dummy (connection);
	g_assert (s_dummy);

	plerr = nm_platform_link_dummy_add (nm_device_get_platform (device), iface, out_plink);
	if (plerr != NM_PLATFORM_ERROR_SUCCESS) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_CREATION_FAILED,
		             "Failed to create dummy interface '%s' for '%s': %s",
		             iface,
		             nm_connection_get_id (connection),
		             nm_platform_error_to_string_a (plerr));
		return FALSE;
	}

	return TRUE;
}

static gboolean
check_connection_compatible (NMDevice *device, NMConnection *connection)
{
	NMSettingDummy *s_dummy;

	if (!NM_DEVICE_CLASS (nm_device_dummy_parent_class)->check_connection_compatible (device, connection))
		return FALSE;

	s_dummy = nm_connection_get_setting_dummy (connection);
	if (!s_dummy)
		return FALSE;

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

static void
nm_device_dummy_class_init (NMDeviceDummyClass *klass)
{
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	NM_DEVICE_CLASS_DECLARE_TYPES (klass, NULL, NM_LINK_TYPE_DUMMY)

	device_class->connection_type = NM_SETTING_DUMMY_SETTING_NAME;
	device_class->complete_connection = complete_connection;
	device_class->check_connection_compatible = check_connection_compatible;
	device_class->create_and_realize = create_and_realize;
	device_class->get_generic_capabilities = get_generic_capabilities;
	device_class->update_connection = update_connection;
	device_class->act_stage1_prepare = act_stage1_prepare;
	device_class->get_configured_mtu = nm_device_get_configured_mtu_for_wired;

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (klass),
	                                        NMDBUS_TYPE_DEVICE_DUMMY_SKELETON,
	                                        NULL);
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
