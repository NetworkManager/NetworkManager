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
 * Copyright (C) 2019 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-manager.h"
#include "nm-device-contrail-vrouter.h"
#include "platform/nm-platform.h"
#include "nm-core-internal.h"
#include "devices/nm-device-factory.h"

/*****************************************************************************/

typedef struct {
	NMDeviceFactory parent;
} NMContrailFactory;

typedef struct {
	NMDeviceFactoryClass parent;
} NMContrailFactoryClass;

#define NM_TYPE_CONTRAIL_FACTORY            (nm_contrail_factory_get_type ())
#define NM_CONTRAIL_FACTORY(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_CONTRAIL_FACTORY, NMContrailFactory))
#define NM_CONTRAIL_FACTORY_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_CONTRAIL_FACTORY, NMContrailFactoryClass))
#define NM_IS_CONTRAIL_FACTORY(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_CONTRAIL_FACTORY))
#define NM_IS_CONTRAIL_FACTORY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_CONTRAIL_FACTORY))
#define NM_CONTRAIL_FACTORY_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_CONTRAIL_FACTORY, NMContrailFactoryClass))

static GType nm_contrail_factory_get_type (void);
G_DEFINE_TYPE (NMContrailFactory, nm_contrail_factory, NM_TYPE_DEVICE_FACTORY)

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_DEVICE
#define _NMLOG(level, ...) __NMLOG_DEFAULT (level, _NMLOG_DOMAIN, "contrail", __VA_ARGS__)

/*****************************************************************************/

NM_DEVICE_FACTORY_DECLARE_TYPES (
	NM_DEVICE_FACTORY_DECLARE_LINK_TYPES    (NM_LINK_TYPE_CONTRAILVROUTER)
	NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES (NM_SETTING_CONTRAIL_VROUTER_SETTING_NAME)
)

G_MODULE_EXPORT NMDeviceFactory *
nm_device_factory_create (GError **error)
{
	return (NMDeviceFactory *) g_object_new (NM_TYPE_CONTRAIL_FACTORY, NULL);
}

static NMDevice *
new_device_from_type (const char *name, NMDeviceType device_type)
{
	GType type;
	const char *type_desc;
	NMLinkType link_type = NM_LINK_TYPE_NONE;

	if (nm_manager_get_device (nm_manager_get (), name, device_type))
		return NULL;

	if (device_type == NM_DEVICE_TYPE_CONTRAIL_VROUTER) {
		type = NM_TYPE_DEVICE_CONTRAIL_VROUTER;
		type_desc = "Contrail Vrouter";
		link_type = NM_LINK_TYPE_CONTRAILVROUTER;
	} else {
		return NULL;
	}

	return g_object_new (type,
	                     NM_DEVICE_IFACE, name,
	                     NM_DEVICE_DRIVER, "vrouter",
	                     NM_DEVICE_DEVICE_TYPE, device_type,
	                     NM_DEVICE_TYPE_DESC, type_desc,
	                     NM_DEVICE_LINK_TYPE, link_type,
	                     NULL);
}

static void
device_added (const char *name, NMDeviceType device_type, NMDeviceFactory *self)
{
	NMDevice *device = NULL;

	device = new_device_from_type (name, device_type);
	if (!device)
		return;

	g_signal_emit_by_name (self, NM_DEVICE_FACTORY_DEVICE_ADDED, device);
	g_object_unref (device);
}

static void
device_removed (const char *name, NMDeviceType device_type, NMDeviceFactory *self)
{
	NMDevice *device;
	NMDeviceState device_state;

	device = nm_manager_get_device (nm_manager_get (), name, device_type);
	if (!device)
		return;

	device_state = nm_device_get_state (device);
	if (   device_type == NM_DEVICE_TYPE_CONTRAIL_VROUTER
	    && device_state > NM_DEVICE_STATE_DISCONNECTED
	    && device_state < NM_DEVICE_STATE_DEACTIVATING) {
		nm_device_state_changed (device,
		                         NM_DEVICE_STATE_DEACTIVATING,
		                         NM_DEVICE_STATE_REASON_REMOVED);
	} else if (device_state == NM_DEVICE_STATE_UNMANAGED) {
		nm_device_unrealize (device, TRUE, NULL);
	}
}

static NMDevice *
create_device (NMDeviceFactory *self,
               const char *iface,
               const NMPlatformLink *plink,
               NMConnection *connection,
               gboolean *out_ignore)
{
	NMDeviceType device_type = NM_DEVICE_TYPE_UNKNOWN;
	const char *connection_type = NULL;

	if (connection)
		connection_type = nm_connection_get_connection_type (connection);

	if (plink)
		device_type = NM_DEVICE_TYPE_CONTRAIL_VROUTER;
	else if (g_strcmp0 (connection_type, NM_SETTING_CONTRAIL_VROUTER_SETTING_NAME) == 0)
		device_type = NM_DEVICE_TYPE_CONTRAIL_VROUTER;

	return new_device_from_type (iface, device_type);
}

static void
nm_contrail_factory_init (NMContrailFactory *self)
{
}

static void
nm_contrail_factory_class_init (NMContrailFactoryClass *klass)
{
	NMDeviceFactoryClass *factory_class = NM_DEVICE_FACTORY_CLASS (klass);

	factory_class->get_supported_types = get_supported_types;
	factory_class->create_device = create_device;
}
