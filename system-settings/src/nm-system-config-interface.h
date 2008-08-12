/* NetworkManager -- Network link manager
 *
 * Dan Williams <dcbw@redhat.com>
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
 * (C) Copyright 2007 Red Hat, Inc.
 */

#ifndef NM_SYSTEM_CONFIG_INTERFACE_H
#define NM_SYSTEM_CONFIG_INTERFACE_H

#include <glib.h>
#include <glib-object.h>
#include <nm-connection.h>
#include <nm-settings.h>

#include "nm-system-config-hal-manager.h"

G_BEGIN_DECLS

#define PLUGIN_PRINT(pname, fmt, args...) \
	{ g_message ("   " pname ": " fmt, ##args); }

#define PLUGIN_WARN(pname, fmt, args...) \
	{ g_warning ("   " pname ": " fmt, ##args); }


/* Plugin's factory function that returns a GObject that implements
 * NMSystemConfigInterface.
 */
GObject * nm_system_config_factory (void);

/* NOTE:
 *   When passing NMConnection objects to NetworkManager, any properties
 * of that NMConnection's NMSetting objects that are secrets must be set as
 * GObject data items on the NMSetting object, _not_ inside the NMSetting
 * object itself.  This is to ensure that the secrets are only given to
 * NetworkManager itself and not exposed to clients like nm-applet that need
 * connection details, but not secrets.
 */

#define NM_TYPE_SYSTEM_CONFIG_INTERFACE      (nm_system_config_interface_get_type ())
#define NM_SYSTEM_CONFIG_INTERFACE(obj)      (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SYSTEM_CONFIG_INTERFACE, NMSystemConfigInterface))
#define NM_IS_SYSTEM_CONFIG_INTERFACE(obj)   (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SYSTEM_CONFIG_INTERFACE))
#define NM_SYSTEM_CONFIG_INTERFACE_GET_INTERFACE(obj) (G_TYPE_INSTANCE_GET_INTERFACE ((obj), NM_TYPE_SYSTEM_CONFIG_INTERFACE, NMSystemConfigInterface))


#define NM_SYSTEM_CONFIG_INTERFACE_NAME "name"
#define NM_SYSTEM_CONFIG_INTERFACE_INFO "info"
#define NM_SYSTEM_CONFIG_INTERFACE_HOSTNAME "hostname"

typedef enum {
	NM_SYSTEM_CONFIG_INTERFACE_PROP_FIRST = 0x1000,

	NM_SYSTEM_CONFIG_INTERFACE_PROP_NAME = NM_SYSTEM_CONFIG_INTERFACE_PROP_FIRST,
	NM_SYSTEM_CONFIG_INTERFACE_PROP_INFO,
	NM_SYSTEM_CONFIG_INTERFACE_PROP_HOSTNAME,
} NMSystemConfigInterfaceProp;


typedef struct _NMSystemConfigInterface NMSystemConfigInterface;

struct _NMSystemConfigInterface {
	GTypeInterface g_iface;

	/* Called when the plugin is loaded to initialize it */
	void     (*init) (NMSystemConfigInterface *config, NMSystemConfigHalManager *hal_manager);

	/* Returns the plugins currently known list of connections.  The returned
	 * list is freed by the system settings service.
	 */
	GSList * (*get_connections) (NMSystemConfigInterface *config);

	/*
	 * Return a list of HAL UDIs of devices which NetworkManager should not
	 * manage.  Returned list will be freed by the system settings service, and
	 * each element must be allocated using g_malloc() or its variants.
	 */
	GSList * (*get_unmanaged_devices) (NMSystemConfigInterface *config);

	/*
	 * Add a new connection.
	 */
	gboolean (*add_connection) (NMSystemConfigInterface *config, NMConnection *connection, GError **error);

	/* Signals */

	/* Emitted when a new connection has been found by the plugin */
	void (*connection_added)   (NMSystemConfigInterface *config, NMExportedConnection *connection);

	/* Emitted when the list of unmanaged devices changes */
	void (*unmanaged_devices_changed) (NMSystemConfigInterface *config);
};

GType nm_system_config_interface_get_type (void);

void nm_system_config_interface_init (NMSystemConfigInterface *config,
                                      NMSystemConfigHalManager *hal_manager);

GSList * nm_system_config_interface_get_connections (NMSystemConfigInterface *config);

GSList *nm_system_config_interface_get_unmanaged_devices (NMSystemConfigInterface *config);

gboolean nm_system_config_interface_supports_add (NMSystemConfigInterface *config);

gboolean nm_system_config_interface_add_connection (NMSystemConfigInterface *config,
                                                    NMConnection *connection,
                                                    GError **error);

G_END_DECLS

#endif	/* NM_SYSTEM_CONFIG_INTERFACE_H */
