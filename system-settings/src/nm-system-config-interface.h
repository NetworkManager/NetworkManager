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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2007 Red Hat, Inc.
 */

#ifndef NM_SYSTEM_CONFIG_INTERFACE_H
#define NM_SYSTEM_CONFIG_INTERFACE_H

#include <glib.h>
#include <glib-object.h>
#include <nm-connection.h>

G_BEGIN_DECLS

#define PLUGIN_PRINT(pname, fmt, args...) \
	{ g_print ("   " pname ": " fmt "\n", ##args); }

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

typedef enum {
	NM_SYSTEM_CONFIG_INTERFACE_PROP_FIRST = 0x1000,

	NM_SYSTEM_CONFIG_INTERFACE_PROP_NAME = NM_SYSTEM_CONFIG_INTERFACE_PROP_FIRST,
	NM_SYSTEM_CONFIG_INTERFACE_PROP_INFO,
} NMSystemConfigInterfaceProp;


typedef struct _NMSystemConfigInterface NMSystemConfigInterface;

struct _NMSystemConfigInterface {
	GTypeInterface g_iface;

	/* Called when the plugin is loaded to initialize it */
	void     (*init) (NMSystemConfigInterface *config);

	/* Returns the plugins currently known list of connections.  The returned
	 * list is freed by the system settings service.
	 */
	GSList * (*get_connections) (NMSystemConfigInterface *config);

	/* Return the secrets associated with a specific setting of a specific
	 * connection.  The returned hash table is unreffed by the system settings
	 * service.
	 */
	GHashTable * (*get_secrets) (NMSystemConfigInterface *config, NMConnection *connection, NMSetting *setting);

	/* Signals */

	/* Emitted when a new connection has been found by the plugin */
	void (*connection_added)   (NMSystemConfigInterface *config, NMConnection *connection);

	/* Emitted when a connection has been removed by the plugin */
	void (*connection_removed) (NMSystemConfigInterface *config, NMConnection *connection);

	/* Emitted when any non-secret settings of the connection change */
	void (*connection_updated) (NMSystemConfigInterface *config, NMConnection *connection);
};

GType nm_system_config_interface_get_type (void);

void nm_system_config_interface_init (NMSystemConfigInterface *config);

GSList * nm_system_config_interface_get_connections (NMSystemConfigInterface *config);

GHashTable *nm_system_config_interface_get_secrets (NMSystemConfigInterface *config,
                                                    NMConnection *connection,
                                                    NMSetting *setting);

G_END_DECLS

#endif	/* NM_SYSTEM_CONFIG_INTERFACE_H */
