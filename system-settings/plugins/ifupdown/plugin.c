/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/* NetworkManager system settings service (ifupdown)
 *
 * Alexander Sack <asac@ubuntu.com>
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
 * (C) Copyright 2007,2008 Canonical Ltd.
 * (C) Copyright 2009 Red Hat, Inc.
 */

#include <string.h>
#include <sys/inotify.h>

#include <net/ethernet.h>
#include <netinet/ether.h>

#include <gmodule.h>
#include <glib-object.h>
#include <glib/gi18n.h>
#include <glib.h>
#include <nm-setting-connection.h>

#include "interface_parser.h"

#include "NetworkManager.h"
#include "nm-system-config-interface.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-wireless.h"
#include "nm-setting-wired.h"
#include "nm-setting-ppp.h"

#include "nm-ifupdown-connection.h"
#include "plugin.h"
#include "parser.h"
#include "nm-inotify-helper.h"

#include <nm-utils.h>

#include <arpa/inet.h>

#define G_UDEV_API_IS_SUBJECT_TO_CHANGE
#include <gudev/gudev.h>

#define IFUPDOWN_PLUGIN_NAME "ifupdown"
#define IFUPDOWN_PLUGIN_INFO "(C) 2008 Canonical Ltd.  To report bugs please use the NetworkManager mailing list."
#define IFUPDOWN_SYSTEM_HOSTNAME_FILE "/etc/hostname"

#define IFUPDOWN_SYSTEM_SETTINGS_KEY_FILE SYSCONFDIR "/NetworkManager/NetworkManager.conf"
#define IFUPDOWN_OLD_SYSTEM_SETTINGS_KEY_FILE SYSCONFDIR "/NetworkManager/nm-system-settings.conf"

#define IFUPDOWN_KEY_FILE_GROUP "ifupdown"
#define IFUPDOWN_KEY_FILE_KEY_MANAGED "managed"
#define IFUPDOWN_UNMANAGE_WELL_KNOWN_DEFAULT TRUE

/* #define ALWAYS_UNMANAGE TRUE */
#ifndef ALWAYS_UNMANAGE
#	define ALWAYS_UNMANAGE FALSE
#endif

typedef struct {
	GUdevClient *client;

	GHashTable *iface_connections;
	gchar* hostname;

	GHashTable *well_known_interfaces;
	GHashTable *well_known_ifaces;
	gboolean unmanage_well_known;
	const char *conf_file;

	gulong inotify_event_id;
	int inotify_system_hostname_wd;
} SCPluginIfupdownPrivate;

static void
system_config_interface_init (NMSystemConfigInterface *system_config_interface_class);

G_DEFINE_TYPE_EXTENDED (SCPluginIfupdown, sc_plugin_ifupdown, G_TYPE_OBJECT, 0,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_SYSTEM_CONFIG_INTERFACE,
                                               system_config_interface_init))

#define SC_PLUGIN_IFUPDOWN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SC_TYPE_PLUGIN_IFUPDOWN, SCPluginIfupdownPrivate))

static void
sc_plugin_ifupdown_class_init (SCPluginIfupdownClass *req_class);

static void
SCPluginIfupdown_init (NMSystemConfigInterface *config);

/* Returns the plugins currently known list of connections.  The returned
 * list is freed by the system settings service.
 */
static GSList*
SCPluginIfupdown_get_connections (NMSystemConfigInterface *config);

/*
 * Return a list of device specifications which NetworkManager should not
 * manage.  Returned list will be freed by the system settings service, and
 * each element must be allocated using g_malloc() or its variants.
 */
static GSList*
SCPluginIfupdown_get_unmanaged_specs (NMSystemConfigInterface *config);


/*  GObject */
static void
GObject__get_property (GObject *object, guint prop_id,
				   GValue *value, GParamSpec *pspec);

static void
GObject__set_property (GObject *object, guint prop_id,
				   const GValue *value, GParamSpec *pspec);

static void
GObject__dispose (GObject *object);

/* other helpers */
static const char *
get_hostname (NMSystemConfigInterface *config);


static void
update_system_hostname(NMInotifyHelper *inotify_helper,
                       struct inotify_event *evt,
                       const char *path,
                       NMSystemConfigInterface *config);


static void
system_config_interface_init (NMSystemConfigInterface *system_config_interface_class)
{
	system_config_interface_class->init = SCPluginIfupdown_init;
	system_config_interface_class->get_connections = SCPluginIfupdown_get_connections;
	system_config_interface_class->get_unmanaged_specs = SCPluginIfupdown_get_unmanaged_specs;
}

static void
sc_plugin_ifupdown_class_init (SCPluginIfupdownClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	g_type_class_add_private (req_class, sizeof (SCPluginIfupdownPrivate));

	object_class->dispose = GObject__dispose;
	object_class->get_property = GObject__get_property;
	object_class->set_property = GObject__set_property;

	g_object_class_override_property (object_class,
	                                  NM_SYSTEM_CONFIG_INTERFACE_PROP_NAME,
	                                  NM_SYSTEM_CONFIG_INTERFACE_NAME);

	g_object_class_override_property (object_class,
	                                  NM_SYSTEM_CONFIG_INTERFACE_PROP_INFO,
	                                  NM_SYSTEM_CONFIG_INTERFACE_INFO);

	g_object_class_override_property (object_class,
	                                  NM_SYSTEM_CONFIG_INTERFACE_PROP_CAPABILITIES,
	                                  NM_SYSTEM_CONFIG_INTERFACE_CAPABILITIES);

	g_object_class_override_property (object_class,
	                                  NM_SYSTEM_CONFIG_INTERFACE_PROP_HOSTNAME,
	                                  NM_SYSTEM_CONFIG_INTERFACE_HOSTNAME);
}

static void
ignore_cb (NMSettingsConnectionInterface *connection,
           GError *error,
           gpointer user_data)
{
}

static void
bind_device_to_connection (SCPluginIfupdown *self,
                           GUdevDevice *device,
                           NMIfupdownConnection *exported)
{
	GByteArray *mac_address;
	NMSetting *s_wired = NULL;
	NMSetting *s_wifi = NULL;
	const char *iface, *address;
	struct ether_addr *tmp_mac;

	iface = g_udev_device_get_name (device);
	if (!iface) {
		PLUGIN_WARN ("SCPluginIfupdown", "failed to get ifname for device.");
		return;
	}

	address = g_udev_device_get_sysfs_attr (device, "address");
	if (!address || !strlen (address)) {
		PLUGIN_WARN ("SCPluginIfupdown", "failed to get MAC address for %s", iface);
		return;
	}

	tmp_mac = ether_aton (address);
	if (!tmp_mac) {
		PLUGIN_WARN ("SCPluginIfupdown", "failed to parse MAC address '%s' for %s",
		             address, iface);
		return;
	}

	mac_address = g_byte_array_sized_new (ETH_ALEN);
	g_byte_array_append (mac_address, &(tmp_mac->ether_addr_octet[0]), ETH_ALEN);

	s_wired = nm_connection_get_setting (NM_CONNECTION (exported), NM_TYPE_SETTING_WIRED);
	s_wifi = nm_connection_get_setting (NM_CONNECTION (exported), NM_TYPE_SETTING_WIRELESS);
	if (s_wired) {
		PLUGIN_PRINT ("SCPluginIfupdown", "locking wired connection setting");
		g_object_set (s_wired, NM_SETTING_WIRED_MAC_ADDRESS, mac_address, NULL);
	} else if (s_wifi) {
		PLUGIN_PRINT ("SCPluginIfupdown", "locking wireless connection setting");
		g_object_set (s_wifi, NM_SETTING_WIRELESS_MAC_ADDRESS, mac_address, NULL);
	}
	g_byte_array_free (mac_address, TRUE);

	nm_settings_connection_interface_update (NM_SETTINGS_CONNECTION_INTERFACE (exported),
	                                         ignore_cb,
	                                         NULL);
}    

static void
udev_device_added (SCPluginIfupdown *self, GUdevDevice *device)
{
	SCPluginIfupdownPrivate *priv = SC_PLUGIN_IFUPDOWN_GET_PRIVATE (self);
	const char *iface, *path;
	NMIfupdownConnection *exported;

	iface = g_udev_device_get_name (device);
	path = g_udev_device_get_sysfs_path (device);
	if (!iface || !path)
		return;

	PLUGIN_PRINT("SCPlugin-Ifupdown",
	             "devices added (path: %s, iface: %s)", path, iface);

	/* if we have a configured connection for this particular iface
	 * we want to either unmanage the device or lock it
	 */
	exported = (NMIfupdownConnection *) g_hash_table_lookup (priv->iface_connections, iface);
	if (!exported && !g_hash_table_lookup (priv->well_known_interfaces, iface)) {
		PLUGIN_PRINT("SCPlugin-Ifupdown",
			"device added (path: %s, iface: %s): no ifupdown configuration found.", path, iface);
		return;
	}

	g_hash_table_insert (priv->well_known_ifaces, g_strdup (iface), g_object_ref (device));

	if (exported)
		bind_device_to_connection (self, device, exported);

	if (ALWAYS_UNMANAGE || priv->unmanage_well_known)
		g_signal_emit_by_name (G_OBJECT (self), NM_SYSTEM_CONFIG_INTERFACE_UNMANAGED_SPECS_CHANGED);
}

static void
udev_device_removed (SCPluginIfupdown *self, GUdevDevice *device)
{
	SCPluginIfupdownPrivate *priv = SC_PLUGIN_IFUPDOWN_GET_PRIVATE (self);
	const char *iface, *path;

	iface = g_udev_device_get_name (device);
	path = g_udev_device_get_sysfs_path (device);
	if (!iface || !path)
		return;

	PLUGIN_PRINT("SCPlugin-Ifupdown",
	             "devices removed (path: %s, iface: %s)", path, iface);

	if (!g_hash_table_remove (priv->well_known_ifaces, iface))
		return;

	if (ALWAYS_UNMANAGE || priv->unmanage_well_known)
		g_signal_emit_by_name (G_OBJECT (self), NM_SYSTEM_CONFIG_INTERFACE_UNMANAGED_SPECS_CHANGED);
}

static void
handle_uevent (GUdevClient *client,
               const char *action,
               GUdevDevice *device,
               gpointer user_data)
{
	SCPluginIfupdown *self = SC_PLUGIN_IFUPDOWN (user_data);
	const char *subsys;

	g_return_if_fail (action != NULL);

	/* A bit paranoid */
	subsys = g_udev_device_get_subsystem (device);
	g_return_if_fail (subsys != NULL);
	g_return_if_fail (strcmp (subsys, "net") == 0);

	if (!strcmp (action, "add"))
		udev_device_added (self, device);
	else if (!strcmp (action, "remove"))
		udev_device_removed (self, device);
}

static void
SCPluginIfupdown_init (NMSystemConfigInterface *config)
{
	SCPluginIfupdown *self = SC_PLUGIN_IFUPDOWN (config);
	SCPluginIfupdownPrivate *priv = SC_PLUGIN_IFUPDOWN_GET_PRIVATE (self);
	GHashTable *auto_ifaces;
	if_block *block = NULL;
	NMInotifyHelper *inotify_helper;
	GKeyFile* keyfile;
	GError *error = NULL;
	GList *keys, *iter;
	const char *subsys[2] = { "net", NULL };

	auto_ifaces = g_hash_table_new (g_str_hash, g_str_equal);

	if(!priv->iface_connections)
		priv->iface_connections = g_hash_table_new (g_str_hash, g_str_equal);

	if(!priv->well_known_ifaces)
		priv->well_known_ifaces = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_object_unref);

	if(!priv->well_known_interfaces)
		priv->well_known_interfaces = g_hash_table_new (g_str_hash, g_str_equal);

	PLUGIN_PRINT("SCPlugin-Ifupdown", "init!");

	priv->client = g_udev_client_new (subsys);
	if (!priv->client) {
		PLUGIN_WARN ("SCPlugin-Ifupdown", "    error initializing libgudev");
	} else
		g_signal_connect (priv->client, "uevent", G_CALLBACK (handle_uevent), self);

	priv->unmanage_well_known = IFUPDOWN_UNMANAGE_WELL_KNOWN_DEFAULT;
 
	inotify_helper = nm_inotify_helper_get ();
	priv->inotify_event_id = g_signal_connect (inotify_helper,
	                                           "event",
	                                           G_CALLBACK (update_system_hostname),
	                                           config);

	priv->inotify_system_hostname_wd =
		nm_inotify_helper_add_watch (inotify_helper, IFUPDOWN_SYSTEM_HOSTNAME_FILE);

	update_system_hostname (inotify_helper, NULL, NULL, config);

	/* Read in all the interfaces */
	ifparser_init ();
	block = ifparser_getfirst ();
	while (block) {
		if(!strcmp ("auto", block->type) || !strcmp ("allow-hotplug", block->type))
			g_hash_table_insert (auto_ifaces, block->name, GUINT_TO_POINTER (1));
		else if (!strcmp ("iface", block->type) && strcmp ("lo", block->name)) {
			NMIfupdownConnection *exported;

			/* Remove any connection for this block that was previously found */
			exported = g_hash_table_lookup (priv->iface_connections, block->name);
			if (exported) {
				nm_settings_connection_interface_delete (NM_SETTINGS_CONNECTION_INTERFACE (exported),
				                                         ignore_cb,
				                                         NULL);
				g_hash_table_remove (priv->iface_connections, block->name);
			}

			/* add the new connection */
			exported = nm_ifupdown_connection_new (block);
			if (exported) {
				g_hash_table_insert (priv->iface_connections, block->name, exported);
				g_hash_table_insert (priv->well_known_interfaces, block->name, "known");
			}
		} else if (!strcmp ("mapping", block->type)) {
			g_hash_table_insert (priv->well_known_interfaces, block->name, "known");
		}
		block = block->next;
	}

	/* Make 'auto' interfaces autoconnect=TRUE */
	keys = g_hash_table_get_keys (priv->iface_connections);
	for (iter = keys; iter; iter = g_list_next (iter)) {
		NMIfupdownConnection *exported;
		NMSetting *setting;

		if (!g_hash_table_lookup (auto_ifaces, iter->data))
			continue;

		exported = g_hash_table_lookup (priv->iface_connections, iter->data);
		setting = NM_SETTING (nm_connection_get_setting (NM_CONNECTION (exported), NM_TYPE_SETTING_CONNECTION));
		g_object_set (setting, NM_SETTING_CONNECTION_AUTOCONNECT, TRUE, NULL);

		nm_settings_connection_interface_update (NM_SETTINGS_CONNECTION_INTERFACE (exported),
		                                         ignore_cb,
		                                         NULL);

		PLUGIN_PRINT("SCPlugin-Ifupdown", "autoconnect");
	}
	g_list_free (keys);
	g_hash_table_destroy (auto_ifaces);

	/* Find the config file */
	if (g_file_test (IFUPDOWN_SYSTEM_SETTINGS_KEY_FILE, G_FILE_TEST_EXISTS))
		priv->conf_file = IFUPDOWN_SYSTEM_SETTINGS_KEY_FILE;
	else
		priv->conf_file = IFUPDOWN_OLD_SYSTEM_SETTINGS_KEY_FILE;

	keyfile = g_key_file_new ();
	if (!g_key_file_load_from_file (keyfile,
	                                priv->conf_file,
	                                G_KEY_FILE_NONE,
	                                &error)) {
		nm_info ("loading system config file (%s) caused error: (%d) %s",
		         priv->conf_file,
		         error ? error->code : -1,
		         error && error->message ? error->message : "(unknown)");
	} else {
		gboolean manage_well_known;
		error = NULL;

		manage_well_known = g_key_file_get_boolean (keyfile,
		                                            IFUPDOWN_KEY_FILE_GROUP,
		                                            IFUPDOWN_KEY_FILE_KEY_MANAGED,
		                                            &error);
		if (error) {
			nm_info ("getting keyfile key '%s' in group '%s' failed: (%d) %s",
			         IFUPDOWN_KEY_FILE_GROUP,
			         IFUPDOWN_KEY_FILE_KEY_MANAGED,
			         error ? error->code : -1,
			         error && error->message ? error->message : "(unknown)");
		} else
			priv->unmanage_well_known = !manage_well_known;
	}
	PLUGIN_PRINT ("SCPluginIfupdown", "management mode: %s", priv->unmanage_well_known ? "unmanaged" : "managed");
	if (keyfile)
		g_key_file_free (keyfile);

	/* Add well-known interfaces */
	keys = g_udev_client_query_by_subsystem (priv->client, "net");
	for (iter = keys; iter; iter = g_list_next (iter)) {
		udev_device_added (self, G_UDEV_DEVICE (iter->data));
		g_object_unref (G_UDEV_DEVICE (iter->data));
	}
	g_list_free (keys);

	/* Now if we're running in managed mode, let NM know there are new connections */
	if (!priv->unmanage_well_known) {
		GList *con_list = g_hash_table_get_values (priv->iface_connections);
		GList *cl_iter;

		for (cl_iter = con_list; cl_iter; cl_iter = g_list_next (cl_iter)) {
			g_signal_emit_by_name (self,
			                       NM_SYSTEM_CONFIG_INTERFACE_CONNECTION_ADDED,
			                       NM_EXPORTED_CONNECTION (cl_iter->data));
		}
		g_list_free (con_list);
	}

	PLUGIN_PRINT("SCPlugin-Ifupdown", "end _init.");
}


/* Returns the plugins currently known list of connections.  The returned
 * list is freed by the system settings service.
 */
static GSList*
SCPluginIfupdown_get_connections (NMSystemConfigInterface *config)
{
	SCPluginIfupdownPrivate *priv = SC_PLUGIN_IFUPDOWN_GET_PRIVATE (config);
	GSList *connections = NULL;
	GHashTableIter iter;
	gpointer value;

	PLUGIN_PRINT("SCPlugin-Ifupdown", "(%d) ... get_connections.", GPOINTER_TO_UINT(config));

	if(priv->unmanage_well_known) {
		PLUGIN_PRINT("SCPlugin-Ifupdown", "(%d) ... get_connections (managed=false): return empty list.", GPOINTER_TO_UINT(config));
		return NULL;
	}

	g_hash_table_iter_init (&iter, priv->iface_connections);
	while (g_hash_table_iter_next (&iter, NULL, &value))
		connections = g_slist_prepend (connections, value);

	PLUGIN_PRINT("SCPlugin-Ifupdown", "(%d) connections count: %d", GPOINTER_TO_UINT(config), g_slist_length(connections));
	return connections;
}

/*
 * Return a list of device specifications which NetworkManager should not
 * manage.  Returned list will be freed by the system settings service, and
 * each element must be allocated using g_malloc() or its variants.
 */
static GSList*
SCPluginIfupdown_get_unmanaged_specs (NMSystemConfigInterface *config)
{
	SCPluginIfupdownPrivate *priv = SC_PLUGIN_IFUPDOWN_GET_PRIVATE (config);
	GSList *specs = NULL;
	GHashTableIter iter;
	gpointer value;

	if (!ALWAYS_UNMANAGE && !priv->unmanage_well_known)
		return NULL;

	PLUGIN_PRINT("Ifupdown", "get unmanaged devices count: %d",
	             g_hash_table_size (priv->well_known_ifaces));

	g_hash_table_iter_init (&iter, priv->well_known_ifaces);
	while (g_hash_table_iter_next (&iter, NULL, &value)) {
		GUdevDevice *device = G_UDEV_DEVICE (value);
		const char *address;

		address = g_udev_device_get_sysfs_attr (device, "address");
		if (address)
			specs = g_slist_append (specs, g_strdup_printf ("mac:%s", address));
	}
	return specs;
}


static const char *
get_hostname (NMSystemConfigInterface *config)
{
	SCPluginIfupdownPrivate *priv = SC_PLUGIN_IFUPDOWN_GET_PRIVATE (config);
	return priv->hostname;
}

static void
update_system_hostname(NMInotifyHelper *inotify_helper,
                       struct inotify_event *evt,
                       const char *path,
                       NMSystemConfigInterface *config)
{
	SCPluginIfupdownPrivate *priv = SC_PLUGIN_IFUPDOWN_GET_PRIVATE (config);
	gchar *hostname_file = NULL;
	gsize hostname_file_len = 0;
	GError *error = NULL;

	PLUGIN_PRINT ("SCPlugin-Ifupdown", "update_system_hostname");

	if (evt && evt->wd != priv->inotify_system_hostname_wd)
		return;

	if(!g_file_get_contents ( IFUPDOWN_SYSTEM_HOSTNAME_FILE,
						 &hostname_file,
						 &hostname_file_len,
						 &error)) {
		nm_warning ("update_system_hostname() - couldn't read "
				  IFUPDOWN_SYSTEM_HOSTNAME_FILE " (%d/%s)",
				  error->code, error->message);
		return;
	}

	if (priv->hostname)
		g_free(priv->hostname);

	priv->hostname = g_strstrip(hostname_file);

	g_object_notify (G_OBJECT (config), NM_SYSTEM_CONFIG_INTERFACE_HOSTNAME);
}

static void
write_system_hostname(NMSystemConfigInterface *config,
				  const char *newhostname)
{
	GError *error = NULL;
	SCPluginIfupdownPrivate *priv = SC_PLUGIN_IFUPDOWN_GET_PRIVATE (config);
	PLUGIN_PRINT ("SCPlugin-Ifupdown", "write_system_hostname: %s", newhostname);

	g_return_if_fail (newhostname);

	if(!g_file_set_contents ( IFUPDOWN_SYSTEM_HOSTNAME_FILE,
						 newhostname,
						 -1,
						 &error)) {
		nm_warning ("update_system_hostname() - couldn't write hostname (%s) to "
				  IFUPDOWN_SYSTEM_HOSTNAME_FILE " (%d/%s)",
				  newhostname, error->code, error->message);	
	} else {
		priv->hostname = g_strdup (newhostname);
	}
	g_object_notify (G_OBJECT (config), NM_SYSTEM_CONFIG_INTERFACE_HOSTNAME);
}


static void
sc_plugin_ifupdown_init (SCPluginIfupdown *plugin)
{
}

static void
GObject__get_property (GObject *object, guint prop_id,
				   GValue *value, GParamSpec *pspec)
{
	NMSystemConfigInterface *self = NM_SYSTEM_CONFIG_INTERFACE (object);

	switch (prop_id) {
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_NAME:
		g_value_set_string (value, IFUPDOWN_PLUGIN_NAME);
		break;
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_INFO:
		g_value_set_string (value, IFUPDOWN_PLUGIN_INFO);
		break;
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_CAPABILITIES:
		g_value_set_uint (value, NM_SYSTEM_CONFIG_INTERFACE_CAP_MODIFY_HOSTNAME);
		break;
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_HOSTNAME:
		{
			g_value_set_string (value, get_hostname(self));
			break;
		}
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
GObject__set_property (GObject *object, guint prop_id,
				   const GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_HOSTNAME:
		{
			const gchar *hostname = g_value_get_string (value);
			if (hostname && strlen (hostname) < 1)
				hostname = NULL;
			write_system_hostname(NM_SYSTEM_CONFIG_INTERFACE(object),
							  hostname);
			break;
		}
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
GObject__dispose (GObject *object)
{
	SCPluginIfupdown *plugin = SC_PLUGIN_IFUPDOWN (object);
	SCPluginIfupdownPrivate *priv = SC_PLUGIN_IFUPDOWN_GET_PRIVATE (plugin);
	NMInotifyHelper *inotify_helper = nm_inotify_helper_get ();

	g_signal_handler_disconnect (inotify_helper, priv->inotify_event_id);

	if (priv->inotify_system_hostname_wd >= 0)
		nm_inotify_helper_remove_watch (inotify_helper, priv->inotify_system_hostname_wd);

	if (priv->well_known_ifaces)
		g_hash_table_destroy(priv->well_known_ifaces);

	if (priv->well_known_interfaces)
		g_hash_table_destroy(priv->well_known_interfaces);

	if (priv->client)
		g_object_unref (priv->client);

	G_OBJECT_CLASS (sc_plugin_ifupdown_parent_class)->dispose (object);
}

G_MODULE_EXPORT GObject *
nm_system_config_factory (void)
{
	static SCPluginIfupdown *singleton = NULL;

	if (!singleton)
		singleton = SC_PLUGIN_IFUPDOWN (g_object_new (SC_TYPE_PLUGIN_IFUPDOWN, NULL));
	else
		g_object_ref (singleton);

	return G_OBJECT (singleton);
}

