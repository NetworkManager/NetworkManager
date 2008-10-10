/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2007,2008 Canonical Ltd.
 */

#include <string.h>
#include <sys/inotify.h>

#include <net/ethernet.h>
#include <netinet/ether.h>

#include <gmodule.h>
#include <glib-object.h>
#include <glib/gi18n.h>
#include <glib/gslist.h>
#include <nm-setting-connection.h>

#include "interface_parser.h"

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
#include <sha1.h>

#include <arpa/inet.h>

#define IFUPDOWN_PLUGIN_NAME "ifupdown"
#define IFUPDOWN_PLUGIN_INFO "(C) 2008 Canonical Ltd.  To report bugs please use the NetworkManager mailing list."
#define IFUPDOWN_SYSTEM_HOSTNAME_FILE "/etc/hostname"

#define IFUPDOWN_SYSTEM_SETTINGS_KEY_FILE SYSCONFDIR "/NetworkManager/nm-system-settings.conf"
#define IFUPDOWN_KEY_FILE_GROUP "ifupdown"
#define IFUPDOWN_KEY_FILE_KEY_MANAGED "managed"
#define IFUPDOWN_UNMANAGE_WELL_KNOWN_DEFAULT TRUE

/* #define ALWAYS_UNMANAGE TRUE */
#ifndef ALWAYS_UNMANAGE
#	define ALWAYS_UNMANAGE FALSE
#endif

typedef struct {

	DBusGConnection *g_connection;
	NMSystemConfigHalManager *hal_mgr;

	GHashTable *iface_connections;
	gchar* hostname;

	GHashTable *well_known_udis;
	gboolean unmanage_well_known;

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
SCPluginIfupdown_init (NMSystemConfigInterface *config,
				   NMSystemConfigHalManager *hal_manager);

/* Returns the plugins currently known list of connections.  The returned
 * list is freed by the system settings service.
 */
static GSList*
SCPluginIfupdown_get_connections (NMSystemConfigInterface *config);

/*
 * Return a list of HAL UDIs of devices which NetworkManager should not
 * manage.  Returned list will be freed by the system settings service, and
 * each element must be allocated using g_malloc() or its variants.
 */
static GSList*
SCPluginIfupdown_get_unmanaged_devices (NMSystemConfigInterface *config);


/*  GObject */
static void
GObject__get_property (GObject *object, guint prop_id,
				   GValue *value, GParamSpec *pspec);

static void
GObject__set_property (GObject *object, guint prop_id,
				   const GValue *value, GParamSpec *pspec);

static void
GObject__dispose (GObject *object);

static void
GObject__finalize (GObject *object);

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
	system_config_interface_class->get_unmanaged_devices = SCPluginIfupdown_get_unmanaged_devices;
}

static void
sc_plugin_ifupdown_class_init (SCPluginIfupdownClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	g_type_class_add_private (req_class, sizeof (SCPluginIfupdownPrivate));

	object_class->dispose = GObject__dispose;
	object_class->finalize = GObject__finalize;
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

static GByteArray*
get_net_address_for_udi (DBusGConnection *g_connection,
					const gchar* udi,
					GError **error)
{
	DBusGProxy *dev_proxy;
	char *address = NULL;
	GByteArray *mac_address = NULL;
	dev_proxy = dbus_g_proxy_new_for_name (g_connection,
								    "org.freedesktop.Hal",
								    udi,
								    "org.freedesktop.Hal.Device");
	if (!dev_proxy)
		return NULL;

	if (!dbus_g_proxy_call_with_timeout (dev_proxy,
								  "GetPropertyString", 10000, error,
								  G_TYPE_STRING, "net.address", G_TYPE_INVALID,
								  G_TYPE_STRING, &address, G_TYPE_INVALID)) {
		goto out;
	}

	if (address && strlen (address)) {
		struct ether_addr *dev_mac;
		mac_address = g_byte_array_new();
		dev_mac = ether_aton (address);
		g_byte_array_append (mac_address, dev_mac->ether_addr_octet, ETH_ALEN);
	}

 out:
	g_free(address);
	g_object_unref (dev_proxy);
	return mac_address;
}

static gchar*
get_iface_for_udi (DBusGConnection *g_connection,
			    const gchar* udi,
			    GError **error)
{
	DBusGProxy *dev_proxy;
	char *iface = NULL;
	dev_proxy = dbus_g_proxy_new_for_name (g_connection,
								    "org.freedesktop.Hal",
								    udi,
								    "org.freedesktop.Hal.Device");
	if (!dev_proxy)
		return NULL;

	if (dbus_g_proxy_call_with_timeout (dev_proxy,
								 "GetPropertyString", 10000, error,
								 G_TYPE_STRING, "net.interface", G_TYPE_INVALID,
								 G_TYPE_STRING, &iface, G_TYPE_INVALID)) {
		g_object_unref (dev_proxy);
		return iface;
	}
	g_object_unref (dev_proxy);
	return NULL;
}

static void
bind_device_to_connection (NMSystemConfigInterface *config,
					 DBusGConnection *g_connection,
					 const gchar* udi,
					 NMExportedConnection *exported_iface_connection)
{
	GByteArray *mac_address;
	GError *error = NULL;
	NMConnection *iface_connection;
	NMSetting *wired_setting = NULL;
	NMSetting *wireless_setting = NULL;

	iface_connection = nm_exported_connection_get_connection (exported_iface_connection);
	if (!iface_connection) {
		nm_warning ("no device locking possible. NMExportedConnection doesnt have a real connection.");
		return;
	}

	mac_address = get_net_address_for_udi (g_connection, udi, &error);

	if(error) {
		PLUGIN_PRINT ("SCPluginIfupdown", "getting mac address for managed device"
				    "failed: %s (%d)", error->message, error->code);
		return;
	}

	wired_setting = nm_connection_get_setting (iface_connection,
									   NM_TYPE_SETTING_WIRED);
	wireless_setting = nm_connection_get_setting (iface_connection,
										 NM_TYPE_SETTING_WIRELESS);
	if (wired_setting) {
		PLUGIN_PRINT ("SCPluginIfupdown", "locking wired connection setting");
		g_object_set (wired_setting, NM_SETTING_WIRED_MAC_ADDRESS, mac_address, NULL);
	} else if (wireless_setting) {
		PLUGIN_PRINT ("SCPluginIfupdown", "locking wireless connection setting");
		g_object_set (wireless_setting, NM_SETTING_WIRELESS_MAC_ADDRESS, mac_address, NULL);
	}

	if(mac_address)
		g_byte_array_free (mac_address, TRUE);
}    

static void
hal_device_added_cb (NMSystemConfigHalManager *hal_mgr,
				 const gchar* udi,
				 NMDeviceType devtype,
				 NMSystemConfigInterface *config)
{
	SCPluginIfupdownPrivate *priv = SC_PLUGIN_IFUPDOWN_GET_PRIVATE (config);
	gchar *iface = NULL;
	GError *error = NULL;
	gpointer exported_iface_connection;
	NMConnection *iface_connection = NULL;

	iface = get_iface_for_udi (priv->g_connection,
						  udi,
						  &error);

	PLUGIN_PRINT("SCPlugin-Ifupdown",
			   "devices added (udi: %s, iface: %s)", udi, iface);

	if(!iface)
		return;

	exported_iface_connection =
		NM_EXPORTED_CONNECTION (g_hash_table_lookup (priv->iface_connections, iface));

	/* if we have a configured connection for this particular iface
	 * we want to either unmanage the device or lock it
	 */
	if(!exported_iface_connection)
		goto out;

	iface_connection = nm_exported_connection_get_connection (exported_iface_connection);

	if(!iface_connection)
		goto out;

	g_hash_table_insert (priv->well_known_udis, (gpointer)udi, "nothing");

	if (ALWAYS_UNMANAGE || priv->unmanage_well_known)
		g_signal_emit_by_name (G_OBJECT(config), "unmanaged-devices-changed");
	else
		bind_device_to_connection (config, priv->g_connection, udi, exported_iface_connection);

 out:
	g_free (iface);
}

static void
hal_device_removed_cb (NMSystemConfigHalManager *hal_mgr,
				   const gchar* udi,
 				   NMDeviceType devtype,
				   NMSystemConfigInterface *config)
{
	SCPluginIfupdownPrivate *priv = SC_PLUGIN_IFUPDOWN_GET_PRIVATE (config);

	PLUGIN_PRINT("SCPlugin-Ifupdown",
			   "devices removed (udi: %s)", udi);

	if(!g_hash_table_remove (priv->well_known_udis, udi))
		return;

	if (ALWAYS_UNMANAGE || priv->unmanage_well_known)
		g_signal_emit_by_name (G_OBJECT(config), "unmanaged-devices-changed");
}

static void
hal_device_added_cb2 (gpointer data,
				  gpointer user_data)
{
	NMSystemConfigHalManager *hal_mgr = ((gpointer*)user_data)[0];
	NMSystemConfigInterface *config = ((gpointer*)user_data)[1];
	NMDeviceType devtype = GPOINTER_TO_INT(((gpointer*)user_data)[2]);
	const gchar *udi  = data;

	hal_device_added_cb (hal_mgr,
					 udi,
					 devtype,
					 config);
}

static void
SCPluginIfupdown_init (NMSystemConfigInterface *config,
				   NMSystemConfigHalManager *hal_manager)
{
	SCPluginIfupdownPrivate *priv = SC_PLUGIN_IFUPDOWN_GET_PRIVATE (config);
	GHashTable *auto_ifaces = g_hash_table_new (g_str_hash, g_str_equal);
	if_block *block = NULL;
	NMInotifyHelper *inotify_helper;
	GKeyFile* keyfile;
	GError *error = NULL;

	if(!priv->iface_connections)
		priv->iface_connections = g_hash_table_new (g_str_hash, g_str_equal);

	if(!priv->well_known_udis)
		priv->well_known_udis = g_hash_table_new (g_str_hash, g_str_equal);

	PLUGIN_PRINT("SCPlugin-Ifupdown", "init!");
	priv->hal_mgr = g_object_ref (hal_manager);

	g_signal_connect (G_OBJECT(hal_manager),
				   "device-added",
				   G_CALLBACK(hal_device_added_cb),
				   config);

	g_signal_connect (G_OBJECT(hal_manager),
				   "device-removed",
				   G_CALLBACK(hal_device_removed_cb),
				   config);
 
	inotify_helper = nm_inotify_helper_get ();
	priv->inotify_event_id = g_signal_connect (inotify_helper,
									   "event",
									   G_CALLBACK (update_system_hostname),
									   config);

	priv->inotify_system_hostname_wd =
		nm_inotify_helper_add_watch (inotify_helper, IFUPDOWN_SYSTEM_HOSTNAME_FILE);

	update_system_hostname(inotify_helper, NULL, NULL, config);

	ifparser_init();
	block = ifparser_getfirst();

	while(block) {
		if(!strcmp("auto", block->type)) {
			g_hash_table_insert (auto_ifaces, block->name, "auto");
		} else if (!strcmp ("iface", block->type) && strcmp ("lo", block->name)) {
			NMExportedConnection *connection = g_hash_table_lookup(priv->iface_connections, block->name);
			g_hash_table_remove (priv->iface_connections, block->name);

			connection = NM_EXPORTED_CONNECTION(nm_ifupdown_connection_new(block));
			ifupdown_update_connection_from_if_block (nm_exported_connection_get_connection(connection),
											  block);

			g_hash_table_insert (priv->iface_connections, block->name, connection);
		}
		block = block -> next;
	}

	{
		GList *keys = g_hash_table_get_keys (priv->iface_connections);
		GList *key_it = keys;
		while(key_it) {
			gpointer val = g_hash_table_lookup(auto_ifaces, key_it->data);
			if(val) {
				NMExportedConnection *connection =
					g_hash_table_lookup(priv->iface_connections, key_it->data);
				NMConnection *wrapped = NULL;
				NMSetting *setting;
				g_object_get(connection,
						   NM_EXPORTED_CONNECTION_CONNECTION, &wrapped, NULL);
				setting = NM_SETTING(nm_connection_get_setting
								 (wrapped, NM_TYPE_SETTING_CONNECTION));
				g_object_set (setting,
						    "autoconnect", TRUE,
						    NULL);
				PLUGIN_PRINT("SCPlugin-Ifupdown", "autoconnect");
			}
			key_it = key_it -> next;
		}
	}

	priv->unmanage_well_known = IFUPDOWN_UNMANAGE_WELL_KNOWN_DEFAULT;
	keyfile = g_key_file_new ();
	if (!g_key_file_load_from_file (keyfile,
							  IFUPDOWN_SYSTEM_SETTINGS_KEY_FILE,
							  G_KEY_FILE_NONE,
							  &error)) {
		nm_info ("loading system config file (%s) caused error: %s (%d)",
			    IFUPDOWN_SYSTEM_SETTINGS_KEY_FILE,
			    error->message,
			    error->code);
	} else {
		gboolean manage_well_known;
		error = NULL;

		manage_well_known = g_key_file_get_boolean (keyfile,
										    IFUPDOWN_KEY_FILE_GROUP,
										    IFUPDOWN_KEY_FILE_KEY_MANAGED,
										    &error);
		if (error) {
			nm_info ("getting keyfile key '%s' in group '%s' failed: %s (%d)",
				    IFUPDOWN_KEY_FILE_GROUP,
				    IFUPDOWN_KEY_FILE_KEY_MANAGED,
				    error->message,
				    error->code);
		} else {
			priv->unmanage_well_known = !manage_well_known;
		}
	}
	PLUGIN_PRINT ("SCPluginIfupdown", "management mode: %s", priv->unmanage_well_known ? "unmanaged" : "managed");
	if (keyfile)
		g_key_file_free (keyfile);

	{
		/* init well_known_udis */
		GSList *wired_devices = nm_system_config_hal_manager_get_devices_of_type (hal_manager, NM_DEVICE_TYPE_ETHERNET);
		GSList *wifi_devices = nm_system_config_hal_manager_get_devices_of_type (hal_manager, NM_DEVICE_TYPE_WIFI);
		gpointer *user_data;

		/* 3g in /etc/network/interfaces? no clue if thats mappable

		GSList *gsm_devices = nm_system_config_hal_manager_get_devices_of_type (hal_manager, NM_DEVICE_TYPE_GSM);
		GSList *cdma_devices = nm_system_config_hal_manager_get_devices_of_type (hal_manager, NM_DEVICE_TYPE_CDMA);
		*/

		user_data = g_new0 (gpointer, 3);
		user_data[0] = hal_manager;
		user_data[1] = config;
		user_data[2] = GINT_TO_POINTER (NM_DEVICE_TYPE_ETHERNET);

		g_slist_foreach (wired_devices, hal_device_added_cb2, user_data);

		user_data[0] = hal_manager;
		user_data[1] = config;
		user_data[2] = GINT_TO_POINTER (NM_DEVICE_TYPE_ETHERNET);
		g_slist_foreach (wifi_devices, hal_device_added_cb2, user_data);
	}		

	g_hash_table_unref(auto_ifaces);
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
	GList *priv_list = g_hash_table_get_values(priv->iface_connections);
	GList *it = priv_list;
	PLUGIN_PRINT("SCPlugin-Ifupdown", "(%d) ... get_connections.", GPOINTER_TO_UINT(config));

	while(it) {
		NMExportedConnection *conn = it->data;
		connections = g_slist_append(connections, conn);
		it = it->next;
	}
	PLUGIN_PRINT("SCPlugin-Ifupdown", "(%d) connections count: %d", GPOINTER_TO_UINT(config), g_slist_length(connections));
	return connections;
}

/*
 * Return a list of HAL UDIs of devices which NetworkManager should not
 * manage.  Returned list will be freed by the system settings service, and
 * each element must be allocated using g_malloc() or its variants.
 */
static GSList*
SCPluginIfupdown_get_unmanaged_devices (NMSystemConfigInterface *config)
{
	SCPluginIfupdownPrivate *priv = SC_PLUGIN_IFUPDOWN_GET_PRIVATE (config);
	GList *keys;
	GSList *udis = NULL;

	if (!ALWAYS_UNMANAGE && !priv->unmanage_well_known)
		return NULL;

	keys = g_hash_table_get_keys (priv->well_known_udis);
	PLUGIN_PRINT("Ifupdown", "get unmanaged devices count: %d", g_list_length(keys));
 	while(keys) {
		udis = g_slist_append(udis, g_strdup(keys->data));
		keys = g_list_next(keys);
	}
	return udis;
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
	SCPluginIfupdownPrivate *priv = SC_PLUGIN_IFUPDOWN_GET_PRIVATE (plugin);
	GError *error = NULL;

	priv->g_connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, &error);
	if (!priv->g_connection) {
		PLUGIN_PRINT ("SCPlugin-Ifupdown", "    dbus-glib error: %s",
		              error->message ? error->message : "(unknown)");
		g_error_free (error);
	}
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

	if (priv->well_known_udis)
		g_hash_table_destroy(priv->well_known_udis);

	g_object_unref (priv->hal_mgr);
	G_OBJECT_CLASS (sc_plugin_ifupdown_parent_class)->dispose (object);
}

static void
GObject__finalize (GObject *object)
{
	G_OBJECT_CLASS (sc_plugin_ifupdown_parent_class)->finalize (object);
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

