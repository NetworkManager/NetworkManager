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
 * (C) Copyright 2009 - 2011 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nms-ifupdown-plugin.h"

#include <arpa/inet.h>
#include <gmodule.h>

#include "nm-setting-connection.h"
#include "nm-dbus-interface.h"
#include "settings/nm-settings-plugin.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-wireless.h"
#include "nm-setting-wired.h"
#include "nm-setting-ppp.h"
#include "nm-utils.h"
#include "nm-core-internal.h"
#include "NetworkManagerUtils.h"
#include "nm-config.h"

#include "nms-ifupdown-interface-parser.h"
#include "nms-ifupdown-connection.h"
#include "nms-ifupdown-parser.h"

#define ENI_INTERFACES_FILE "/etc/network/interfaces"

#define IFUPDOWN_UNMANAGE_WELL_KNOWN_DEFAULT TRUE

/*****************************************************************************/

typedef struct {
	/* Stores an entry for blocks/interfaces read from /e/n/i and (if exists)
	 * the NMIfupdownConnection associated with the block.
	 */
	GHashTable *eni_ifaces;

	bool ifupdown_managed;
} SettingsPluginIfupdownPrivate;

struct _SettingsPluginIfupdown {
	NMSettingsPlugin parent;
	SettingsPluginIfupdownPrivate _priv;
};

struct _SettingsPluginIfupdownClass {
	NMSettingsPluginClass parent;
};

G_DEFINE_TYPE (SettingsPluginIfupdown, settings_plugin_ifupdown, NM_TYPE_SETTINGS_PLUGIN)

#define SETTINGS_PLUGIN_IFUPDOWN_GET_PRIVATE(self) _NM_GET_PRIVATE (self, SettingsPluginIfupdown, SETTINGS_IS_PLUGIN_IFUPDOWN)

/*****************************************************************************/

static SettingsPluginIfupdown *settings_plugin_ifupdown_get (void);
NM_DEFINE_SINGLETON_GETTER (SettingsPluginIfupdown, settings_plugin_ifupdown_get, SETTINGS_TYPE_PLUGIN_IFUPDOWN);

/*****************************************************************************/

#define _NMLOG_PREFIX_NAME      "ifupdown"
#define _NMLOG_DOMAIN           LOGD_SETTINGS
#define _NMLOG(level, ...) \
    nm_log ((level), _NMLOG_DOMAIN, NULL, NULL, \
            "%s" _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
            _NMLOG_PREFIX_NAME": " \
            _NM_UTILS_MACRO_REST (__VA_ARGS__))

/*****************************************************************************/

/* Returns the plugins currently known list of connections.  The returned
 * list is freed by the system settings service.
 */
static GSList*
get_connections (NMSettingsPlugin *plugin)
{
	SettingsPluginIfupdown *self = SETTINGS_PLUGIN_IFUPDOWN (plugin);
	SettingsPluginIfupdownPrivate *priv = SETTINGS_PLUGIN_IFUPDOWN_GET_PRIVATE (self);
	GSList *list = NULL;
	GHashTableIter iter;
	void *value;

	if (!priv->ifupdown_managed) {
		_LOGD ("get_connections: not connections due to managed=false");
		return NULL;
	}

	g_hash_table_iter_init (&iter, priv->eni_ifaces);
	while (g_hash_table_iter_next (&iter, NULL, &value)) {
		if (value)
			list = g_slist_prepend (list, value);
	}

	_LOGD ("get_connections: %u connections", g_slist_length (list));
	return list;
}

/*
 * Return a list of device specifications which NetworkManager should not
 * manage.  Returned list will be freed by the system settings service, and
 * each element must be allocated using g_malloc() or its variants.
 */
static GSList*
get_unmanaged_specs (NMSettingsPlugin *plugin)
{
	SettingsPluginIfupdown *self = SETTINGS_PLUGIN_IFUPDOWN (plugin);
	SettingsPluginIfupdownPrivate *priv = SETTINGS_PLUGIN_IFUPDOWN_GET_PRIVATE (self);
	GSList *specs = NULL;
	GHashTableIter iter;
	const char *iface;

	if (priv->ifupdown_managed)
		return NULL;

	_LOGD ("unmanaged-specs: unmanaged devices count %u",
	       g_hash_table_size (priv->eni_ifaces));

	g_hash_table_iter_init (&iter, priv->eni_ifaces);
	while (g_hash_table_iter_next (&iter, (gpointer) &iface, NULL))
		specs = g_slist_append (specs, g_strdup_printf ("interface-name:=%s", iface));
	return specs;
}

/*****************************************************************************/

static void
initialize (NMSettingsPlugin *plugin)
{
	SettingsPluginIfupdown *self = SETTINGS_PLUGIN_IFUPDOWN (plugin);
	SettingsPluginIfupdownPrivate *priv = SETTINGS_PLUGIN_IFUPDOWN_GET_PRIVATE (self);
	gs_unref_hashtable GHashTable *auto_ifaces = NULL;
	nm_auto_ifparser if_parser *parser = NULL;
	if_block *block;
	GHashTableIter con_iter;
	const char *block_name;
	NMIfupdownConnection *conn;

	parser = ifparser_parse (ENI_INTERFACES_FILE, 0);

	c_list_for_each_entry (block, &parser->block_lst_head, block_lst) {

		if (NM_IN_STRSET (block->type, "auto", "allow-hotplug")) {
			if (!auto_ifaces)
				auto_ifaces = g_hash_table_new_full (nm_str_hash, g_str_equal, g_free, NULL);
			g_hash_table_add (auto_ifaces, g_strdup (block->name));
			continue;
		}

		if (nm_streq (block->type, "iface")) {
			/* Bridge configuration */
			if (g_str_has_prefix (block->name, "br")) {
				/* Try to find bridge ports */
				const char *ports = ifparser_getkey (block, "bridge-ports");

				if (ports) {
					int state = 0;
					gs_free const char **port_ifaces = NULL;
					gsize i;

					_LOGD ("parse: found bridge ports %s for %s", ports, block->name);

					port_ifaces = nm_utils_strsplit_set (ports, " \t");
					for (i = 0; port_ifaces && port_ifaces[i]; i++) {
						const char *token = port_ifaces[i];

						/* Skip crazy stuff like regex or all */
						if (nm_streq (token, "all"))
							continue;

						/* Small SM to skip everything inside regex */
						if (nm_streq (token, "regex")) {
							state++;
							continue;
						}
						if (nm_streq (token, "noregex")) {
							state--;
							continue;
						}
						if (nm_streq (token, "none"))
							continue;
						if (state == 0) {
							conn = g_hash_table_lookup (priv->eni_ifaces, block->name);
							if (!conn) {
								_LOGD ("parse: adding bridge port \"%s\"", token);
								g_hash_table_insert (priv->eni_ifaces, g_strdup (token), NULL);
							} else {
								_LOGD ("parse: adding bridge port \"%s\" (have connection %s)", token,
								       nm_settings_connection_get_uuid (NM_SETTINGS_CONNECTION (conn)));
							}
						}
					}
				}
				continue;
			}

			/* Skip loopback configuration */
			if (nm_streq (block->name, "lo"))
				continue;

			/* Remove any connection for this block that was previously found */
			conn = g_hash_table_lookup (priv->eni_ifaces, block->name);
			if (conn) {
				_LOGD ("parse: replace connection \"%s\" (%s)",
				       block->name,
				       nm_settings_connection_get_uuid (NM_SETTINGS_CONNECTION (conn)));
				nm_settings_connection_delete (NM_SETTINGS_CONNECTION (conn), NULL);
				g_hash_table_remove (priv->eni_ifaces, block->name);
			}

			/* add the new connection */
			conn = nm_ifupdown_connection_new (block);
			if (conn) {
				_LOGD ("parse: adding connection \"%s\" (%s)", block->name,
				       nm_settings_connection_get_uuid (NM_SETTINGS_CONNECTION (conn)));
			} else
				_LOGD ("parse: adding place holder for connection \"%s\"", block->name);
			g_hash_table_insert (priv->eni_ifaces, g_strdup (block->name), conn);
			continue;
		}

		if (nm_streq (block->type, "mapping")) {
			conn = g_hash_table_lookup (priv->eni_ifaces, block->name);
			if (!conn) {
				_LOGD ("parse: adding mapping \"%s\"", block->name);
				g_hash_table_insert (priv->eni_ifaces, g_strdup (block->name), NULL);
			} else {
				_LOGD ("parse: adding mapping \"%s\" (have connection %s)", block->name,
				       nm_settings_connection_get_uuid (NM_SETTINGS_CONNECTION (conn)));
			}
			continue;
		}
	}

	/* Make 'auto' interfaces autoconnect=TRUE */
	g_hash_table_iter_init (&con_iter, priv->eni_ifaces);
	while (g_hash_table_iter_next (&con_iter, (gpointer) &block_name, (gpointer) &conn)) {
		NMSettingConnection *setting;

		if (   !conn
		    || !auto_ifaces
		    || !g_hash_table_contains (auto_ifaces, block_name))
			continue;

		/* FIXME(copy-on-write-connection): avoid modifying NMConnection instances and share them via copy-on-write. */
		setting = nm_connection_get_setting_connection (nm_settings_connection_get_connection (NM_SETTINGS_CONNECTION (conn)));
		g_object_set (setting, NM_SETTING_CONNECTION_AUTOCONNECT, TRUE, NULL);
	}

	/* Check the config file to find out whether to manage interfaces */
	priv->ifupdown_managed = nm_config_data_get_value_boolean (NM_CONFIG_GET_DATA_ORIG,
	                                                           NM_CONFIG_KEYFILE_GROUP_IFUPDOWN,
	                                                           NM_CONFIG_KEYFILE_KEY_IFUPDOWN_MANAGED,
	                                                           !IFUPDOWN_UNMANAGE_WELL_KNOWN_DEFAULT);
	_LOGI ("management mode: %s", priv->ifupdown_managed ? "managed" : "unmanaged");

	/* Now if we're running in managed mode, let NM know there are new connections */
	if (priv->ifupdown_managed) {
		GHashTableIter iter;

		g_hash_table_iter_init (&iter, priv->eni_ifaces);
		while (g_hash_table_iter_next (&iter, NULL, (gpointer) &conn)) {
			if (conn) {
				_nm_settings_plugin_emit_signal_connection_added (NM_SETTINGS_PLUGIN (self),
				                                                  NM_SETTINGS_CONNECTION (conn));
			}
		}
	}
}

/*****************************************************************************/

static void
settings_plugin_ifupdown_init (SettingsPluginIfupdown *self)
{
	SettingsPluginIfupdownPrivate *priv = SETTINGS_PLUGIN_IFUPDOWN_GET_PRIVATE (self);

	priv->eni_ifaces = g_hash_table_new_full (nm_str_hash, g_str_equal, g_free, g_object_unref);
}

static void
dispose (GObject *object)
{
	SettingsPluginIfupdown *plugin = SETTINGS_PLUGIN_IFUPDOWN (object);
	SettingsPluginIfupdownPrivate *priv = SETTINGS_PLUGIN_IFUPDOWN_GET_PRIVATE (plugin);

	g_clear_pointer (&priv->eni_ifaces, g_hash_table_destroy);

	G_OBJECT_CLASS (settings_plugin_ifupdown_parent_class)->dispose (object);
}

static void
settings_plugin_ifupdown_class_init (SettingsPluginIfupdownClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMSettingsPluginClass *plugin_class = NM_SETTINGS_PLUGIN_CLASS (klass);

	object_class->dispose = dispose;

	plugin_class->initialize          = initialize;
	plugin_class->get_connections     = get_connections;
	plugin_class->get_unmanaged_specs = get_unmanaged_specs;
}

/*****************************************************************************/

G_MODULE_EXPORT NMSettingsPlugin *
nm_settings_plugin_factory (void)
{
	return NM_SETTINGS_PLUGIN (g_object_ref (settings_plugin_ifupdown_get ()));
}
