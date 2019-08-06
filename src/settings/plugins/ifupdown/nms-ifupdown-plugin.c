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

#include "nm-core-internal.h"
#include "nm-core-utils.h"
#include "nm-config.h"
#include "settings/nm-settings-plugin.h"
#include "settings/nm-settings-storage.h"

#include "nms-ifupdown-interface-parser.h"
#include "nms-ifupdown-parser.h"

#define ENI_INTERFACES_FILE "/etc/network/interfaces"

#define IFUPDOWN_UNMANAGE_WELL_KNOWN_DEFAULT TRUE

/*****************************************************************************/

typedef struct {
	NMConnection *connection;
	NMSettingsStorage *storage;
} StorageData;

typedef struct {
	/* Stores an entry for blocks/interfaces read from /e/n/i and (if exists)
	 * the StorageData associated with the block.
	 */
	GHashTable *eni_ifaces;

	bool ifupdown_managed:1;

	bool initialized:1;

	bool already_reloaded:1;
} NMSIfupdownPluginPrivate;

struct _NMSIfupdownPlugin {
	NMSettingsPlugin parent;
	NMSIfupdownPluginPrivate _priv;
};

struct _NMSIfupdownPluginClass {
	NMSettingsPluginClass parent;
};

G_DEFINE_TYPE (NMSIfupdownPlugin, nms_ifupdown_plugin, NM_TYPE_SETTINGS_PLUGIN)

#define NMS_IFUPDOWN_PLUGIN_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMSIfupdownPlugin, NMS_IS_IFUPDOWN_PLUGIN)

/*****************************************************************************/

#define _NMLOG_PREFIX_NAME      "ifupdown"
#define _NMLOG_DOMAIN           LOGD_SETTINGS
#define _NMLOG(level, ...) \
    nm_log ((level), _NMLOG_DOMAIN, NULL, NULL, \
            "%s" _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
            _NMLOG_PREFIX_NAME": " \
            _NM_UTILS_MACRO_REST (__VA_ARGS__))

/*****************************************************************************/

static GHashTable *load_eni_ifaces (NMSIfupdownPlugin *self);

/*****************************************************************************/

static void
_storage_data_destroy (StorageData *sd)
{
	nm_g_object_unref (sd->connection);
	nm_g_object_unref (sd->storage);
	g_slice_free (StorageData, sd);
}

/*****************************************************************************/

static void
initialize (NMSIfupdownPlugin *self)
{
	NMSIfupdownPluginPrivate *priv = NMS_IFUPDOWN_PLUGIN_GET_PRIVATE (self);
	gboolean ifupdown_managed;

	nm_assert (!priv->initialized);

	priv->initialized = TRUE;

	ifupdown_managed = nm_config_data_get_value_boolean (NM_CONFIG_GET_DATA_ORIG,
	                                                     NM_CONFIG_KEYFILE_GROUP_IFUPDOWN,
	                                                     NM_CONFIG_KEYFILE_KEY_IFUPDOWN_MANAGED,
	                                                     !IFUPDOWN_UNMANAGE_WELL_KNOWN_DEFAULT);
	_LOGI ("management mode: %s", ifupdown_managed ? "managed" : "unmanaged");
	priv->ifupdown_managed = ifupdown_managed;

	priv->eni_ifaces = load_eni_ifaces (self);
}

static void
reload_connections (NMSettingsPlugin *plugin,
                    NMSettingsPluginConnectionLoadCallback callback,
                    gpointer user_data)
{
	NMSIfupdownPlugin *self = NMS_IFUPDOWN_PLUGIN (plugin);
	NMSIfupdownPluginPrivate *priv = NMS_IFUPDOWN_PLUGIN_GET_PRIVATE (self);
	gs_unref_hashtable GHashTable *eni_ifaces_old = NULL;
	GHashTableIter iter;
	StorageData *sd;
	StorageData *sd2;
	const char *block_name;

	if (!priv->initialized)
		initialize (self);
	else if (!priv->already_reloaded) {
		/* This is the first call to reload, but we are already initialized.
		 *
		 * This happens because during start NMSettings first queries unmanaged-specs,
		 * and then issues a reload call right away.
		 *
		 * On future reloads, we really want to load /e/n/i again. */
		priv->already_reloaded = TRUE;
	} else {
		eni_ifaces_old = priv->eni_ifaces;
		priv->eni_ifaces = load_eni_ifaces (self);

		g_hash_table_iter_init (&iter, eni_ifaces_old);
		while (g_hash_table_iter_next (&iter, (gpointer *) &block_name, (gpointer *) &sd)) {
			if (!sd)
				continue;

			sd2 = g_hash_table_lookup (priv->eni_ifaces, block_name);
			if (!sd2)
				continue;

			nm_assert (nm_streq (nm_settings_storage_get_uuid (sd->storage), nm_settings_storage_get_uuid (sd2->storage)));
			nm_g_object_ref_set (&sd2->storage, sd->storage);
			g_hash_table_iter_remove (&iter);
		}
	}

	if (!priv->ifupdown_managed)
		_LOGD ("load: no connections due to managed=false");

	g_hash_table_iter_init (&iter, priv->eni_ifaces);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &sd)) {
		gs_unref_object NMConnection *connection = NULL;

		if (!sd)
			continue;

		connection = g_steal_pointer (&sd->connection);

		if (!priv->ifupdown_managed)
			continue;

		_LOGD ("load: %s (%s)",
		        nm_settings_storage_get_uuid (sd->storage),
		        nm_connection_get_id (connection));
		callback (plugin,
		          sd->storage,
		          connection,
		          user_data);
	}
	if (   eni_ifaces_old
	    && priv->ifupdown_managed) {
		g_hash_table_iter_init (&iter, eni_ifaces_old);
		while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &sd)) {
			if (!sd)
				continue;
			_LOGD ("unload: %s",
			        nm_settings_storage_get_uuid (sd->storage));
			callback (plugin,
			          sd->storage,
			          NULL,
			          user_data);
		}
	}
}

/*****************************************************************************/

static GSList *
_unmanaged_specs (GHashTable *eni_ifaces)
{
	gs_free const char **keys = NULL;
	GSList *specs = NULL;
	guint i, len;

	keys = nm_utils_strdict_get_keys (eni_ifaces, TRUE, &len);
	for (i = len; i > 0; ) {
		i--;
		specs = g_slist_prepend (specs, g_strdup_printf (NM_MATCH_SPEC_INTERFACE_NAME_TAG"=%s", keys[i]));
	}
	return specs;
}

static GSList*
get_unmanaged_specs (NMSettingsPlugin *plugin)
{
	NMSIfupdownPlugin *self = NMS_IFUPDOWN_PLUGIN (plugin);
	NMSIfupdownPluginPrivate *priv = NMS_IFUPDOWN_PLUGIN_GET_PRIVATE (self);

	if (G_UNLIKELY (!priv->initialized))
		initialize (self);

	if (priv->ifupdown_managed)
		return NULL;

	_LOGD ("unmanaged-specs: unmanaged devices count %u",
	       g_hash_table_size (priv->eni_ifaces));

	return _unmanaged_specs (priv->eni_ifaces);
}

/*****************************************************************************/

static GHashTable *
load_eni_ifaces (NMSIfupdownPlugin *self)
{
	gs_unref_hashtable GHashTable *eni_ifaces = NULL;
	gs_unref_hashtable GHashTable *auto_ifaces = NULL;
	nm_auto_ifparser if_parser *parser = NULL;
	if_block *block;
	StorageData *sd;

	eni_ifaces = g_hash_table_new_full (nm_str_hash, g_str_equal, g_free, (GDestroyNotify) _storage_data_destroy);

	parser = ifparser_parse (ENI_INTERFACES_FILE, 0);

	c_list_for_each_entry (block, &parser->block_lst_head, block_lst) {
		if (NM_IN_STRSET (block->type, "auto",
		                               "allow-hotplug")) {
			if (!auto_ifaces)
				auto_ifaces = g_hash_table_new (nm_str_hash, g_str_equal);
			g_hash_table_add (auto_ifaces, (char *) block->name);
		}
	}

	c_list_for_each_entry (block, &parser->block_lst_head, block_lst) {

		if (NM_IN_STRSET (block->type, "auto",
		                               "allow-hotplug"))
			continue;

		if (nm_streq (block->type, "iface")) {
			gs_free_error GError *local = NULL;
			gs_unref_object NMConnection *connection = NULL;
			gs_unref_object NMSettingsStorage *storage = NULL;
			const char *uuid = NULL;
			StorageData *sd_repl;

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
							sd = g_hash_table_lookup (eni_ifaces, block->name);
							if (!sd) {
								_LOGD ("parse: adding bridge port \"%s\"", token);
								g_hash_table_insert (eni_ifaces, g_strdup (token), NULL);
							} else {
								_LOGD ("parse: adding bridge port \"%s\" (have connection %s)", token,
								       nm_settings_storage_get_uuid (sd->storage));
							}
						}
					}
				}
				continue;
			}

			/* Skip loopback configuration */
			if (nm_streq (block->name, "lo"))
				continue;

			sd_repl = g_hash_table_lookup (eni_ifaces, block->name);
			if (sd_repl) {
				_LOGD ("parse: replace connection \"%s\" (%s)",
				       block->name,
				       nm_settings_storage_get_uuid (sd_repl->storage));
				storage = g_steal_pointer (&sd_repl->storage);
				g_hash_table_remove (eni_ifaces, block->name);
			}

			connection = ifupdown_new_connection_from_if_block (block,
			                                                       auto_ifaces
			                                                    && g_hash_table_contains (auto_ifaces, block->name),
			                                                    &local);

			if (!connection) {
				_LOGD ("parse: adding place holder for \"%s\"%s%s%s",
				       block->name,
				       NM_PRINT_FMT_QUOTED (local, " (", local->message, ")", ""));
				sd = NULL;
			} else {

				nmtst_connection_assert_unchanging (connection);
				uuid = nm_connection_get_uuid (connection);

				if (!storage)
					storage = nm_settings_storage_new (NM_SETTINGS_PLUGIN (self), uuid, NULL);

				sd = g_slice_new (StorageData);
				*sd = (StorageData) {
					.connection = g_steal_pointer (&connection),
					.storage    = g_steal_pointer (&storage),
				};
				_LOGD ("parse: adding connection \"%s\" (%s)", block->name, uuid);
			}

			g_hash_table_replace (eni_ifaces, g_strdup (block->name), sd);
			continue;
		}

		if (nm_streq (block->type, "mapping")) {
			sd = g_hash_table_lookup (eni_ifaces, block->name);
			if (!sd) {
				_LOGD ("parse: adding mapping \"%s\"", block->name);
				g_hash_table_insert (eni_ifaces, g_strdup (block->name), NULL);
			} else {
				_LOGD ("parse: adding mapping \"%s\" (have connection %s)", block->name,
				       nm_settings_storage_get_uuid (sd->storage));
			}
			continue;
		}
	}

	nm_clear_pointer (&auto_ifaces, g_hash_table_destroy);

	return g_steal_pointer (&eni_ifaces);
}

/*****************************************************************************/

static void
nms_ifupdown_plugin_init (NMSIfupdownPlugin *self)
{
}

static void
dispose (GObject *object)
{
	NMSIfupdownPlugin *plugin = NMS_IFUPDOWN_PLUGIN (object);
	NMSIfupdownPluginPrivate *priv = NMS_IFUPDOWN_PLUGIN_GET_PRIVATE (plugin);

	g_clear_pointer (&priv->eni_ifaces, g_hash_table_destroy);

	G_OBJECT_CLASS (nms_ifupdown_plugin_parent_class)->dispose (object);
}

static void
nms_ifupdown_plugin_class_init (NMSIfupdownPluginClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMSettingsPluginClass *plugin_class = NM_SETTINGS_PLUGIN_CLASS (klass);

	object_class->dispose = dispose;

	plugin_class->plugin_name         = "ifupdown";
	plugin_class->reload_connections  = reload_connections;
	plugin_class->get_unmanaged_specs = get_unmanaged_specs;
}

/*****************************************************************************/

G_MODULE_EXPORT NMSettingsPlugin *
nm_settings_plugin_factory (void)
{
	return g_object_new (NMS_TYPE_IFUPDOWN_PLUGIN, NULL);
}
