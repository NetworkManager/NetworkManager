/* NetworkManager system settings service
 *
 * Søren Sandmann <sandmann@daimi.au.dk>
 * Dan Williams <dcbw@redhat.com>
 * Tambet Ingo <tambet@gmail.com>
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
 * (C) Copyright 2007 - 2011 Red Hat, Inc.
 * (C) Copyright 2008 Novell, Inc.
 */

#include "nm-default.h"

#include "nm-settings.h"

#include <unistd.h>
#include <sys/stat.h>
#include <gmodule.h>
#include <pwd.h>

#if HAVE_SELINUX
#include <selinux/selinux.h>
#endif

#include "nm-libnm-core-intern/nm-common-macros.h"
#include "nm-glib-aux/nm-keyfile-aux.h"
#include "nm-keyfile-internal.h"
#include "nm-dbus-interface.h"
#include "nm-connection.h"
#include "nm-setting-8021x.h"
#include "nm-setting-bluetooth.h"
#include "nm-setting-cdma.h"
#include "nm-setting-connection.h"
#include "nm-setting-gsm.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-ip6-config.h"
#include "nm-setting-olpc-mesh.h"
#include "nm-setting-ppp.h"
#include "nm-setting-pppoe.h"
#include "nm-setting-serial.h"
#include "nm-setting-vpn.h"
#include "nm-setting-wired.h"
#include "nm-setting-adsl.h"
#include "nm-setting-wireless.h"
#include "nm-setting-wireless-security.h"
#include "nm-setting-proxy.h"
#include "nm-setting-bond.h"
#include "nm-utils.h"
#include "nm-core-internal.h"

#include "nm-std-aux/c-list-util.h"
#include "nm-glib-aux/nm-c-list.h"
#include "nm-dbus-object.h"
#include "devices/nm-device-ethernet.h"
#include "nm-settings-connection.h"
#include "nm-settings-plugin.h"
#include "nm-dbus-manager.h"
#include "nm-auth-utils.h"
#include "nm-auth-subject.h"
#include "nm-session-monitor.h"
#include "plugins/keyfile/nms-keyfile-plugin.h"
#include "plugins/keyfile/nms-keyfile-storage.h"
#include "nm-agent-manager.h"
#include "nm-config.h"
#include "nm-audit-manager.h"
#include "NetworkManagerUtils.h"
#include "nm-dispatcher.h"
#include "nm-hostname-manager.h"

/*****************************************************************************/

static NM_CACHED_QUARK_FCN ("default-wired-connection", _default_wired_connection_quark)

/*****************************************************************************/

typedef struct _StorageData {
	CList sd_lst;
	NMSettingsStorage *storage;
	NMConnection *connection;
	bool prioritize:1;
} StorageData;

static StorageData *
_storage_data_new_stale (NMSettingsStorage *storage,
                         NMConnection *connection)
{
	StorageData *sd;

	sd = g_slice_new (StorageData);
	sd->storage    = g_object_ref (storage);
	sd->connection = nm_g_object_ref (connection);
	sd->prioritize = FALSE;
	return sd;
}

static void
_storage_data_destroy (StorageData *sd)
{
	c_list_unlink_stale (&sd->sd_lst);
	g_object_unref (sd->storage);
	nm_g_object_unref (sd->connection);
	g_slice_free (StorageData, sd);
}

static StorageData *
_storage_data_find_in_lst (CList *head,
                           NMSettingsStorage *storage)
{
	StorageData *sd;

	nm_assert (head);
	nm_assert (NM_IS_SETTINGS_STORAGE (storage));

	c_list_for_each_entry (sd, head, sd_lst) {
		if (sd->storage == storage)
			return sd;
	}
	return NULL;
}

static void
nm_assert_storage_data_lst (CList *head)
{
#if NM_MORE_ASSERTS > 5
	const char *uuid = NULL;
	StorageData *sd;
	CList *iter;

	nm_assert (head);

	if (c_list_is_empty (head))
		return;

	c_list_for_each_entry (sd, head, sd_lst) {
		const char *u;

		nm_assert (NM_IS_SETTINGS_STORAGE (sd->storage));
		nm_assert (!sd->connection || NM_IS_CONNECTION (sd->connection));
		u = nm_settings_storage_get_uuid (sd->storage);
		if (!uuid) {
			uuid = u;
			nm_assert (nm_utils_is_uuid (uuid));
		} else
			nm_assert (nm_streq0 (uuid, u));
	}

	/* assert that all storages are unique. */
	c_list_for_each_entry (sd, head, sd_lst) {
		for (iter = sd->sd_lst.next; iter != head; iter = iter->next)
			nm_assert (c_list_entry (iter, StorageData, sd_lst)->storage != sd->storage);
	}
#endif
}

static gboolean
_storage_data_is_alive (StorageData *sd)
{
	/* If the storage tracks a connection, it is considered alive.
	 *
	 * Meta-data storages are special: they never track a connection.
	 * We need to check them specially to know when to drop them. */
	return    sd->connection
	       || nm_settings_storage_is_meta_data_alive (sd->storage);
}

/*****************************************************************************/

typedef struct {
	const char *uuid;
	NMSettingsConnection *sett_conn;
	NMSettingsStorage *storage;
	CList sd_lst_head;
	CList dirty_sd_lst_head;

	CList sce_dirty_lst;

	char _uuid_data[];
} SettConnEntry;

static SettConnEntry *
_sett_conn_entry_new (const char *uuid)
{
	SettConnEntry *sett_conn_entry;
	gsize l_p_1;

	nm_assert (nm_utils_is_uuid (uuid));

	l_p_1 = strlen (uuid) + 1;

	sett_conn_entry = g_malloc (sizeof (SettConnEntry) + l_p_1);
	sett_conn_entry->uuid = sett_conn_entry->_uuid_data;
	sett_conn_entry->sett_conn = NULL;
	sett_conn_entry->storage = NULL;
	c_list_init (&sett_conn_entry->sd_lst_head);
	c_list_init (&sett_conn_entry->dirty_sd_lst_head);
	c_list_init (&sett_conn_entry->sce_dirty_lst);
	memcpy (sett_conn_entry->_uuid_data, uuid, l_p_1);
	return sett_conn_entry;
}

static void
_sett_conn_entry_free (SettConnEntry *sett_conn_entry)
{
	c_list_unlink_stale (&sett_conn_entry->sce_dirty_lst);
	nm_c_list_free_all (&sett_conn_entry->sd_lst_head,       StorageData, sd_lst, _storage_data_destroy);
	nm_c_list_free_all (&sett_conn_entry->dirty_sd_lst_head, StorageData, sd_lst, _storage_data_destroy);
	nm_g_object_unref (sett_conn_entry->sett_conn);
	nm_g_object_unref (sett_conn_entry->storage);
	g_free (sett_conn_entry);
}

static NMSettingsConnection *
_sett_conn_entry_get_conn (SettConnEntry *sett_conn_entry)
{
	return sett_conn_entry ? sett_conn_entry->sett_conn : NULL;
}

/**
 * _sett_conn_entry_storage_find_conflicting_storage:
 * @sett_conn_entry: the list of settings-storages for the given UUID.
 * @target_plugin: the settings plugin to check
 * @storage_check_including: (allow-none): optionally compare against this storage.
 * @plugins: the list of plugins sorted in descending priority. This determines
 *   the priority and whether a storage conflicts.
 *
 * If we were to add the a storage to @target_plugin, then this function checks
 * whether there are already other storages that would hide the storage after we
 * add it. Those conflicting/hiding storages are a problem, because they have higher
 * priority, so we cannot add the storage.
 *
 * @storage_check_including is optional, and if given then it checks whether updating
 * the profile in this storage would result in confict. This is the check before
 * update-connection. If this parameter is omitted, then it's about what happens
 * when adding a new profile (add-connection).
 *
 * Returns: the conflicting storage or %NULL if there is none.
 */
static NMSettingsStorage *
_sett_conn_entry_storage_find_conflicting_storage (SettConnEntry *sett_conn_entry,
                                                   NMSettingsPlugin *target_plugin,
                                                   NMSettingsStorage *storage_check_including,
                                                   const GSList *plugins)
{
	StorageData *sd;

	if (!sett_conn_entry)
		return NULL;

	if (   storage_check_including
	    && nm_settings_storage_is_keyfile_run (storage_check_including)) {
		/* the storage we check against is in-memory. It always has highest
		 * priority, so there can be no other conflicting storages. */
		return NULL;
	}

	/* Finds the first (highest priority) storage that has a connection.
	 * Note that due to tombstones (that have a high priority), the connection
	 * may not actually be exposed. This is to find hidden/shadowed storages
	 * that provide a connection. */
	c_list_for_each_entry (sd, &sett_conn_entry->sd_lst_head, sd_lst) {
		nm_assert (NM_IS_SETTINGS_STORAGE (sd->storage));

		if (!sd->connection) {
			/* We only consider storages with connection. In particular,
			 * tombstones are not relevant, because we can delete them to
			 * resolve the conflict. */
			continue;
		}

		if (sd->storage == storage_check_including) {
			/* ok, the storage is the one we are about to check. All other
			 * storages are lower priority, so there is no storage that hides
			 * our storage_check_including. */
			return NULL;
		}

		if (nm_settings_plugin_cmp_by_priority (nm_settings_storage_get_plugin (sd->storage),
		                                        target_plugin,
		                                        plugins) <= 0) {
			/* the plugin of the existing storage is less important than @target_plugin.
			 * We have no conflicting/hiding storage. */
			return NULL;
		}

		/* Found. If we would add the profile to @target_plugin, then it would be hidden
		 * by existing_storage. */
		return sd->storage;
	}

	return NULL;
}

static NMSettingsStorage *
_sett_conn_entry_find_shadowed_storage (SettConnEntry *sett_conn_entry,
                                        const char *shadowed_storage_filename,
                                        NMSettingsStorage *blacklisted_storage)
{
	StorageData *sd;

	if (!shadowed_storage_filename)
		return NULL;

	c_list_for_each_entry (sd, &sett_conn_entry->sd_lst_head, sd_lst) {

		nm_assert (NM_IS_SETTINGS_STORAGE (sd->storage));

		if (!sd->connection)
			continue;

		if (blacklisted_storage == sd->storage)
			continue;

		if (!nm_streq0 (nm_settings_storage_get_filename_for_shadowed_storage (sd->storage), shadowed_storage_filename))
			continue;

		return sd->storage;
	}

	return NULL;
}

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NMSettings,
	PROP_UNMANAGED_SPECS,
	PROP_HOSTNAME,
	PROP_CAN_MODIFY,
	PROP_CONNECTIONS,
	PROP_STARTUP_COMPLETE,
);

enum {
	CONNECTION_ADDED,
	CONNECTION_UPDATED,
	CONNECTION_REMOVED,
	CONNECTION_FLAGS_CHANGED,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

typedef struct {
	NMAgentManager *agent_mgr;

	NMConfig *config;

	NMPlatform *platform;

	NMHostnameManager *hostname_manager;

	NMSessionMonitor *session_monitor;

	CList auth_lst_head;

	NMSKeyfilePlugin *keyfile_plugin;

	GSList *plugins;

	NMKeyFileDB *kf_db_timestamps;
	NMKeyFileDB *kf_db_seen_bssids;

	GHashTable *sce_idx;

	CList sce_dirty_lst_head;

	CList connections_lst_head;

	NMSettingsConnection **connections_cached_list;

	GSList *unmanaged_specs;
	GSList *unrecognized_specs;

	GHashTable *startup_complete_idx;
	NMSettingsConnection *startup_complete_blocked_by;
	gulong startup_complete_platform_change_id;
	guint startup_complete_timeout_id;

	guint connections_len;

	guint connections_generation;

	guint kf_db_flush_idle_id_timestamps;
	guint kf_db_flush_idle_id_seen_bssids;

	bool started:1;

} NMSettingsPrivate;

struct _NMSettings {
	NMDBusObject parent;
	NMSettingsPrivate _priv;
};

struct _NMSettingsClass {
	NMDBusObjectClass parent;
};

G_DEFINE_TYPE (NMSettings, nm_settings, NM_TYPE_DBUS_OBJECT);

#define NM_SETTINGS_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMSettings, NM_IS_SETTINGS)

/*****************************************************************************/

/* FIXME: a lot of logging lines are directly connected to a profile. Set the @con_uuid
 *   argument for structured logging. */

#define _NMLOG_DOMAIN         LOGD_SETTINGS
#define _NMLOG(level, ...) __NMLOG_DEFAULT (level, _NMLOG_DOMAIN, "settings", __VA_ARGS__)

/*****************************************************************************/

static const NMDBusInterfaceInfoExtended interface_info_settings;
static const GDBusSignalInfo signal_info_new_connection;
static const GDBusSignalInfo signal_info_connection_removed;

static void default_wired_clear_tag (NMSettings *self,
                                     NMDevice *device,
                                     NMSettingsConnection *sett_conn,
                                     gboolean add_to_no_auto_default);

static void _clear_connections_cached_list (NMSettingsPrivate *priv);

static void _startup_complete_check (NMSettings *self,
                                     gint64 now_us);

/*****************************************************************************/

static void
_emit_connection_added (NMSettings *self,
                        NMSettingsConnection *sett_conn)
{
	g_signal_emit (self, signals[CONNECTION_ADDED], 0, sett_conn);
}

static void
_emit_connection_updated (NMSettings *self,
                          NMSettingsConnection *sett_conn,
                          NMSettingsConnectionUpdateReason update_reason)
{
	_nm_settings_connection_emit_signal_updated_internal (sett_conn, update_reason);
	g_signal_emit (self, signals[CONNECTION_UPDATED], 0, sett_conn, (guint) update_reason);
}

static void
_emit_connection_removed (NMSettings *self,
                          NMSettingsConnection *sett_conn)
{
	g_signal_emit (self, signals[CONNECTION_REMOVED], 0, sett_conn);
}

static void
_emit_connection_flags_changed (NMSettings *self,
                                NMSettingsConnection *sett_conn)
{
	g_signal_emit (self, signals[CONNECTION_FLAGS_CHANGED], 0, sett_conn);
}

/*****************************************************************************/

typedef struct {
	NMSettingsConnection *sett_conn;
	gint64 start_at;
	gint64 timeout;
} StartupCompleteData;

static void
_startup_complete_data_destroy (StartupCompleteData *scd)
{
	g_object_unref (scd->sett_conn);
	g_slice_free (StartupCompleteData, scd);
}

static gboolean
_startup_complete_check_is_ready (NMPlatform *platform,
                                  NMSettingsConnection *sett_conn)
{
	const NMPlatformLink *plink;
	const char *ifname;

	/* FIXME: instead of just looking for the interface name, it would be better
	 *        to wait for a device that is compatible with the profile. */

	ifname = nm_connection_get_interface_name (nm_settings_connection_get_connection (sett_conn));

	if (!ifname)
		return TRUE;

	plink = nm_platform_link_get_by_ifname (platform, ifname);
	return plink && plink->initialized;
}

static gboolean
_startup_complete_timeout_cb (gpointer user_data)
{
	NMSettings *self = user_data;
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);

	priv->startup_complete_timeout_id = 0;
	_startup_complete_check (self, 0);
	return G_SOURCE_REMOVE;
}

static void
_startup_complete_platform_change_cb (NMPlatform *platform,
                                      int obj_type_i,
                                      int ifindex,
                                      const NMPlatformLink *link,
                                      int change_type_i,
                                      NMSettings *self)
{
	const NMPlatformSignalChangeType change_type = change_type_i;
	NMSettingsPrivate *priv;
	const char *ifname;

	if (change_type == NM_PLATFORM_SIGNAL_REMOVED)
		return;

	if (!link->initialized)
		return;

	priv = NM_SETTINGS_GET_PRIVATE (self);

	ifname = nm_connection_get_interface_name (nm_settings_connection_get_connection (priv->startup_complete_blocked_by));
	if (   ifname
	    && !nm_streq (ifname, link->name))
		return;

	nm_assert (priv->startup_complete_timeout_id > 0);

	nm_clear_g_source (&priv->startup_complete_timeout_id);
	priv->startup_complete_timeout_id = g_idle_add (_startup_complete_timeout_cb, self);
}

static void
_startup_complete_check (NMSettings *self,
                         gint64 now_us)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	gint64 next_expiry;
	StartupCompleteData *scd;
	NMSettingsConnection *next_sett_conn = NULL;
	GHashTableIter iter;

	if (!priv->started) {
		/* before we are started, we don't setup the timers... */
		return;
	}

	if (!priv->startup_complete_idx)
		goto ready;

	if (!now_us)
		now_us = nm_utils_get_monotonic_timestamp_us ();

	next_expiry = 0;

	g_hash_table_iter_init (&iter, priv->startup_complete_idx);
	while (g_hash_table_iter_next (&iter, (gpointer *) &scd, NULL)) {
		gint64 expiry;

		if (scd->start_at == 0) {
			/* once ready, the decision is remembered and there is nothing
			 * left to check. */
			continue;
		}

		expiry = scd->start_at + scd->timeout;
		if (expiry <= now_us) {
			scd->start_at = 0;
			continue;
		}

		if (_startup_complete_check_is_ready (priv->platform, scd->sett_conn)) {
			scd->start_at = 0;
			continue;
		}

		next_expiry = expiry;
		next_sett_conn = scd->sett_conn;
		/* we found one timeout for which to wait. that's good enough. */
		break;
	}

	nm_clear_g_source (&priv->startup_complete_timeout_id);
	nm_g_object_ref_set (&priv->startup_complete_blocked_by, next_sett_conn);
	if (next_expiry > 0) {
		nm_assert (priv->startup_complete_blocked_by);
		if (priv->startup_complete_platform_change_id == 0) {
			priv->startup_complete_platform_change_id = g_signal_connect (priv->platform,
			                                                              NM_PLATFORM_SIGNAL_LINK_CHANGED,
			                                                              G_CALLBACK (_startup_complete_platform_change_cb),
			                                                              self);
		}
		priv->startup_complete_timeout_id = g_timeout_add (NM_MIN (3600u*1000u, (next_expiry - now_us) / 1000u),
		                                                   _startup_complete_timeout_cb,
		                                                   self);
		_LOGT ("startup-complete: wait for device \"%s\" due to connection %s (%s)",
		       nm_connection_get_interface_name (nm_settings_connection_get_connection (priv->startup_complete_blocked_by)),
		       nm_settings_connection_get_uuid (priv->startup_complete_blocked_by),
		       nm_settings_connection_get_id (priv->startup_complete_blocked_by));
		return;
	}

	nm_clear_pointer (&priv->startup_complete_idx, g_hash_table_destroy);
	nm_clear_g_signal_handler (priv->platform, &priv->startup_complete_platform_change_id);

ready:
	_LOGT ("startup-complete: ready, no profiles to wait for");
	nm_assert (priv->started);
	nm_assert (!priv->startup_complete_blocked_by);
	nm_assert (!priv->startup_complete_idx);
	nm_assert (priv->startup_complete_timeout_id == 0);
	nm_assert (priv->startup_complete_platform_change_id == 0);
	_notify (self, PROP_STARTUP_COMPLETE);
}

static void
_startup_complete_notify_connection (NMSettings *self,
                                     NMSettingsConnection *sett_conn,
                                     gboolean forget)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	gint64 timeout;
	gint64 now_us = 0;

	nm_assert (   !priv->started
	           || priv->startup_complete_idx);

	timeout = 0;
	if (!forget) {
		NMSettingConnection *s_con;
		gint32 v;

		s_con = nm_connection_get_setting_connection (nm_settings_connection_get_connection (sett_conn));
		v = nm_setting_connection_get_wait_device_timeout (s_con);
		if (v > 0) {
			nm_assert (nm_setting_connection_get_interface_name (s_con));
			timeout = ((gint64) v) * 1000;
		}
	}

	if (timeout == 0) {
		if (   !priv->startup_complete_idx
		    || !g_hash_table_remove (priv->startup_complete_idx, &sett_conn))
			return;
	} else {
		StartupCompleteData *scd;

		if (!priv->startup_complete_idx) {
			nm_assert (!priv->started);
			priv->startup_complete_idx = g_hash_table_new_full (nm_pdirect_hash,
			                                                    nm_pdirect_equal,
			                                                    NULL,
			                                                    (GDestroyNotify) _startup_complete_data_destroy);
			scd = NULL;
		} else
			scd = g_hash_table_lookup (priv->startup_complete_idx, &sett_conn);
		if (!scd) {
			now_us = nm_utils_get_monotonic_timestamp_us ();
			scd = g_slice_new (StartupCompleteData);
			*scd = (StartupCompleteData) {
				.sett_conn = g_object_ref (sett_conn),
				.start_at  = now_us,
				.timeout   = timeout,
			};
			g_hash_table_add (priv->startup_complete_idx, scd);
		} else {
			if (scd->start_at == 0) {
				/* the entry already is ready and no longer relevant. Ignore it. */
				return;
			}
			scd->timeout = timeout;
		}
	}

	_startup_complete_check (self, now_us);
}

const char *
nm_settings_get_startup_complete_blocked_reason (NMSettings *self)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	const char *uuid = NULL;

	if (priv->started) {
		if (!priv->startup_complete_idx)
			return NULL;
		if (priv->startup_complete_blocked_by)
			uuid = nm_settings_connection_get_uuid (priv->startup_complete_blocked_by);
	}
	return uuid ?: "unknown";
}

/*****************************************************************************/

const GSList *
nm_settings_get_unmanaged_specs (NMSettings *self)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);

	return priv->unmanaged_specs;
}

static gboolean
update_specs (NMSettings *self, GSList **specs_ptr,
              GSList * (*get_specs_func) (NMSettingsPlugin *))
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	GSList *new = NULL;
	GSList *iter;

	for (iter = priv->plugins; iter; iter = g_slist_next (iter)) {
		GSList *specs;

		specs = get_specs_func (iter->data);
		while (specs) {
			GSList *s = specs;

			specs = g_slist_remove_link (specs, s);
			if (nm_utils_g_slist_find_str (new, s->data)) {
				g_free (s->data);
				g_slist_free_1 (s);
				continue;
			}
			s->next = new;
			new = s;
		}
	}

	if (nm_utils_g_slist_strlist_cmp (new, *specs_ptr) == 0) {
		g_slist_free_full (new, g_free);
		return FALSE;
	}

	g_slist_free_full (*specs_ptr, g_free);
	*specs_ptr = new;
	return TRUE;

}

static void
_plugin_unmanaged_specs_changed (NMSettingsPlugin *config,
                                 gpointer user_data)
{
	NMSettings *self = NM_SETTINGS (user_data);
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);

	if (update_specs (self, &priv->unmanaged_specs,
	                  nm_settings_plugin_get_unmanaged_specs))
		_notify (self, PROP_UNMANAGED_SPECS);
}

static void
_plugin_unrecognized_specs_changed (NMSettingsPlugin *config,
                                    gpointer user_data)
{
	NMSettings *self = NM_SETTINGS (user_data);
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);

	update_specs (self, &priv->unrecognized_specs,
	              nm_settings_plugin_get_unrecognized_specs);
}

/*****************************************************************************/

static void
connection_flags_changed (NMSettingsConnection *sett_conn,
                          gpointer user_data)
{
	_emit_connection_flags_changed (NM_SETTINGS (user_data), sett_conn);
}

/*****************************************************************************/

static SettConnEntry *
_sett_conn_entries_get (NMSettings *self,
                        const char *uuid)
{
	nm_assert (uuid);
	return g_hash_table_lookup (NM_SETTINGS_GET_PRIVATE (self)->sce_idx, &uuid);
}

static SettConnEntry *
_sett_conn_entries_create_and_add (NMSettings *self,
                                   const char *uuid)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	SettConnEntry *sett_conn_entry;

	sett_conn_entry = _sett_conn_entry_new (uuid);

	if (!g_hash_table_add (priv->sce_idx, sett_conn_entry))
		nm_assert_not_reached ();
	else if (g_hash_table_size (priv->sce_idx) == 1)
		g_object_ref (self);

	return sett_conn_entry;
}

static void
_sett_conn_entries_remove_and_destroy (NMSettings *self,
                                       SettConnEntry *sett_conn_entry)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);

	if (!g_hash_table_remove (priv->sce_idx, sett_conn_entry))
		nm_assert_not_reached ();
	else if (g_hash_table_size (priv->sce_idx) == 0)
		g_object_unref (self);
}

/*****************************************************************************/

static int
_sett_conn_entry_sds_update_cmp_ascending (const StorageData *sd_a,
                                           const StorageData *sd_b,
                                           const GSList *plugins)
{
	const NMSettingsMetaData *meta_data_a;
	const NMSettingsMetaData *meta_data_b;
	bool is_keyfile_run_a;
	bool is_keyfile_run_b;

	/* Sort storages by priority. More important storages are sorted
	 * higher (ascending sort). For example, if "sd_a" is more important than
	 * "sd_b" (sd_a>sd_b), a positive integer is returned. */

	meta_data_a = nm_settings_storage_is_meta_data (sd_a->storage);
	meta_data_b = nm_settings_storage_is_meta_data (sd_b->storage);

	/* runtime storages (both connections and meta-data) are always more
	 * important. */
	is_keyfile_run_a = nm_settings_storage_is_keyfile_run (sd_a->storage);
	is_keyfile_run_b = nm_settings_storage_is_keyfile_run (sd_b->storage);
	if (is_keyfile_run_a != is_keyfile_run_b) {

		if (   !meta_data_a
		    && !meta_data_b) {
			/* Ok, both are non-meta-data providing actual profiles. But one is in /run and one is in
			 * another storage. In this case we first honor whether one of the storages is explicitly
			 * prioritized. The prioritize flag is an in-memory hack to overwrite relative priorities
			 * contrary to what exists on-disk.
			 *
			 * This is done because when we use explicit D-Bus API (like update-connection)
			 * to update a profile, then we really want to prioritize the candidate
			 * despite having multiple other profiles.
			 *
			 * The example is if you have the same UUID twice in /run (one of them shadowed).
			 * If you move it to disk, then one of the profiles gets deleted and re-created
			 * on disk, but that on-disk profile must win against the remainging profile in
			 * /run. At least until the next reload/restart. */
			NM_CMP_FIELD_UNSAFE (sd_a, sd_b, prioritize);
		}

		/* in-memory has higher priority. That is regardless of whether any of
		 * them is meta-data/tombstone or a profile.
		 *
		 * That works, because if any of them are tombstones/metadata, then we are in full
		 * control. There can by only one meta-data file, which is fully owned (and accordingly
		 * created/deleted) by NetworkManager.
		 *
		 * The only case where this might not be right is if we have profiles
		 * in /run that are shadowed. When we move such a profile to disk, then
		 * a conflict might arise. That is handled by "prioritize" above! */
		NM_CMP_DIRECT (is_keyfile_run_a, is_keyfile_run_b);
	}

	/* After we determined that both profiles are either in /run or not,
	 * tombstones are always more important than non-tombstones. */
	NM_CMP_DIRECT (meta_data_a && meta_data_a->is_tombstone,
	               meta_data_b && meta_data_b->is_tombstone);

	/* Again, prioritized entries are sorted first (higher priority). */
	NM_CMP_FIELD_UNSAFE (sd_a, sd_b, prioritize);

	/* finally, compare the storages. This basically honors the timestamp
	 * of the profile and the relative order of the source plugin (via the
	 * @plugins list). */
	return nm_settings_storage_cmp (sd_a->storage, sd_b->storage, plugins);
}

static int
_sett_conn_entry_sds_update_cmp (const CList *ls_a,
                                 const CList *ls_b,
                                 gconstpointer user_data)
{
	/* we sort highest priority storages first (descending). Hence, the order is swapped. */
	return _sett_conn_entry_sds_update_cmp_ascending (c_list_entry (ls_b, StorageData, sd_lst),
	                                                  c_list_entry (ls_a, StorageData, sd_lst),
	                                                  user_data);
}

static void
_sett_conn_entry_sds_update (NMSettings *self,
                             SettConnEntry *sett_conn_entry)
{
	StorageData *sd;
	StorageData *sd_safe;
	StorageData *sd_dirty;
	gboolean reprioritize;

	nm_assert_storage_data_lst (&sett_conn_entry->sd_lst_head);
	nm_assert_storage_data_lst (&sett_conn_entry->dirty_sd_lst_head);

	/* we merge the dirty list with the previous list.
	 *
	 * The idea is:
	 *
	 *  - _connection_changed_track() appends events for the same UUID. Meaning:
	 *    if the storage is new, it get appended (having lower priority).
	 *    If it already exist and is an update for an event that we already
	 *    track it, it keeps the list position in @dirty_sd_lst_head unchanged.
	 *
	 *  - during merge, we want to preserve the previous order (with higher
	 *    priority first in the list).
	 */

	/* first go through all storages that we track and check whether they
	 * got an update...*/

	reprioritize = FALSE;
	c_list_for_each_entry (sd, &sett_conn_entry->dirty_sd_lst_head, sd_lst) {
		if (sd->prioritize) {
			reprioritize = TRUE;
			break;
		}
	}

	nm_assert_storage_data_lst (&sett_conn_entry->sd_lst_head);

	c_list_for_each_entry_safe (sd, sd_safe, &sett_conn_entry->sd_lst_head, sd_lst) {

		sd_dirty = _storage_data_find_in_lst (&sett_conn_entry->dirty_sd_lst_head, sd->storage);
		if (!sd_dirty) {
			/* there is no update for this storage (except maybe reprioritize). */
			if (reprioritize)
				sd->prioritize = FALSE;
			continue;
		}

		nm_g_object_ref_set (&sd->connection, sd_dirty->connection);
		sd->prioritize = sd_dirty->prioritize;

		_storage_data_destroy (sd_dirty);
	}

	nm_assert_storage_data_lst (&sett_conn_entry->sd_lst_head);

	/* all remaining (so far unseen) dirty entries are appended to the merged list.
	 * (append means lower priority). */

	c_list_splice (&sett_conn_entry->sd_lst_head, &sett_conn_entry->dirty_sd_lst_head);

	nm_assert_storage_data_lst (&sett_conn_entry->sd_lst_head);

	/* we drop the entries that are no longer "alive" (meaning, they no longer
	 * indicate a connection and are not a tombstone). */
	c_list_for_each_entry_safe (sd, sd_safe, &sett_conn_entry->sd_lst_head, sd_lst) {
		if (!_storage_data_is_alive (sd))
			_storage_data_destroy (sd);
	}

	nm_assert_storage_data_lst (&sett_conn_entry->sd_lst_head);
	nm_assert (c_list_is_empty (&sett_conn_entry->dirty_sd_lst_head));

	/* as last, we sort the entries. Note that this is a stable-sort... */
	c_list_sort (&sett_conn_entry->sd_lst_head,
	             _sett_conn_entry_sds_update_cmp,
	             NM_SETTINGS_GET_PRIVATE (self)->plugins);

	nm_assert_storage_data_lst (&sett_conn_entry->sd_lst_head);
	nm_assert (c_list_is_empty (&sett_conn_entry->dirty_sd_lst_head));
}

/*****************************************************************************/

static NMConnection *
_connection_changed_normalize_connection (NMSettingsStorage *storage,
                                          NMConnection *connection,
                                          GVariant *secrets_to_merge,
                                          NMConnection **out_connection_cloned)
{
	gs_unref_object NMConnection *connection_cloned = NULL;
	gs_free_error GError *error = NULL;
	const char *uuid;

	nm_assert (NM_IS_SETTINGS_STORAGE (storage));
	nm_assert (out_connection_cloned && !*out_connection_cloned);

	if (!connection)
		return NULL;

	nm_assert (NM_IS_CONNECTION (connection));

	uuid = nm_settings_storage_get_uuid (storage);

	if (secrets_to_merge) {
		connection_cloned = nm_simple_connection_new_clone (connection);
		connection = connection_cloned;
		nm_connection_update_secrets (connection,
		                              NULL,
		                              secrets_to_merge,
		                              NULL);
	}

	if (!_nm_connection_ensure_normalized (connection,
	                                       !!connection_cloned,
	                                       uuid,
	                                       FALSE,
	                                       connection_cloned ? NULL : &connection_cloned,
	                                       &error)) {
		/* this is most likely a bug in the plugin. It provided a connection that no longer verifies.
		 * Well, I guess it could also happen when we merge @secrets_to_merge above. In any case
		 * somewhere is a bug. */
		_LOGT ("storage[%s,"NM_SETTINGS_STORAGE_PRINT_FMT"]: plugin provided an invalid connection: %s",
		       uuid,
		       NM_SETTINGS_STORAGE_PRINT_ARG (storage),
		       error->message);
		return NULL;
	}
	if (connection_cloned)
		connection = connection_cloned;

	*out_connection_cloned = g_steal_pointer (&connection_cloned);
	return connection;
}

/*****************************************************************************/

static void
_connection_changed_update (NMSettings *self,
                            SettConnEntry *sett_conn_entry,
                            NMConnection *connection,
                            NMSettingsConnectionIntFlags sett_flags,
                            NMSettingsConnectionIntFlags sett_mask,
                            NMSettingsConnectionUpdateReason update_reason)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	gs_unref_object NMConnection *connection_old = NULL;
	NMSettingsStorage *storage = sett_conn_entry->storage;
	gs_unref_object NMSettingsConnection *sett_conn = g_object_ref (sett_conn_entry->sett_conn);
	const char *path;
	gboolean is_new;

	nm_assert (!NM_FLAGS_ANY (sett_mask, ~_NM_SETTINGS_CONNECTION_INT_FLAGS_PERSISTENT_MASK));
	nm_assert (!NM_FLAGS_ANY (sett_flags, ~sett_mask));

	is_new = c_list_is_empty (&sett_conn->_connections_lst);

	_LOGT ("update[%s]: %s connection \"%s\" ("NM_SETTINGS_STORAGE_PRINT_FMT")",
	       nm_settings_storage_get_uuid (storage),
	       is_new ? "adding" : "updating",
	       nm_connection_get_id (connection),
	       NM_SETTINGS_STORAGE_PRINT_ARG (storage));

	_nm_settings_connection_set_storage (sett_conn, storage);

	_nm_settings_connection_set_connection (sett_conn, connection, &connection_old, update_reason);


	if (is_new) {
		_nm_settings_connection_register_kf_dbs (sett_conn,
		                                         priv->kf_db_timestamps,
		                                         priv->kf_db_seen_bssids);

		_clear_connections_cached_list (priv);
		c_list_link_tail (&priv->connections_lst_head, &sett_conn->_connections_lst);
		priv->connections_len++;
		priv->connections_generation++;

		g_signal_connect (sett_conn, NM_SETTINGS_CONNECTION_FLAGS_CHANGED, G_CALLBACK (connection_flags_changed), self);
	}

	if (NM_FLAGS_HAS (update_reason, NM_SETTINGS_CONNECTION_UPDATE_REASON_BLOCK_AUTOCONNECT)) {
		nm_settings_connection_autoconnect_blocked_reason_set (sett_conn,
		                                                       NM_SETTINGS_AUTO_CONNECT_BLOCKED_REASON_USER_REQUEST,
		                                                       TRUE);
	}

	sett_mask |= NM_SETTINGS_CONNECTION_INT_FLAGS_VISIBLE;
	if (nm_settings_connection_check_visibility (sett_conn, priv->session_monitor))
		sett_flags |= NM_SETTINGS_CONNECTION_INT_FLAGS_VISIBLE;
	else
		nm_assert (!NM_FLAGS_HAS (sett_flags, NM_SETTINGS_CONNECTION_INT_FLAGS_VISIBLE));

	sett_mask |= NM_SETTINGS_CONNECTION_INT_FLAGS_UNSAVED;
	if (nm_settings_storage_is_keyfile_run (storage))
		sett_flags |= NM_SETTINGS_CONNECTION_INT_FLAGS_UNSAVED;
	else {
		nm_assert (!NM_FLAGS_HAS (sett_flags, NM_SETTINGS_CONNECTION_INT_FLAGS_UNSAVED));

		/* Profiles that don't reside in /run, are never nm-generated
		 * and never volatile. */
		sett_mask |= (  NM_SETTINGS_CONNECTION_INT_FLAGS_NM_GENERATED
		              | NM_SETTINGS_CONNECTION_INT_FLAGS_VOLATILE);
		sett_flags &= ~(  NM_SETTINGS_CONNECTION_INT_FLAGS_NM_GENERATED
		                | NM_SETTINGS_CONNECTION_INT_FLAGS_VOLATILE);
	}

	nm_settings_connection_set_flags_full (sett_conn,
	                                       sett_mask,
	                                       sett_flags);

	if (is_new) {
		/* FIXME(shutdown): The NMSettings instance can't be disposed
		 * while there is any exported connection. Ideally we should
		 * unexport all connections on NMSettings' disposal, but for now
		 * leak @self on termination when there are connections alive. */
		path = nm_dbus_object_export (NM_DBUS_OBJECT (sett_conn));
	} else
		path = nm_dbus_object_get_path (NM_DBUS_OBJECT (sett_conn));

	if (   is_new
	    || connection_old) {
		nm_utils_log_connection_diff (nm_settings_connection_get_connection (sett_conn),
		                              connection_old,
		                              LOGL_DEBUG,
		                              LOGD_CORE,
		                              is_new ? "new connection" : "update connection",
		                              "++ ",
		                              path);
	}

	if (is_new) {
		nm_dbus_object_emit_signal (NM_DBUS_OBJECT (self),
		                            &interface_info_settings,
		                            &signal_info_new_connection,
		                            "(o)",
		                            path);
		_notify (self, PROP_CONNECTIONS);
		_emit_connection_added (self, sett_conn);
	} else {
		_nm_settings_connection_emit_dbus_signal_updated (sett_conn);
		_emit_connection_updated (self, sett_conn, update_reason);
	}

	if (   !priv->started
	    || priv->startup_complete_idx) {
		if (nm_settings_has_connection (self, sett_conn))
			_startup_complete_notify_connection (self, sett_conn, FALSE);
	}
}

static void
_connection_changed_delete (NMSettings *self,
                            NMSettingsStorage *storage,
                            NMSettingsConnection *sett_conn,
                            gboolean allow_add_to_no_auto_default)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	gs_unref_object NMConnection *connection_for_agents = NULL;
	NMDevice *device;
	const char *uuid;

	nm_assert (NM_IS_SETTINGS_CONNECTION (sett_conn));
	nm_assert (c_list_contains (&priv->connections_lst_head, &sett_conn->_connections_lst));
	nm_assert (nm_dbus_object_is_exported (NM_DBUS_OBJECT (sett_conn)));

	uuid = nm_settings_storage_get_uuid (storage);

	_LOGT ("update[%s]: delete connection \"%s\" ("NM_SETTINGS_STORAGE_PRINT_FMT")",
	       uuid,
	       nm_settings_connection_get_id (sett_conn),
	       NM_SETTINGS_STORAGE_PRINT_ARG (storage));

	/* When the default wired sett_conn is removed (either deleted or saved to
	 * a new persistent sett_conn by a plugin), write the MAC address of the
	 * wired device to the config file and don't create a new default wired
	 * sett_conn for that device again.
	 */
	device = nm_settings_connection_default_wired_get_device (sett_conn);
	if (device)
		default_wired_clear_tag (self, device, sett_conn, allow_add_to_no_auto_default);

	g_signal_handlers_disconnect_by_func (sett_conn, G_CALLBACK (connection_flags_changed), self);

	_clear_connections_cached_list (priv);
	c_list_unlink (&sett_conn->_connections_lst);
	priv->connections_len--;
	priv->connections_generation++;

	/* Tell agents to remove secrets for this connection */
	connection_for_agents = nm_simple_connection_new_clone (nm_settings_connection_get_connection (sett_conn));
	nm_connection_clear_secrets (connection_for_agents);
	nm_agent_manager_delete_secrets (priv->agent_mgr,
	                                 nm_dbus_object_get_path (NM_DBUS_OBJECT (self)),
	                                 connection_for_agents);

	_notify (self, PROP_CONNECTIONS);
	_nm_settings_connection_emit_dbus_signal_removed (sett_conn);
	nm_dbus_object_emit_signal (NM_DBUS_OBJECT (self),
	                            &interface_info_settings,
	                            &signal_info_connection_removed,
	                            "(o)",
	                            nm_dbus_object_get_path (NM_DBUS_OBJECT (sett_conn)));

	nm_dbus_object_unexport (NM_DBUS_OBJECT (sett_conn));

	nm_settings_connection_set_flags (sett_conn,
	                                    NM_SETTINGS_CONNECTION_INT_FLAGS_VISIBLE
	                                  | NM_SETTINGS_CONNECTION_INT_FLAGS_VOLATILE,
	                                  FALSE);

	_emit_connection_removed (self, sett_conn);

	_nm_settings_connection_cleanup_after_remove (sett_conn);

	nm_key_file_db_remove_key (priv->kf_db_timestamps, uuid);
	nm_key_file_db_remove_key (priv->kf_db_seen_bssids, uuid);

	if (   !priv->started
	    || priv->startup_complete_idx)
		_startup_complete_notify_connection (self, sett_conn, TRUE);
}

static void
_connection_changed_process_one (NMSettings *self,
                                 SettConnEntry *sett_conn_entry,
                                 gboolean allow_add_to_no_auto_default,
                                 NMSettingsConnectionIntFlags sett_flags,
                                 NMSettingsConnectionIntFlags sett_mask,
                                 gboolean override_sett_flags,
                                 NMSettingsConnectionUpdateReason update_reason)
{
	StorageData *sd_best;

	c_list_unlink (&sett_conn_entry->sce_dirty_lst);

	_sett_conn_entry_sds_update (self, sett_conn_entry);

	sd_best = c_list_first_entry (&sett_conn_entry->sd_lst_head, StorageData, sd_lst);;

	if (   !sd_best
	    || !sd_best->connection) {
		gs_unref_object NMSettingsConnection *sett_conn = NULL;
		gs_unref_object NMSettingsStorage *storage = NULL;

		if (!sett_conn_entry->sett_conn) {

			if (!sd_best) {
				_sett_conn_entries_remove_and_destroy (self, sett_conn_entry);
				return;
			}

			if (sett_conn_entry->storage != sd_best->storage) {
				_LOGT ("update[%s]: shadow UUID ("NM_SETTINGS_STORAGE_PRINT_FMT")",
				       sett_conn_entry->uuid,
				       NM_SETTINGS_STORAGE_PRINT_ARG (sd_best->storage));
			}

			nm_g_object_ref_set (&sett_conn_entry->storage, sd_best->storage);
			return;
		}

		sett_conn = g_steal_pointer (&sett_conn_entry->sett_conn);
		if (sd_best) {
			storage = g_object_ref (sd_best->storage);
			nm_g_object_ref_set (&sett_conn_entry->storage, storage);
			nm_assert_valid_settings_storage (NULL, storage);
		} else {
			storage = g_object_ref (sett_conn_entry->storage);
			_sett_conn_entries_remove_and_destroy (self, sett_conn_entry);
		}

		_connection_changed_delete (self, storage, sett_conn, allow_add_to_no_auto_default);
		return;
	}

	if (override_sett_flags) {
		NMSettingsConnectionIntFlags s_f, s_m;

		nm_settings_storage_load_sett_flags (sd_best->storage, &s_f, &s_m);

		nm_assert (!NM_FLAGS_ANY (s_f, ~s_m));

		sett_mask |= s_m;
		sett_flags = (sett_flags & ~s_m) | (s_f & s_m);
	}

	nm_g_object_ref_set (&sett_conn_entry->storage, sd_best->storage);

	if (!sett_conn_entry->sett_conn)
		sett_conn_entry->sett_conn = nm_settings_connection_new ();

	_connection_changed_update (self,
	                            sett_conn_entry,
	                            sd_best->connection,
	                            sett_flags,
	                            sett_mask,
	                            update_reason);
}

static void
_connection_changed_process_all_dirty (NMSettings *self,
                                       gboolean allow_add_to_no_auto_default,
                                       NMSettingsConnectionIntFlags sett_flags,
                                       NMSettingsConnectionIntFlags sett_mask,
                                       gboolean override_sett_flags,
                                       NMSettingsConnectionUpdateReason update_reason)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	SettConnEntry *sett_conn_entry;

	while ((sett_conn_entry = c_list_first_entry (&priv->sce_dirty_lst_head, SettConnEntry, sce_dirty_lst))) {
		_connection_changed_process_one (self,
		                                 sett_conn_entry,
		                                 allow_add_to_no_auto_default,
		                                 sett_flags,
		                                 sett_mask,
		                                 override_sett_flags,
		                                 update_reason);
	}
}

static SettConnEntry *
_connection_changed_track (NMSettings *self,
                           NMSettingsStorage *storage,
                           NMConnection *connection,
                           gboolean prioritize)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	SettConnEntry *sett_conn_entry;
	StorageData *sd;
	const char *uuid;

	nm_assert_valid_settings_storage (NULL, storage);

	uuid = nm_settings_storage_get_uuid (storage);

	nm_assert (!connection || NM_IS_CONNECTION (connection));
	nm_assert (!connection || (_nm_connection_verify (connection, NULL) == NM_SETTING_VERIFY_SUCCESS));
	nm_assert (!connection || nm_streq0 (uuid, nm_connection_get_uuid (connection)));

	nmtst_connection_assert_unchanging (connection);

	sett_conn_entry =    _sett_conn_entries_get (self, uuid)
	                  ?: _sett_conn_entries_create_and_add (self, uuid);

	if (_LOGT_ENABLED ()) {
		const char *filename;
		const NMSettingsMetaData *meta_data;
		const char *shadowed_storage;
		gboolean shadowed_owned;

		filename = nm_settings_storage_get_filename (storage);
		if (connection) {
			shadowed_storage = nm_settings_storage_get_shadowed_storage (storage, &shadowed_owned);
			_LOGT ("storage[%s,"NM_SETTINGS_STORAGE_PRINT_FMT"]: change event with connection \"%s\"%s%s%s%s%s%s",
			       sett_conn_entry->uuid,
			       NM_SETTINGS_STORAGE_PRINT_ARG (storage),
			       nm_connection_get_id (connection),
			       NM_PRINT_FMT_QUOTED (filename, " (file \"", filename, "\")", ""),
			       NM_PRINT_FMT_QUOTED (shadowed_storage, shadowed_owned ? " (owns \"" : " (shadows \"", shadowed_storage, "\")", ""));
		} else if ((meta_data = nm_settings_storage_is_meta_data (storage))) {
			nm_assert (meta_data->is_tombstone);
			shadowed_storage = nm_settings_storage_get_shadowed_storage (storage, &shadowed_owned);
			_LOGT ("storage[%s,"NM_SETTINGS_STORAGE_PRINT_FMT"]: change event for %shiding profile%s%s%s%s%s%s",
			       sett_conn_entry->uuid,
			       NM_SETTINGS_STORAGE_PRINT_ARG (storage),
			       nm_settings_storage_is_meta_data_alive  (storage) ? "" : "dropping ",
			       NM_PRINT_FMT_QUOTED (filename, " (file \"", filename, "\")", ""),
			       NM_PRINT_FMT_QUOTED (shadowed_storage, shadowed_owned ? " (owns \"" : " (shadows \"", shadowed_storage, "\")", ""));
		} else {
			_LOGT ("storage[%s,"NM_SETTINGS_STORAGE_PRINT_FMT"]: change event for dropping profile%s%s%s",
			       sett_conn_entry->uuid,
			       NM_SETTINGS_STORAGE_PRINT_ARG (storage),
			       NM_PRINT_FMT_QUOTED (filename, " (file \"", filename, "\")", ""));
		}
	}

	/* see _sett_conn_entry_sds_update() for why we append the new events
	 * and leave existing ones at their position. */
	sd = _storage_data_find_in_lst (&sett_conn_entry->dirty_sd_lst_head, storage);
	if (sd)
		nm_g_object_ref_set (&sd->connection, connection);
	else {
		sd = _storage_data_new_stale (storage, connection);
		c_list_link_tail (&sett_conn_entry->dirty_sd_lst_head, &sd->sd_lst);
	}

	if (prioritize) {
		StorageData *sd2;

		/* only one entry can be prioritized. */
		c_list_for_each_entry (sd2, &sett_conn_entry->dirty_sd_lst_head, sd_lst)
			sd2->prioritize = FALSE;
		sd->prioritize = TRUE;
	}

	nm_c_list_move_tail (&priv->sce_dirty_lst_head, &sett_conn_entry->sce_dirty_lst);

	return sett_conn_entry;
}

/*****************************************************************************/

static void
_plugin_connections_reload_cb (NMSettingsPlugin *plugin,
                               NMSettingsStorage *storage,
                               NMConnection *connection,
                               gpointer user_data)
{
	_connection_changed_track (user_data, storage, connection, FALSE);
}

static void
_plugin_connections_reload (NMSettings *self)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	GSList *iter;

	for (iter = priv->plugins; iter; iter = iter->next) {
		nm_settings_plugin_reload_connections (iter->data,
		                                       _plugin_connections_reload_cb,
		                                       self);
	}

	_connection_changed_process_all_dirty (self,
	                                       FALSE,
	                                       NM_SETTINGS_CONNECTION_INT_FLAGS_NONE,
	                                       NM_SETTINGS_CONNECTION_INT_FLAGS_NONE,
	                                       TRUE,
	                                         NM_SETTINGS_CONNECTION_UPDATE_REASON_RESET_SYSTEM_SECRETS
	                                       | NM_SETTINGS_CONNECTION_UPDATE_REASON_RESET_AGENT_SECRETS);

	for (iter = priv->plugins; iter; iter = iter->next)
		nm_settings_plugin_load_connections_done (iter->data);
}

/*****************************************************************************/

static gboolean
_add_connection_to_first_plugin (NMSettings *self,
                                 SettConnEntry *sett_conn_entry,
                                 NMConnection *new_connection,
                                 gboolean in_memory,
                                 NMSettingsConnectionIntFlags sett_flags,
                                 const char *shadowed_storage,
                                 gboolean shadowed_owned,
                                 NMSettingsStorage **out_new_storage,
                                 NMConnection **out_new_connection,
                                 GError **error)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	gs_free_error GError *first_error = NULL;
	GSList *iter;
	const char *uuid;

	uuid = nm_connection_get_uuid (new_connection);

	nm_assert (nm_utils_is_uuid (uuid));

	for (iter = priv->plugins; iter; iter = iter->next) {
		NMSettingsPlugin *plugin = NM_SETTINGS_PLUGIN (iter->data);
		gs_unref_object NMSettingsStorage *storage = NULL;
		gs_unref_object NMConnection *connection_to_add = NULL;
		gs_unref_object NMConnection *connection_to_add_cloned = NULL;
		NMConnection *connection_to_add_real = NULL;
		gs_unref_variant GVariant *agent_owned_secrets = NULL;
		gs_free_error GError *add_error = NULL;
		gboolean success;
		const char *filename;

		if (!in_memory) {
			NMSettingsStorage *conflicting_storage;

			conflicting_storage = _sett_conn_entry_storage_find_conflicting_storage (sett_conn_entry, plugin, NULL, priv->plugins);
			if (conflicting_storage) {
				/* we have a connection provided by a plugin with higher priority than the one
				 * we would want to add the connection. We cannot do that, because doing so
				 * would result in adding a connection that gets hidden by the existing profile.
				 * Also, since we test the plugins in order of priority, all following plugins
				 * are unsuitable.
				 *
				 * Multiple connection plugins are so cumbersome, especially if they are unable
				 * to add the connection. I suggest to disable all plugins except keyfile. */
				_LOGT ("add-connection: failed to add %s/'%s': there is an existing storage "NM_SETTINGS_STORAGE_PRINT_FMT" with higher priority",
				       nm_connection_get_uuid (new_connection),
				       nm_connection_get_id (new_connection),
				       NM_SETTINGS_STORAGE_PRINT_ARG (conflicting_storage));
				nm_assert (first_error);
				break;
			}
		}

		if (plugin == (NMSettingsPlugin *) priv->keyfile_plugin) {
			success = nms_keyfile_plugin_add_connection (priv->keyfile_plugin,
			                                             new_connection,
			                                             in_memory,
			                                             NM_FLAGS_HAS (sett_flags, NM_SETTINGS_CONNECTION_INT_FLAGS_NM_GENERATED),
			                                             NM_FLAGS_HAS (sett_flags, NM_SETTINGS_CONNECTION_INT_FLAGS_VOLATILE),
			                                             shadowed_storage,
			                                             shadowed_owned,
			                                             &storage,
			                                             &connection_to_add,
			                                             &add_error);
		} else {
			if (in_memory)
				continue;
			nm_assert (!NM_FLAGS_HAS (sett_flags, NM_SETTINGS_CONNECTION_INT_FLAGS_NM_GENERATED));
			nm_assert (!NM_FLAGS_HAS (sett_flags, NM_SETTINGS_CONNECTION_INT_FLAGS_VOLATILE));
			success = nm_settings_plugin_add_connection (plugin,
			                                             new_connection,
			                                             &storage,
			                                             &connection_to_add,
			                                             &add_error);
		}

		if (!success) {
			_LOGT ("add-connection: failed to add %s/'%s': %s",
			       nm_connection_get_uuid (new_connection),
			       nm_connection_get_id (new_connection),
			       add_error->message);
			if (!first_error)
				first_error = g_steal_pointer (&add_error);
			continue;
		}

		if (!nm_streq0 (nm_settings_storage_get_uuid (storage), uuid)) {
			nm_assert_not_reached ();
			continue;
		}

		agent_owned_secrets = nm_connection_to_dbus (new_connection,
		                                               NM_CONNECTION_SERIALIZE_ONLY_SECRETS
		                                             | NM_CONNECTION_SERIALIZE_WITH_SECRETS_AGENT_OWNED);
		connection_to_add_real = _connection_changed_normalize_connection (storage,
		                                                                   connection_to_add,
		                                                                   agent_owned_secrets,
		                                                                   &connection_to_add_cloned);
		if (!connection_to_add_real) {
			nm_assert_not_reached ();
			continue;
		}

		filename = nm_settings_storage_get_filename (storage);
		_LOGT ("add-connection: successfully added connection %s,'%s' ("NM_SETTINGS_STORAGE_PRINT_FMT"%s%s%s",
		       nm_settings_storage_get_uuid (storage),
		       nm_connection_get_id (new_connection),
		       NM_SETTINGS_STORAGE_PRINT_ARG (storage),
		       NM_PRINT_FMT_QUOTED (filename, ", \"", filename, "\")", ")"));

		*out_new_storage = g_steal_pointer (&storage);
		*out_new_connection =    g_steal_pointer (&connection_to_add_cloned)
		                      ?: g_steal_pointer (&connection_to_add);
		nm_assert (NM_IS_CONNECTION (*out_new_connection));
		return TRUE;
	}

	nm_assert (first_error);
	g_propagate_error (error, g_steal_pointer (&first_error));
	return FALSE;
}

static gboolean
_update_connection_to_plugin (NMSettings *self,
                              NMSettingsStorage *storage,
                              NMConnection *connection,
                              NMSettingsConnectionIntFlags sett_flags,
                              gboolean force_rename,
                              const char *shadowed_storage,
                              gboolean shadowed_owned,
                              NMSettingsStorage **out_new_storage,
                              NMConnection **out_new_connection,
                              GError **error)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	NMSettingsPlugin *plugin;
	gboolean success;

	plugin = nm_settings_storage_get_plugin (storage);

	if (plugin == (NMSettingsPlugin *) priv->keyfile_plugin) {
		success = nms_keyfile_plugin_update_connection (priv->keyfile_plugin,
		                                                storage,
		                                                connection,
		                                                NM_FLAGS_HAS (sett_flags, NM_SETTINGS_CONNECTION_INT_FLAGS_NM_GENERATED),
		                                                NM_FLAGS_HAS (sett_flags, NM_SETTINGS_CONNECTION_INT_FLAGS_VOLATILE),
		                                                shadowed_storage,
		                                                shadowed_owned,
		                                                force_rename,
		                                                out_new_storage,
		                                                out_new_connection,
		                                                error);
	} else {
		nm_assert (!shadowed_storage);
		nm_assert (!shadowed_owned);
		success = nm_settings_plugin_update_connection (plugin,
		                                                storage,
		                                                connection,
		                                                out_new_storage,
		                                                out_new_connection,
		                                                error);
	}

	return success;
}

static void
_set_nmmeta_tombstone (NMSettings *self,
                       const char *uuid,
                       gboolean tombstone_on_disk,
                       gboolean tombstone_in_memory,
                       const char *shadowed_storage)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	gs_unref_object NMSettingsStorage *tombstone_1_storage = NULL;
	gs_unref_object NMSettingsStorage *tombstone_2_storage = NULL;

	if (tombstone_on_disk) {
		if (!nms_keyfile_plugin_set_nmmeta_tombstone (priv->keyfile_plugin,
		                                              FALSE,
		                                              uuid,
		                                              FALSE,
		                                              TRUE,
		                                              NULL,
		                                              &tombstone_1_storage,
		                                              NULL))
			tombstone_in_memory = TRUE;
		if (tombstone_1_storage)
			_connection_changed_track (self, tombstone_1_storage, NULL, FALSE);
	}

	if (tombstone_in_memory) {
		if (!nms_keyfile_plugin_set_nmmeta_tombstone (priv->keyfile_plugin,
		                                              FALSE,
		                                              uuid,
		                                              TRUE,
		                                              TRUE,
		                                              shadowed_storage,
		                                              &tombstone_2_storage,
		                                              NULL)) {
			nms_keyfile_plugin_set_nmmeta_tombstone (priv->keyfile_plugin,
			                                         TRUE,
			                                         uuid,
			                                         TRUE,
			                                         TRUE,
			                                         shadowed_storage,
			                                         &tombstone_2_storage,
			                                         NULL);
		}
		_connection_changed_track (self, tombstone_2_storage, NULL, FALSE);
	}
}

/**
 * nm_settings_add_connection:
 * @self: the #NMSettings object
 * @connection: the source connection to create a new #NMSettingsConnection from
 * @persist_mode: the persist-mode for this profile.
 * @add_reason: the add-reason flags.
 * @sett_flags: the settings flags to set.
 * @out_sett_conn: (allow-none) (transfer none): the added settings connection on success.
 * @error: on return, a location to store any errors that may occur
 *
 * Creates a new #NMSettingsConnection for the given source @connection.
 * The returned object is owned by @self and the caller must reference
 * the object to continue using it.
 *
 * Returns: TRUE on success.
 */
gboolean
nm_settings_add_connection (NMSettings *self,
                            NMConnection *connection,
                            NMSettingsConnectionPersistMode persist_mode,
                            NMSettingsConnectionAddReason add_reason,
                            NMSettingsConnectionIntFlags sett_flags,
                            NMSettingsConnection **out_sett_conn,
                            GError **error)
{
	NMSettingsPrivate *priv;
	gs_unref_object NMConnection *connection_cloned_1 = NULL;
	gs_unref_object NMConnection *new_connection = NULL;
	gs_unref_object NMSettingsStorage *new_storage = NULL;
	gs_unref_object NMSettingsStorage *shadowed_storage = NULL;
	NMSettingsStorage *update_storage = NULL;
	gs_free_error GError *local = NULL;
	SettConnEntry *sett_conn_entry;
	const char *uuid;
	StorageData *sd;
	gboolean new_in_memory;
	gboolean success;
	const char *shadowed_storage_filename = NULL;

	priv = NM_SETTINGS_GET_PRIVATE (self);

	nm_assert (NM_IN_SET (persist_mode, NM_SETTINGS_CONNECTION_PERSIST_MODE_TO_DISK,
	                                    NM_SETTINGS_CONNECTION_PERSIST_MODE_IN_MEMORY_ONLY));

	new_in_memory = (persist_mode != NM_SETTINGS_CONNECTION_PERSIST_MODE_TO_DISK);

	nm_assert (!NM_FLAGS_ANY (sett_flags, ~_NM_SETTINGS_CONNECTION_INT_FLAGS_PERSISTENT_MASK));

	if (NM_FLAGS_ANY (sett_flags,   NM_SETTINGS_CONNECTION_INT_FLAGS_VOLATILE
	                              | NM_SETTINGS_CONNECTION_INT_FLAGS_NM_GENERATED)) {
		nm_assert (new_in_memory);
		new_in_memory = TRUE;
	}

	nm_assert (!NM_FLAGS_ANY (add_reason, ~NM_SETTINGS_CONNECTION_ADD_REASON_BLOCK_AUTOCONNECT));

	NM_SET_OUT (out_sett_conn, NULL);

	uuid = nm_connection_get_uuid (connection);

	sett_conn_entry = _sett_conn_entries_get (self, uuid);
	if (_sett_conn_entry_get_conn (sett_conn_entry)) {
		g_set_error_literal (error,
		                     NM_SETTINGS_ERROR,
		                     NM_SETTINGS_ERROR_UUID_EXISTS,
		                     "a connection with this UUID already exists");
		return FALSE;
	}

	if (!_nm_connection_ensure_normalized (connection,
	                                       FALSE,
	                                       NULL,
	                                       FALSE,
	                                       &connection_cloned_1,
	                                       &local)) {
		g_set_error (error,
		             NM_SETTINGS_ERROR,
		             NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "connection is invalid: %s",
		             local->message);
		return FALSE;
	}
	if (connection_cloned_1)
		connection = connection_cloned_1;

	if (sett_conn_entry) {
		c_list_for_each_entry (sd, &sett_conn_entry->sd_lst_head, sd_lst) {
			if (!nm_settings_storage_is_meta_data (sd->storage))
				continue;
			shadowed_storage = nm_g_object_ref (_sett_conn_entry_find_shadowed_storage (sett_conn_entry,
			                                                                            nm_settings_storage_get_shadowed_storage (sd->storage, NULL),
			                                                                            NULL));
			if (shadowed_storage) {
				/* We have a nmmeta tombstone that indicates that a storage is shadowed.
				 *
				 * This happens when deleting a in-memory profile that was decoupled from
				 * the persitant storage with NM_SETTINGS_CONNECTION_PERSIST_MODE_IN_MEMORY_DETACHED.
				 * We need to take over this storage again... */
				break;
			}
		}
	}

	if (   shadowed_storage
	    && !new_in_memory) {
		NMSettingsStorage *conflicting_storage;

		conflicting_storage = _sett_conn_entry_storage_find_conflicting_storage (sett_conn_entry,
		                                                                         nm_settings_storage_get_plugin (shadowed_storage),
		                                                                         shadowed_storage,
		                                                                         priv->plugins);
		if (conflicting_storage) {
			/* We cannot add the profile as @shadowed_storage, because there is another, existing storage
			 * that would hide it. Just add it as new storage. In general, this leads to duplication of profiles,
			 * but the circumstances where this happens are very exotic (you need at least one additional settings
			 * plugin, then going through the paths of making shadowed_storage in-memory-detached and delete it,
			 * and finally adding the conflicting storage outside of NM and restart/reload). */
			_LOGT ("ignore shadowed storage "NM_SETTINGS_STORAGE_PRINT_FMT" due to conflicting storage "NM_SETTINGS_STORAGE_PRINT_FMT,
			       NM_SETTINGS_STORAGE_PRINT_ARG (shadowed_storage),
			       NM_SETTINGS_STORAGE_PRINT_ARG (conflicting_storage));
		} else
			update_storage = shadowed_storage;
	}

	shadowed_storage_filename =   (   shadowed_storage
	                               && !update_storage)
	                            ? nm_settings_storage_get_filename_for_shadowed_storage (shadowed_storage)
	                            : NULL;

again_add_connection:

	if (!update_storage) {
		success = _add_connection_to_first_plugin (self,
		                                           sett_conn_entry,
		                                           connection,
		                                           new_in_memory,
		                                           sett_flags,
		                                           shadowed_storage_filename,
		                                           FALSE,
		                                           &new_storage,
		                                           &new_connection,
		                                           &local);
	} else {
		success = _update_connection_to_plugin (self,
		                                        update_storage,
		                                        connection,
		                                        sett_flags,
		                                        FALSE,
		                                        shadowed_storage_filename,
		                                        FALSE,
		                                        &new_storage,
		                                        &new_connection,
		                                        &local);
		if (!success) {
			if (!NMS_IS_KEYFILE_STORAGE (update_storage)) {
				/* hm, the intended storage is not keyfile (it's ifcfg-rh). This settings
				 * plugin may not support the new connection. So step back and retry adding
				 * the profile anew. */
				_LOGT ("failure to add profile as existing storage \"%s\": %s",
				       nm_settings_storage_get_filename (update_storage),
				       local->message);
				update_storage = NULL;
				g_clear_object (&shadowed_storage);
				shadowed_storage_filename = NULL;
				g_clear_error (&local);
				goto again_add_connection;
			}
		}
	}

	if (!success) {
		if (!update_storage) {
			g_set_error (error,
			             NM_SETTINGS_ERROR,
			             NM_SETTINGS_ERROR_FAILED,
			             "failure adding connection: %s",
			             local->message);
		} else {
			g_set_error (error,
			             NM_SETTINGS_ERROR,
			             NM_SETTINGS_ERROR_FAILED,
			             "failure writing connection to existing storage \"%s\": %s",
			             nm_settings_storage_get_filename (update_storage),
			             local->message);
		}
		return FALSE;
	}

	sett_conn_entry = _connection_changed_track (self, new_storage, new_connection, TRUE);

	c_list_for_each_entry (sd, &sett_conn_entry->sd_lst_head, sd_lst) {
		const NMSettingsMetaData *meta_data;
		gs_unref_object NMSettingsStorage *new_tombstone_storage = NULL;
		gboolean in_memory;
		gboolean simulate;

		meta_data = nm_settings_storage_is_meta_data_alive (sd->storage);
		if (   !meta_data
		    || !meta_data->is_tombstone)
			continue;

		if (nm_settings_storage_is_keyfile_run (sd->storage))
			in_memory = TRUE;
		else {
			if (nm_settings_storage_is_keyfile_run (new_storage)) {
				/* Don't remove the file from /etc if we just wrote an in-memory connection */
				continue;
			}
			in_memory = FALSE;
		}

		simulate = FALSE;
again_delete_tombstone:
		if (!nms_keyfile_plugin_set_nmmeta_tombstone (priv->keyfile_plugin,
		                                              simulate,
		                                              uuid,
		                                              in_memory,
		                                              FALSE,
		                                              NULL,
		                                              &new_tombstone_storage,
		                                              NULL)) {
			/* Ups, something went wrong. We really need to get rid of the tombstone. At least
			 * forget about it in-memory. Upong next restart/reload, this might be reverted
			 * however :( .*/
			if (!simulate) {
				simulate = TRUE;
				goto again_delete_tombstone;
			}
		}
		if (new_tombstone_storage)
			_connection_changed_track (self, new_tombstone_storage, NULL, FALSE);
	}

	_connection_changed_process_all_dirty (self,
	                                       FALSE,
	                                       sett_flags,
	                                       _NM_SETTINGS_CONNECTION_INT_FLAGS_PERSISTENT_MASK,
	                                       FALSE,
	                                         NM_SETTINGS_CONNECTION_UPDATE_REASON_RESET_SYSTEM_SECRETS
	                                       | NM_SETTINGS_CONNECTION_UPDATE_REASON_RESET_AGENT_SECRETS
	                                       | (  NM_FLAGS_HAS (add_reason, NM_SETTINGS_CONNECTION_ADD_REASON_BLOCK_AUTOCONNECT)
	                                          ? NM_SETTINGS_CONNECTION_UPDATE_REASON_BLOCK_AUTOCONNECT
	                                          : NM_SETTINGS_CONNECTION_UPDATE_REASON_NONE));

	nm_assert (sett_conn_entry == _sett_conn_entries_get (self, sett_conn_entry->uuid));
	nm_assert (NM_IS_SETTINGS_CONNECTION (sett_conn_entry->sett_conn));

	NM_SET_OUT (out_sett_conn, _sett_conn_entry_get_conn (sett_conn_entry));
	return TRUE;
}

/*****************************************************************************/

gboolean
nm_settings_update_connection (NMSettings *self,
                               NMSettingsConnection *sett_conn,
                               NMConnection *connection,
                               NMSettingsConnectionPersistMode persist_mode,
                               NMSettingsConnectionIntFlags sett_flags,
                               NMSettingsConnectionIntFlags sett_mask,
                               NMSettingsConnectionUpdateReason update_reason,
                               const char *log_context_name,
                               GError **error)
{
	gs_unref_object NMConnection *connection_cloned_1 = NULL;
	gs_unref_object NMConnection *new_connection_cloned = NULL;
	gs_unref_object NMConnection *new_connection = NULL;
	NMConnection *new_connection_real;
	gs_unref_object NMSettingsStorage *cur_storage = NULL;
	gs_unref_object NMSettingsStorage *new_storage = NULL;
	NMSettingsStorage *drop_storage = NULL;
	SettConnEntry *sett_conn_entry;
	gboolean cur_in_memory;
	gboolean new_in_memory;
	const char *uuid;
	gboolean tombstone_in_memory = FALSE;
	gboolean tombstone_on_disk = FALSE;

	g_return_val_if_fail (NM_IS_SETTINGS (self), FALSE);
	g_return_val_if_fail (NM_IS_SETTINGS_CONNECTION (sett_conn), FALSE);
	g_return_val_if_fail (!connection || NM_IS_CONNECTION (connection), FALSE);

	nm_assert (!NM_FLAGS_ANY (sett_mask, ~_NM_SETTINGS_CONNECTION_INT_FLAGS_PERSISTENT_MASK));
	nm_assert (!NM_FLAGS_ANY (sett_flags, ~sett_mask));
	nm_assert (NM_IN_SET (persist_mode, NM_SETTINGS_CONNECTION_PERSIST_MODE_KEEP,
	                                    NM_SETTINGS_CONNECTION_PERSIST_MODE_NO_PERSIST,
	                                    NM_SETTINGS_CONNECTION_PERSIST_MODE_TO_DISK,
	                                    NM_SETTINGS_CONNECTION_PERSIST_MODE_IN_MEMORY,
	                                    NM_SETTINGS_CONNECTION_PERSIST_MODE_IN_MEMORY_DETACHED,
	                                    NM_SETTINGS_CONNECTION_PERSIST_MODE_IN_MEMORY_ONLY));

	cur_storage = g_object_ref (nm_settings_connection_get_storage (sett_conn));

	uuid = nm_settings_storage_get_uuid (cur_storage);

	nm_assert (NM_IS_SETTINGS_STORAGE (cur_storage));

	sett_conn_entry = _sett_conn_entries_get (self, uuid);

	nm_assert (_sett_conn_entry_get_conn (sett_conn_entry) == sett_conn);

	if (connection) {
		gs_free_error GError *local = NULL;

		if (!_nm_connection_ensure_normalized (connection,
		                                       FALSE,
		                                       uuid,
		                                       TRUE,
		                                       &connection_cloned_1,
		                                       &local)) {
			_LOGT ("update[%s]: %s: failed because profile is invalid: %s",
			       nm_settings_storage_get_uuid (cur_storage),
			       log_context_name,
			       local->message);
			g_set_error (error,
			             NM_SETTINGS_ERROR,
			             NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "connection is invalid: %s",
			             local->message);
			return FALSE;
		}
		if (connection_cloned_1)
			connection = connection_cloned_1;
	} else
		connection = nm_settings_connection_get_connection (sett_conn);

	cur_in_memory = nm_settings_storage_is_keyfile_run (cur_storage);

	if (persist_mode == NM_SETTINGS_CONNECTION_PERSIST_MODE_KEEP) {
		persist_mode =   cur_in_memory
		               ? NM_SETTINGS_CONNECTION_PERSIST_MODE_IN_MEMORY
		               : NM_SETTINGS_CONNECTION_PERSIST_MODE_TO_DISK;
	}

	if (   NM_FLAGS_HAS (sett_mask, NM_SETTINGS_CONNECTION_INT_FLAGS_NM_GENERATED)
	    && !NM_FLAGS_HAS (sett_flags, NM_SETTINGS_CONNECTION_INT_FLAGS_NM_GENERATED)) {
		NMDevice *device;

		/* The connection has been changed by the user, it should no longer be
		 * considered a default wired connection, and should no longer affect
		 * the no-auto-default configuration option.
		 */
		device = nm_settings_connection_default_wired_get_device (sett_conn);
		if (device) {
			nm_assert (cur_in_memory);
			nm_assert (!NM_FLAGS_ANY (nm_settings_connection_get_flags (sett_conn),
			                            NM_SETTINGS_CONNECTION_INT_FLAGS_NM_GENERATED
			                          | NM_SETTINGS_CONNECTION_INT_FLAGS_VOLATILE));

			default_wired_clear_tag (self, device, sett_conn, FALSE);

			if (NM_IN_SET (persist_mode, NM_SETTINGS_CONNECTION_PERSIST_MODE_NO_PERSIST)) {
				/* making a default-wired-connection a regular connection implies persisting
				 * it to disk (unless specified differently).
				 *
				 * Actually, this line is probably unreached, because we should not use
				 * NM_SETTINGS_CONNECTION_PERSIST_MODE_NO_PERSIST to toggle the nm-generated
				 * flag. */
				nm_assert_not_reached ();
				persist_mode = NM_SETTINGS_CONNECTION_PERSIST_MODE_TO_DISK;
			}
		}
	}

	if (   persist_mode == NM_SETTINGS_CONNECTION_PERSIST_MODE_NO_PERSIST
	    && NM_FLAGS_ANY (sett_mask,   NM_SETTINGS_CONNECTION_INT_FLAGS_NM_GENERATED
	                                | NM_SETTINGS_CONNECTION_INT_FLAGS_VOLATILE)
	    && NM_FLAGS_ANY ((sett_flags ^ nm_settings_connection_get_flags (sett_conn)) & sett_mask,
	                       NM_SETTINGS_CONNECTION_INT_FLAGS_NM_GENERATED
	                     | NM_SETTINGS_CONNECTION_INT_FLAGS_VOLATILE)) {
		/* we update the nm-generated/volatile setting of a profile (which is inherrently
		 * in-memory. The caller did not request to persist this to disk, however we need
		 * to store the flags in run. */
		nm_assert (cur_in_memory);
		persist_mode = NM_SETTINGS_CONNECTION_PERSIST_MODE_IN_MEMORY;
	}

	if (persist_mode == NM_SETTINGS_CONNECTION_PERSIST_MODE_TO_DISK)
		new_in_memory = FALSE;
	else if (NM_IN_SET (persist_mode, NM_SETTINGS_CONNECTION_PERSIST_MODE_IN_MEMORY,
	                                  NM_SETTINGS_CONNECTION_PERSIST_MODE_IN_MEMORY_DETACHED,
	                                  NM_SETTINGS_CONNECTION_PERSIST_MODE_IN_MEMORY_ONLY))
		new_in_memory = TRUE;
	else {
		nm_assert (persist_mode == NM_SETTINGS_CONNECTION_PERSIST_MODE_NO_PERSIST);
		new_in_memory = cur_in_memory;
	}

	if (!new_in_memory) {
		/* Persistent connections cannot be volatile nor nm-generated.
		 *
		 * That is obviously true for volatile, as it is enforced by Update2() API.
		 *
		 * For nm-generated profiles also, because the nm-generated flag is only stored
		 * for in-memory profiles. If we would persist the profile to /etc it would loose
		 * the nm-generated flag after restart/reload, and that cannot be right. If a profile
		 * ends up on disk, the information who created it gets lost. */
		nm_assert (!NM_FLAGS_ANY (sett_flags,   NM_SETTINGS_CONNECTION_INT_FLAGS_NM_GENERATED
		                                      | NM_SETTINGS_CONNECTION_INT_FLAGS_VOLATILE));
		sett_mask |=   NM_SETTINGS_CONNECTION_INT_FLAGS_NM_GENERATED
		             | NM_SETTINGS_CONNECTION_INT_FLAGS_VOLATILE;
		sett_flags &= ~(  NM_SETTINGS_CONNECTION_INT_FLAGS_NM_GENERATED
		                | NM_SETTINGS_CONNECTION_INT_FLAGS_VOLATILE);
	}

	if (persist_mode == NM_SETTINGS_CONNECTION_PERSIST_MODE_NO_PERSIST) {
		new_storage = g_object_ref (cur_storage);
		new_connection_real = connection;
		_LOGT ("update[%s]: %s: update profile \"%s\" (not persisted)",
		       nm_settings_storage_get_uuid (cur_storage),
		       log_context_name,
		       nm_connection_get_id (connection));
	} else {
		NMSettingsStorage *shadowed_storage;
		const char *cur_shadowed_storage_filename;
		const char *new_shadowed_storage_filename = NULL;
		gboolean cur_shadowed_owned;
		gboolean new_shadowed_owned = FALSE;
		NMSettingsStorage *update_storage = NULL;
		gs_free_error GError *local = NULL;
		gboolean success;

		cur_shadowed_storage_filename = nm_settings_storage_get_shadowed_storage (cur_storage, &cur_shadowed_owned);

		shadowed_storage = _sett_conn_entry_find_shadowed_storage (sett_conn_entry, cur_shadowed_storage_filename, cur_storage);
		if (!shadowed_storage) {
			cur_shadowed_storage_filename = NULL;
			cur_shadowed_owned = FALSE;
		}

		if (   new_in_memory
		    && persist_mode == NM_SETTINGS_CONNECTION_PERSIST_MODE_IN_MEMORY_ONLY) {
			if (cur_in_memory) {
				drop_storage = shadowed_storage;
				update_storage = cur_storage;
			} else
				drop_storage = cur_storage;
		} else if (   !new_in_memory
		           && cur_in_memory
		           && shadowed_storage) {
			drop_storage = cur_storage;
			update_storage = shadowed_storage;
		} else if (new_in_memory != cur_in_memory) {
			if (!new_in_memory)
				drop_storage = cur_storage;
			else if (persist_mode == NM_SETTINGS_CONNECTION_PERSIST_MODE_IN_MEMORY_ONLY)
				drop_storage = cur_storage;
			else {
				nm_assert (NM_IN_SET (persist_mode, NM_SETTINGS_CONNECTION_PERSIST_MODE_IN_MEMORY,
				                                    NM_SETTINGS_CONNECTION_PERSIST_MODE_IN_MEMORY_DETACHED));
			}
		} else if (nm_settings_storage_is_keyfile_lib (cur_storage)) {
			/* the profile is a keyfile in /usr/lib. It cannot be overwritten, we must migrate it
			 * from /usr/lib to /etc. */
		} else
			update_storage = cur_storage;

		if (new_in_memory) {
			if (persist_mode == NM_SETTINGS_CONNECTION_PERSIST_MODE_IN_MEMORY_ONLY) {
				/* pass */
			} else if (!cur_in_memory) {
				new_shadowed_storage_filename = nm_settings_storage_get_filename_for_shadowed_storage (cur_storage);
				if (   new_shadowed_storage_filename
				    && persist_mode != NM_SETTINGS_CONNECTION_PERSIST_MODE_IN_MEMORY_DETACHED)
					new_shadowed_owned = TRUE;
			} else {
				new_shadowed_storage_filename = cur_shadowed_storage_filename;
				if (   new_shadowed_storage_filename
				    && persist_mode == NM_SETTINGS_CONNECTION_PERSIST_MODE_IN_MEMORY)
					new_shadowed_owned = TRUE;
			}
		}

		if (!update_storage) {
			success = _add_connection_to_first_plugin (self,
			                                           sett_conn_entry,
			                                           connection,
			                                           new_in_memory,
			                                           sett_flags,
			                                           new_shadowed_storage_filename,
			                                           new_shadowed_owned,
			                                           &new_storage,
			                                           &new_connection,
			                                           &local);
		} else {
			success = _update_connection_to_plugin (self,
			                                        update_storage,
			                                        connection,
			                                        sett_flags,
			                                        update_reason,
			                                        new_shadowed_storage_filename,
			                                        new_shadowed_owned,
			                                        &new_storage,
			                                        &new_connection,
			                                        &local);
		}
		if (!success) {
			gboolean ignore_failure;

			ignore_failure = NM_FLAGS_ANY (update_reason, NM_SETTINGS_CONNECTION_UPDATE_REASON_IGNORE_PERSIST_FAILURE);

			_LOGT ("update[%s]: %s: %sfailure to %s connection \"%s\" on storage: %s",
			       nm_settings_storage_get_uuid (cur_storage),
			       log_context_name,
			       ignore_failure ? "ignore " : "",
			       update_storage ? "update" : "write",
			       nm_connection_get_id (connection),
			       local->message);
			if (!ignore_failure) {
				g_set_error (error,
				             NM_SETTINGS_ERROR,
				             NM_SETTINGS_ERROR_INVALID_CONNECTION,
				             "failed to %s connection: %s",
				             update_storage ? "update" : "write",
				             local->message);
				return FALSE;
			}

			new_storage = g_object_ref (cur_storage);
			new_connection_real = connection;
		} else {
			gs_unref_variant GVariant *agent_owned_secrets = NULL;

			_LOGT ("update[%s]: %s: %s profile \"%s\"",
			       nm_settings_storage_get_uuid (cur_storage),
			       log_context_name,
			       update_storage ? "update" : "write",
			       nm_connection_get_id (connection));

			nm_assert_valid_settings_storage (NULL, new_storage);
			nm_assert (NM_IS_CONNECTION (new_connection));
			nm_assert (nm_streq (uuid, nm_settings_storage_get_uuid (new_storage)));


			agent_owned_secrets = nm_connection_to_dbus (connection,
			                                               NM_CONNECTION_SERIALIZE_ONLY_SECRETS
			                                             | NM_CONNECTION_SERIALIZE_WITH_SECRETS_AGENT_OWNED);
			new_connection_real = _connection_changed_normalize_connection (new_storage,
			                                                                new_connection,
			                                                                agent_owned_secrets,
			                                                                &new_connection_cloned);
			if (!new_connection_real) {
				nm_assert_not_reached ();
				new_connection_real = new_connection;
			}
		}
	}

	nm_assert (NM_IS_SETTINGS_STORAGE (new_storage));
	nm_assert (NM_IS_CONNECTION (new_connection_real));

	_connection_changed_track (self, new_storage, new_connection_real, TRUE);

	if (   drop_storage
	    && drop_storage != new_storage) {
		gs_free_error GError *local = NULL;

		if (!nm_settings_plugin_delete_connection (nm_settings_storage_get_plugin (drop_storage),
		                                           drop_storage,
		                                           &local)) {
			const char *filename;

			filename = nm_settings_storage_get_filename (drop_storage);
			_LOGT ("update[%s]: failed to delete moved storage "NM_SETTINGS_STORAGE_PRINT_FMT"%s%s%s: %s",
			       nm_settings_storage_get_uuid (drop_storage),
			       NM_SETTINGS_STORAGE_PRINT_ARG (drop_storage),
			       NM_PRINT_FMT_QUOTED (filename, " (file \"", filename, "\")", ""),
			       local->message);
			/* there is no aborting back form this. We must get rid of the connection and
			 * cannot do better than log a message. Proceed, but remember to write tombstones. */
			if (nm_settings_storage_is_keyfile_run (cur_storage))
				tombstone_in_memory = TRUE;
			else
				tombstone_on_disk = TRUE;
		} else
			_connection_changed_track (self, drop_storage, NULL, FALSE);
	}

	_set_nmmeta_tombstone (self,
	                       uuid,
	                       tombstone_on_disk,
	                       tombstone_in_memory,
	                       NULL);

	_connection_changed_process_all_dirty (self,
	                                       FALSE,
	                                       sett_flags,
	                                       sett_mask,
	                                       FALSE,
	                                       update_reason);

	return TRUE;
}

void
nm_settings_delete_connection (NMSettings *self,
                               NMSettingsConnection *sett_conn,
                               gboolean allow_add_to_no_auto_default)
{
	NMSettingsStorage *cur_storage;
	NMSettingsStorage *shadowed_storage;
	NMSettingsStorage *shadowed_storage_unowned = NULL;
	NMSettingsStorage *drop_storages[2] = { };
	gs_free_error GError *local = NULL;
	SettConnEntry *sett_conn_entry;
	const char *cur_shadowed_storage_filename;
	const char *new_shadowed_storage_filename = NULL;
	gboolean cur_shadowed_owned;
	const char *uuid;
	gboolean tombstone_in_memory = FALSE;
	gboolean tombstone_on_disk = FALSE;
	int i;

	g_return_if_fail (NM_IS_SETTINGS (self));
	g_return_if_fail (NM_IS_SETTINGS_CONNECTION (sett_conn));
	g_return_if_fail (nm_settings_has_connection (self, sett_conn));

	cur_storage = nm_settings_connection_get_storage (sett_conn);

	nm_assert (NM_IS_SETTINGS_STORAGE (cur_storage));

	uuid = nm_settings_storage_get_uuid (cur_storage);
	nm_assert (nm_utils_is_uuid (uuid));

	sett_conn_entry = _sett_conn_entries_get (self, uuid);

	g_return_if_fail (sett_conn_entry);
	nm_assert (sett_conn_entry->sett_conn == sett_conn);
	g_return_if_fail (sett_conn_entry->storage == cur_storage);

	if (NMS_IS_KEYFILE_STORAGE (cur_storage)) {
		NMSKeyfileStorage *s = NMS_KEYFILE_STORAGE (cur_storage);

		if (NM_IN_SET (s->storage_type, NMS_KEYFILE_STORAGE_TYPE_RUN,
		                                NMS_KEYFILE_STORAGE_TYPE_ETC))
			drop_storages[0] = cur_storage;
		else
			tombstone_on_disk = TRUE;
	} else
		drop_storages[0] = cur_storage;

	cur_shadowed_storage_filename = nm_settings_storage_get_shadowed_storage (cur_storage, &cur_shadowed_owned);

	shadowed_storage = _sett_conn_entry_find_shadowed_storage (sett_conn_entry, cur_shadowed_storage_filename, cur_storage);
	if (shadowed_storage) {
		if (!cur_shadowed_owned)
			shadowed_storage_unowned = g_steal_pointer (&shadowed_storage);
	}
	drop_storages[1] = shadowed_storage;

	for (i = 0; i < (int) G_N_ELEMENTS (drop_storages); i++) {
		NMSettingsStorage *storage;
		StorageData *sd;

		storage = drop_storages[i];
		if (!storage)
			continue;

		if (!nm_settings_plugin_delete_connection (nm_settings_storage_get_plugin (storage),
		                                           storage,
		                                           &local)) {
			_LOGT ("delete-connection: failed to delete storage "NM_SETTINGS_STORAGE_PRINT_FMT": %s",
			       NM_SETTINGS_STORAGE_PRINT_ARG (storage),
			       local->message);
			g_clear_error (&local);
			/* there is no aborting back form this. We must get rid of the connection and
			 * cannot do better than log a message. Proceed, but remember to write tombstones. */
			if (nm_settings_storage_is_keyfile_run (cur_storage))
				tombstone_in_memory = TRUE;
			else
				tombstone_on_disk = TRUE;
			sett_conn_entry = _sett_conn_entries_get (self, uuid);
		} else
			sett_conn_entry = _connection_changed_track (self, storage, NULL, FALSE);

		c_list_for_each_entry (sd, &sett_conn_entry->sd_lst_head, sd_lst) {
			if (NM_IN_SET (sd->storage, drop_storages[0],
			                            drop_storages[1]))
				continue;
			if (!_storage_data_is_alive (sd))
				continue;
			if (nm_settings_storage_is_meta_data (sd->storage))
				continue;

			if (sd->storage == shadowed_storage_unowned) {
				/* this only happens if we leak a profile on disk after NM_SETTINGS_CONNECTION_PERSIST_MODE_IN_MEMORY_DETACHED.
				 * We need to write a tombstone and remember the shadowed-storage. */
				tombstone_in_memory = TRUE;
				new_shadowed_storage_filename = nm_settings_storage_get_filename (shadowed_storage_unowned);
				continue;
			}

			/* we have still conflicting storages. We need to hide them with tombstones. */
			if (nm_settings_storage_is_keyfile_run (sd->storage)) {
				tombstone_in_memory = TRUE;
				continue;
			}
			tombstone_on_disk = TRUE;
		}
	}

	_set_nmmeta_tombstone (self,
	                       uuid,
	                       tombstone_on_disk,
	                       tombstone_in_memory,
	                       new_shadowed_storage_filename);

	_connection_changed_process_all_dirty (self,
	                                       allow_add_to_no_auto_default,
	                                       NM_SETTINGS_CONNECTION_INT_FLAGS_NONE,
	                                       NM_SETTINGS_CONNECTION_INT_FLAGS_NONE,
	                                       FALSE,
	                                       NM_SETTINGS_CONNECTION_UPDATE_REASON_NONE);
}

/*****************************************************************************/

static void
send_agent_owned_secrets (NMSettings *self,
                          NMSettingsConnection *sett_conn,
                          NMAuthSubject *subject)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	gs_unref_object NMConnection *for_agent = NULL;

	/* Dupe the connection so we can clear out non-agent-owned secrets,
	 * as agent-owned secrets are the only ones we send back to be saved.
	 * Only send secrets to agents of the same UID that called update too.
	 */
	for_agent = nm_simple_connection_new_clone (nm_settings_connection_get_connection (sett_conn));
	_nm_connection_clear_secrets_by_secret_flags (for_agent,
	                                              NM_SETTING_SECRET_FLAG_AGENT_OWNED);
	nm_agent_manager_save_secrets (priv->agent_mgr,
	                               nm_dbus_object_get_path (NM_DBUS_OBJECT (sett_conn)),
	                               for_agent,
	                               subject);
}

static void
pk_add_cb (NMAuthChain *chain,
           GDBusMethodInvocation *context,
           gpointer user_data)
{
	NMSettings *self = NM_SETTINGS (user_data);
	NMAuthCallResult result;
	gs_free_error GError *error = NULL;
	NMConnection *connection = NULL;
	gs_unref_object NMSettingsConnection *added = NULL;
	NMSettingsAddCallback callback;
	gpointer callback_data;
	NMAuthSubject *subject;
	const char *perm;

	nm_assert (G_IS_DBUS_METHOD_INVOCATION (context));

	c_list_unlink (nm_auth_chain_parent_lst_list (chain));

	perm = nm_auth_chain_get_data (chain, "perm");
	nm_assert (perm);

	result = nm_auth_chain_get_result (chain, perm);

	if (result != NM_AUTH_CALL_RESULT_YES) {
		error = g_error_new_literal (NM_SETTINGS_ERROR,
		                             NM_SETTINGS_ERROR_PERMISSION_DENIED,
		                             "Insufficient privileges.");
	} else {
		/* Authorized */
		connection = nm_auth_chain_get_data (chain, "connection");
		nm_assert (NM_IS_CONNECTION (connection));

		nm_settings_add_connection (self,
		                            connection,
		                            GPOINTER_TO_UINT (nm_auth_chain_get_data (chain, "persist-mode")),
		                            GPOINTER_TO_UINT (nm_auth_chain_get_data (chain, "add-reason")),
		                            GPOINTER_TO_UINT (nm_auth_chain_get_data (chain, "sett-flags")),
		                            &added,
		                            &error);

		/* The callback may remove the connection from the settings manager (e.g.
		 * because it's found to be incompatible with the device on AddAndActivate).
		 * But we need to keep it alive for a bit longer, precisely to check wehther
		 * it's still known to the setting manager. */
		nm_g_object_ref (added);
	}

	callback = nm_auth_chain_get_data (chain, "callback");
	callback_data = nm_auth_chain_get_data (chain, "callback-data");
	subject = nm_auth_chain_get_data (chain, "subject");

	callback (self, added, error, context, subject, callback_data);

	/* Send agent-owned secrets to the agents */
	if (   added
	    && nm_settings_has_connection (self, added))
		send_agent_owned_secrets (self, added, subject);
}

void
nm_settings_add_connection_dbus (NMSettings *self,
                                 NMConnection *connection,
                                 NMSettingsConnectionPersistMode persist_mode,
                                 NMSettingsConnectionAddReason add_reason,
                                 NMSettingsConnectionIntFlags sett_flags,
                                 NMAuthSubject *subject,
                                 GDBusMethodInvocation *context,
                                 NMSettingsAddCallback callback,
                                 gpointer user_data)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	NMSettingConnection *s_con;
	NMAuthChain *chain;
	GError *error = NULL, *tmp_error = NULL;
	const char *perm;

	g_return_if_fail (NM_IS_CONNECTION (connection));
	g_return_if_fail (NM_IS_AUTH_SUBJECT (subject));
	g_return_if_fail (G_IS_DBUS_METHOD_INVOCATION (context));

	nm_assert (!NM_FLAGS_ANY (sett_flags, ~_NM_SETTINGS_CONNECTION_INT_FLAGS_PERSISTENT_MASK));

	/* Connection must be valid, of course */
	if (_nm_connection_verify (connection, &tmp_error) != NM_SETTING_VERIFY_SUCCESS) {
		error = g_error_new (NM_SETTINGS_ERROR,
		                     NM_SETTINGS_ERROR_INVALID_CONNECTION,
		                     "The connection was invalid: %s",
		                     tmp_error->message);
		g_error_free (tmp_error);
		goto done;
	}

	/* FIXME: The kernel doesn't support Ad-Hoc WPA connections well at this time,
	 * and turns them into open networks.  It's been this way since at least
	 * 2.6.30 or so; until that's fixed, disable WPA-protected Ad-Hoc networks.
	 */
	if (nm_utils_connection_is_adhoc_wpa (connection)) {
		error = g_error_new_literal (NM_SETTINGS_ERROR,
		                             NM_SETTINGS_ERROR_INVALID_CONNECTION,
		                             "WPA Ad-Hoc disabled due to kernel bugs");
		goto done;
	}

	if (!nm_auth_is_subject_in_acl_set_error (connection,
	                                          subject,
	                                          NM_SETTINGS_ERROR,
	                                          NM_SETTINGS_ERROR_PERMISSION_DENIED,
	                                          &error))
		goto done;

	/* If the caller is the only user in the connection's permissions, then
	 * we use the 'modify.own' permission instead of 'modify.system'.  If the
	 * request affects more than just the caller, require 'modify.system'.
	 */
	s_con = nm_connection_get_setting_connection (connection);
	nm_assert (s_con);
	if (nm_setting_connection_get_num_permissions (s_con) == 1)
		perm = NM_AUTH_PERMISSION_SETTINGS_MODIFY_OWN;
	else
		perm = NM_AUTH_PERMISSION_SETTINGS_MODIFY_SYSTEM;

	/* Validate the user request */
	chain = nm_auth_chain_new_subject (subject, context, pk_add_cb, self);
	if (!chain) {
		error = g_error_new_literal (NM_SETTINGS_ERROR,
		                             NM_SETTINGS_ERROR_PERMISSION_DENIED,
		                             "Unable to authenticate the request.");
		goto done;
	}

	c_list_link_tail (&priv->auth_lst_head, nm_auth_chain_parent_lst_list (chain));

	nm_auth_chain_set_data (chain, "perm", (gpointer) perm, NULL);
	nm_auth_chain_set_data (chain, "connection", g_object_ref (connection), g_object_unref);
	nm_auth_chain_set_data (chain, "callback", callback, NULL);
	nm_auth_chain_set_data (chain, "callback-data", user_data, NULL);
	nm_auth_chain_set_data (chain, "subject", g_object_ref (subject), g_object_unref);
	nm_auth_chain_set_data (chain, "persist-mode", GUINT_TO_POINTER (persist_mode), NULL);
	nm_auth_chain_set_data (chain, "add-reason", GUINT_TO_POINTER (add_reason), NULL);
	nm_auth_chain_set_data (chain, "sett-flags", GUINT_TO_POINTER (sett_flags), NULL);
	nm_auth_chain_add_call_unsafe (chain, perm, TRUE);
	return;

done:
	nm_assert (error);
	callback (self, NULL, error, context, subject, user_data);
	g_error_free (error);
}

static void
settings_add_connection_add_cb (NMSettings *self,
                                NMSettingsConnection *connection,
                                GError *error,
                                GDBusMethodInvocation *context,
                                NMAuthSubject *subject,
                                gpointer user_data)
{
	gboolean is_add_connection_2 = GPOINTER_TO_INT (user_data);

	if (error) {
		g_dbus_method_invocation_return_gerror (context, error);
		nm_audit_log_connection_op (NM_AUDIT_OP_CONN_ADD, NULL, FALSE, NULL, subject, error->message);
		return;
	}

	if (is_add_connection_2) {
		GVariantBuilder builder;

		g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);
		g_dbus_method_invocation_return_value (context,
		                                       g_variant_new ("(oa{sv})",
		                                                      nm_dbus_object_get_path (NM_DBUS_OBJECT (connection)),
		                                                      &builder));
	} else {
		g_dbus_method_invocation_return_value (context,
		                                       g_variant_new ("(o)",
		                                                      nm_dbus_object_get_path (NM_DBUS_OBJECT (connection))));
	}
	nm_audit_log_connection_op (NM_AUDIT_OP_CONN_ADD, connection, TRUE, NULL,
	                            subject, NULL);
}

static void
settings_add_connection_helper (NMSettings *self,
                                GDBusMethodInvocation *context,
                                gboolean is_add_connection_2,
                                GVariant *settings,
                                NMSettingsAddConnection2Flags flags)
{
	gs_unref_object NMConnection *connection = NULL;
	GError *error = NULL;
	gs_unref_object NMAuthSubject *subject = NULL;
	NMSettingsConnectionPersistMode persist_mode;

	connection = _nm_simple_connection_new_from_dbus (settings,
	                                                    NM_SETTING_PARSE_FLAGS_STRICT
	                                                  | NM_SETTING_PARSE_FLAGS_NORMALIZE,
	                                                  &error);

	if (   !connection
	    || !nm_connection_verify_secrets (connection, &error)) {
		g_dbus_method_invocation_take_error (context, error);
		return;
	}

	subject = nm_auth_subject_new_unix_process_from_context (context);
	if (!subject) {
		g_dbus_method_invocation_return_error_literal (context,
		                                               NM_SETTINGS_ERROR,
		                                               NM_SETTINGS_ERROR_PERMISSION_DENIED,
		                                               "Unable to determine UID of request.");
		return;
	}

	if (NM_FLAGS_HAS (flags, NM_SETTINGS_ADD_CONNECTION2_FLAG_TO_DISK))
		persist_mode = NM_SETTINGS_CONNECTION_PERSIST_MODE_TO_DISK;
	else {
		nm_assert (NM_FLAGS_HAS (flags, NM_SETTINGS_ADD_CONNECTION2_FLAG_IN_MEMORY));
		persist_mode = NM_SETTINGS_CONNECTION_PERSIST_MODE_IN_MEMORY_ONLY;
	}

	nm_settings_add_connection_dbus (self,
	                                 connection,
	                                 persist_mode,
	                                   NM_FLAGS_HAS (flags, NM_SETTINGS_ADD_CONNECTION2_FLAG_BLOCK_AUTOCONNECT)
	                                 ? NM_SETTINGS_CONNECTION_ADD_REASON_BLOCK_AUTOCONNECT
	                                 : NM_SETTINGS_CONNECTION_ADD_REASON_NONE,
	                                 NM_SETTINGS_CONNECTION_INT_FLAGS_NONE,
	                                 subject,
	                                 context,
	                                 settings_add_connection_add_cb,
	                                 GINT_TO_POINTER (!!is_add_connection_2));
}

static void
impl_settings_add_connection (NMDBusObject *obj,
                              const NMDBusInterfaceInfoExtended *interface_info,
                              const NMDBusMethodInfoExtended *method_info,
                              GDBusConnection *connection,
                              const char *sender,
                              GDBusMethodInvocation *invocation,
                              GVariant *parameters)
{
	NMSettings *self = NM_SETTINGS (obj);
	gs_unref_variant GVariant *settings = NULL;

	g_variant_get (parameters, "(@a{sa{sv}})", &settings);
	settings_add_connection_helper (self, invocation, FALSE, settings, NM_SETTINGS_ADD_CONNECTION2_FLAG_TO_DISK);
}

static void
impl_settings_add_connection_unsaved (NMDBusObject *obj,
                                      const NMDBusInterfaceInfoExtended *interface_info,
                                      const NMDBusMethodInfoExtended *method_info,
                                      GDBusConnection *connection,
                                      const char *sender,
                                      GDBusMethodInvocation *invocation,
                                      GVariant *parameters)
{
	NMSettings *self = NM_SETTINGS (obj);
	gs_unref_variant GVariant *settings = NULL;

	g_variant_get (parameters, "(@a{sa{sv}})", &settings);
	settings_add_connection_helper (self, invocation, FALSE, settings, NM_SETTINGS_ADD_CONNECTION2_FLAG_IN_MEMORY);
}

static void
impl_settings_add_connection2 (NMDBusObject *obj,
                               const NMDBusInterfaceInfoExtended *interface_info,
                               const NMDBusMethodInfoExtended *method_info,
                               GDBusConnection *connection,
                               const char *sender,
                               GDBusMethodInvocation *invocation,
                               GVariant *parameters)
{
	NMSettings *self = NM_SETTINGS (obj);
	gs_unref_variant GVariant *settings = NULL;
	gs_unref_variant GVariant *args = NULL;
	NMSettingsAddConnection2Flags flags;
	const char *args_name;
	GVariantIter iter;
	guint32 flags_u;

	g_variant_get (parameters, "(@a{sa{sv}}u@a{sv})", &settings, &flags_u, &args);

	if (NM_FLAGS_ANY (flags_u, ~((guint32) (  NM_SETTINGS_ADD_CONNECTION2_FLAG_TO_DISK
	                                        | NM_SETTINGS_ADD_CONNECTION2_FLAG_IN_MEMORY
	                                        | NM_SETTINGS_ADD_CONNECTION2_FLAG_BLOCK_AUTOCONNECT)))) {
		g_dbus_method_invocation_take_error (invocation,
		                                     g_error_new_literal (NM_SETTINGS_ERROR,
		                                                          NM_SETTINGS_ERROR_INVALID_ARGUMENTS,
		                                                          "Unknown flags"));
		return;
	}

	flags = flags_u;

	if (!NM_FLAGS_ANY (flags,   NM_SETTINGS_ADD_CONNECTION2_FLAG_TO_DISK
	                          | NM_SETTINGS_ADD_CONNECTION2_FLAG_IN_MEMORY)) {
		g_dbus_method_invocation_take_error (invocation,
		                                     g_error_new_literal (NM_SETTINGS_ERROR,
		                                                          NM_SETTINGS_ERROR_INVALID_ARGUMENTS,
		                                                          "Requires either to-disk (0x1) or in-memory (0x2) flags"));
		return;
	}

	if (NM_FLAGS_ALL (flags,   NM_SETTINGS_ADD_CONNECTION2_FLAG_TO_DISK
	                         | NM_SETTINGS_ADD_CONNECTION2_FLAG_IN_MEMORY)) {
		g_dbus_method_invocation_take_error (invocation,
		                                     g_error_new_literal (NM_SETTINGS_ERROR,
		                                                          NM_SETTINGS_ERROR_INVALID_ARGUMENTS,
		                                                          "Cannot set to-disk (0x1) and in-memory (0x2) flags together"));
		return;
	}

	nm_assert (g_variant_is_of_type (args, G_VARIANT_TYPE ("a{sv}")));

	g_variant_iter_init (&iter, args);
	while (g_variant_iter_next (&iter, "{&sv}", &args_name, NULL)) {
		g_dbus_method_invocation_take_error (invocation,
		                                     g_error_new (NM_SETTINGS_ERROR,
		                                                  NM_SETTINGS_ERROR_INVALID_ARGUMENTS,
		                                                  "Unsupported argument '%s'", args_name));
		return;
	}

	settings_add_connection_helper (self, invocation, TRUE, settings, flags);
}

/*****************************************************************************/

static void
impl_settings_load_connections (NMDBusObject *obj,
                                const NMDBusInterfaceInfoExtended *interface_info,
                                const NMDBusMethodInfoExtended *method_info,
                                GDBusConnection *dbus_connection,
                                const char *sender,
                                GDBusMethodInvocation *invocation,
                                GVariant *parameters)
{
	NMSettings *self = NM_SETTINGS (obj);
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	gs_unref_ptrarray GPtrArray *failures = NULL;
	gs_free const char **filenames = NULL;
	gs_free char *op_result_str = NULL;

	g_variant_get (parameters, "(^a&s)", &filenames);

	/* The permission is already enforced by the D-Bus daemon, but we ensure
	 * that the caller is still alive so that clients are forced to wait and
	 * we'll be able to switch to polkit without breaking behavior.
	 */
	if (!nm_dbus_manager_ensure_uid (nm_dbus_object_get_manager (obj),
	                                 invocation,
	                                 G_MAXULONG,
	                                 NM_SETTINGS_ERROR,
	                                 NM_SETTINGS_ERROR_PERMISSION_DENIED))
		return;

	if (   filenames
	    && filenames[0]) {
		NMSettingsPluginConnectionLoadEntry *entries;
		gsize n_entries;
		gsize i;
		GSList *iter;

		entries = nm_settings_plugin_create_connection_load_entries (filenames, &n_entries);

		for (iter = priv->plugins; iter; iter = iter->next) {
			NMSettingsPlugin *plugin = iter->data;

			nm_settings_plugin_load_connections (plugin,
			                                     entries,
			                                     n_entries,
			                                     _plugin_connections_reload_cb,
			                                     self);
		}

		for (i = 0; i < n_entries; i++) {
			NMSettingsPluginConnectionLoadEntry *entry = &entries[i];

			if (!entry->handled)
				_LOGW ("load: no settings plugin could load \"%s\"", entry->filename);
			else if (entry->error) {
				_LOGW ("load: failure to load \"%s\": %s", entry->filename, entry->error->message);
				g_clear_error (&entry->error);
			} else
				continue;

			if (!failures)
				failures = g_ptr_array_new ();
			g_ptr_array_add (failures, (char *) entry->filename);
		}

		nm_clear_g_free (&entries);

		_connection_changed_process_all_dirty (self,
		                                       TRUE,
		                                       NM_SETTINGS_CONNECTION_INT_FLAGS_NONE,
		                                       NM_SETTINGS_CONNECTION_INT_FLAGS_NONE,
		                                       TRUE,
		                                         NM_SETTINGS_CONNECTION_UPDATE_REASON_RESET_SYSTEM_SECRETS
		                                       | NM_SETTINGS_CONNECTION_UPDATE_REASON_RESET_AGENT_SECRETS);

		for (iter = priv->plugins; iter; iter = iter->next)
			nm_settings_plugin_load_connections_done (iter->data);
	}

	if (failures)
		g_ptr_array_add (failures, NULL);

	nm_audit_log_connection_op (NM_AUDIT_OP_CONNS_LOAD,
	                            NULL,
	                            !failures,
	                            (op_result_str = g_strjoinv (",", (char **) filenames)),
	                            invocation,
	                            NULL);

	g_dbus_method_invocation_return_value (invocation,
	                                       g_variant_new ("(b^as)",
	                                                      (gboolean) (!failures),
	                                                      failures
	                                                        ? (const char **) failures->pdata
	                                                        : NM_PTRARRAY_EMPTY (const char *)));
}

static void
impl_settings_reload_connections (NMDBusObject *obj,
                                  const NMDBusInterfaceInfoExtended *interface_info,
                                  const NMDBusMethodInfoExtended *method_info,
                                  GDBusConnection *connection,
                                  const char *sender,
                                  GDBusMethodInvocation *invocation,
                                  GVariant *parameters)
{
	NMSettings *self = NM_SETTINGS (obj);

	/* The permission is already enforced by the D-Bus daemon, but we ensure
	 * that the caller is still alive so that clients are forced to wait and
	 * we'll be able to switch to polkit without breaking behavior.
	 */
	if (!nm_dbus_manager_ensure_uid (nm_dbus_object_get_manager (obj),
	                                 invocation,
	                                 G_MAXULONG,
	                                 NM_SETTINGS_ERROR,
	                                 NM_SETTINGS_ERROR_PERMISSION_DENIED))
		return;

	_plugin_connections_reload (self);

	nm_audit_log_connection_op (NM_AUDIT_OP_CONNS_RELOAD, NULL, TRUE, NULL, invocation, NULL);

	g_dbus_method_invocation_return_value (invocation, g_variant_new ("(b)", TRUE));
}

/*****************************************************************************/

static void
_clear_connections_cached_list (NMSettingsPrivate *priv)
{
	if (!priv->connections_cached_list)
		return;

	nm_assert (priv->connections_len == NM_PTRARRAY_LEN (priv->connections_cached_list));

#if NM_MORE_ASSERTS
	/* set the pointer to a bogus value. This makes it more apparent
	 * if somebody has a reference to the cached list and still uses
	 * it. That is a bug, this code just tries to make it blow up
	 * more eagerly. */
	memset (priv->connections_cached_list,
	        0x43,
	        sizeof (NMSettingsConnection *) * (priv->connections_len + 1));
#endif

	nm_clear_g_free (&priv->connections_cached_list);
}

static void
impl_settings_list_connections (NMDBusObject *obj,
                                const NMDBusInterfaceInfoExtended *interface_info,
                                const NMDBusMethodInfoExtended *method_info,
                                GDBusConnection *dbus_connection,
                                const char *sender,
                                GDBusMethodInvocation *invocation,
                                GVariant *parameters)
{
	NMSettings *self = NM_SETTINGS (obj);
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	gs_free const char **strv = NULL;

	strv = nm_dbus_utils_get_paths_for_clist (&priv->connections_lst_head,
	                                          priv->connections_len,
	                                          G_STRUCT_OFFSET (NMSettingsConnection, _connections_lst),
	                                          TRUE);
	g_dbus_method_invocation_return_value (invocation,
	                                       g_variant_new ("(^ao)", strv));
}

NMSettingsConnection *
nm_settings_get_connection_by_uuid (NMSettings *self, const char *uuid)
{
	g_return_val_if_fail (NM_IS_SETTINGS (self), NULL);
	g_return_val_if_fail (uuid != NULL, NULL);

	return _sett_conn_entry_get_conn (_sett_conn_entries_get (self, uuid));
}

const char *
nm_settings_get_dbus_path_for_uuid (NMSettings *self,
                                    const char *uuid)
{
	NMSettingsConnection *sett_conn;

	sett_conn = nm_settings_get_connection_by_uuid (self, uuid);

	if (!sett_conn)
		return NULL;

	return nm_dbus_object_get_path (NM_DBUS_OBJECT (sett_conn));
}

static void
impl_settings_get_connection_by_uuid (NMDBusObject *obj,
                                      const NMDBusInterfaceInfoExtended *interface_info,
                                      const NMDBusMethodInfoExtended *method_info,
                                      GDBusConnection *dbus_connection,
                                      const char *sender,
                                      GDBusMethodInvocation *invocation,
                                      GVariant *parameters)
{
	NMSettings *self = NM_SETTINGS (obj);
	NMSettingsConnection *sett_conn;
	gs_unref_object NMAuthSubject *subject = NULL;
	GError *error = NULL;
	const char *uuid;

	g_variant_get (parameters, "(&s)", &uuid);

	sett_conn = nm_settings_get_connection_by_uuid (self, uuid);
	if (!sett_conn) {
		error = g_error_new_literal (NM_SETTINGS_ERROR,
		                             NM_SETTINGS_ERROR_INVALID_CONNECTION,
		                             "No connection with the UUID was found.");
		goto error;
	}

	subject = nm_auth_subject_new_unix_process_from_context (invocation);
	if (!subject) {
		error = g_error_new_literal (NM_SETTINGS_ERROR,
		                             NM_SETTINGS_ERROR_PERMISSION_DENIED,
		                             "Unable to determine UID of request.");
		goto error;
	}

	if (!nm_auth_is_subject_in_acl_set_error (nm_settings_connection_get_connection (sett_conn),
	                                          subject,
	                                          NM_SETTINGS_ERROR,
	                                          NM_SETTINGS_ERROR_PERMISSION_DENIED,
	                                          &error))
		goto error;

	g_dbus_method_invocation_return_value (invocation,
	                                       g_variant_new ("(o)",
	                                                      nm_dbus_object_get_path (NM_DBUS_OBJECT (sett_conn))));
	return;

error:
	g_dbus_method_invocation_take_error (invocation, error);
}

/**
 * nm_settings_get_connections:
 * @self: the #NMSettings
 * @out_len: (out) (allow-none): returns the number of returned
 *   connections.
 *
 * Returns: (transfer none): a list of NMSettingsConnections. The list is
 * unsorted and NULL terminated. The result is never %NULL, in case of no
 * connections, it returns an empty list.
 * The returned list is cached internally, only valid until the next
 * NMSettings operation.
 */
NMSettingsConnection *const*
nm_settings_get_connections (NMSettings *self, guint *out_len)
{
	NMSettingsPrivate *priv;
	NMSettingsConnection **v;
	NMSettingsConnection *con;
	guint i;

	g_return_val_if_fail (NM_IS_SETTINGS (self), NULL);

	priv = NM_SETTINGS_GET_PRIVATE (self);

	nm_assert (priv->connections_len == c_list_length (&priv->connections_lst_head));

	if (G_UNLIKELY (!priv->connections_cached_list)) {
		v = g_new (NMSettingsConnection *, priv->connections_len + 1);

		i = 0;
		c_list_for_each_entry (con, &priv->connections_lst_head, _connections_lst) {
			nm_assert (i < priv->connections_len);
			v[i++] = con;
		}
		nm_assert (i == priv->connections_len);
		v[i] = NULL;

		priv->connections_cached_list = v;
	}

	NM_SET_OUT (out_len, priv->connections_len);
	return priv->connections_cached_list;
}

/**
 * nm_settings_get_connections_clone:
 * @self: the #NMSetting
 * @out_len: (allow-none): optional output argument
 * @func: caller-supplied function for filtering connections
 * @func_data: caller-supplied data passed to @func
 * @sort_compare_func: (allow-none): optional function pointer for
 *   sorting the returned list.
 * @sort_data: user data for @sort_compare_func.
 *
 * Returns: (transfer container) (element-type NMSettingsConnection):
 *   an NULL terminated array of #NMSettingsConnection objects that were
 *   filtered by @func (or all connections if no filter was specified).
 *   The order is arbitrary.
 *   Caller is responsible for freeing the returned array with free(),
 *   the contained values do not need to be unrefed.
 */
NMSettingsConnection **
nm_settings_get_connections_clone (NMSettings *self,
                                   guint *out_len,
                                   NMSettingsConnectionFilterFunc func,
                                   gpointer func_data,
                                   GCompareDataFunc sort_compare_func,
                                   gpointer sort_data)
{
	NMSettingsConnection *const*list_cached;
	NMSettingsConnection **list;
	guint len, i, j;

	g_return_val_if_fail (NM_IS_SETTINGS (self), NULL);

	list_cached = nm_settings_get_connections (self, &len);

#if NM_MORE_ASSERTS
	nm_assert (list_cached);
	for (i = 0; i < len; i++)
		nm_assert (NM_IS_SETTINGS_CONNECTION (list_cached[i]));
	nm_assert (!list_cached[i]);
#endif

	list = g_new (NMSettingsConnection *, ((gsize) len + 1));
	if (func) {
		for (i = 0, j = 0; i < len; i++) {
			if (func (self, list_cached[i], func_data))
				list[j++] = list_cached[i];
		}
		list[j] = NULL;
		len = j;
	} else
		memcpy (list, list_cached, sizeof (list[0]) * ((gsize) len + 1));

	if (   len > 1
	    && sort_compare_func) {
		g_qsort_with_data (list, len, sizeof (NMSettingsConnection *),
		                   sort_compare_func, sort_data);
	}
	NM_SET_OUT (out_len, len);
	return list;
}

NMSettingsConnection *
nm_settings_get_connection_by_path (NMSettings *self, const char *path)
{
	NMSettingsPrivate *priv;
	NMSettingsConnection *connection;

	g_return_val_if_fail (NM_IS_SETTINGS (self), NULL);
	g_return_val_if_fail (path, NULL);

	priv = NM_SETTINGS_GET_PRIVATE (self);

	connection = nm_dbus_manager_lookup_object (nm_dbus_object_get_manager (NM_DBUS_OBJECT (self)),
	                                            path);
	if (   !connection
	    || !NM_IS_SETTINGS_CONNECTION (connection))
		return NULL;

	nm_assert (c_list_contains (&priv->connections_lst_head, &connection->_connections_lst));
	return connection;
}

gboolean
nm_settings_has_connection (NMSettings *self, NMSettingsConnection *connection)
{
	gboolean has;

	g_return_val_if_fail (NM_IS_SETTINGS (self), FALSE);
	g_return_val_if_fail (NM_IS_SETTINGS_CONNECTION (connection), FALSE);

	has = !c_list_is_empty (&connection->_connections_lst);

	nm_assert (has == nm_c_list_contains_entry (&NM_SETTINGS_GET_PRIVATE (self)->connections_lst_head,
                                                connection,
                                                _connections_lst));
	nm_assert (({
		NMSettingsConnection *candidate = NULL;
		const char *path;

		path = nm_dbus_object_get_path (NM_DBUS_OBJECT (connection));
		if (path)
			candidate = nm_settings_get_connection_by_path (self, path);

		(has == (connection == candidate));
	}));

	return has;
}

/*****************************************************************************/

static void
add_plugin (NMSettings *self,
            NMSettingsPlugin *plugin,
            const char *pname,
            const char *path)
{
	NMSettingsPrivate *priv;

	nm_assert (NM_IS_SETTINGS (self));
	nm_assert (NM_IS_SETTINGS_PLUGIN (plugin));

	nm_assert (pname);
	nm_assert (nm_streq0 (pname, nm_settings_plugin_get_plugin_name (plugin)));

	priv = NM_SETTINGS_GET_PRIVATE (self);

	nm_assert (!g_slist_find (priv->plugins, plugin));

	priv->plugins = g_slist_append (priv->plugins, g_object_ref (plugin));

	nm_shutdown_wait_obj_register_full (G_OBJECT (plugin),
	                                    g_strdup_printf ("%s-settings-plugin", pname),
	                                    TRUE);

	_LOGI ("Loaded settings plugin: %s (%s%s%s)",
	       pname,
	       NM_PRINT_FMT_QUOTED (path, "\"", path, "\"", "internal"));
}

static gboolean
add_plugin_load_file (NMSettings *self, const char *pname, GError **error)
{
	gs_free char *full_name = NULL;
	gs_free char *path = NULL;
	gs_unref_object NMSettingsPlugin *plugin = NULL;
	GModule *module;
	NMSettingsPluginFactoryFunc factory_func;
	struct stat st;
	int errsv;

	full_name = g_strdup_printf ("nm-settings-plugin-%s", pname);
	path = g_module_build_path (NMPLUGINDIR, full_name);

	if (stat (path, &st) != 0) {
		errsv = errno;
		_LOGW ("could not load plugin '%s' from file '%s': %s", pname, path, nm_strerror_native (errsv));
		return TRUE;
	}
	if (!S_ISREG (st.st_mode)) {
		_LOGW ("could not load plugin '%s' from file '%s': not a file", pname, path);
		return TRUE;
	}
	if (st.st_uid != 0) {
		_LOGW ("could not load plugin '%s' from file '%s': file must be owned by root", pname, path);
		return TRUE;
	}
	if (st.st_mode & (S_IWGRP | S_IWOTH | S_ISUID)) {
		_LOGW ("could not load plugin '%s' from file '%s': invalid file permissions", pname, path);
		return TRUE;
	}

	module = g_module_open (path, G_MODULE_BIND_LOCAL);
	if (!module) {
		_LOGW ("could not load plugin '%s' from file '%s': %s",
		     pname, path, g_module_error ());
		return TRUE;
	}

	/* errors after this point are fatal, because we loaded the shared library already. */

	if (!g_module_symbol (module, "nm_settings_plugin_factory", (gpointer) (&factory_func))) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Could not find plugin '%s' factory function.",
		             pname);
		g_module_close (module);
		return FALSE;
	}

	/* after accessing the plugin we cannot unload it anymore, because the glib
	 * types cannot be properly unregistered. */
	g_module_make_resident (module);

	plugin = (*factory_func) ();
	if (!NM_IS_SETTINGS_PLUGIN (plugin)) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "plugin '%s' returned invalid settings plugin",
		             pname);
		return FALSE;
	}

	add_plugin (self, NM_SETTINGS_PLUGIN (plugin), pname, path);
	return TRUE;
}

static void
add_plugin_keyfile (NMSettings *self)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);

	if (priv->keyfile_plugin)
		return;
	priv->keyfile_plugin = nms_keyfile_plugin_new ();
	add_plugin (self, NM_SETTINGS_PLUGIN (priv->keyfile_plugin), "keyfile", NULL);
}

static gboolean
load_plugins (NMSettings *self, const char *const*plugins, GError **error)
{
	const char *const*iter;
	gboolean success = TRUE;

	for (iter = plugins; iter && *iter; iter++) {
		const char *pname = *iter;

		if (!*pname || strchr (pname, '/')) {
			_LOGW ("ignore invalid plugin \"%s\"", pname);
			continue;
		}

		if (NM_IN_STRSET (pname, "ifcfg-suse", "ifnet", "ibft", "no-ibft")) {
			_LOGW ("skipping deprecated plugin %s", pname);
			continue;
		}

		/* keyfile plugin is built-in now */
		if (nm_streq (pname, "keyfile")) {
			add_plugin_keyfile (self);
			continue;
		}

		if (nm_utils_strv_find_first ((char **) plugins,
		                              iter - plugins,
		                              pname) >= 0) {
			/* the plugin is already mentioned in the list previously.
			 * Don't load a duplicate. */
			continue;
		}

		success = add_plugin_load_file (self, pname, error);
		if (!success)
			break;
	}

	/* If keyfile plugin was not among configured plugins, add it as the last one */
	if (success)
		add_plugin_keyfile (self);

	return success;
}

/*****************************************************************************/

static void
pk_hostname_cb (NMAuthChain *chain,
                GDBusMethodInvocation *context,
                gpointer user_data)
{
	NMSettings *self = NM_SETTINGS (user_data);
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	NMAuthCallResult result;
	GError *error = NULL;
	const char *hostname;

	nm_assert (G_IS_DBUS_METHOD_INVOCATION (context));

	c_list_unlink (nm_auth_chain_parent_lst_list (chain));

	result = nm_auth_chain_get_result (chain, NM_AUTH_PERMISSION_SETTINGS_MODIFY_HOSTNAME);

	/* If our NMSettingsConnection is already gone, do nothing */
	if (result != NM_AUTH_CALL_RESULT_YES) {
		error = g_error_new_literal (NM_SETTINGS_ERROR,
		                             NM_SETTINGS_ERROR_PERMISSION_DENIED,
		                             "Insufficient privileges.");
	} else {
		hostname = nm_auth_chain_get_data (chain, "hostname");

		if (!nm_hostname_manager_write_hostname (priv->hostname_manager, hostname)) {
			error = g_error_new_literal (NM_SETTINGS_ERROR,
			                             NM_SETTINGS_ERROR_FAILED,
			                             "Saving the hostname failed.");
		}
	}

	if (error)
		g_dbus_method_invocation_take_error (context, error);
	else
		g_dbus_method_invocation_return_value (context, NULL);
}

static void
impl_settings_save_hostname (NMDBusObject *obj,
                             const NMDBusInterfaceInfoExtended *interface_info,
                             const NMDBusMethodInfoExtended *method_info,
                             GDBusConnection *connection,
                             const char *sender,
                             GDBusMethodInvocation *invocation,
                             GVariant *parameters)
{
	NMSettings *self = NM_SETTINGS (obj);
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	NMAuthChain *chain;
	const char *hostname;

	g_variant_get (parameters, "(&s)", &hostname);

	/* Minimal validation of the hostname */
	if (!nm_hostname_manager_validate_hostname (hostname)) {
		g_dbus_method_invocation_return_error_literal (invocation,
		                                               NM_SETTINGS_ERROR,
		                                               NM_SETTINGS_ERROR_INVALID_HOSTNAME,
		                                               "The hostname was too long or contained invalid characters.");
		return;
	}

	chain = nm_auth_chain_new_context (invocation, pk_hostname_cb, self);
	if (!chain) {
		g_dbus_method_invocation_return_error_literal (invocation,
		                                               NM_SETTINGS_ERROR,
		                                               NM_SETTINGS_ERROR_PERMISSION_DENIED,
		                                               "Unable to authenticate the request.");
		return;
	}

	c_list_link_tail (&priv->auth_lst_head, nm_auth_chain_parent_lst_list (chain));
	nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_SETTINGS_MODIFY_HOSTNAME, TRUE);
	nm_auth_chain_set_data (chain, "hostname", g_strdup (hostname), g_free);
}

/*****************************************************************************/

static void
_hostname_changed_cb (NMHostnameManager *hostname_manager,
                      GParamSpec *pspec,
                      gpointer user_data)
{
	_notify (user_data, PROP_HOSTNAME);
}

/*****************************************************************************/

static gboolean
have_connection_for_device (NMSettings *self, NMDevice *device)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	NMSettingWired *s_wired;
	const char *setting_hwaddr;
	const char *perm_hw_addr;
	NMSettingsConnection *sett_conn;

	g_return_val_if_fail (NM_IS_SETTINGS (self), FALSE);

	perm_hw_addr = nm_device_get_permanent_hw_address (device);

	/* Find a wired connection locked to the given MAC address, if any */
	c_list_for_each_entry (sett_conn, &priv->connections_lst_head, _connections_lst) {
		NMConnection *connection = nm_settings_connection_get_connection (sett_conn);
		NMSettingConnection *s_con = nm_connection_get_setting_connection (connection);
		const char *ctype;
		const char *iface;

		ctype = nm_setting_connection_get_connection_type (s_con);
		if (!NM_IN_STRSET (ctype, NM_SETTING_WIRED_SETTING_NAME,
		                          NM_SETTING_PPPOE_SETTING_NAME))
			continue;

		if (!nm_device_check_connection_compatible (device, connection, NULL))
			continue;

		if (nm_settings_connection_default_wired_get_device (sett_conn))
			continue;

		if (NM_FLAGS_ANY (nm_settings_connection_get_flags (sett_conn),
		                  NM_SETTINGS_CONNECTION_INT_FLAGS_VOLATILE))
			continue;

		iface = nm_setting_connection_get_interface_name (s_con);
		if (!nm_streq0 (iface, nm_device_get_iface (device)))
			continue;

		s_wired = nm_connection_get_setting_wired (connection);
		if (   !s_wired
		    && nm_streq (ctype, NM_SETTING_PPPOE_SETTING_NAME)) {
			/* No wired setting; therefore the PPPoE connection applies to any device */
			return TRUE;
		}

		setting_hwaddr = nm_setting_wired_get_mac_address (s_wired);
		if (setting_hwaddr) {
			/* A connection mac-locked to this device */
			if (   perm_hw_addr
			    && nm_utils_hwaddr_matches (setting_hwaddr, -1, perm_hw_addr, -1))
				return TRUE;
		} else {
			/* A connection that applies to any wired device */
			return TRUE;
		}
	}

	/* See if there's a known non-NetworkManager configuration for the device */
	if (nm_device_spec_match_list (device, priv->unrecognized_specs))
		return TRUE;

	return FALSE;
}

static void
default_wired_clear_tag (NMSettings *self,
                         NMDevice *device,
                         NMSettingsConnection *sett_conn,
                         gboolean add_to_no_auto_default)
{
	nm_assert (NM_IS_SETTINGS (self));
	nm_assert (NM_IS_DEVICE (device));
	nm_assert (NM_IS_SETTINGS_CONNECTION (sett_conn));
	nm_assert (device == nm_settings_connection_default_wired_get_device (sett_conn));
	nm_assert (sett_conn == g_object_get_qdata (G_OBJECT (device), _default_wired_connection_quark ()));

	_LOGT ("auto-default: forget association between %s (%s) and device %s (%s)",
	       nm_settings_connection_get_uuid (sett_conn),
	       nm_settings_connection_get_id (sett_conn),
	       nm_device_get_iface (device),
	       add_to_no_auto_default ? "persisted" : "temporary");

	nm_settings_connection_default_wired_set_device (sett_conn, NULL);

	g_object_set_qdata (G_OBJECT (device), _default_wired_connection_quark (), NULL);

	if (add_to_no_auto_default)
		nm_config_set_no_auto_default_for_device (NM_SETTINGS_GET_PRIVATE (self)->config, device);
}

static void
device_realized (NMDevice *device, GParamSpec *pspec, NMSettings *self)
{
	gs_unref_object NMConnection *connection = NULL;
	NMSettingsPrivate *priv;
	NMSettingsConnection *added;
	GError *error = NULL;

	if (!nm_device_is_real (device))
		return;

	g_signal_handlers_disconnect_by_func (device,
	                                      G_CALLBACK (device_realized),
	                                      self);

	priv = NM_SETTINGS_GET_PRIVATE (self);

	/* If the device isn't managed or it already has a default wired connection,
	 * ignore it.
	 */
	if (   !nm_device_get_managed (device, FALSE)
	    || g_object_get_qdata (G_OBJECT (device), _default_wired_connection_quark ())
	    || have_connection_for_device (self, device)
	    || nm_config_get_no_auto_default_for_device (priv->config, device))
		return;

	connection = nm_device_new_default_connection (device);
	if (!connection)
		return;

	_LOGT ("auto-default: creating in-memory connection %s (%s) for device %s",
	       nm_connection_get_uuid (connection),
	       nm_connection_get_id (connection),
	       nm_device_get_iface (device));

	nm_settings_add_connection (self,
	                            connection,
	                            NM_SETTINGS_CONNECTION_PERSIST_MODE_IN_MEMORY_ONLY,
	                            NM_SETTINGS_CONNECTION_ADD_REASON_NONE,
	                            NM_SETTINGS_CONNECTION_INT_FLAGS_NM_GENERATED,
	                            &added,
	                            &error);
	if (!added) {
		if (!g_error_matches (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_UUID_EXISTS)) {
			_LOGW ("(%s) couldn't create default wired connection: %s",
			       nm_device_get_iface (device),
			       error->message);
		}
		g_clear_error (&error);
		return;
	}

	nm_settings_connection_default_wired_set_device (added, device);

	g_object_set_qdata (G_OBJECT (device), _default_wired_connection_quark (), added);

	_LOGI ("(%s): created default wired connection '%s'",
	       nm_device_get_iface (device),
	       nm_settings_connection_get_id (added));
}

void
nm_settings_device_added (NMSettings *self, NMDevice *device)
{
	if (nm_device_is_real (device))
		device_realized (device, NULL, self);
	else {
		/* FIXME(shutdown): we need to disconnect this signal handler during
		 *   shutdown. */
		g_signal_connect_after (device, "notify::" NM_DEVICE_REAL,
		                        G_CALLBACK (device_realized),
		                        self);
	}
}

void
nm_settings_device_removed (NMSettings *self, NMDevice *device, gboolean quitting)
{
	NMSettingsConnection *connection;

	g_signal_handlers_disconnect_by_func (device,
	                                      G_CALLBACK (device_realized),
	                                      self);

	connection = g_object_get_qdata (G_OBJECT (device), _default_wired_connection_quark ());
	if (connection) {
		default_wired_clear_tag (self, device, connection, FALSE);

		/* Don't delete the default wired connection on shutdown, so that it
		 * remains up and can be assumed if NM starts again.
		 */
		if (quitting == FALSE)
			nm_settings_connection_delete (connection, TRUE);
	}
}

/*****************************************************************************/

static void
session_monitor_changed_cb (NMSessionMonitor *session_monitor,
                            NMSettings *self)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	NMSettingsConnection *const*list;
	guint i, len;
	guint generation;

again:
	list = nm_settings_get_connections (self, &len);
	generation = priv->connections_generation;
	for (i = 0; i < len; i++) {
		gboolean is_visible;

		is_visible = nm_settings_connection_check_visibility (list[i],
		                                                      session_monitor);
		nm_settings_connection_set_flags (list[i],
		                                  NM_SETTINGS_CONNECTION_INT_FLAGS_VISIBLE,
		                                  is_visible);
		if (generation != priv->connections_generation) {
			/* the cached list was invalidated. Start again.
			 *
			 * Note that nm_settings_connection_recheck_visibility() will do nothing
			 * if the visibility didn't change (including emitting no signals,
			 * and not invalidating the list).
			 *
			 * Hence, for this to be an endless loop, the settings would have
			 * to constantly change the visibility flag and also invalidate the list. */
			goto again;
		}
	}
}

/*****************************************************************************/

G_GNUC_PRINTF (4, 5)
static void
_kf_db_log_fcn (NMKeyFileDB *kf_db,
                int syslog_level,
                gpointer user_data,
                const char *fmt,
                ...)
{
	NMSettings *self = user_data;
	NMLogLevel level = nm_log_level_from_syslog (syslog_level);

	if (_NMLOG_ENABLED (level)) {
		NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
		gs_free char *msg = NULL;
		va_list ap;
		const char *prefix;

		va_start (ap, fmt);
		msg = g_strdup_vprintf (fmt, ap);
		va_end (ap);

		if (priv->kf_db_timestamps == kf_db)
			prefix = "timestamps";
		else if (priv->kf_db_seen_bssids == kf_db)
			prefix = "seen-bssids";
		else {
			nm_assert_not_reached ();
			prefix = "???";
		}

		_NMLOG (level, "[%s-keyfile]: %s", prefix, msg);
	}
}

static gboolean
_kf_db_got_dirty_flush (NMSettings *self,
                        gboolean is_timestamps)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	const char *prefix;
	NMKeyFileDB *kf_db;

	if (is_timestamps) {
		prefix = "timestamps";
		kf_db = priv->kf_db_timestamps;
		priv->kf_db_flush_idle_id_timestamps = 0;
	} else {
		prefix = "seen-bssids";
		kf_db = priv->kf_db_seen_bssids;
		priv->kf_db_flush_idle_id_seen_bssids = 0;
	}

	if (nm_key_file_db_is_dirty (kf_db))
		nm_key_file_db_to_file (kf_db, FALSE);
	else {
		_LOGT ("[%s-keyfile]: skip saving changes to \"%s\"",
		       prefix,
		       nm_key_file_db_get_filename (kf_db));
	}

	return G_SOURCE_REMOVE;
}

static gboolean
_kf_db_got_dirty_flush_timestamps_cb (gpointer user_data)
{
	return _kf_db_got_dirty_flush (user_data,
	                               TRUE);
}

static gboolean
_kf_db_got_dirty_flush_seen_bssids_cb (gpointer user_data)
{
	return _kf_db_got_dirty_flush (user_data,
	                               FALSE);
}

static void
_kf_db_got_dirty_fcn (NMKeyFileDB *kf_db,
                      gpointer user_data)
{
	NMSettings *self = user_data;
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	GSourceFunc idle_func;
	guint *p_id;
	const char *prefix;

	if (priv->kf_db_timestamps == kf_db) {
		prefix = "timestamps";
		p_id = &priv->kf_db_flush_idle_id_timestamps;
		idle_func = _kf_db_got_dirty_flush_timestamps_cb;
	} else if (priv->kf_db_seen_bssids == kf_db) {
		prefix = "seen-bssids";
		p_id = &priv->kf_db_flush_idle_id_seen_bssids;
		idle_func = _kf_db_got_dirty_flush_seen_bssids_cb;
	} else {
		nm_assert_not_reached ();
		return;
	}

	if (*p_id != 0)
		return;
	_LOGT ("[%s-keyfile]: schedule flushing changes to disk", prefix);
	*p_id = g_idle_add_full (G_PRIORITY_LOW, idle_func, self, NULL);
}

void
nm_settings_kf_db_write (NMSettings *self)
{
	NMSettingsPrivate *priv;

	g_return_if_fail (NM_IS_SETTINGS (self));

	priv = NM_SETTINGS_GET_PRIVATE (self);
	if (priv->kf_db_timestamps)
		nm_key_file_db_to_file (priv->kf_db_timestamps, TRUE);
	if (priv->kf_db_seen_bssids)
		nm_key_file_db_to_file (priv->kf_db_seen_bssids, TRUE);
}

/*****************************************************************************/

gboolean
nm_settings_start (NMSettings *self, GError **error)
{
	NMSettingsPrivate *priv;
	gs_strfreev char **plugins = NULL;
	GSList *iter;

	priv = NM_SETTINGS_GET_PRIVATE (self);

	nm_assert (!priv->started);

	priv->hostname_manager = g_object_ref (nm_hostname_manager_get ());

	priv->kf_db_timestamps = nm_key_file_db_new (NMSTATEDIR "/timestamps",
	                                             "timestamps",
	                                             _kf_db_log_fcn,
	                                             _kf_db_got_dirty_fcn,
	                                             self);
	priv->kf_db_seen_bssids = nm_key_file_db_new (NMSTATEDIR "/seen-bssids",
	                                              "seen-bssids",
	                                              _kf_db_log_fcn,
	                                              _kf_db_got_dirty_fcn,
	                                              self);
	nm_key_file_db_start (priv->kf_db_timestamps);
	nm_key_file_db_start (priv->kf_db_seen_bssids);

	/* Load the plugins; fail if a plugin is not found. */
	plugins = nm_config_data_get_plugins (nm_config_get_data_orig (priv->config), TRUE);

	if (!load_plugins (self, (const char *const*) plugins, error))
		return FALSE;

	for (iter = priv->plugins; iter; iter = iter->next) {
		NMSettingsPlugin *plugin = NM_SETTINGS_PLUGIN (iter->data);

		g_signal_connect (plugin, NM_SETTINGS_PLUGIN_UNMANAGED_SPECS_CHANGED,
		                  G_CALLBACK (_plugin_unmanaged_specs_changed), self);
		g_signal_connect (plugin, NM_SETTINGS_PLUGIN_UNRECOGNIZED_SPECS_CHANGED,
		                  G_CALLBACK (_plugin_unrecognized_specs_changed), self);
	}

	_plugin_unmanaged_specs_changed (NULL, self);
	_plugin_unrecognized_specs_changed (NULL, self);

	_plugin_connections_reload (self);

	g_signal_connect (priv->hostname_manager,
	                  "notify::"NM_HOSTNAME_MANAGER_HOSTNAME,
	                  G_CALLBACK (_hostname_changed_cb),
	                  self);
	if (nm_hostname_manager_get_hostname (priv->hostname_manager))
		_notify (self, PROP_HOSTNAME);

	priv->started = TRUE;
	_startup_complete_check (self, 0);

	/* FIXME(shutdown): we also need a nm_settings_stop() during shutdown.
	 *
	 * In particular, we need to remove all in-memory keyfiles from /run that are nm-generated.
	 * alternatively, the nm-generated flag must also be persisted and loaded to /run. */

	return TRUE;
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettings *self = NM_SETTINGS (object);
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	const char **strv;

	switch (prop_id) {
	case PROP_UNMANAGED_SPECS:
		g_value_take_boxed (value,
		                    _nm_utils_slist_to_strv (nm_settings_get_unmanaged_specs (self),
		                                             TRUE));
		break;
	case PROP_HOSTNAME:
		g_value_set_string (value,
		                      priv->hostname_manager
		                    ? nm_hostname_manager_get_hostname (priv->hostname_manager)
		                    : NULL);
		break;
	case PROP_CAN_MODIFY:
		g_value_set_boolean (value, TRUE);
		break;
	case PROP_CONNECTIONS:
		strv = nm_dbus_utils_get_paths_for_clist (&priv->connections_lst_head,
		                                          priv->connections_len,
		                                          G_STRUCT_OFFSET (NMSettingsConnection, _connections_lst),
		                                          TRUE);
		g_value_take_boxed (value, nm_utils_strv_make_deep_copied (strv));
		break;
	case PROP_STARTUP_COMPLETE:
		g_value_set_boolean (value, !nm_settings_get_startup_complete_blocked_reason (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_settings_init (NMSettings *self)
{
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);

	c_list_init (&priv->auth_lst_head);
	c_list_init (&priv->connections_lst_head);

	c_list_init (&priv->sce_dirty_lst_head);
	priv->sce_idx = g_hash_table_new_full (nm_pstr_hash, nm_pstr_equal,
	                                       NULL, (GDestroyNotify) _sett_conn_entry_free);

	priv->config = g_object_ref (nm_config_get ());

	priv->agent_mgr = g_object_ref (nm_agent_manager_get ());

	priv->platform = g_object_ref (NM_PLATFORM_GET);

	priv->session_monitor = g_object_ref (nm_session_monitor_get ());
	g_signal_connect (priv->session_monitor,
	                  NM_SESSION_MONITOR_CHANGED,
	                  G_CALLBACK (session_monitor_changed_cb),
	                  self);
}

NMSettings *
nm_settings_new (void)
{
	return g_object_new (NM_TYPE_SETTINGS, NULL);
}

static void
dispose (GObject *object)
{
	NMSettings *self = NM_SETTINGS (object);
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	CList *iter;

	nm_assert (c_list_is_empty (&priv->sce_dirty_lst_head));
	nm_assert (g_hash_table_size (priv->sce_idx) == 0);

	nm_clear_g_source (&priv->startup_complete_timeout_id);
	nm_clear_g_signal_handler (priv->platform, &priv->startup_complete_platform_change_id);
	nm_clear_pointer (&priv->startup_complete_idx, g_hash_table_destroy);
	g_clear_object (&priv->startup_complete_blocked_by);

	while ((iter = c_list_first (&priv->auth_lst_head)))
		nm_auth_chain_destroy (nm_auth_chain_parent_lst_entry (iter));

	if (priv->hostname_manager) {
		g_signal_handlers_disconnect_by_func (priv->hostname_manager,
		                                      G_CALLBACK (_hostname_changed_cb),
		                                      self);
		g_clear_object (&priv->hostname_manager);
	}

	if (priv->session_monitor) {
		g_signal_handlers_disconnect_by_func (priv->session_monitor,
		                                      G_CALLBACK (session_monitor_changed_cb),
		                                      self);
		g_clear_object (&priv->session_monitor);
	}

	G_OBJECT_CLASS (nm_settings_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMSettings *self = NM_SETTINGS (object);
	NMSettingsPrivate *priv = NM_SETTINGS_GET_PRIVATE (self);
	GSList *iter;

	_clear_connections_cached_list (priv);

	nm_assert (c_list_is_empty (&priv->connections_lst_head));

	nm_assert (c_list_is_empty (&priv->sce_dirty_lst_head));
	nm_assert (g_hash_table_size (priv->sce_idx) == 0);

	nm_clear_pointer (&priv->sce_idx, g_hash_table_destroy);

	g_slist_free_full (priv->unmanaged_specs, g_free);
	g_slist_free_full (priv->unrecognized_specs, g_free);

	while ((iter = priv->plugins)) {
		gs_unref_object NMSettingsPlugin *plugin = iter->data;

		priv->plugins = g_slist_delete_link (priv->plugins, iter);
		g_signal_handlers_disconnect_by_data (plugin, self);
	}

	g_clear_object (&priv->keyfile_plugin);

	g_clear_object (&priv->agent_mgr);

	nm_clear_g_source (&priv->kf_db_flush_idle_id_timestamps);
	nm_clear_g_source (&priv->kf_db_flush_idle_id_seen_bssids);
	nm_key_file_db_to_file (priv->kf_db_timestamps, FALSE);
	nm_key_file_db_to_file (priv->kf_db_seen_bssids, FALSE);
	nm_key_file_db_destroy (priv->kf_db_timestamps);
	nm_key_file_db_destroy (priv->kf_db_seen_bssids);

	G_OBJECT_CLASS (nm_settings_parent_class)->finalize (object);

	g_clear_object (&priv->config);

	g_clear_object (&priv->platform);
}

static const GDBusSignalInfo signal_info_new_connection = NM_DEFINE_GDBUS_SIGNAL_INFO_INIT (
	"NewConnection",
	.args = NM_DEFINE_GDBUS_ARG_INFOS (
		NM_DEFINE_GDBUS_ARG_INFO ("connection", "o"),
	),
);

static const GDBusSignalInfo signal_info_connection_removed = NM_DEFINE_GDBUS_SIGNAL_INFO_INIT (
	"ConnectionRemoved",
	.args = NM_DEFINE_GDBUS_ARG_INFOS (
		NM_DEFINE_GDBUS_ARG_INFO ("connection", "o"),
	),
);

static const NMDBusInterfaceInfoExtended interface_info_settings = {
	.parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT (
		NM_DBUS_INTERFACE_SETTINGS,
		.methods = NM_DEFINE_GDBUS_METHOD_INFOS (
			NM_DEFINE_DBUS_METHOD_INFO_EXTENDED (
				NM_DEFINE_GDBUS_METHOD_INFO_INIT (
					"ListConnections",
					.out_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("connections", "ao"),
					),
				),
				.handle = impl_settings_list_connections,
			),
			NM_DEFINE_DBUS_METHOD_INFO_EXTENDED (
				NM_DEFINE_GDBUS_METHOD_INFO_INIT (
					"GetConnectionByUuid",
					.in_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("uuid", "s"),
					),
					.out_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("connection", "o"),
					),
				),
				.handle = impl_settings_get_connection_by_uuid,
			),
			NM_DEFINE_DBUS_METHOD_INFO_EXTENDED (
				NM_DEFINE_GDBUS_METHOD_INFO_INIT (
					"AddConnection",
					.in_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("connection", "a{sa{sv}}"),
					),
					.out_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("path", "o"),
					),
				),
				.handle = impl_settings_add_connection,
			),
			NM_DEFINE_DBUS_METHOD_INFO_EXTENDED (
				NM_DEFINE_GDBUS_METHOD_INFO_INIT (
					"AddConnectionUnsaved",
					.in_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("connection", "a{sa{sv}}"),
					),
					.out_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("path", "o"),
					),
				),
				.handle = impl_settings_add_connection_unsaved,
			),
			NM_DEFINE_DBUS_METHOD_INFO_EXTENDED (
				NM_DEFINE_GDBUS_METHOD_INFO_INIT (
					"AddConnection2",
					.in_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("settings", "a{sa{sv}}"),
						NM_DEFINE_GDBUS_ARG_INFO ("flags",    "u"),
						NM_DEFINE_GDBUS_ARG_INFO ("args",     "a{sv}"),
					),
					.out_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("path", "o"),
						NM_DEFINE_GDBUS_ARG_INFO ("result", "a{sv}"),
					),
				),
				.handle = impl_settings_add_connection2,
			),
			NM_DEFINE_DBUS_METHOD_INFO_EXTENDED (
				NM_DEFINE_GDBUS_METHOD_INFO_INIT (
					"LoadConnections",
					.in_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("filenames", "as"),
					),
					.out_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("status", "b"),
						NM_DEFINE_GDBUS_ARG_INFO ("failures", "as"),
					),
				),
				.handle = impl_settings_load_connections,
			),
			NM_DEFINE_DBUS_METHOD_INFO_EXTENDED (
				NM_DEFINE_GDBUS_METHOD_INFO_INIT (
					"ReloadConnections",
					.out_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("status", "b"),
					),
				),
				.handle = impl_settings_reload_connections,
			),
			NM_DEFINE_DBUS_METHOD_INFO_EXTENDED (
				NM_DEFINE_GDBUS_METHOD_INFO_INIT (
					"SaveHostname",
					.in_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("hostname", "s"),
					),
				),
				.handle = impl_settings_save_hostname,
			),
		),
		.signals = NM_DEFINE_GDBUS_SIGNAL_INFOS (
			&nm_signal_info_property_changed_legacy,
			&signal_info_new_connection,
			&signal_info_connection_removed,
		),
		.properties = NM_DEFINE_GDBUS_PROPERTY_INFOS (
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Connections", "ao", NM_SETTINGS_CONNECTIONS),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Hostname",    "s",  NM_SETTINGS_HOSTNAME),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("CanModify",   "b",  NM_SETTINGS_CAN_MODIFY),
		),
	),
	.legacy_property_changed = TRUE,
};

static void
nm_settings_class_init (NMSettingsClass *class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (class);
	NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS (class);

	dbus_object_class->export_path = NM_DBUS_EXPORT_PATH_STATIC (NM_DBUS_PATH_SETTINGS);
	dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS (&interface_info_settings);

	object_class->get_property = get_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	obj_properties[PROP_UNMANAGED_SPECS] =
	    g_param_spec_boxed (NM_SETTINGS_UNMANAGED_SPECS, "", "",
	                        G_TYPE_STRV,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_HOSTNAME] =
	    g_param_spec_string (NM_SETTINGS_HOSTNAME, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_CAN_MODIFY] =
	    g_param_spec_boolean (NM_SETTINGS_CAN_MODIFY, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_CONNECTIONS] =
	    g_param_spec_boxed (NM_SETTINGS_CONNECTIONS, "", "",
	                        G_TYPE_STRV,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_STARTUP_COMPLETE] =
	    g_param_spec_boolean (NM_SETTINGS_STARTUP_COMPLETE, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	signals[CONNECTION_ADDED] =
	    g_signal_new (NM_SETTINGS_SIGNAL_CONNECTION_ADDED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL,
	                  g_cclosure_marshal_VOID__OBJECT,
	                  G_TYPE_NONE, 1, NM_TYPE_SETTINGS_CONNECTION);

	signals[CONNECTION_UPDATED] =
	    g_signal_new (NM_SETTINGS_SIGNAL_CONNECTION_UPDATED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL,
	                  NULL,
	                  G_TYPE_NONE, 2, NM_TYPE_SETTINGS_CONNECTION, G_TYPE_UINT);

	signals[CONNECTION_REMOVED] =
	    g_signal_new (NM_SETTINGS_SIGNAL_CONNECTION_REMOVED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL,
	                  g_cclosure_marshal_VOID__OBJECT,
	                  G_TYPE_NONE, 1, NM_TYPE_SETTINGS_CONNECTION);

	signals[CONNECTION_FLAGS_CHANGED] =
	    g_signal_new (NM_SETTINGS_SIGNAL_CONNECTION_FLAGS_CHANGED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL,
	                  g_cclosure_marshal_VOID__OBJECT,
	                  G_TYPE_NONE, 1, NM_TYPE_SETTINGS_CONNECTION);
}
