/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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
 * Copyright (C) 2011 Red Hat, Inc.
 */

#include "config.h"

#include <string.h>
#include <glib.h>
#include <gio/gio.h>
#include <dbus/dbus.h>

#include "nm-firewall-manager.h"
#include "nm-dbus-manager.h"
#include "nm-logging.h"

#define NM_FIREWALL_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                              NM_TYPE_FIREWALL_MANAGER, \
                                              NMFirewallManagerPrivate))

G_DEFINE_TYPE (NMFirewallManager, nm_firewall_manager, G_TYPE_OBJECT)

/* Properties */
enum {
	PROP_0 = 0,
	PROP_AVAILABLE,
	LAST_PROP
};

typedef struct {
	NMDBusManager * dbus_mgr;
	guint           name_owner_id;
	DBusGProxy *    proxy;
	gboolean        running;

	GSList         *pending_calls;
} NMFirewallManagerPrivate;

enum {
	STARTED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

/********************************************************************/

#define PENDING_CALL_DUMMY               ((NMFirewallPendingCall) GUINT_TO_POINTER(1))
#define PENDING_CALL_FROM_INFO(info)     ((NMFirewallPendingCall) info)

typedef struct {
	NMFirewallManager *self;
	char *iface;
	FwAddToZoneFunc callback;
	gpointer user_data;
	guint id;
	gboolean completed;

	guint idle_id;
	DBusGProxyCall *dbus_call;
} CBInfo;

static void
_cb_info_free (CBInfo *info)
{
	NMFirewallManagerPrivate *priv;

	g_return_if_fail (info != NULL);

	if (!info->completed) {
		nm_log_dbg (LOGD_FIREWALL, "(%s) firewall zone call cancelled [%u]", info->iface, info->id);
		if (info->callback) {
			GError *error;

			error = g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED,
			                             "Operation was cancelled");
			info->callback (error, info->user_data);
			g_error_free (error);
		}
	}
	g_free (info->iface);

	priv = NM_FIREWALL_MANAGER_GET_PRIVATE (info->self);
	priv->pending_calls = g_slist_remove (priv->pending_calls, info);
	g_object_unref (info->self);

	g_slice_free (CBInfo, info);
}

static CBInfo *
_cb_info_create (NMFirewallManager *self, const char *iface, FwAddToZoneFunc callback, gpointer user_data)
{
	NMFirewallManagerPrivate *priv = NM_FIREWALL_MANAGER_GET_PRIVATE (self);
	static guint id;
	CBInfo *info;

	info = g_slice_new0 (CBInfo);
	if (++id == 0)
		++id;
	info->self = g_object_ref (self);
	info->id = id;
	info->iface = g_strdup (iface);
	info->completed = FALSE;
	info->callback = callback;
	info->user_data = user_data;

	priv->pending_calls = g_slist_prepend (priv->pending_calls, info);
	return info;
}

static gboolean
add_or_change_idle_cb (gpointer user_data)
{
	CBInfo *info = user_data;

	if (info->idle_id == 0) {
		/* operation was cancelled. _cb_info_free will invoke callback. */
	} else {
		nm_log_dbg (LOGD_FIREWALL, "(%s) firewall zone call pretends success [%u]",
		            info->iface, info->id);
		if (info->callback)
			info->callback (NULL, info->user_data);
		info->completed = TRUE;
		info->idle_id = 0;
	}

	_cb_info_free (info);
	return G_SOURCE_REMOVE;
}

static void
add_or_change_cb (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	CBInfo *info = user_data;
	GError *error = NULL;
	char *zone = NULL;

	if (!dbus_g_proxy_end_call (proxy, call_id, &error,
	                            G_TYPE_STRING, &zone,
	                            G_TYPE_INVALID)) {
		g_assert (error);
		if (g_strcmp0 (error->message, "ZONE_ALREADY_SET") != 0) {
			nm_log_warn (LOGD_FIREWALL, "(%s) firewall zone add/change failed [%u]: (%d) %s",
			             info->iface, info->id, error->code, error->message);
		} else {
			nm_log_dbg (LOGD_FIREWALL, "(%s) firewall zone add/change failed [%u]: (%d) %s",
			            info->iface, info->id, error->code, error->message);
		}
	} else {
		nm_log_dbg (LOGD_FIREWALL, "(%s) firewall zone add/change succeeded [%u]",
		            info->iface, info->id);
	}

	if (info->callback)
		info->callback (error, info->user_data);

	info->completed = TRUE;
	g_free (zone);
	g_clear_error (&error);
}

NMFirewallPendingCall
nm_firewall_manager_add_or_change_zone (NMFirewallManager *self,
                                        const char *iface,
                                        const char *zone,
                                        gboolean add, /* TRUE == add, FALSE == change */
                                        FwAddToZoneFunc callback,
                                        gpointer user_data)
{
	NMFirewallManagerPrivate *priv = NM_FIREWALL_MANAGER_GET_PRIVATE (self);
	CBInfo *info;

	if (priv->running == FALSE) {
		if (callback) {
			info = _cb_info_create (self, iface, callback, user_data);
			info->idle_id = g_idle_add (add_or_change_idle_cb, info);
			nm_log_dbg (LOGD_FIREWALL, "(%s) firewall zone %s -> %s%s%s [%u] (not running, simulate success)", iface, add ? "add" : "change",
			            zone?"\"":"", zone ? zone : "default", zone?"\"":"", info->id);
			return PENDING_CALL_FROM_INFO (info);
		} else {
			nm_log_dbg (LOGD_FIREWALL, "(%s) firewall zone add/change skipped (not running)", iface);
			return PENDING_CALL_DUMMY;
		}
	}

	info = _cb_info_create (self, iface, callback, user_data);

	nm_log_dbg (LOGD_FIREWALL, "(%s) firewall zone %s -> %s%s%s [%u]", iface, add ? "add" : "change",
	                           zone?"\"":"", zone ? zone : "default", zone?"\"":"", info->id);
	info->dbus_call = dbus_g_proxy_begin_call_with_timeout (priv->proxy,
	                                                        add ? "addInterface" : "changeZone",
	                                                        add_or_change_cb,
	                                                        info,
	                                                        (GDestroyNotify) _cb_info_free,
	                                                        10000,      /* timeout */
	                                                        G_TYPE_STRING, zone ? zone : "",
	                                                        G_TYPE_STRING, iface,
	                                                        G_TYPE_INVALID);
	return PENDING_CALL_FROM_INFO (info);
}

static void
remove_cb (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	CBInfo *info = user_data;
	GError *error = NULL;
	char * zone = NULL;

	if (!dbus_g_proxy_end_call (proxy, call_id, &error,
	                            G_TYPE_STRING, &zone,
	                            G_TYPE_INVALID)) {
		g_assert (error);
		/* ignore UNKNOWN_INTERFACE errors */
		if (error->message && !strstr (error->message, "UNKNOWN_INTERFACE")) {
			nm_log_warn (LOGD_FIREWALL, "(%s) firewall zone remove failed [%u]: (%d) %s",
			             info->iface, info->id, error->code, error->message);
		} else {
			nm_log_dbg (LOGD_FIREWALL, "(%s) firewall zone remove failed [%u]: (%d) %s",
			            info->iface, info->id, error->code, error->message);
		}
	} else {
		nm_log_dbg (LOGD_FIREWALL, "(%s) firewall zone remove succeeded [%u]",
		            info->iface, info->id);
	}

	info->completed = TRUE;
	g_free (zone);
	g_clear_error (&error);
}

NMFirewallPendingCall
nm_firewall_manager_remove_from_zone (NMFirewallManager *self,
                                      const char *iface,
                                      const char *zone)
{
	NMFirewallManagerPrivate *priv = NM_FIREWALL_MANAGER_GET_PRIVATE (self);
	CBInfo *info;

	if (priv->running == FALSE) {
		nm_log_dbg (LOGD_FIREWALL, "(%s) firewall zone remove skipped (not running)", iface);
		return PENDING_CALL_DUMMY;
	}

	info = _cb_info_create (self, iface, NULL, NULL);

	nm_log_dbg (LOGD_FIREWALL, "(%s) firewall zone remove -> %s%s%s [%u]", iface,
	                           zone?"\"":"", zone ? zone : "*", zone?"\"":"", info->id);
	info->dbus_call = dbus_g_proxy_begin_call_with_timeout (priv->proxy,
	                                                        "removeInterface",
	                                                        remove_cb,
	                                                        info,
	                                                        (GDestroyNotify) _cb_info_free,
	                                                        10000,      /* timeout */
	                                                        G_TYPE_STRING, zone ? zone : "",
	                                                        G_TYPE_STRING, iface,
	                                                        G_TYPE_INVALID);
	return PENDING_CALL_FROM_INFO (info);
}

void nm_firewall_manager_cancel_call (NMFirewallManager *self, NMFirewallPendingCall call)
{
	NMFirewallManagerPrivate *priv = NM_FIREWALL_MANAGER_GET_PRIVATE (self);
	GSList *pending;
	CBInfo *info;

	g_return_if_fail (NM_IS_FIREWALL_MANAGER (self));

	if (call == PENDING_CALL_DUMMY)
		return;

	pending = g_slist_find (priv->pending_calls, call);

	if (!pending)
		return;
	priv->pending_calls = g_slist_remove_link (priv->pending_calls, pending);

	info = (CBInfo *) call;
	if (info->idle_id)
		info->idle_id = 0;
	else {
		dbus_g_proxy_cancel_call (NM_FIREWALL_MANAGER_GET_PRIVATE (self)->proxy,
		                          info->dbus_call);
	}
}

static void
set_running (NMFirewallManager *self, gboolean now_running)
{
	NMFirewallManagerPrivate *priv = NM_FIREWALL_MANAGER_GET_PRIVATE (self);
	gboolean old_running = priv->running;

	priv->running = now_running;
	if (old_running != priv->running)
		g_object_notify (G_OBJECT (self), NM_FIREWALL_MANAGER_AVAILABLE);
}

static void
name_owner_changed (NMDBusManager *dbus_mgr,
                    const char *name,
                    const char *old_owner,
                    const char *new_owner,
                    gpointer user_data)
{
	NMFirewallManager *self = NM_FIREWALL_MANAGER (user_data);
	gboolean old_owner_good = (old_owner && strlen (old_owner));
	gboolean new_owner_good = (new_owner && strlen (new_owner));

	/* We only care about the firewall here */
	if (strcmp (FIREWALL_DBUS_SERVICE, name) != 0)
		return;

	if (!old_owner_good && new_owner_good) {
		nm_log_dbg (LOGD_FIREWALL, "firewall started");
		set_running (self, TRUE);
		g_signal_emit (self, signals[STARTED], 0);
	} else if (old_owner_good && !new_owner_good) {
		nm_log_dbg (LOGD_FIREWALL, "firewall stopped");
		set_running (self, FALSE);
	}
}

/*******************************************************************/

NMFirewallManager *
nm_firewall_manager_get (void)
{
	static NMFirewallManager *singleton = NULL;

	if (G_UNLIKELY (!singleton)) {
		singleton = NM_FIREWALL_MANAGER (g_object_new (NM_TYPE_FIREWALL_MANAGER, NULL));
		g_assert (singleton);
	}

	return singleton;
}

static void
nm_firewall_manager_init (NMFirewallManager * self)
{
	NMFirewallManagerPrivate *priv = NM_FIREWALL_MANAGER_GET_PRIVATE (self);
	DBusGConnection *bus;

	priv->dbus_mgr = g_object_ref (nm_dbus_manager_get ());
	priv->name_owner_id = g_signal_connect (priv->dbus_mgr,
	                                        NM_DBUS_MANAGER_NAME_OWNER_CHANGED,
	                                        G_CALLBACK (name_owner_changed),
	                                        self);
	priv->running = nm_dbus_manager_name_has_owner (priv->dbus_mgr, FIREWALL_DBUS_SERVICE);
	nm_log_dbg (LOGD_FIREWALL, "firewall %s running", priv->running ? "is" : "is not" );

	bus = nm_dbus_manager_get_connection (priv->dbus_mgr);
	priv->proxy = dbus_g_proxy_new_for_name (bus,
	                                         FIREWALL_DBUS_SERVICE,
	                                         FIREWALL_DBUS_PATH,
	                                         FIREWALL_DBUS_INTERFACE_ZONE);
}

static void
set_property (GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
	G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
}

static void
get_property (GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	case PROP_AVAILABLE:
		g_value_set_boolean (value, NM_FIREWALL_MANAGER_GET_PRIVATE (object)->running);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
dispose (GObject *object)
{
	NMFirewallManagerPrivate *priv = NM_FIREWALL_MANAGER_GET_PRIVATE (object);

	g_assert (priv->pending_calls == NULL);

	if (priv->dbus_mgr) {
		g_signal_handler_disconnect (priv->dbus_mgr, priv->name_owner_id);
		priv->name_owner_id = 0;
		g_clear_object (&priv->dbus_mgr);
	}

	g_clear_object (&priv->proxy);

	/* Chain up to the parent class */
	G_OBJECT_CLASS (nm_firewall_manager_parent_class)->dispose (object);
}

static void
nm_firewall_manager_class_init (NMFirewallManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMFirewallManagerPrivate));

	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->dispose = dispose;

	g_object_class_install_property
		(object_class, PROP_AVAILABLE,
		 g_param_spec_boolean (NM_FIREWALL_MANAGER_AVAILABLE, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	signals[STARTED] =
		g_signal_new ("started",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMFirewallManagerClass, started),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__VOID,
					  G_TYPE_NONE, 0);

}

