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

#include "nm-default.h"
#include "nm-firewall-manager.h"
#include "NetworkManagerUtils.h"

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
	GDBusProxy *    proxy;
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

	guint idle_id;
	GCancellable *cancellable;
} CBInfo;

static void
_cb_info_complete_and_free (CBInfo *info,
                            const char *tag,
                            const char *debug_error_match,
                            GError *error)
{
	gs_free_error GError *local = NULL;

	g_return_if_fail (info != NULL);
	g_return_if_fail (tag != NULL);

	/* A cancelled idle call won't set the error; catch that here */
	if (!error && g_cancellable_is_cancelled (info->cancellable)) {
		error = local = g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED,
		                                     "Operation was cancelled");
	}

	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		nm_log_dbg (LOGD_FIREWALL, "(%s) firewall zone %s call cancelled [%u]",
		            info->iface, tag, info->id);
	} else if (error) {
		g_dbus_error_strip_remote_error (error);
		if (!g_strcmp0 (error->message, debug_error_match)) {
			nm_log_dbg (LOGD_FIREWALL, "(%s) firewall zone %s failed [%u]: %s",
			            info->iface, tag, info->id, error->message);
		} else {
			nm_log_warn (LOGD_FIREWALL, "(%s) firewall zone %s failed [%u]: %s",
			             info->iface, tag, info->id, error->message);
		}
	} else {
		nm_log_dbg (LOGD_FIREWALL, "(%s) firewall zone %s succeeded [%u]",
		            info->iface, tag, info->id);
	}

	if (info->callback)
		info->callback (error, info->user_data);

	g_free (info->iface);
	g_object_unref (info->cancellable);
	g_slice_free (CBInfo, info);
}

static CBInfo *
_cb_info_create (NMFirewallManager *self, const char *iface, FwAddToZoneFunc callback, gpointer user_data)
{
	NMFirewallManagerPrivate *priv = NM_FIREWALL_MANAGER_GET_PRIVATE (self);
	static guint id = 1;
	CBInfo *info;

	info = g_slice_new0 (CBInfo);
	info->self = g_object_ref (self);
	info->id = id++;
	info->iface = g_strdup (iface);
	info->cancellable = g_cancellable_new ();
	info->callback = callback;
	info->user_data = user_data;

	priv->pending_calls = g_slist_prepend (priv->pending_calls, info);
	return info;
}

static gboolean
add_or_change_idle_cb (gpointer user_data)
{
	CBInfo *info = user_data;

	info->idle_id = 0;
	_cb_info_complete_and_free (info, "idle call", NULL, NULL);
	return G_SOURCE_REMOVE;
}

static void
add_or_change_cb (GObject *proxy, GAsyncResult *result, gpointer user_data)
{
	CBInfo *info = user_data;
	gs_free_error GError *error = NULL;
	gs_unref_variant GVariant *ret = NULL;

	ret = g_dbus_proxy_call_finish (G_DBUS_PROXY (proxy), result, &error);
	_cb_info_complete_and_free (info, "add/change", "ZONE_ALREADY_SET", error);
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
	g_dbus_proxy_call (priv->proxy,
	                   add ? "addInterface" : "changeZone",
	                   g_variant_new ("(ss)", zone ? zone : "", iface),
	                   G_DBUS_CALL_FLAGS_NONE, 10000,
	                   info->cancellable,
	                   add_or_change_cb, info);
	return (NMFirewallPendingCall) info;
}

static void
remove_cb (GObject *proxy, GAsyncResult *result, gpointer user_data)
{
	CBInfo *info = user_data;
	gs_free_error GError *error = NULL;
	gs_unref_variant GVariant *ret = NULL;

	ret = g_dbus_proxy_call_finish (G_DBUS_PROXY (proxy), result, &error);
	_cb_info_complete_and_free (info, "remove", "UNKNOWN_INTERFACE", error);
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
	g_dbus_proxy_call (priv->proxy,
	                   "removeInterface",
	                   g_variant_new ("(ss)", zone ? zone : "", iface),
	                   G_DBUS_CALL_FLAGS_NONE, 10000,
	                   info->cancellable,
	                   remove_cb, info);
	return (NMFirewallPendingCall) info;
}

void
nm_firewall_manager_cancel_call (NMFirewallManager *self, NMFirewallPendingCall call)
{
	CBInfo *info = (CBInfo *) call;

	g_return_if_fail (NM_IS_FIREWALL_MANAGER (self));

	info->callback = NULL;
	info->idle_id = 0;
	g_cancellable_cancel (info->cancellable);
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
name_owner_changed (GObject    *object,
                    GParamSpec *pspec,
                    gpointer    user_data)
{
	NMFirewallManager *self = NM_FIREWALL_MANAGER (user_data);
	gs_free char *owner = NULL;

	owner = g_dbus_proxy_get_name_owner (G_DBUS_PROXY (object));
	if (owner) {
		nm_log_dbg (LOGD_FIREWALL, "firewall started");
		set_running (self, TRUE);
		g_signal_emit (self, signals[STARTED], 0);
	} else {
		nm_log_dbg (LOGD_FIREWALL, "firewall stopped");
		set_running (self, FALSE);
	}
}

/*******************************************************************/

NM_DEFINE_SINGLETON_GETTER (NMFirewallManager, nm_firewall_manager_get, NM_TYPE_FIREWALL_MANAGER);

static void
nm_firewall_manager_init (NMFirewallManager * self)
{
	NMFirewallManagerPrivate *priv = NM_FIREWALL_MANAGER_GET_PRIVATE (self);
	gs_free char *owner = NULL;

	priv->proxy = g_dbus_proxy_new_for_bus_sync (G_BUS_TYPE_SYSTEM,
	                                             G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES |
	                                                 G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS,
	                                             NULL,
	                                             FIREWALL_DBUS_SERVICE,
	                                             FIREWALL_DBUS_PATH,
	                                             FIREWALL_DBUS_INTERFACE_ZONE,
	                                             NULL, NULL);

	g_signal_connect (priv->proxy, "notify::g-name-owner",
	                  G_CALLBACK (name_owner_changed), self);
	owner = g_dbus_proxy_get_name_owner (priv->proxy);
	priv->running = (owner != NULL);
	nm_log_dbg (LOGD_FIREWALL, "firewall %s running", priv->running ? "is" : "is not" );

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

