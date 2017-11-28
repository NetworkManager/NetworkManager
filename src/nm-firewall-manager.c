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
 * Copyright (C) 2011 - 2015 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-firewall-manager.h"

#include <string.h>

#include "NetworkManagerUtils.h"
#include "nm-utils/c-list.h"

/*****************************************************************************/

enum {
	STATE_CHANGED,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

typedef struct {
	GDBusProxy     *proxy;
	GCancellable   *proxy_cancellable;

	CList           pending_calls;
	bool            running;
} NMFirewallManagerPrivate;

struct _NMFirewallManager {
	GObject parent;
	NMFirewallManagerPrivate _priv;
};

struct _NMFirewallManagerClass {
	GObjectClass parent;
};

G_DEFINE_TYPE (NMFirewallManager, nm_firewall_manager, G_TYPE_OBJECT)

#define NM_FIREWALL_MANAGER_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMFirewallManager, NM_IS_FIREWALL_MANAGER)

/*****************************************************************************/

NM_DEFINE_SINGLETON_GETTER (NMFirewallManager, nm_firewall_manager_get, NM_TYPE_FIREWALL_MANAGER);

/*****************************************************************************/

typedef enum {
	CB_INFO_OPS_ADD = 1,
	CB_INFO_OPS_CHANGE,
	CB_INFO_OPS_REMOVE,
} CBInfoOpsType;

typedef enum {
	CB_INFO_MODE_IDLE = 1,
	CB_INFO_MODE_DBUS_WAITING,
	CB_INFO_MODE_DBUS,
	CB_INFO_MODE_DBUS_COMPLETED,
} CBInfoMode;

struct _NMFirewallManagerCallId {
	CList lst;
	NMFirewallManager *self;
	CBInfoOpsType ops_type;
	union {
		const CBInfoMode mode;
		CBInfoMode mode_mutable;
	};
	char *iface;
	NMFirewallManagerAddRemoveCallback callback;
	gpointer user_data;

	union {
		struct {
			GCancellable *cancellable;
			GVariant *arg;
		} dbus;
		struct {
			guint id;
		} idle;
	};
};
typedef struct _NMFirewallManagerCallId CBInfo;

/*****************************************************************************/

static const char *
_ops_type_to_string (CBInfoOpsType ops_type)
{
	switch (ops_type) {
	case CB_INFO_OPS_ADD:    return "add";
	case CB_INFO_OPS_REMOVE: return "remove";
	case CB_INFO_OPS_CHANGE: return "change";
	default: g_return_val_if_reached ("unknown");
	}
}

#define _NMLOG_DOMAIN      LOGD_FIREWALL
#define _NMLOG_PREFIX_NAME "firewall"
#define _NMLOG(level, info, ...) \
    G_STMT_START { \
        if (nm_logging_enabled ((level), (_NMLOG_DOMAIN))) { \
            CBInfo *__info = (info); \
            char __prefix_name[30]; \
            char __prefix_info[64]; \
            \
            _nm_log ((level), (_NMLOG_DOMAIN), 0, NULL, NULL, \
                     "%s: %s" _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
                     (self) != singleton_instance \
                        ? ({ \
                                g_snprintf (__prefix_name, sizeof (__prefix_name), "%s[%p]", ""_NMLOG_PREFIX_NAME, (self)); \
                                __prefix_name; \
                           }) \
                        : _NMLOG_PREFIX_NAME, \
                     __info \
                        ? ({ \
                                g_snprintf (__prefix_info, sizeof (__prefix_info), "[%p,%s%s:%s%s%s]: ", __info, \
                                            _ops_type_to_string (__info->ops_type), __info->mode == CB_INFO_MODE_IDLE ? "*" : "", \
                                            NM_PRINT_FMT_QUOTE_STRING (__info->iface)); \
                                __prefix_info; \
                           }) \
                        : "" \
                     _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
        } \
    } G_STMT_END

/*****************************************************************************/

gboolean
nm_firewall_manager_get_running (NMFirewallManager *self)
{
	g_return_val_if_fail (NM_IS_FIREWALL_MANAGER (self), FALSE);

	return NM_FIREWALL_MANAGER_GET_PRIVATE (self)->running;
}

/*****************************************************************************/

static CBInfo *
_cb_info_create (NMFirewallManager *self,
                 CBInfoOpsType ops_type,
                 const char *iface,
                 const char *zone,
                 NMFirewallManagerAddRemoveCallback callback,
                 gpointer user_data)
{
	NMFirewallManagerPrivate *priv = NM_FIREWALL_MANAGER_GET_PRIVATE (self);
	CBInfo *info;

	info = g_slice_new0 (CBInfo);
	info->self = g_object_ref (self);
	info->ops_type = ops_type;
	info->iface = g_strdup (iface);
	info->callback = callback;
	info->user_data = user_data;

	if (priv->running || priv->proxy_cancellable) {
		info->mode_mutable = CB_INFO_MODE_DBUS_WAITING;
		info->dbus.arg = g_variant_new ("(ss)", zone ? zone : "", iface);
	} else
		info->mode_mutable = CB_INFO_MODE_IDLE;

	c_list_link_tail (&priv->pending_calls, &info->lst);

	return info;
}

static void
_cb_info_free (CBInfo *info)
{
	c_list_unlink_stale (&info->lst);
	if (info->mode != CB_INFO_MODE_IDLE) {
		if (info->dbus.arg)
			g_variant_unref (info->dbus.arg);
		g_clear_object (&info->dbus.cancellable);
	}
	g_free (info->iface);
	if (info->self)
		g_object_unref (info->self);
	g_slice_free (CBInfo, info);
}

static void
_cb_info_callback (CBInfo *info,
                   GError *error)
{
	if (info->callback)
		info->callback (info->self, info, error, info->user_data);
}

static void
_cb_info_complete_normal (CBInfo *info, GError *error)
{
	NMFirewallManagerPrivate *priv = NM_FIREWALL_MANAGER_GET_PRIVATE (info->self);

	nm_assert (c_list_contains (&priv->pending_calls, &info->lst));

	c_list_unlink (&info->lst);

	_cb_info_callback (info, error);
	_cb_info_free (info);
}

static gboolean
_handle_idle (gpointer user_data)
{
	NMFirewallManager *self;
	CBInfo *info = user_data;

	nm_assert (info && NM_IS_FIREWALL_MANAGER (info->self));

	self = info->self;

	_LOGD (info, "complete: fake success");

	_cb_info_complete_normal (info, NULL);
	return G_SOURCE_REMOVE;
}

static void
_handle_dbus (GObject *proxy, GAsyncResult *result, gpointer user_data)
{
	NMFirewallManager *self;
	CBInfo *info = user_data;
	gs_free_error GError *error = NULL;
	gs_unref_variant GVariant *ret = NULL;

	if (info->mode != CB_INFO_MODE_DBUS) {
		_cb_info_free (info);
		return;
	}

	self = info->self;

	ret = g_dbus_proxy_call_finish (G_DBUS_PROXY (proxy), result, &error);

	if (error) {
		const char *non_error = NULL;

		g_dbus_error_strip_remote_error (error);

		switch (info->ops_type) {
		case CB_INFO_OPS_ADD:
		case CB_INFO_OPS_CHANGE:
			non_error = "ZONE_ALREADY_SET";
			break;
		case CB_INFO_OPS_REMOVE:
			non_error = "UNKNOWN_INTERFACE";
			break;
		}
		if (   error->message
		    && non_error
		    && g_str_has_prefix (error->message, non_error)
		    && NM_IN_SET (error->message[strlen (non_error)], '\0', ':')) {
			_LOGD (info, "complete: request failed with a non-error (%s)", error->message);

			/* The operation failed with an error reason that we don't want
			 * to propagate. Instead, signal success. */
			g_clear_error (&error);
		} else
			_LOGW (info, "complete: request failed (%s)", error->message);
	} else
		_LOGD (info, "complete: success");

	_cb_info_complete_normal (info, error);
}

static void
_handle_dbus_start (NMFirewallManager *self,
                    CBInfo *info)
{
	NMFirewallManagerPrivate *priv = NM_FIREWALL_MANAGER_GET_PRIVATE (self);
	const char *dbus_method = NULL;
	GVariant *arg;

	nm_assert (info);
	nm_assert (priv->running);
	nm_assert (info->mode == CB_INFO_MODE_DBUS_WAITING);

	switch (info->ops_type) {
	case CB_INFO_OPS_ADD:
		dbus_method = "addInterface";
		break;
	case CB_INFO_OPS_CHANGE:
		dbus_method = "changeZone";
		break;
	case CB_INFO_OPS_REMOVE:
		dbus_method = "removeInterface";
		break;
	}
	nm_assert (dbus_method);

	arg = info->dbus.arg;
	info->dbus.arg = NULL;

	nm_assert (arg && g_variant_is_floating (arg));

	info->mode_mutable = CB_INFO_MODE_DBUS;
	info->dbus.cancellable = g_cancellable_new ();

	g_dbus_proxy_call (priv->proxy,
	                   dbus_method,
	                   arg,
	                   G_DBUS_CALL_FLAGS_NONE, 10000,
	                   info->dbus.cancellable,
	                   _handle_dbus,
	                   info);
}

static NMFirewallManagerCallId
_start_request (NMFirewallManager *self,
                CBInfoOpsType ops_type,
                const char *iface,
                const char *zone,
                NMFirewallManagerAddRemoveCallback callback,
                gpointer user_data)
{
	NMFirewallManagerPrivate *priv;
	CBInfo *info;

	g_return_val_if_fail (NM_IS_FIREWALL_MANAGER (self), NULL);
	g_return_val_if_fail (iface && *iface, NULL);

	priv = NM_FIREWALL_MANAGER_GET_PRIVATE (self);

	info = _cb_info_create (self, ops_type, iface, zone, callback, user_data);

	_LOGD (info, "firewall zone %s %s:%s%s%s%s",
	       _ops_type_to_string (info->ops_type),
	       iface,
	       NM_PRINT_FMT_QUOTED (zone, "\"", zone, "\"", "default"),
	       info->mode == CB_INFO_MODE_IDLE
	         ? " (not running, simulate success)"
	         : (!priv->running
	              ? " (waiting to initialize)"
	              : ""));

	if (info->mode == CB_INFO_MODE_DBUS_WAITING) {
		if (priv->running)
			_handle_dbus_start (self, info);
		if (!info->callback) {
			/* if the user did not provide a callback, the call_id is useless.
			 * Especially, the user cannot use the call-id to cancel the request,
			 * because he cannot know whether the request is still pending.
			 *
			 * Hence, returning %NULL doesn't mean that the request could not be started
			 * (the request will always be started). */
			return NULL;
		}
	} else if (info->mode == CB_INFO_MODE_IDLE) {
		if (!info->callback) {
			/* if the user did not provide a callback and firewalld is not running,
			 * there is no point in scheduling an idle-request to fake success. Just
			 * return right away. */
			_LOGD (info, "complete: drop request simulating success");
			_cb_info_complete_normal (info, NULL);
			return NULL;
		} else
			info->idle.id = g_idle_add (_handle_idle, info);
	} else
		nm_assert_not_reached ();

	return info;
}

NMFirewallManagerCallId
nm_firewall_manager_add_or_change_zone (NMFirewallManager *self,
                                        const char *iface,
                                        const char *zone,
                                        gboolean add, /* TRUE == add, FALSE == change */
                                        NMFirewallManagerAddRemoveCallback callback,
                                        gpointer user_data)
{
	return _start_request (self,
	                       add ? CB_INFO_OPS_ADD : CB_INFO_OPS_CHANGE,
	                       iface,
	                       zone,
	                       callback,
	                       user_data);
}

NMFirewallManagerCallId
nm_firewall_manager_remove_from_zone (NMFirewallManager *self,
                                      const char *iface,
                                      const char *zone,
                                      NMFirewallManagerAddRemoveCallback callback,
                                      gpointer user_data)
{
	return _start_request (self,
	                       CB_INFO_OPS_REMOVE,
	                       iface,
	                       zone,
	                       callback,
	                       user_data);
}

void
nm_firewall_manager_cancel_call (NMFirewallManagerCallId call)
{
	NMFirewallManager *self;
	NMFirewallManagerPrivate *priv;
	CBInfo *info = call;
	gs_free_error GError *error = NULL;

	g_return_if_fail (info);
	g_return_if_fail (NM_IS_FIREWALL_MANAGER (info->self));

	self = info->self;
	priv = NM_FIREWALL_MANAGER_GET_PRIVATE (self);

	nm_assert (c_list_contains (&priv->pending_calls, &info->lst));

	c_list_unlink (&info->lst);

	nm_utils_error_set_cancelled (&error, FALSE, "NMFirewallManager");

	_LOGD (info, "complete: cancel (%s)", error->message);

	_cb_info_callback (info, error);

	if (info->mode == CB_INFO_MODE_DBUS_WAITING)
		_cb_info_free (info);
	else if (info->mode == CB_INFO_MODE_IDLE) {
		g_source_remove (info->idle.id);
		_cb_info_free (info);
	} else {
		info->mode_mutable = CB_INFO_MODE_DBUS_COMPLETED;
		g_cancellable_cancel (info->dbus.cancellable);
		g_clear_object (&info->self);
	}
}

/*****************************************************************************/

static gboolean
name_owner_changed (NMFirewallManager *self)
{
	NMFirewallManagerPrivate *priv = NM_FIREWALL_MANAGER_GET_PRIVATE (self);
	gs_free char *owner = NULL;
	gboolean now_running;

	owner = g_dbus_proxy_get_name_owner (priv->proxy);
	now_running = !!owner;

	if (now_running == priv->running)
		return FALSE;

	priv->running = now_running;
	_LOGD (NULL, "firewall %s", now_running ? "started" : "stopped");
	return TRUE;
}

static void
name_owner_changed_cb (GObject    *object,
                       GParamSpec *pspec,
                       gpointer    user_data)
{
	NMFirewallManager *self = user_data;

	nm_assert (NM_IS_FIREWALL_MANAGER (self));
	nm_assert (G_IS_DBUS_PROXY (object));
	nm_assert (NM_FIREWALL_MANAGER_GET_PRIVATE (self)->proxy == G_DBUS_PROXY (object));

	if (name_owner_changed (self))
		g_signal_emit (self, signals[STATE_CHANGED], 0, FALSE);
}

static void
_proxy_new_cb (GObject *source_object,
               GAsyncResult *result,
               gpointer user_data)
{
	NMFirewallManager *self;
	NMFirewallManagerPrivate *priv;
	GDBusProxy *proxy;
	gs_free_error GError *error = NULL;
	CBInfo *info;
	CList *iter;

	proxy = g_dbus_proxy_new_for_bus_finish (result, &error);
	if (   !proxy
	    && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = user_data;
	priv = NM_FIREWALL_MANAGER_GET_PRIVATE (self);
	g_clear_object (&priv->proxy_cancellable);

	if (!proxy) {
		_LOGW (NULL, "could not connect to system D-Bus (%s)", error->message);
		return;
	}

	priv->proxy = proxy;
	g_signal_connect (priv->proxy, "notify::g-name-owner",
	                  G_CALLBACK (name_owner_changed_cb), self);

	if (!name_owner_changed (self))
		_LOGD (NULL, "firewall %s", "initialized (not running)");

again:
	c_list_for_each (iter, &priv->pending_calls) {
		info = c_list_entry (iter, CBInfo, lst);

		if (info->mode != CB_INFO_MODE_DBUS_WAITING)
			continue;
		if (priv->running) {
			_LOGD (info, "make D-Bus call");
			_handle_dbus_start (self, info);
		} else {
			_LOGD (info, "complete: fake success");
			c_list_unlink (&info->lst);
			_cb_info_callback (info, NULL);
			_cb_info_free (info);
			goto again;
		}
	}

	/* we always emit a state-changed signal, even if the
	 * "running" property is still false. */
	g_signal_emit (self, signals[STATE_CHANGED], 0, TRUE);
}

/*****************************************************************************/

static void
nm_firewall_manager_init (NMFirewallManager * self)
{
	NMFirewallManagerPrivate *priv = NM_FIREWALL_MANAGER_GET_PRIVATE (self);

	c_list_init (&priv->pending_calls);
}

static void
constructed (GObject *object)
{
	NMFirewallManager *self = (NMFirewallManager *) object;
	NMFirewallManagerPrivate *priv = NM_FIREWALL_MANAGER_GET_PRIVATE (self);

	priv->proxy_cancellable = g_cancellable_new ();

	g_dbus_proxy_new_for_bus (G_BUS_TYPE_SYSTEM,
	                            G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES
	                          | G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS,
	                          NULL,
	                          FIREWALL_DBUS_SERVICE,
	                          FIREWALL_DBUS_PATH,
	                          FIREWALL_DBUS_INTERFACE_ZONE,
	                          priv->proxy_cancellable,
	                          _proxy_new_cb,
	                          self);

	G_OBJECT_CLASS (nm_firewall_manager_parent_class)->constructed (object);
}

static void
dispose (GObject *object)
{
	NMFirewallManager *self = NM_FIREWALL_MANAGER (object);
	NMFirewallManagerPrivate *priv = NM_FIREWALL_MANAGER_GET_PRIVATE (self);

	/* as every pending operation takes a reference to the manager,
	 * we don't expect pending operations at this point. */
	nm_assert (c_list_is_empty (&priv->pending_calls));

	nm_clear_g_cancellable (&priv->proxy_cancellable);
	g_clear_object (&priv->proxy);

	G_OBJECT_CLASS (nm_firewall_manager_parent_class)->dispose (object);
}

static void
nm_firewall_manager_class_init (NMFirewallManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->constructed = constructed;
	object_class->dispose = dispose;

	signals[STATE_CHANGED] =
	    g_signal_new (NM_FIREWALL_MANAGER_STATE_CHANGED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0,
	                  NULL, NULL,
	                  g_cclosure_marshal_VOID__BOOLEAN,
	                  G_TYPE_NONE, 1,
	                  G_TYPE_BOOLEAN /* initialized_now */);
}
