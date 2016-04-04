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

	GHashTable     *pending_calls;
} NMFirewallManagerPrivate;

enum {
	STARTED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

NM_DEFINE_SINGLETON_GETTER (NMFirewallManager, nm_firewall_manager_get, NM_TYPE_FIREWALL_MANAGER);

/********************************************************************/

typedef enum {
	CB_INFO_OPS_ADD = 1,
	CB_INFO_OPS_CHANGE,
	CB_INFO_OPS_REMOVE,
} CBInfoOpsType;

typedef enum {
	CB_INFO_MODE_IDLE = 1,
	CB_INFO_MODE_DBUS,
	CB_INFO_MODE_DBUS_COMPLETED,
} CBInfoMode;

struct _NMFirewallManagerCallId {
	NMFirewallManager *self;
	CBInfoOpsType ops_type;
	CBInfoMode mode;
	char *iface;
	NMFirewallManagerAddRemoveCallback callback;
	gpointer user_data;

	union {
		struct {
			GCancellable *cancellable;
		} dbus;
		struct {
			guint id;
		} idle;
	};
};
typedef struct _NMFirewallManagerCallId CBInfo;

/********************************************************************/

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
            _nm_log ((level), (_NMLOG_DOMAIN), 0, \
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
                                            _ops_type_to_string (__info->ops_type), _cb_info_is_idle (__info) ? "*" : "", \
                                            NM_PRINT_FMT_QUOTE_STRING (__info->iface)); \
                                __prefix_info; \
                           }) \
                        : "" \
                     _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
        } \
    } G_STMT_END

/********************************************************************/

static gboolean
_cb_info_is_idle (CBInfo *info)
{
	return info->mode == CB_INFO_MODE_IDLE;
}

static CBInfo *
_cb_info_create (NMFirewallManager *self,
                 CBInfoOpsType ops_type,
                 const char *iface,
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

	if (priv->running) {
		info->mode = CB_INFO_MODE_DBUS;
		info->dbus.cancellable = g_cancellable_new ();
	} else
		info->mode = CB_INFO_MODE_IDLE;

	if (!nm_g_hash_table_add (priv->pending_calls, info))
		g_return_val_if_reached (NULL);

	return info;
}

static void
_cb_info_free (CBInfo *info)
{
	if (!_cb_info_is_idle (info))
		g_object_unref (info->dbus.cancellable);
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

	if (!g_hash_table_remove (priv->pending_calls, info))
		g_return_if_reached ();

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
		if (!g_strcmp0 (error->message, non_error)) {
			_LOGD (info, "complete: request failed with a non-error (%s)", error->message);

			/* The operation failed with an error reason that we don't want
			 * to propagate. Instead, signal success. */
			g_clear_error (&error);
		}
		else
			_LOGW (info, "complete: request failed (%s)", error->message);
	} else
		_LOGD (info, "complete: success");

	_cb_info_complete_normal (info, error);
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
	const char *dbus_method;

	g_return_val_if_fail (NM_IS_FIREWALL_MANAGER (self), NULL);
	g_return_val_if_fail (iface && *iface, NULL);

	priv = NM_FIREWALL_MANAGER_GET_PRIVATE (self);

	info = _cb_info_create (self, ops_type, iface, callback, user_data);

	_LOGD (info, "firewall zone %s %s:%s%s%s%s",
	       _ops_type_to_string (info->ops_type),
	       iface,
	       NM_PRINT_FMT_QUOTED (zone, "\"", zone, "\"", "default"),
	       _cb_info_is_idle (info) ? " (not running, simulate success)" : "");

	if (!_cb_info_is_idle (info)) {

		switch (ops_type) {
		case CB_INFO_OPS_ADD:
			dbus_method = "addInterface";
			break;
		case CB_INFO_OPS_CHANGE:
			dbus_method = "changeZone";
			break;
		case CB_INFO_OPS_REMOVE:
			dbus_method = "removeInterface";
			break;
		default:
			g_assert_not_reached ();
		}

		g_dbus_proxy_call (priv->proxy,
		                   dbus_method,
		                   g_variant_new ("(ss)", zone ? zone : "", iface),
		                   G_DBUS_CALL_FLAGS_NONE, 10000,
		                   info->dbus.cancellable,
		                   _handle_dbus,
		                   info);

		if (!info->callback) {
			/* if the user did not provide a callback, the call_id is useless.
			 * Especially, the user cannot use the call-id to cancel the request,
			 * because he cannot know whether the request is still pending.
			 *
			 * Hence, returning %NULL doesn't mean that the request could not be started
			 * (the request will always be started). */
			return NULL;
		}
	} else if (!info->callback) {
		/* if the user did not provide a callback and firewalld is not running,
		 * there is no point in scheduling an idle-request to fake success. Just
		 * return right away. */
		_LOGD (info, "complete: drop request simulating success");
		_cb_info_complete_normal (info, NULL);
		return NULL;
	} else
		info->idle.id = g_idle_add (_handle_idle, info);

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

	if (!g_hash_table_remove (priv->pending_calls, info))
		g_return_if_reached ();

	nm_utils_error_set_cancelled (&error, FALSE, "NMFirewallManager");

	_LOGD (info, "complete: cancel (%s)", error->message);

	_cb_info_callback (info, error);

	if (_cb_info_is_idle (info)) {
		g_source_remove (info->idle.id);
		_cb_info_free (info);
	} else {
		info->mode = CB_INFO_MODE_DBUS_COMPLETED;
		g_cancellable_cancel (info->dbus.cancellable);
		g_clear_object (&info->self);
	}
}

/*******************************************************************/

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
		_LOGD (NULL, "firewall started");
		set_running (self, TRUE);
		g_signal_emit (self, signals[STARTED], 0);
	} else {
		_LOGD (NULL, "firewall stopped");
		set_running (self, FALSE);
	}
}

/*******************************************************************/

static void
nm_firewall_manager_init (NMFirewallManager * self)
{
	NMFirewallManagerPrivate *priv = NM_FIREWALL_MANAGER_GET_PRIVATE (self);

	priv->pending_calls = g_hash_table_new (g_direct_hash, g_direct_equal);
}

static void
constructed (GObject *object)
{
	NMFirewallManager *self = (NMFirewallManager *) object;
	NMFirewallManagerPrivate *priv = NM_FIREWALL_MANAGER_GET_PRIVATE (self);
	gs_free char *owner = NULL;
	gs_free_error GError *error = NULL;

	G_OBJECT_CLASS (nm_firewall_manager_parent_class)->constructed (object);

	priv->proxy = g_dbus_proxy_new_for_bus_sync (G_BUS_TYPE_SYSTEM,
	                                             G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES |
	                                                 G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS,
	                                             NULL,
	                                             FIREWALL_DBUS_SERVICE,
	                                             FIREWALL_DBUS_PATH,
	                                             FIREWALL_DBUS_INTERFACE_ZONE,
	                                             NULL, &error);
        if (priv->proxy) {
		g_signal_connect (priv->proxy, "notify::g-name-owner",
				  G_CALLBACK (name_owner_changed), self);
		owner = g_dbus_proxy_get_name_owner (priv->proxy);
		priv->running = (owner != NULL);
        } else {
                _LOGW (NULL, "could not connect to system D-Bus (%s)", error->message);
	}

	_LOGD (NULL, "firewall constructed (%srunning)", priv->running ? "" : "not");
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
	NMFirewallManager *self = NM_FIREWALL_MANAGER (object);
	NMFirewallManagerPrivate *priv = NM_FIREWALL_MANAGER_GET_PRIVATE (self);

	if (priv->pending_calls) {
		/* as every pending operation takes a reference to the manager,
		 * we don't expect pending operations at this point. */
		g_assert (g_hash_table_size (priv->pending_calls) == 0);
		g_hash_table_unref (priv->pending_calls);
		priv->pending_calls = NULL;
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

	object_class->constructed = constructed;
	object_class->get_property = get_property;
	object_class->dispose = dispose;

	g_object_class_install_property
	    (object_class, PROP_AVAILABLE,
	     g_param_spec_boolean (NM_FIREWALL_MANAGER_AVAILABLE, "", "",
	                           FALSE,
	                           G_PARAM_READABLE |
	                           G_PARAM_STATIC_STRINGS));

	signals[STARTED] =
	    g_signal_new (NM_FIREWALL_MANAGER_STARTED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  G_STRUCT_OFFSET (NMFirewallManagerClass, started),
	                  NULL, NULL,
	                  g_cclosure_marshal_VOID__VOID,
	                  G_TYPE_NONE, 0);

}

