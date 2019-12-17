// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-client.h"

#include <libudev.h>

#include "nm-std-aux/c-list-util.h"
#include "nm-glib-aux/nm-c-list.h"
#include "nm-glib-aux/nm-dbus-aux.h"
#include "nm-libnm-core-intern/nm-common-macros.h"

#include "nm-access-point.h"
#include "nm-active-connection.h"
#include "nm-checkpoint.h"
#include "nm-core-internal.h"
#include "nm-dbus-helpers.h"
#include "nm-device-6lowpan.h"
#include "nm-device-adsl.h"
#include "nm-device-bond.h"
#include "nm-device-bridge.h"
#include "nm-device-bt.h"
#include "nm-device-dummy.h"
#include "nm-device-ethernet.h"
#include "nm-device-generic.h"
#include "nm-device-infiniband.h"
#include "nm-device-ip-tunnel.h"
#include "nm-device-macsec.h"
#include "nm-device-macvlan.h"
#include "nm-device-modem.h"
#include "nm-device-olpc-mesh.h"
#include "nm-device-ovs-bridge.h"
#include "nm-device-ovs-interface.h"
#include "nm-device-ovs-port.h"
#include "nm-device-ppp.h"
#include "nm-device-team.h"
#include "nm-device-tun.h"
#include "nm-device-vlan.h"
#include "nm-device-vxlan.h"
#include "nm-device-wifi-p2p.h"
#include "nm-device-wifi.h"
#include "nm-device-wireguard.h"
#include "nm-device-wpan.h"
#include "nm-dhcp-config.h"
#include "nm-dhcp4-config.h"
#include "nm-dhcp6-config.h"
#include "nm-dns-manager.h"
#include "nm-ip4-config.h"
#include "nm-ip6-config.h"
#include "nm-object-private.h"
#include "nm-remote-connection.h"
#include "nm-utils.h"
#include "nm-vpn-connection.h"
#include "nm-wifi-p2p-peer.h"

/*****************************************************************************/

NM_CACHED_QUARK_FCN ("nm-context-busy-watcher", nm_context_busy_watcher_quark)

static void
_context_busy_watcher_attach_integration_source_cb (gpointer data,
                                                    GObject *where_the_object_was)
{
	nm_g_source_destroy_and_unref (data);
}

void
nm_context_busy_watcher_integrate_source (GMainContext *outer_context,
                                          GMainContext *inner_context,
                                          GObject *context_busy_watcher)
{
	GSource *source;

	nm_assert (outer_context);
	nm_assert (inner_context);
	nm_assert (outer_context != inner_context);
	nm_assert (G_IS_OBJECT (context_busy_watcher));

	source = nm_utils_g_main_context_create_integrate_source (inner_context);
	g_source_attach (source, outer_context);

	/* The problem is...
	 *
	 * NMClient is associated with a GMainContext, just like its underlying GDBusConnection
	 * also queues signals and callbacks on that main context. During operation, NMClient
	 * will schedule async operations which will return asynchronously on the GMainContext.
	 *
	 * Note that depending on whether NMClient got initialized synchronously or asynchronously,
	 * it has an internal priv->dbus_context that is different from the outer priv->main_context.
	 * However, the problem is in both cases.
	 *
	 * So, as long as there are pending D-Bus calls, the GMainContext is referenced and kept alive.
	 * When NMClient gets destroyed, the pending calls get cancelled, but the async callback are still
	 * scheduled to return.
	 * That means, the main context stays alive until it gets iterated long enough so that all pending
	 * operations are completed.
	 *
	 * Note that pending operations don't keep NMClient alive, so NMClient can already be gone by
	 * then, but the user still should iterate the main context long enough to process the (cancelled)
	 * callbacks... at least, if the user cares about whether the remaining memory and file descriptors
	 * of the GMainContext can be reclaimed.
	 *
	 * In hindsight, maybe pending references should kept NMClient alive. But then NMClient would
	 * need a special "shutdown()" API that the user must invoke, because unrefing would no longer
	 * be enough to ensure a shutdown (imagine a situation where NMClient receives a constant flow
	 * of "CheckPermissions" signals, which keeps retriggering an async request). Anyway, we cannot
	 * add such a shutdown API now, as it would break client's expectations that they can just unref
	 * the NMClient to destroy it.
	 *
	 * So, we allow NMClient to unref, but the user is advised to keep iterating the main context.
	 * But for how long? Here comes nm_client_get_context_busy_watcher() into play. The user may
	 * subscribe a weak pointer to that instance and should keep iterating as long as the object
	 * exists.
	 *
	 * Now, back to synchronous initialization. Here we have the internal priv->dbus_context context.
	 * We also cannot remove that context right away, instead we need to keep it integrated in the
	 * caller's priv->main_context as long as we have pending calls: that is, as long as the
	 * context-busy-watcher is alive.
	 */

	g_object_weak_ref (context_busy_watcher,
	                   _context_busy_watcher_attach_integration_source_cb,
	                   source);
}

/*****************************************************************************/

typedef struct {

	/* It is quite wasteful to require 2 pointers per property (of an instance) only to track whether
	 * the property got changed. But it's convenient! */
	CList changed_prop_lst;

	GVariant *prop_data_value;
} NMLDBusObjPropData;

typedef struct {
	CList iface_lst;
	union {
		const NMLDBusMetaIface *meta;
		NMRefString *name;
	} dbus_iface;

	CList changed_prop_lst_head;

	/* We also keep track of non-well known interfaces. The presence of a D-Bus interface
	 * is what makes a D-Bus alive or not. As we should track all D-Bus objects, we also
	 * need to track whether there are any interfaces on it -- even if we otherwise don't
	 * care about the interface. */
	bool dbus_iface_is_wellknown:1;

	/* if TRUE, the interface is about to be removed. */
	bool iface_removed:1;

	bool nmobj_checked:1;
	bool nmobj_compatible:1;

	NMLDBusObjPropData prop_datas[];
} NMLDBusObjIfaceData;

/* The dbus_path must be the first element, so when we hash the object by the dbus_path,
 * we also can lookup the object by only having a NMRefString at hand
 * using nm_pdirect_hash()/nm_pdirect_equal(). */
G_STATIC_ASSERT (G_STRUCT_OFFSET (NMLDBusObject, dbus_path) == 0);

typedef void (*NMLDBusObjWatchNotifyFcn) (NMClient *client,
                                          gpointer obj_watcher);

struct _NMLDBusObjWatcher {
	NMLDBusObject *dbobj;
	struct {
		CList watcher_lst;
		NMLDBusObjWatchNotifyFcn notify_fcn;
	} _priv;
};

typedef struct {
	NMLDBusObjWatcher parent;
	gpointer user_data;
} NMLDBusObjWatcherWithPtr;

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NMClient,
	PROP_DBUS_CONNECTION,
	PROP_DBUS_NAME_OWNER,
	PROP_VERSION,
	PROP_INSTANCE_FLAGS,
	PROP_STATE,
	PROP_STARTUP,
	PROP_NM_RUNNING,
	PROP_NETWORKING_ENABLED,
	PROP_WIRELESS_ENABLED,
	PROP_WIRELESS_HARDWARE_ENABLED,
	PROP_WWAN_ENABLED,
	PROP_WWAN_HARDWARE_ENABLED,
	PROP_WIMAX_ENABLED,
	PROP_WIMAX_HARDWARE_ENABLED,
	PROP_ACTIVE_CONNECTIONS,
	PROP_CONNECTIVITY,
	PROP_CONNECTIVITY_CHECK_URI,
	PROP_CONNECTIVITY_CHECK_AVAILABLE,
	PROP_CONNECTIVITY_CHECK_ENABLED,
	PROP_PRIMARY_CONNECTION,
	PROP_ACTIVATING_CONNECTION,
	PROP_DEVICES,
	PROP_ALL_DEVICES,
	PROP_CONNECTIONS,
	PROP_HOSTNAME,
	PROP_CAN_MODIFY,
	PROP_METERED,
	PROP_DNS_MODE,
	PROP_DNS_RC_MANAGER,
	PROP_DNS_CONFIGURATION,
	PROP_CHECKPOINTS,
	PROP_CAPABILITIES,
	PROP_PERMISSIONS_STATE,
);

enum {
	DEVICE_ADDED,
	DEVICE_REMOVED,
	ANY_DEVICE_ADDED,
	ANY_DEVICE_REMOVED,
	PERMISSION_CHANGED,
	CONNECTION_ADDED,
	CONNECTION_REMOVED,
	ACTIVE_CONNECTION_ADDED,
	ACTIVE_CONNECTION_REMOVED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROPERTY_O_IDX_NM_ACTIVATING_CONNECTION = 0,
	PROPERTY_O_IDX_NM_PRIMAY_CONNECTION,
	_PROPERTY_O_IDX_NM_NUM,
};

enum {
	PROPERTY_AO_IDX_DEVICES = 0,
	PROPERTY_AO_IDX_ALL_DEVICES,
	PROPERTY_AO_IDX_ACTIVE_CONNECTIONS,
	PROPERTY_AO_IDX_CHECKPOINTS,
	_PROPERTY_AO_IDX_NM_NUM,
};

typedef struct {
	struct udev *udev;
	GMainContext *main_context;
	GMainContext *dbus_context;
	GObject *context_busy_watcher;
	GDBusConnection *dbus_connection;
	NMLInitData *init_data;
	GHashTable *dbus_objects;
	CList obj_changed_lst_head;
	GCancellable *name_owner_get_cancellable;
	GCancellable *get_managed_objects_cancellable;

	CList queue_notify_lst_head;
	CList notify_event_lst_head;

	CList dbus_objects_lst_head_watched_only;
	CList dbus_objects_lst_head_on_dbus;
	CList dbus_objects_lst_head_with_nmobj_not_ready;
	CList dbus_objects_lst_head_with_nmobj_ready;

	NMLDBusObject *dbobj_nm;
	NMLDBusObject *dbobj_settings;
	NMLDBusObject *dbobj_dns_manager;

	guint8 *permissions;
	GCancellable *permissions_cancellable;

	char *name_owner;
	guint name_owner_changed_id;
	guint dbsid_nm_object_manager;
	guint dbsid_dbus_properties_properties_changed;
	guint dbsid_nm_settings_connection_updated;
	guint dbsid_nm_connection_active_state_changed;
	guint dbsid_nm_vpn_connection_state_changed;
	guint dbsid_nm_check_permissions;

	NMClientInstanceFlags instance_flags:3;

	NMTernary permissions_state:3;

	bool instance_flags_constructed:1;

	bool udev_inited:1;
	bool notify_event_lst_changed:1;
	bool check_dbobj_visible_all:1;
	bool nm_running:1;

	struct {
		NMLDBusPropertyO property_o[_PROPERTY_O_IDX_NM_NUM];
		NMLDBusPropertyAO property_ao[_PROPERTY_AO_IDX_NM_NUM];
		char *connectivity_check_uri;
		char *version;
		guint32 *capabilities_arr;
		gsize capabilities_len;
		guint32 connectivity;
		guint32 state;
		guint32 metered;
		bool connectivity_check_available;
		bool connectivity_check_enabled;
		bool networking_enabled;
		bool startup;
		bool wireless_enabled;
		bool wireless_hardware_enabled;
		bool wwan_enabled;
		bool wwan_hardware_enabled;
	} nm;

	struct {
		NMLDBusPropertyAO connections;
		char *hostname;
		bool can_modify;
	} settings;

	struct {
		GPtrArray *configuration;
		char *mode;
		char *rc_manager;
	} dns_manager;

} NMClientPrivate;

struct _NMClient {
	union {
		GObject parent;
		NMObjectBase obj_base;
	};
	NMClientPrivate _priv;
};

struct _NMClientClass {
	union {
		GObjectClass parent;
		NMObjectBaseClass obj_base;
	};
};

static void nm_client_initable_iface_init (GInitableIface *iface);
static void nm_client_async_initable_iface_init (GAsyncInitableIface *iface);

G_DEFINE_TYPE_WITH_CODE (NMClient, nm_client, G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, nm_client_initable_iface_init);
                         G_IMPLEMENT_INTERFACE (G_TYPE_ASYNC_INITABLE, nm_client_async_initable_iface_init);
                         )

#define NM_CLIENT_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMClient, NM_IS_CLIENT)

/*****************************************************************************/

static void _init_start_check_complete (NMClient *self);

static void name_owner_changed_cb (GDBusConnection *connection,
                                   const char *sender_name,
                                   const char *object_path,
                                   const char *interface_name,
                                   const char *signal_name,
                                   GVariant *parameters,
                                   gpointer user_data);

static void name_owner_get_call (NMClient *self);

static void _set_nm_running (NMClient *self);

/*****************************************************************************/

static NMRefString *_dbus_path_nm          = NULL;
static NMRefString *_dbus_path_settings    = NULL;
static NMRefString *_dbus_path_dns_manager = NULL;

/*****************************************************************************/

NM_UTILS_LOOKUP_STR_DEFINE_STATIC (nml_dbus_obj_state_to_string, NMLDBusObjState,
	NM_UTILS_LOOKUP_DEFAULT_WARN ("???"),
	NM_UTILS_LOOKUP_ITEM (NML_DBUS_OBJ_STATE_UNLINKED,             "unlinked"),
	NM_UTILS_LOOKUP_ITEM (NML_DBUS_OBJ_STATE_WATCHED_ONLY,         "watched-only"),
	NM_UTILS_LOOKUP_ITEM (NML_DBUS_OBJ_STATE_ON_DBUS,              "on-dbus"),
	NM_UTILS_LOOKUP_ITEM (NML_DBUS_OBJ_STATE_WITH_NMOBJ_NOT_READY, "not-ready"),
	NM_UTILS_LOOKUP_ITEM (NML_DBUS_OBJ_STATE_WITH_NMOBJ_READY,     "ready"),
);

/*****************************************************************************/

/**
 * nm_client_error_quark:
 *
 * Registers an error quark for #NMClient if necessary.
 *
 * Returns: the error quark used for #NMClient errors.
 **/
NM_CACHED_QUARK_FCN ("nm-client-error-quark", nm_client_error_quark)

/*****************************************************************************/

NMLInitData *
nml_init_data_new_sync (GCancellable *cancellable,
                        GMainLoop *main_loop,
                        GError **error_location)
{
	NMLInitData *init_data;

	init_data = g_slice_new (NMLInitData);
	*init_data = (NMLInitData) {
		.cancellable = nm_g_object_ref (cancellable),
		.is_sync     = TRUE,
		.data.sync   = {
			.main_loop      = main_loop,
			.error_location = error_location,
		},
	};
	return init_data;
}

NMLInitData *
nml_init_data_new_async (GCancellable *cancellable,
                         GTask *task_take)
{
	NMLInitData *init_data;

	init_data = g_slice_new (NMLInitData);
	*init_data = (NMLInitData) {
		.cancellable = nm_g_object_ref (cancellable),
		.is_sync     = FALSE,
		.data.async  = {
			.task = g_steal_pointer (&task_take),
		},
	};
	return init_data;
}

/*****************************************************************************/

GError *
_nm_client_new_error_nm_not_running (void)
{
	return g_error_new_literal (NM_CLIENT_ERROR,
	                            NM_CLIENT_ERROR_MANAGER_NOT_RUNNING,
	                            "NetworkManager is not running");
}

GError *
_nm_client_new_error_nm_not_cached (void)
{
	return g_error_new_literal (NM_CLIENT_ERROR,
	                            NM_CLIENT_ERROR_FAILED,
	                            "Object is no longer in the client cache");
}

static void
_nm_client_dbus_call_simple_cb (GObject *source, GAsyncResult *result, gpointer data)
{
	GAsyncReadyCallback callback;
	gpointer user_data;
	gs_unref_object GObject *context_busy_watcher = NULL;

	nm_utils_user_data_unpack (data, &callback, &user_data, &context_busy_watcher);

	callback (source, result, user_data);
}

void
_nm_client_dbus_call_simple (NMClient *self,
                             GCancellable *cancellable,
                             const char *object_path,
                             const char *interface_name,
                             const char *method_name,
                             GVariant *parameters,
                             const GVariantType *reply_type,
                             GDBusCallFlags flags,
                             int timeout_msec,
                             GAsyncReadyCallback callback,
                             gpointer user_data)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (self);
	nm_auto_pop_gmaincontext GMainContext *dbus_context = NULL;

	nm_assert (priv->name_owner);
	nm_assert (!cancellable || G_IS_CANCELLABLE (cancellable));
	nm_assert (callback);
	nm_assert (object_path);
	nm_assert (interface_name);
	nm_assert (method_name);
	nm_assert (parameters);
	nm_assert (reply_type);

	dbus_context = nm_g_main_context_push_thread_default_if_necessary (priv->dbus_context);

	g_dbus_connection_call (priv->dbus_connection,
	                        priv->name_owner,
	                        object_path,
	                        interface_name,
	                        method_name,
	                        parameters,
	                        reply_type,
	                        flags,
	                        timeout_msec,
	                        cancellable,
	                        _nm_client_dbus_call_simple_cb,
	                        nm_utils_user_data_pack (callback, user_data, g_object_ref (priv->context_busy_watcher)));
}

void
_nm_client_dbus_call (NMClient *self,
                      gpointer source_obj,
                      gpointer source_tag,
                      GCancellable *cancellable,
                      GAsyncReadyCallback user_callback,
                      gpointer user_callback_data,
                      const char *object_path,
                      const char *interface_name,
                      const char *method_name,
                      GVariant *parameters,
                      const GVariantType *reply_type,
                      GDBusCallFlags flags,
                      int timeout_msec,
                      GAsyncReadyCallback internal_callback)
{
	NMClientPrivate *priv;
	gs_unref_object GTask *task = NULL;

	nm_assert (!source_obj || G_IS_OBJECT (source_obj));
	nm_assert (source_tag);
	nm_assert (!cancellable || G_IS_CANCELLABLE (cancellable));
	nm_assert (internal_callback);
	nm_assert (object_path);
	nm_assert (interface_name);
	nm_assert (method_name);
	nm_assert (parameters);
	nm_assert (reply_type);

	task = nm_g_task_new (source_obj, cancellable, source_tag, user_callback, user_callback_data);

	if (!self) {
		nm_g_variant_unref_floating (parameters);
		g_task_return_error (task, _nm_client_new_error_nm_not_cached ());
		return;
	}

	priv = NM_CLIENT_GET_PRIVATE (self);
	if (!priv->name_owner) {
		nm_g_variant_unref_floating (parameters);
		g_task_return_error (task, _nm_client_new_error_nm_not_running ());
		return;
	}

	_nm_client_dbus_call_simple (self,
	                             cancellable,
	                             object_path,
	                             interface_name,
	                             method_name,
	                             parameters,
	                             reply_type,
	                             flags,
	                             timeout_msec,
	                             internal_callback,
	                             g_steal_pointer (&task));
}

GVariant *
_nm_client_dbus_call_sync (NMClient *self,
                           GCancellable *cancellable,
                           const char *object_path,
                           const char *interface_name,
                           const char *method_name,
                           GVariant *parameters,
                           const GVariantType *reply_type,
                           GDBusCallFlags flags,
                           int timeout_msec,
                           gboolean strip_dbus_error,
                           GError **error)
{
	NMClientPrivate *priv;
	gs_unref_variant GVariant *ret = NULL;

	nm_assert (!cancellable || G_IS_CANCELLABLE (cancellable));
	nm_assert (!error || !*error);
	nm_assert (object_path);
	nm_assert (interface_name);
	nm_assert (method_name);
	nm_assert (parameters);
	nm_assert (reply_type);

	if (!self) {
		nm_g_variant_unref_floating (parameters);
		nm_g_set_error_take_lazy (error, _nm_client_new_error_nm_not_cached ());
		return NULL;
	}

	priv = NM_CLIENT_GET_PRIVATE (self);
	if (!priv->name_owner) {
		nm_g_variant_unref_floating (parameters);
		nm_g_set_error_take_lazy (error, _nm_client_new_error_nm_not_running ());
		return NULL;
	}

	ret = g_dbus_connection_call_sync (priv->dbus_connection,
	                                   priv->name_owner,
	                                   object_path,
	                                   interface_name,
	                                   method_name,
	                                   parameters,
	                                   reply_type,
	                                   flags,
	                                   timeout_msec,
	                                   cancellable,
	                                   error);
	if (!ret) {
		if (error && strip_dbus_error)
			g_dbus_error_strip_remote_error (*error);
		return NULL;
	}

	return g_steal_pointer (&ret);
}

gboolean
_nm_client_dbus_call_sync_void (NMClient *self,
                                GCancellable *cancellable,
                                const char *object_path,
                                const char *interface_name,
                                const char *method_name,
                                GVariant *parameters,
                                GDBusCallFlags flags,
                                int timeout_msec,
                                gboolean strip_dbus_error,
                                GError **error)
{
	gs_unref_variant GVariant *ret = NULL;

	ret = _nm_client_dbus_call_sync (self,
	                                 cancellable,
	                                 object_path,
	                                 interface_name,
	                                 method_name,
	                                 parameters,
	                                 G_VARIANT_TYPE ("()"),
	                                 flags,
	                                 timeout_msec,
	                                 strip_dbus_error,
	                                 error);
	return !!ret;
}

void
_nm_client_set_property_sync_legacy (NMClient *self,
                                     const char *object_path,
                                     const char *interface_name,
                                     const char *property_name,
                                     const char *format_string,
                                     ...)
{
	NMClientPrivate *priv;
	GVariant *val;
	gs_unref_variant GVariant *ret = NULL;
	va_list ap;

	nm_assert (!self || NM_IS_CLIENT (self));
	nm_assert (interface_name);
	nm_assert (property_name);
	nm_assert (format_string);

	if (!self)
		return;

	priv = NM_CLIENT_GET_PRIVATE (self);
	if (!priv->name_owner)
		return;

	va_start (ap, format_string);
	val = g_variant_new_va (format_string, NULL, &ap);
	va_end (ap);

	nm_assert (val);

	/* A synchronous D-Bus call that is not cancellable an ignores the return value.
	 * This function only exists for backward compatibility. */
	ret = g_dbus_connection_call_sync (priv->dbus_connection,
	                                   priv->name_owner,
	                                   object_path,
	                                   DBUS_INTERFACE_PROPERTIES,
	                                   "Set",
	                                   g_variant_new ("(ssv)",
	                                                  interface_name,
	                                                  property_name,
	                                                  val),
	                                   NULL,
	                                   G_DBUS_CALL_FLAGS_NONE,
	                                   2000,
	                                   NULL,
	                                   NULL);
}

/*****************************************************************************/

#define _assert_main_context_is_current_source(self, x_context) \
	G_STMT_START { \
		if (NM_MORE_ASSERTS > 0) { \
			GSource *_source = g_main_current_source (); \
			\
			if (_source) { \
				NMClientPrivate *_priv = NM_CLIENT_GET_PRIVATE (self); \
				\
				nm_assert (g_source_get_context (_source) == _priv->x_context); \
				nm_assert (g_main_context_is_owner (_priv->x_context)); \
			} \
		} \
	} G_STMT_END

#define _assert_main_context_is_current_thread_default(self, x_context) \
	G_STMT_START { \
		if (NM_MORE_ASSERTS > 0) { \
			NMClientPrivate *_priv = NM_CLIENT_GET_PRIVATE (self); \
			\
			nm_assert ((g_main_context_get_thread_default () ?: g_main_context_default ()) == _priv->x_context); \
			nm_assert (g_main_context_is_owner (_priv->x_context)); \
		} \
	} G_STMT_END

/*****************************************************************************/

void
_nm_client_queue_notify_object (NMClient *self,
                                gpointer nmobj,
                                const GParamSpec *pspec)
{
	NMObjectBase *base;

	nm_assert (NM_IS_CLIENT (self));
	nm_assert (NM_IS_OBJECT (nmobj) || NM_IS_CLIENT (nmobj));

	base = (NMObjectBase *) nmobj;

	if (base->is_disposing) {
		/* Don't emit property changed signals once the NMClient
		 * instance is about to shut down. */
		nm_assert (nmobj == self);
		return;
	}

	if (c_list_is_empty (&base->queue_notify_lst)) {
		c_list_link_tail (&NM_CLIENT_GET_PRIVATE (self)->queue_notify_lst_head,
		                  &base->queue_notify_lst);
		g_object_ref (nmobj);
		g_object_freeze_notify (nmobj);
	}

	if (pspec)
		g_object_notify_by_pspec (nmobj, (GParamSpec *) pspec);
}

/*****************************************************************************/

gpointer
_nm_client_notify_event_queue (NMClient *self,
                               int priority,
                               NMClientNotifyEventCb callback,
                               gsize event_size)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (self);
	NMClientNotifyEvent *notify_event;

	nm_assert (callback);
	nm_assert (event_size > sizeof (NMClientNotifyEvent));

	notify_event = g_malloc (event_size);
	notify_event->priority = priority;
	notify_event->callback = callback;
	c_list_link_tail (&priv->notify_event_lst_head, &notify_event->lst);
	priv->notify_event_lst_changed = TRUE;
	return notify_event;
}

NMClientNotifyEventWithPtr *
_nm_client_notify_event_queue_with_ptr (NMClient *self,
                                        int priority,
                                        NMClientNotifyEventWithPtrCb callback,
                                        gpointer user_data)
{
	NMClientNotifyEventWithPtr *notify_event;

	notify_event = _nm_client_notify_event_queue (self,
	                                              priority,
	                                              (NMClientNotifyEventCb) callback,
	                                              sizeof (NMClientNotifyEventWithPtr));
	notify_event->user_data = user_data;
	return notify_event;
}

/*****************************************************************************/

typedef struct {
	NMClientNotifyEvent parent;
	GObject *source;
	NMObject *obj;
	guint signal_id;
} NMClientNotifyEventObjAddedRemove;

static void
_nm_client_notify_event_queue_emit_obj_signal_cb (NMClient *self,
                                                  gpointer notify_event_base)
{
	NMClientNotifyEventObjAddedRemove *notify_event = notify_event_base;

	NML_NMCLIENT_LOG_T (self, "[%s] emit \"%s\" signal for %s",
	                      NM_IS_CLIENT (notify_event->source)
	                    ? "nmclient"
	                    : _nm_object_get_path (notify_event->source),
	                    g_signal_name (notify_event->signal_id),
	                    _nm_object_get_path (notify_event->obj));

	nm_assert (   NM_IS_OBJECT (notify_event->source)
	           || NM_IS_CLIENT (notify_event->source));

	g_signal_emit (notify_event->source,
	               notify_event->signal_id,
	               0,
	               notify_event->obj);

	g_object_unref (notify_event->obj);
	g_object_unref (notify_event->source);
}

void
_nm_client_notify_event_queue_emit_obj_signal (NMClient *self,
                                               GObject *source,
                                               NMObject *nmobj,
                                               gboolean is_added /* or else removed */,
                                               int prio_offset,
                                               guint signal_id)
{
	NMClientNotifyEventObjAddedRemove *notify_event;

	nm_assert (prio_offset >= 0);
	nm_assert (prio_offset < 20);
	nm_assert (   NM_IS_OBJECT (source)
	           || NM_IS_CLIENT (source));
	nm_assert (NM_IS_OBJECT (nmobj));

	if (((NMObjectBase *) source)->is_disposing) {
		nm_assert (NM_IS_CLIENT (source));
		return;
	}

	notify_event = _nm_client_notify_event_queue (self,
	                                                is_added
	                                              ? NM_CLIENT_NOTIFY_EVENT_PRIO_AFTER - 20 + prio_offset
	                                              : NM_CLIENT_NOTIFY_EVENT_PRIO_BEFORE + 20 - prio_offset,
	                                              _nm_client_notify_event_queue_emit_obj_signal_cb,
	                                              sizeof (NMClientNotifyEventObjAddedRemove));
	notify_event->source    = g_object_ref (source);
	notify_event->obj       = g_object_ref (nmobj);
	notify_event->signal_id = signal_id;
}

/*****************************************************************************/

static int
_nm_client_notify_event_cmp (const CList *a,
                             const CList *b,
                             const void *user_data)
{
	NM_CMP_DIRECT (c_list_entry (a, NMClientNotifyEvent, lst)->priority,
	               c_list_entry (b, NMClientNotifyEvent, lst)->priority);
	return 0;
}

static void
_nm_client_notify_event_emit_parts (NMClient *self,
                                    int max_priority /* included! */)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (self);
	NMClientNotifyEvent *notify_event;

	while (TRUE) {
		if (priv->notify_event_lst_changed) {
			priv->notify_event_lst_changed = FALSE;
			c_list_sort (&priv->notify_event_lst_head, _nm_client_notify_event_cmp, NULL);
		}
		notify_event = c_list_first_entry (&priv->notify_event_lst_head, NMClientNotifyEvent, lst);
		if (!notify_event)
			return;
		if (notify_event->priority > max_priority)
			return;
		c_list_unlink_stale (&notify_event->lst);
		notify_event->callback (self, notify_event);
		g_free (notify_event);
	}
}

static void
_nm_client_notify_event_emit (NMClient *self)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (self);
	NMObjectBase *base;

	_nm_client_notify_event_emit_parts (self, NM_CLIENT_NOTIFY_EVENT_PRIO_GPROP);

	while ((base = c_list_first_entry (&priv->queue_notify_lst_head, NMObjectBase, queue_notify_lst))) {
		c_list_unlink (&base->queue_notify_lst);
		g_object_thaw_notify (G_OBJECT (base));
		g_object_unref (base);
	}

	_nm_client_notify_event_emit_parts (self, G_MAXINT);
}

/*****************************************************************************/

GDBusConnection *
_nm_client_get_dbus_connection (NMClient *self)
{
	return NM_CLIENT_GET_PRIVATE (self)->dbus_connection;
}

const char *
_nm_client_get_dbus_name_owner (NMClient *self)
{
	return NM_CLIENT_GET_PRIVATE (self)->name_owner;
}

GMainContext *
_nm_client_get_context_main (NMClient *self)
{
	return NM_CLIENT_GET_PRIVATE (self)->main_context;
}

GMainContext *
_nm_client_get_context_dbus (NMClient *self)
{
	return NM_CLIENT_GET_PRIVATE (self)->dbus_context;
}

/**
 * nm_client_get_main_context:
 * @self: the #NMClient instance
 *
 * The #NMClient instance is permanently associated with the current
 * thread default #GMainContext, referenced the time when the instance
 * was created. To receive events, the user must iterate this context
 * and can use it to synchronize access to the client.
 *
 * Note that even after #NMClient instance got destroyed, there might
 * still be pending sources registered in the context. That means, to fully
 * clean up, the user must continue iterating the context as long as
 * the nm_client_get_context_busy_watcher() object is alive.
 *
 * Returns: (transfer none): the #GMainContext of the client.
 *
 * Since: 1.22
 */
GMainContext *
nm_client_get_main_context (NMClient *self)
{
	g_return_val_if_fail (NM_IS_CLIENT (self), NULL);

	return _nm_client_get_context_main (self);
}

/**
 * nm_client_get_context_busy_watcher:
 * @self: the NMClient instance.
 *
 * Returns: (transfer none): a GObject that stays alive as long as there are pending
 *   D-Bus operations.
 *
 * NMClient will schedule asynchronous D-Bus requests which will complete on
 * the GMainContext associated with the instance. When destroying the NMClient
 * instance, those requests are cancelled right away, however their pending requests are
 * still outstanding and queued in the GMainContext. These outstanding callbacks
 * keep the GMainContext alive. In order to fully release all resources,
 * the user must keep iterating the main context until all these callbacks
 * are handled. Of course, at this point no more actual callbacks will be invoked
 * for the user, those are all internally cancelled.
 *
 * This just leaves one problem: how long does the user need to keep the
 * GMainContext running to ensure everything is cleaned up? The answer is
 * this GObject. Subscribe a weak reference to the returned object and keep
 * iterating the main context until the object got unreferenced.
 *
 * Note that after the NMClient instance gets destroyed, the remaining callbacks
 * will be invoked right away. That means, the user won't have to iterate the
 * main context much longer.
 *
 * Since: 1.22
 */
GObject *
nm_client_get_context_busy_watcher (NMClient *self)
{
	GObject *w;

	g_return_val_if_fail (NM_IS_CLIENT (self), NULL);

	w = NM_CLIENT_GET_PRIVATE (self)->context_busy_watcher;
	return    g_object_get_qdata (w, nm_context_busy_watcher_quark ())
	       ?: w;
}

struct udev *
_nm_client_get_udev (NMClient *self)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (self);

	if (G_UNLIKELY (!priv->udev_inited)) {
		priv->udev_inited = TRUE;
		/* for testing, we don't want to use udev in libnm. */
		if (!nm_streq0 (g_getenv ("LIBNM_USE_NO_UDEV"), "1"))
			priv->udev = udev_new ();
	}

	return priv->udev;
}

/*****************************************************************************/

static void
_ASSERT_dbobj (NMLDBusObject *dbobj,
               NMClient *self)
{
#if NM_MORE_ASSERTS > 5
	nm_assert (NM_IS_CLIENT (self));
	nm_assert (NML_IS_DBUS_OBJECT (dbobj));
	nm_assert (dbobj == g_hash_table_lookup (NM_CLIENT_GET_PRIVATE (self)->dbus_objects, dbobj));
#endif
}

static NMLDBusObject *
nml_dbus_object_new (NMRefString *dbus_path_take)
{
	NMLDBusObject *dbobj;

	nm_assert (NM_IS_REF_STRING (dbus_path_take));

	dbobj = g_slice_new (NMLDBusObject);
	*dbobj = (NMLDBusObject) {
		.dbus_path        = g_steal_pointer (&dbus_path_take),
		.ref_count        = 1,
		.dbus_objects_lst = C_LIST_INIT (dbobj->dbus_objects_lst),
		.iface_lst_head   = C_LIST_INIT (dbobj->iface_lst_head),
		.watcher_lst_head = C_LIST_INIT (dbobj->watcher_lst_head),
		.obj_changed_lst  = C_LIST_INIT (dbobj->obj_changed_lst),
		.obj_state        = NML_DBUS_OBJ_STATE_UNLINKED,
	};
	return dbobj;
}

NMLDBusObject *
nml_dbus_object_ref (NMLDBusObject *dbobj)
{
	nm_assert (dbobj);
	nm_assert (dbobj->ref_count > 0);

	dbobj->ref_count++;
	return dbobj;
}

void
nml_dbus_object_unref (NMLDBusObject *dbobj)
{
	nm_assert (dbobj);
	nm_assert (dbobj->ref_count > 0);

	if (--dbobj->ref_count > 0)
		return;

	nm_assert (c_list_is_empty (&dbobj->obj_changed_lst));
	nm_assert (c_list_is_empty (&dbobj->iface_lst_head));
	nm_assert (c_list_is_empty (&dbobj->watcher_lst_head));
	nm_assert (!dbobj->nmobj);

	nm_ref_string_unref (dbobj->dbus_path);
	nm_g_slice_free (dbobj);
}

static NMLDBusObjIfaceData *
nml_dbus_object_iface_data_get (NMLDBusObject *dbobj,
                                const char *dbus_iface_name,
                                gboolean allow_create)
{
	const NMLDBusMetaIface *meta_iface;
	NMLDBusObjIfaceData *db_iface_data;
	NMLDBusObjPropData *db_prop_data;
	guint count = 0;
	guint i;

	nm_assert (NML_IS_DBUS_OBJECT (dbobj));
	nm_assert (dbus_iface_name);

#if NM_MORE_ASSERTS > 10
	{
		gboolean expect_well_known = TRUE;

		/* all well-known interfaces must come first in the list. */
		c_list_for_each_entry (db_iface_data, &dbobj->iface_lst_head, iface_lst) {
			if (db_iface_data->dbus_iface_is_wellknown == expect_well_known)
				continue;
			nm_assert (expect_well_known);
			expect_well_known = FALSE;
		}
	}
#endif

	meta_iface = nml_dbus_meta_iface_get (dbus_iface_name);
	if (meta_iface) {
		c_list_for_each_entry (db_iface_data, &dbobj->iface_lst_head, iface_lst) {
			if (!db_iface_data->dbus_iface_is_wellknown)
				break;
			if (db_iface_data->iface_removed)
				continue;
			if (db_iface_data->dbus_iface.meta == meta_iface)
				return db_iface_data;
			count++;
		}
	} else {
		nm_c_list_for_each_entry_prev (db_iface_data, &dbobj->iface_lst_head, iface_lst) {
			if (db_iface_data->dbus_iface_is_wellknown)
				break;
			if (db_iface_data->iface_removed)
				continue;
			if (nm_streq (db_iface_data->dbus_iface.name->str, dbus_iface_name))
				return db_iface_data;
			count++;
		}
	}

	if (!allow_create)
		return NULL;

	if (count > 20) {
		/* We track the list of interfaces that an object has in a linked list.
		 * That is efficient and convenient, if we assume that each object only has a small
		 * number of interfaces (which very much should be the case). Here, something is very
		 * odd, maybe there is a bug or the server side is misbehaving. Anyway, error out. */
		return NULL;
	}

	db_iface_data = g_malloc (  G_STRUCT_OFFSET (NMLDBusObjIfaceData, prop_datas)
	                          + (meta_iface ? (sizeof (NMLDBusObjPropData) * meta_iface->n_dbus_properties): 0u));
	if (meta_iface) {
		*db_iface_data = (NMLDBusObjIfaceData) {
			.dbus_iface.meta         = meta_iface,
			.dbus_iface_is_wellknown = TRUE,
			.changed_prop_lst_head   = C_LIST_INIT (db_iface_data->changed_prop_lst_head),
			.iface_removed           = FALSE,
		};
		db_prop_data = &db_iface_data->prop_datas[0];
		for (i = 0; i < meta_iface->n_dbus_properties; i++, db_prop_data++) {
			*db_prop_data = (NMLDBusObjPropData) {
				.prop_data_value  = NULL,
				.changed_prop_lst = C_LIST_INIT (db_prop_data->changed_prop_lst),
			};
		}
		c_list_link_front (&dbobj->iface_lst_head, &db_iface_data->iface_lst);
	} else {
		/* Intentionally don't initialize the other fields. We are not supposed
		 * to touch them, and a valgrind warning would be preferable. */
		db_iface_data->dbus_iface.name         = nm_ref_string_new (dbus_iface_name);
		db_iface_data->dbus_iface_is_wellknown = FALSE;
		db_iface_data->iface_removed           = FALSE;
		c_list_link_tail (&dbobj->iface_lst_head, &db_iface_data->iface_lst);
	}

	return db_iface_data;
}

static void
nml_dbus_obj_iface_data_destroy (NMLDBusObjIfaceData *db_iface_data)
{
	guint i;

	nm_assert (db_iface_data);
	nm_assert (c_list_is_empty (&db_iface_data->iface_lst));

	if (db_iface_data->dbus_iface_is_wellknown) {
		for (i = 0; i < db_iface_data->dbus_iface.meta->n_dbus_properties; i++)
			nm_g_variant_unref (db_iface_data->prop_datas[i].prop_data_value);
	} else
		nm_ref_string_unref (db_iface_data->dbus_iface.name);

	g_free (db_iface_data);
}

gpointer
nml_dbus_object_get_property_location (NMLDBusObject *dbobj,
                                       const NMLDBusMetaIface *meta_iface,
                                       const NMLDBusMetaProperty *meta_property)
{
	char *target_c;

	target_c = (char *) dbobj->nmobj;
	if (meta_iface->base_struct_offset > 0)
		target_c = *((gpointer *) (&target_c[meta_iface->base_struct_offset]));
	return &target_c[meta_property->prop_struct_offset];
}

static void
nml_dbus_object_set_obj_state (NMLDBusObject *dbobj,
                               NMLDBusObjState obj_state,
                               NMClient *self)
{
	NMClientPrivate *priv;

	nm_assert (NM_IS_CLIENT (self));
	nm_assert (NML_IS_DBUS_OBJECT  (dbobj));

#if NM_MORE_ASSERTS > 10
	priv = NM_CLIENT_GET_PRIVATE (self);
	switch (dbobj->obj_state) {
	case NML_DBUS_OBJ_STATE_UNLINKED:               nm_assert (c_list_is_empty (&dbobj->dbus_objects_lst));                                                    break;
	case NML_DBUS_OBJ_STATE_WATCHED_ONLY:           nm_assert (c_list_contains (&priv->dbus_objects_lst_head_watched_only,           &dbobj->dbus_objects_lst)); break;
	case NML_DBUS_OBJ_STATE_ON_DBUS:                nm_assert (c_list_contains (&priv->dbus_objects_lst_head_on_dbus,                &dbobj->dbus_objects_lst)); break;
	case NML_DBUS_OBJ_STATE_WITH_NMOBJ_NOT_READY:   nm_assert (c_list_contains (&priv->dbus_objects_lst_head_with_nmobj_not_ready,   &dbobj->dbus_objects_lst)); break;
	case NML_DBUS_OBJ_STATE_WITH_NMOBJ_READY:       nm_assert (c_list_contains (&priv->dbus_objects_lst_head_with_nmobj_ready,       &dbobj->dbus_objects_lst)); break;
	}
#endif

	if (dbobj->obj_state == obj_state)
		return;

	NML_NMCLIENT_LOG_T (self, "[%s]: set D-Bus object state %s", dbobj->dbus_path->str, nml_dbus_obj_state_to_string (obj_state));

	priv = NM_CLIENT_GET_PRIVATE (self);
	dbobj->obj_state = obj_state;
	switch (obj_state) {
	case NML_DBUS_OBJ_STATE_UNLINKED:
		c_list_unlink (&dbobj->dbus_objects_lst);
		c_list_unlink (&dbobj->obj_changed_lst);
		dbobj->obj_changed_type = NML_DBUS_OBJ_CHANGED_TYPE_NONE;
		break;
	case NML_DBUS_OBJ_STATE_WATCHED_ONLY:           nm_c_list_move_tail (&priv->dbus_objects_lst_head_watched_only,           &dbobj->dbus_objects_lst); break;
	case NML_DBUS_OBJ_STATE_ON_DBUS:                nm_c_list_move_tail (&priv->dbus_objects_lst_head_on_dbus,                &dbobj->dbus_objects_lst); break;
	case NML_DBUS_OBJ_STATE_WITH_NMOBJ_NOT_READY:   nm_c_list_move_tail (&priv->dbus_objects_lst_head_with_nmobj_not_ready,   &dbobj->dbus_objects_lst); break;
	case NML_DBUS_OBJ_STATE_WITH_NMOBJ_READY:       nm_c_list_move_tail (&priv->dbus_objects_lst_head_with_nmobj_ready,       &dbobj->dbus_objects_lst); break;
	default:
		nm_assert_not_reached ();
	}
}

/*****************************************************************************/

static void
nml_dbus_object_obj_changed_link (NMClient *self,
                                  NMLDBusObject *dbobj,
                                  NMLDBusObjChangedType changed_type)
{
	nm_assert (NM_IS_CLIENT (self));
	nm_assert (NML_IS_DBUS_OBJECT (dbobj));
	nm_assert (changed_type != NML_DBUS_OBJ_CHANGED_TYPE_NONE);

	if (!NM_FLAGS_ALL ((NMLDBusObjChangedType ) dbobj->obj_changed_type, changed_type))
		NML_NMCLIENT_LOG_T (self, "[%s] changed-type 0x%02x linked", dbobj->dbus_path->str, (guint) changed_type);

	if (dbobj->obj_changed_type == NML_DBUS_OBJ_CHANGED_TYPE_NONE) {
		NMClientPrivate *priv;

		/* We set the changed-type flag. Need to queue the object in the
		 * changed list. */
		nm_assert (c_list_is_empty (&dbobj->obj_changed_lst));
		priv = NM_CLIENT_GET_PRIVATE (self);
		c_list_link_tail (&priv->obj_changed_lst_head, &dbobj->obj_changed_lst);
	} else {
		/* The object has changes flags and must be linked already. Note that
		 * this may be priv->obj_changed_lst_head, or a temporary list on the
		 * stack.
		 *
		 * This dance with the temporary list is done to ensure we can enqueue
		 * objects while we process the changes. */
		nm_assert (!c_list_is_empty (&dbobj->obj_changed_lst));
	}

	dbobj->obj_changed_type |= changed_type;

	nm_assert (NM_FLAGS_ALL (dbobj->obj_changed_type, changed_type));
}

static NMLDBusObjChangedType
nml_dbus_object_obj_changed_consume (NMClient *self,
                                     NMLDBusObject *dbobj,
                                     NMLDBusObjChangedType changed_type)
{
	NMClientPrivate *priv;
	NMLDBusObjChangedType changed_type_res;

	nm_assert (NM_IS_CLIENT (self));
	nm_assert (NML_IS_DBUS_OBJECT (dbobj));
	nm_assert (changed_type != NML_DBUS_OBJ_CHANGED_TYPE_NONE);
	nm_assert (dbobj->obj_changed_type != NML_DBUS_OBJ_CHANGED_TYPE_NONE);
	nm_assert (!c_list_is_empty (&dbobj->obj_changed_lst));

	changed_type_res = dbobj->obj_changed_type & changed_type;

	dbobj->obj_changed_type &= ~changed_type;

	if (dbobj->obj_changed_type == NML_DBUS_OBJ_CHANGED_TYPE_NONE) {
		c_list_unlink (&dbobj->obj_changed_lst);
		nm_assert (changed_type_res != NML_DBUS_OBJ_CHANGED_TYPE_NONE);
		NML_NMCLIENT_LOG_T (self, "[%s] changed-type 0x%02x consumed", dbobj->dbus_path->str, (guint) changed_type_res);
		return changed_type_res;
	}

	priv = NM_CLIENT_GET_PRIVATE (self);

	nm_assert (!c_list_contains (&priv->obj_changed_lst_head, &dbobj->obj_changed_lst));
	nm_c_list_move_tail (&priv->obj_changed_lst_head, &dbobj->obj_changed_lst);
	NML_NMCLIENT_LOG_T (self, "[%s] changed-type 0x%02x consumed  (still has 0x%02x)", dbobj->dbus_path->str, (guint) changed_type_res, (guint) dbobj->obj_changed_type);
	return changed_type_res;
}

static gboolean
nml_dbus_object_obj_changed_any_linked (NMClient *self,
                                        NMLDBusObjChangedType changed_type)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (self);
	NMLDBusObject *dbobj;

	nm_assert (changed_type != NML_DBUS_OBJ_CHANGED_TYPE_NONE);

	c_list_for_each_entry (dbobj, &priv->obj_changed_lst_head, obj_changed_lst) {
		nm_assert (dbobj->obj_changed_type != NML_DBUS_OBJ_CHANGED_TYPE_NONE);
		if (NM_FLAGS_ANY (dbobj->obj_changed_type, changed_type))
			return TRUE;
	}
	return FALSE;
}

/*****************************************************************************/

static void
_dbobjs_notify_watchers_for_dbobj (NMClient *self,
                                   NMLDBusObject *dbobj)
{
	NMLDBusObjWatcher *obj_watcher;
	NMLDBusObjWatcher *obj_watcher_safe;

	c_list_for_each_entry_safe (obj_watcher, obj_watcher_safe, &dbobj->watcher_lst_head, _priv.watcher_lst)
		obj_watcher->_priv.notify_fcn (self, obj_watcher);
}

static gboolean
_dbobjs_check_dbobj_ready (NMClient *self,
                           NMLDBusObject *dbobj)
{
	nm_assert (NM_IS_CLIENT (self));
	nm_assert (NML_IS_DBUS_OBJECT (dbobj));
	nm_assert (G_IS_OBJECT (dbobj->nmobj));
	nm_assert (   NM_IS_OBJECT (dbobj->nmobj)
	           || NM_IS_CLIENT (dbobj->nmobj));
	nm_assert (NM_IN_SET ((NMLDBusObjState) dbobj->obj_state, NML_DBUS_OBJ_STATE_WITH_NMOBJ_NOT_READY,
	                                                          NML_DBUS_OBJ_STATE_WITH_NMOBJ_READY));

	if (G_LIKELY (dbobj->obj_state == NML_DBUS_OBJ_STATE_WITH_NMOBJ_READY))
		return TRUE;

	if (!NM_OBJECT_GET_CLASS (dbobj->nmobj)->is_ready (NM_OBJECT (dbobj->nmobj)))
		return FALSE;

	nml_dbus_object_set_obj_state (dbobj, NML_DBUS_OBJ_STATE_WITH_NMOBJ_READY, self);

	nml_dbus_object_obj_changed_link (self, dbobj, NML_DBUS_OBJ_CHANGED_TYPE_NMOBJ);
	_dbobjs_notify_watchers_for_dbobj (self, dbobj);

	return TRUE;
}

void
_nm_client_notify_object_changed (NMClient *self,
                                  NMLDBusObject *dbobj)
{
	nml_dbus_object_obj_changed_link (self, dbobj, NML_DBUS_OBJ_CHANGED_TYPE_NMOBJ);
	_dbobjs_notify_watchers_for_dbobj (self, dbobj);
}

/*****************************************************************************/

static NMLDBusObject *
_dbobjs_dbobj_get_r (NMClient *self,
                     NMRefString *dbus_path_r)
{
	nm_assert (NM_IS_REF_STRING (dbus_path_r));

	return g_hash_table_lookup (NM_CLIENT_GET_PRIVATE (self)->dbus_objects, &dbus_path_r);
}

static NMLDBusObject *
_dbobjs_dbobj_get_s (NMClient *self,
                     const char *dbus_path)
{
	nm_auto_ref_string NMRefString *dbus_path_r = NULL;

	nm_assert (dbus_path);
	dbus_path_r = nm_ref_string_new (dbus_path);
	return _dbobjs_dbobj_get_r (self, dbus_path_r);
}

static NMLDBusObject *
_dbobjs_dbobj_create (NMClient *self,
                      NMRefString *dbus_path_take)
{
	nm_auto_ref_string NMRefString *dbus_path = g_steal_pointer (&dbus_path_take);
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (self);
	NMLDBusObject *dbobj;

	nm_assert (!_dbobjs_dbobj_get_r (self, dbus_path));

	dbobj = nml_dbus_object_new (g_steal_pointer (&dbus_path));
	if (!g_hash_table_add (priv->dbus_objects, dbobj))
		nm_assert_not_reached ();
	return dbobj;
}

static NMLDBusObject *
_dbobjs_dbobj_get_or_create (NMClient *self,
                             NMRefString *dbus_path_take)
{
	nm_auto_ref_string NMRefString *dbus_path = g_steal_pointer (&dbus_path_take);
	NMLDBusObject *dbobj;

	dbobj = _dbobjs_dbobj_get_r (self, dbus_path);
	if (dbobj)
		return dbobj;
	return _dbobjs_dbobj_create (self, g_steal_pointer (&dbus_path));
}

static NMLDBusObject *
_dbobjs_get_nmobj (NMClient *self,
                   const char *dbus_path,
                   GType gtype)
{
	NMLDBusObject *dbobj;

	nm_assert (   gtype == G_TYPE_NONE
	           || g_type_is_a (gtype, NM_TYPE_OBJECT));

	dbobj = _dbobjs_dbobj_get_s (self, dbus_path);

	if (!dbobj)
		return NULL;
	if (!dbobj->nmobj)
		return NULL;

	if (   gtype != G_TYPE_NONE
	    && !g_type_is_a (G_OBJECT_TYPE (dbobj->nmobj), gtype))
		return NULL;

	return dbobj;
}

static gpointer
_dbobjs_get_nmobj_unpack_visible (NMClient *self,
                                  const char *dbus_path,
                                  GType gtype)
{
	NMLDBusObject *dbobj;

	dbobj = _dbobjs_get_nmobj (self, dbus_path, gtype);
	if (!dbobj)
		return NULL;
	if (dbobj->obj_state != NML_DBUS_OBJ_STATE_WITH_NMOBJ_READY)
		return NULL;
	return dbobj->nmobj;
}

/*****************************************************************************/

static gpointer
_dbobjs_obj_watcher_register_o (NMClient *self,
                                NMLDBusObject *dbobj,
                                NMLDBusObjWatchNotifyFcn notify_fcn,
                                gsize struct_size)
{
	NMLDBusObjWatcher *obj_watcher;

	nm_assert (NM_IS_CLIENT (self));
	_ASSERT_dbobj (dbobj, self);
	nm_assert (notify_fcn);
	nm_assert (struct_size > sizeof (NMLDBusObjWatcher));

	obj_watcher = g_malloc (struct_size);
	obj_watcher->dbobj = dbobj;
	obj_watcher->_priv.notify_fcn = notify_fcn;

	/* we must enqueue the item in the front of the list. That is, because while
	 * invoking notify_fcn(), we iterate the watchers front-to-end. As we want to
	 * allow the callee to register new watches and unregister itself, this is
	 * the right way to do it. */
	c_list_link_front (&dbobj->watcher_lst_head, &obj_watcher->_priv.watcher_lst);

	return obj_watcher;
}

static gpointer
_dbobjs_obj_watcher_register_r (NMClient *self,
                                NMRefString *dbus_path_take,
                                NMLDBusObjWatchNotifyFcn notify_fcn,
                                gsize struct_size)
{
	nm_auto_ref_string NMRefString *dbus_path = g_steal_pointer (&dbus_path_take);
	NMLDBusObject *dbobj;

	nm_assert (NM_IS_CLIENT (self));
	nm_assert (notify_fcn);

	dbobj = _dbobjs_dbobj_get_or_create (self, g_steal_pointer (&dbus_path));
	if (dbobj->obj_state == NML_DBUS_OBJ_STATE_UNLINKED)
		nml_dbus_object_set_obj_state (dbobj, NML_DBUS_OBJ_STATE_WATCHED_ONLY, self);
	return _dbobjs_obj_watcher_register_o (self, dbobj, notify_fcn, struct_size);
}

static void
_dbobjs_obj_watcher_unregister (NMClient *self,
                                gpointer obj_watcher_base)
{
	NMLDBusObjWatcher *obj_watcher = obj_watcher_base;
	NMLDBusObject *dbobj;

	nm_assert (NM_IS_CLIENT (self));
	nm_assert (obj_watcher);
	nm_assert (NML_IS_DBUS_OBJECT (obj_watcher->dbobj));
	nm_assert (g_hash_table_lookup (NM_CLIENT_GET_PRIVATE (self)->dbus_objects, obj_watcher->dbobj) == obj_watcher->dbobj);
	nm_assert (c_list_contains (&obj_watcher->dbobj->watcher_lst_head, &obj_watcher->_priv.watcher_lst));

	c_list_unlink (&obj_watcher->_priv.watcher_lst);

	dbobj = obj_watcher->dbobj;

	g_free (obj_watcher);

	if (   c_list_is_empty (&dbobj->iface_lst_head)
	    && c_list_is_empty (&dbobj->watcher_lst_head)) {
		NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (self);

		NML_NMCLIENT_LOG_T (self, "[%s]: drop D-Bus watcher", dbobj->dbus_path->str);
		nml_dbus_object_set_obj_state (dbobj, NML_DBUS_OBJ_STATE_UNLINKED, self);
		if (!g_hash_table_steal (priv->dbus_objects, dbobj))
			nm_assert_not_reached ();
		nml_dbus_object_unref (dbobj);
	}
}

/*****************************************************************************/

typedef struct {
	NMLDBusObjWatcher parent;
	NMLDBusPropertyO *pr_o;
} PropertyOData;

gpointer
nml_dbus_property_o_get_obj (NMLDBusPropertyO *pr_o)
{
	nm_assert (   !pr_o->nmobj
	           || nml_dbus_property_o_is_ready (pr_o));
	return pr_o->nmobj;
}

gboolean
nml_dbus_property_o_is_ready (const NMLDBusPropertyO *pr_o)
{
	return    pr_o->is_ready
	       || !pr_o->owner_dbobj;
}

static void
nml_dbus_property_o_notify_changed (NMLDBusPropertyO *pr_o,
                                    NMClient *self)
{
	const NMLDBusPropertVTableO *vtable;
	GObject *nmobj = NULL;
	gboolean is_ready = TRUE;
	gboolean changed_ready;
	GType gtype;

	nm_assert (pr_o);
	nm_assert (NM_IS_CLIENT (self));

	if (!pr_o->owner_dbobj)
		return;

	if (!pr_o->is_changed) {
		if (pr_o->is_ready)
			return;
		goto done;
	}

	pr_o->is_changed = FALSE;

	if (!pr_o->obj_watcher)
		goto done;

	if (!pr_o->obj_watcher->dbobj->nmobj) {
		if (pr_o->obj_watcher->dbobj->obj_state >= NML_DBUS_OBJ_STATE_ON_DBUS) {
			NML_NMCLIENT_LOG_W (self, "[%s]: property %s references %s but object is not created",
			                    pr_o->owner_dbobj->dbus_path->str,
			                    pr_o->meta_iface->dbus_properties[pr_o->dbus_property_idx].dbus_property_name,
			                    pr_o->obj_watcher->dbobj->dbus_path->str);
		} else {
			NML_NMCLIENT_LOG_E (self, "[%s]: property %s references %s but object is not present on D-Bus",
			                    pr_o->owner_dbobj->dbus_path->str,
			                    pr_o->meta_iface->dbus_properties[pr_o->dbus_property_idx].dbus_property_name,
			                    pr_o->obj_watcher->dbobj->dbus_path->str);
		}
		goto done;
	}

	vtable = pr_o->meta_iface->dbus_properties[pr_o->dbus_property_idx].extra.property_vtable_o;

	gtype = vtable->get_o_type_fcn ();
	if (!g_type_is_a (G_OBJECT_TYPE (pr_o->obj_watcher->dbobj->nmobj), gtype)) {
		NML_NMCLIENT_LOG_E (self, "[%s]: property %s references %s with unexpected GObject type %s instead of %s",
		                    pr_o->owner_dbobj->dbus_path->str,
		                    pr_o->meta_iface->dbus_properties[pr_o->dbus_property_idx].dbus_property_name,
		                    pr_o->obj_watcher->dbobj->dbus_path->str,
		                    G_OBJECT_TYPE_NAME (pr_o->obj_watcher->dbobj->nmobj),
		                    g_type_name (gtype));
		goto done;
	}

	if (pr_o->obj_watcher->dbobj == pr_o->owner_dbobj) {
		NML_NMCLIENT_LOG_W (self, "[%s]: property %s references itself",
		                    pr_o->owner_dbobj->dbus_path->str,
		                    pr_o->meta_iface->dbus_properties[pr_o->dbus_property_idx].dbus_property_name);
		nmobj = pr_o->owner_dbobj->nmobj;
		goto done;
	}

	pr_o->block_is_changed = TRUE;
	is_ready = _dbobjs_check_dbobj_ready (self, pr_o->obj_watcher->dbobj);
	pr_o->block_is_changed = FALSE;

	if (!is_ready) {
		is_ready = vtable->is_always_ready;
		goto done;
	}

	nmobj = pr_o->obj_watcher->dbobj->nmobj;

done:
	changed_ready = FALSE;
	if (!pr_o->is_ready && is_ready) {
		pr_o->is_ready = TRUE;
		changed_ready = TRUE;
	}
	if (pr_o->nmobj != nmobj) {
		pr_o->nmobj = nmobj;
		_nm_client_queue_notify_object (self,
		                                pr_o->owner_dbobj->nmobj,
		                                pr_o->meta_iface->obj_properties[pr_o->meta_iface->dbus_properties[pr_o->dbus_property_idx].obj_properties_idx]);
	}
	if (   changed_ready
	    && pr_o->owner_dbobj->obj_state == NML_DBUS_OBJ_STATE_WITH_NMOBJ_NOT_READY)
		nml_dbus_object_obj_changed_link (self, pr_o->owner_dbobj, NML_DBUS_OBJ_CHANGED_TYPE_NMOBJ);
}

void
nml_dbus_property_o_notify_changed_many (NMLDBusPropertyO *ptr,
                                         guint len,
                                         NMClient *self)
{
	while (len-- > 0)
		nml_dbus_property_o_notify_changed (ptr++, self);
}

static void
nml_dbus_property_o_notify_watch_cb (NMClient *self,
                                     gpointer obj_watcher)
{
	PropertyOData *pr_o_data = obj_watcher;
	NMLDBusPropertyO *pr_o = pr_o_data->pr_o;

	nm_assert (pr_o->obj_watcher == obj_watcher);

	if (   !pr_o->block_is_changed
	    && !pr_o->is_changed) {
		pr_o->is_changed = TRUE;
		nml_dbus_object_obj_changed_link (self, pr_o->owner_dbobj, NML_DBUS_OBJ_CHANGED_TYPE_NMOBJ);
	}
}

static NMLDBusNotifyUpdatePropFlags
nml_dbus_property_o_notify (NMClient *self,
                            NMLDBusPropertyO *pr_o,
                            NMLDBusObject *dbobj,
                            const NMLDBusMetaIface *meta_iface,
                            guint dbus_property_idx,
                            GVariant *value)
{
	const char *dbus_path = NULL;
	gboolean changed = FALSE;

	if (!pr_o->owner_dbobj) {
		nm_assert (!pr_o->meta_iface);
		nm_assert (pr_o->dbus_property_idx == 0);
		nm_assert (!pr_o->is_ready);
		pr_o->owner_dbobj = dbobj;
		pr_o->meta_iface = meta_iface;
		pr_o->dbus_property_idx = dbus_property_idx;
	} else {
		nm_assert (pr_o->owner_dbobj == dbobj);
		nm_assert (pr_o->meta_iface == meta_iface);
		nm_assert (pr_o->dbus_property_idx == dbus_property_idx);
	}

	if (value)
		dbus_path = nm_dbus_path_not_empty (g_variant_get_string (value, NULL));

	if (   pr_o->obj_watcher
	    && (   !dbus_path
	        || !nm_streq (dbus_path, pr_o->obj_watcher->dbobj->dbus_path->str))) {
		_dbobjs_obj_watcher_unregister (self,
		                                g_steal_pointer (&pr_o->obj_watcher));
		changed = TRUE;
	}
	if (   !pr_o->obj_watcher
	    && dbus_path) {
		pr_o->obj_watcher = _dbobjs_obj_watcher_register_r (self,
		                                                    nm_ref_string_new (dbus_path),
		                                                    nml_dbus_property_o_notify_watch_cb,
		                                                    sizeof (PropertyOData));
		((PropertyOData *) pr_o->obj_watcher)->pr_o = pr_o;
		changed = TRUE;
	}

	if (   changed
	    && !pr_o->is_changed) {
		pr_o->is_changed = TRUE;
		nml_dbus_object_obj_changed_link (self, dbobj, NML_DBUS_OBJ_CHANGED_TYPE_NMOBJ);
	}

	return NML_DBUS_NOTIFY_UPDATE_PROP_FLAGS_NONE;
}

void
nml_dbus_property_o_clear (NMLDBusPropertyO *pr_o,
                           NMClient *self)
{
	if (pr_o->obj_watcher) {
		nm_assert (NM_IS_CLIENT (self));
		_dbobjs_obj_watcher_unregister (self,
		                                g_steal_pointer (&pr_o->obj_watcher));
	}
	if (   pr_o->nmobj
	    && pr_o->owner_dbobj
	    && pr_o->owner_dbobj->nmobj) {
		_nm_client_queue_notify_object (self,
		                                pr_o->owner_dbobj->nmobj,
		                                pr_o->meta_iface->obj_properties[pr_o->meta_iface->dbus_properties[pr_o->dbus_property_idx].obj_properties_idx]);
	}
	pr_o->owner_dbobj = NULL;
	pr_o->meta_iface = NULL;
	pr_o->dbus_property_idx = 0;
	pr_o->is_ready = FALSE;
}

void
nml_dbus_property_o_clear_many (NMLDBusPropertyO *pr_o,
                                guint len,
                                NMClient *self)
{
	while (len-- > 0)
		nml_dbus_property_o_clear (pr_o++, self);
}

/*****************************************************************************/

typedef struct _NMLDBusPropertyAOData {
	NMLDBusObjWatcher obj_watcher;
	NMLDBusPropertyAO *parent;
	CList data_lst;
	GObject *nmobj;
	struct _NMLDBusPropertyAOData *changed_next;
	bool is_ready:1;
	bool is_notified:1;
	bool is_changed:1;
	bool block_is_changed:1;
} PropertyAOData;

static void
_ASSERT_pr_ao (NMLDBusPropertyAO *pr_ao)
{
	nm_assert (pr_ao);

#if NM_MORE_ASSERTS > 10
	if (pr_ao->owner_dbobj) {
		guint n_not_ready = 0;
		guint n_is_changed = 0;
		guint n_is_changed_2;
		PropertyAOData *pr_ao_data;

		c_list_for_each_entry (pr_ao_data, &pr_ao->data_lst_head, data_lst) {
			if (pr_ao_data->is_changed)
				n_is_changed++;
			if (!pr_ao_data->is_ready)
				n_not_ready++;
		}
		nm_assert (n_not_ready == pr_ao->n_not_ready);

		n_is_changed_2 = 0;
		pr_ao_data = pr_ao->changed_head;
		while (pr_ao_data) {
			nm_assert (pr_ao_data->is_changed);
			n_is_changed_2++;
			pr_ao_data = pr_ao_data->changed_next;
		}
		nm_assert (n_is_changed == n_is_changed_2);
	}
#endif
}

static gboolean
nml_dbus_property_ao_notify_changed_ao (PropertyAOData *pr_ao_data,
                                        NMClient *self,
                                        gboolean is_added /* or else removed */)
{
	NMLDBusPropertyAO *pr_ao;
	const NMLDBusPropertVTableAO *vtable;

	if (!pr_ao_data->nmobj)
		return FALSE;

	nm_assert (pr_ao_data->is_ready);

	if (is_added) {
		if (pr_ao_data->is_notified)
			return FALSE;
		pr_ao_data->is_notified = TRUE;
	} else {
		if (!pr_ao_data->is_notified)
			return FALSE;
		pr_ao_data->is_notified = FALSE;
	}

	pr_ao = pr_ao_data->parent;

	vtable = pr_ao->meta_iface->dbus_properties[pr_ao->dbus_property_idx].extra.property_vtable_ao;

	if (vtable->notify_changed_ao)
		vtable->notify_changed_ao (pr_ao, self, NM_OBJECT (pr_ao_data->nmobj), is_added);
	return TRUE;
}

const GPtrArray *
nml_dbus_property_ao_get_objs_as_ptrarray (NMLDBusPropertyAO *pr_ao)
{
	if (!pr_ao->arr) {
		PropertyAOData *pr_ao_data;
		gsize n;

		n = 0;
		if (pr_ao->owner_dbobj) {
			c_list_for_each_entry (pr_ao_data, &pr_ao->data_lst_head, data_lst) {
				if (pr_ao_data->nmobj)
					n++;
			}
		}

		pr_ao->arr = g_ptr_array_new_full (n, g_object_unref);
		if (pr_ao->owner_dbobj) {
			c_list_for_each_entry (pr_ao_data, &pr_ao->data_lst_head, data_lst) {
				if (pr_ao_data->nmobj)
					g_ptr_array_add (pr_ao->arr, g_object_ref (pr_ao_data->nmobj));
			}
		}
	}
	return pr_ao->arr;
}

gboolean
nml_dbus_property_ao_is_ready (const NMLDBusPropertyAO *pr_ao)
{
	return pr_ao->n_not_ready == 0;
}

static void
nml_dbus_property_ao_notify_changed (NMLDBusPropertyAO *pr_ao,
                                     NMClient *self)
{
	gboolean changed_prop = FALSE;
	gboolean changed_ready = FALSE;
	PropertyAOData *pr_ao_data;

	nm_assert (NM_IS_CLIENT (self));
	_ASSERT_pr_ao (pr_ao);

	if (!pr_ao->owner_dbobj)
		return;

	if (!pr_ao->is_changed) {
		if (pr_ao->n_not_ready == 0)
			return;
		goto done;
	}

	pr_ao->is_changed = FALSE;

	while (pr_ao->changed_head) {
		const NMLDBusPropertVTableAO *vtable;
		GObject *nmobj = NULL;
		gboolean is_ready = TRUE;
		GType gtype;

		pr_ao_data = g_steal_pointer (&pr_ao->changed_head);
		nm_assert (pr_ao_data->is_changed);

		pr_ao->changed_head = pr_ao_data->changed_next;
		pr_ao_data->is_changed = FALSE;

		if (!pr_ao_data->obj_watcher.dbobj->nmobj) {
			if (pr_ao_data->obj_watcher.dbobj->obj_state >= NML_DBUS_OBJ_STATE_ON_DBUS) {
				NML_NMCLIENT_LOG_W (self, "[%s]: property %s references %s but object is not created",
				                    pr_ao->owner_dbobj->dbus_path->str,
				                    pr_ao->meta_iface->dbus_properties[pr_ao->dbus_property_idx].dbus_property_name,
				                    pr_ao_data->obj_watcher.dbobj->dbus_path->str);
			} else {
				NML_NMCLIENT_LOG_E (self, "[%s]: property %s references %s but object is not present on D-Bus",
				                    pr_ao->owner_dbobj->dbus_path->str,
				                    pr_ao->meta_iface->dbus_properties[pr_ao->dbus_property_idx].dbus_property_name,
				                    pr_ao_data->obj_watcher.dbobj->dbus_path->str);
			}
			goto done_pr_ao_data;
		}

		vtable = pr_ao->meta_iface->dbus_properties[pr_ao->dbus_property_idx].extra.property_vtable_ao;

		gtype = vtable->get_o_type_fcn ();
		if (!g_type_is_a (G_OBJECT_TYPE (pr_ao_data->obj_watcher.dbobj->nmobj), gtype)) {
			NML_NMCLIENT_LOG_E (self, "[%s]: property %s references %s with unexpected GObject type %s instead of %s",
			                    pr_ao->owner_dbobj->dbus_path->str,
			                    pr_ao->meta_iface->dbus_properties[pr_ao->dbus_property_idx].dbus_property_name,
			                    pr_ao_data->obj_watcher.dbobj->dbus_path->str,
			                    G_OBJECT_TYPE_NAME (pr_ao_data->obj_watcher.dbobj->nmobj),
			                    g_type_name (gtype));
			goto done_pr_ao_data;
		}

		if (pr_ao_data->obj_watcher.dbobj == pr_ao->owner_dbobj) {
			NML_NMCLIENT_LOG_W (self, "[%s]: property %s references itself",
			                    pr_ao->owner_dbobj->dbus_path->str,
			                    pr_ao->meta_iface->dbus_properties[pr_ao->dbus_property_idx].dbus_property_name);
			nmobj = pr_ao->owner_dbobj->nmobj;
			goto done_pr_ao_data;
		}

		pr_ao_data->block_is_changed = TRUE;
		is_ready = _dbobjs_check_dbobj_ready (self, pr_ao_data->obj_watcher.dbobj);
		pr_ao_data->block_is_changed = FALSE;

		if (!is_ready) {
			is_ready = vtable->is_always_ready;
			goto done_pr_ao_data;
		}

		if (   vtable->check_nmobj_visible_fcn
		    && !vtable->check_nmobj_visible_fcn (pr_ao_data->obj_watcher.dbobj->nmobj)) {
			is_ready = TRUE;
			goto done_pr_ao_data;
		}

		nmobj = pr_ao_data->obj_watcher.dbobj->nmobj;

done_pr_ao_data:

		if (   !pr_ao_data->is_ready
		    && is_ready) {
			nm_assert (pr_ao->n_not_ready > 0);
			pr_ao->n_not_ready--;
			pr_ao_data->is_ready = TRUE;
			changed_ready = TRUE;
		}

		if (pr_ao_data->nmobj != nmobj) {
			if (nml_dbus_property_ao_notify_changed_ao (pr_ao_data, self, FALSE))
				changed_prop = TRUE;
			pr_ao_data->nmobj = nmobj;
		}

		if (!pr_ao_data->is_notified) {
			if (nml_dbus_property_ao_notify_changed_ao (pr_ao_data, self, TRUE))
				changed_prop = TRUE;
		}
	}

	_ASSERT_pr_ao (pr_ao);

done:
	if (changed_prop) {
		nm_clear_pointer (&pr_ao->arr, g_ptr_array_unref);
		_nm_client_queue_notify_object (self,
		                                pr_ao->owner_dbobj->nmobj,
		                                pr_ao->meta_iface->obj_properties[pr_ao->meta_iface->dbus_properties[pr_ao->dbus_property_idx].obj_properties_idx]);
	}
	if (   changed_ready
	    && pr_ao->n_not_ready == 0
	    && pr_ao->owner_dbobj->obj_state == NML_DBUS_OBJ_STATE_WITH_NMOBJ_NOT_READY)
		nml_dbus_object_obj_changed_link (self, pr_ao->owner_dbobj, NML_DBUS_OBJ_CHANGED_TYPE_NMOBJ);
}

void
nml_dbus_property_ao_notify_changed_many (NMLDBusPropertyAO *ptr,
                                          guint len,
                                          NMClient *self)
{
	while (len-- > 0)
		nml_dbus_property_ao_notify_changed (ptr++, self);
}

static void
nml_dbus_property_ao_notify_watch_cb (NMClient *self,
                                      gpointer obj_watcher)
{
	PropertyAOData *pr_ao_data = obj_watcher;
	NMLDBusPropertyAO *pr_ao = pr_ao_data->parent;

	nm_assert (g_hash_table_lookup (pr_ao->hash, pr_ao_data) == pr_ao_data);

	if (   !pr_ao_data->block_is_changed
	    && !pr_ao_data->is_changed) {
		pr_ao_data->is_changed = TRUE;
		pr_ao_data->changed_next = pr_ao->changed_head;
		pr_ao->changed_head = pr_ao_data;
		if (!pr_ao->is_changed) {
			pr_ao->is_changed = TRUE;
			nml_dbus_object_obj_changed_link (self, pr_ao->owner_dbobj, NML_DBUS_OBJ_CHANGED_TYPE_NMOBJ);
		}
	}

	_ASSERT_pr_ao (pr_ao);
}

static NMLDBusNotifyUpdatePropFlags
nml_dbus_property_ao_notify (NMClient *self,
                             NMLDBusPropertyAO *pr_ao,
                             NMLDBusObject *dbobj,
                             const NMLDBusMetaIface *meta_iface,
                             guint dbus_property_idx,
                             GVariant *value)
{
	CList stale_lst_head = C_LIST_INIT (stale_lst_head);
	PropertyAOData *pr_ao_data;
	gboolean changed_prop = FALSE;
	gboolean changed_obj = FALSE;

	if (!pr_ao->owner_dbobj) {
		nm_assert (!pr_ao->data_lst_head.next);
		nm_assert (!pr_ao->data_lst_head.prev);
		nm_assert (!pr_ao->hash);
		nm_assert (!pr_ao->meta_iface);
		nm_assert (pr_ao->dbus_property_idx == 0);
		nm_assert (pr_ao->n_not_ready == 0);
		nm_assert (!pr_ao->changed_head);
		nm_assert (!pr_ao->is_changed);

		c_list_init (&pr_ao->data_lst_head);
		pr_ao->hash = g_hash_table_new (nm_ppdirect_hash, nm_ppdirect_equal);
		pr_ao->owner_dbobj = dbobj;
		pr_ao->meta_iface = meta_iface;
		pr_ao->dbus_property_idx = dbus_property_idx;
	} else {
		nm_assert (pr_ao->data_lst_head.next);
		nm_assert (pr_ao->data_lst_head.prev);
		nm_assert (pr_ao->hash);
		nm_assert (pr_ao->meta_iface == meta_iface);
		nm_assert (pr_ao->dbus_property_idx == dbus_property_idx);
	}

	c_list_splice (&stale_lst_head, &pr_ao->data_lst_head);

	if (value) {
		GVariantIter iter;
		const char *path;

		g_variant_iter_init (&iter, value);
		while (g_variant_iter_next (&iter, "&o", &path)) {
			nm_auto_ref_string NMRefString *dbus_path_r = NULL;
			gpointer p_dbus_path_1;

			G_STATIC_ASSERT_EXPR (G_STRUCT_OFFSET (PropertyAOData, obj_watcher) == 0);
			G_STATIC_ASSERT_EXPR (G_STRUCT_OFFSET (NMLDBusObjWatcher, dbobj) == 0);
			G_STATIC_ASSERT_EXPR (G_STRUCT_OFFSET (NMLDBusObject, dbus_path) == 0);

			if (!nm_dbus_path_not_empty (path)) {
				/* should not happen. Anyway, silently skip empty paths. */
				continue;
			}

			dbus_path_r = nm_ref_string_new (path);
			p_dbus_path_1 = &dbus_path_r;
			pr_ao_data = g_hash_table_lookup (pr_ao->hash, &p_dbus_path_1);

			if (pr_ao_data) {
				/* With this implementation we cannot track the same path multiple times.
				 * Of course, for none of the properties where we use this, the server
				 * should expose the same path more than once, so this limitation is fine
				 * (maybe even preferable to drop duplicates form NMClient's API). */
				nm_assert (pr_ao_data->obj_watcher.dbobj->dbus_path == dbus_path_r);
				if (   !changed_prop
				    && pr_ao_data->is_notified) {
					/* The order of a notified entry changed. That means, we need to signal
					 * a change of the property. This detection of a change is not always
					 * correct, in particular we might detect some changes when there were
					 * none. That's not a serious problem, and fixing it would be expensive
					 * to implement. */
					changed_prop = (c_list_first (&stale_lst_head) != &pr_ao_data->data_lst);
				}
				nm_c_list_move_tail (&pr_ao->data_lst_head, &pr_ao_data->data_lst);
			} else {
				pr_ao_data = _dbobjs_obj_watcher_register_r (self,
				                                             g_steal_pointer (&dbus_path_r),
				                                             nml_dbus_property_ao_notify_watch_cb,
				                                             sizeof (PropertyAOData)),
				pr_ao_data->parent = pr_ao;
				pr_ao_data->nmobj = NULL;
				pr_ao_data->changed_next = NULL;
				pr_ao_data->is_changed = TRUE;
				pr_ao_data->block_is_changed = FALSE;
				pr_ao_data->is_ready = FALSE;
				pr_ao_data->is_notified = FALSE;
				c_list_link_tail (&pr_ao->data_lst_head, &pr_ao_data->data_lst);
				if (!g_hash_table_add (pr_ao->hash, pr_ao_data))
					nm_assert_not_reached ();
				nm_assert (pr_ao->n_not_ready < G_MAXUINT);
				pr_ao->n_not_ready++;
			}

#if NM_MORE_ASSERTS > 10
			{
				nm_auto_ref_string NMRefString *p = nm_ref_string_new (path);
				gpointer pp = &p;

				nm_assert (g_hash_table_lookup (pr_ao->hash, &pp) == pr_ao_data);
			}
#endif
		}
	}

	pr_ao->changed_head = NULL;
	c_list_for_each_entry (pr_ao_data, &pr_ao->data_lst_head, data_lst) {
		if (pr_ao_data->is_changed) {
			pr_ao_data->changed_next = pr_ao->changed_head;
			pr_ao->changed_head = pr_ao_data;
			changed_obj = TRUE;
		}
	}

	while ((pr_ao_data = c_list_first_entry (&stale_lst_head, PropertyAOData, data_lst))) {
		changed_obj = TRUE;
		c_list_unlink (&pr_ao_data->data_lst);
		if (!g_hash_table_remove (pr_ao->hash, pr_ao_data))
			nm_assert_not_reached ();
		if (!pr_ao_data->is_ready) {
			nm_assert (pr_ao->n_not_ready > 0);
			pr_ao->n_not_ready--;
		} else {
			if (nml_dbus_property_ao_notify_changed_ao (pr_ao_data, self, FALSE))
				changed_prop = TRUE;
		}
		_dbobjs_obj_watcher_unregister (self, pr_ao_data);
	}

	_ASSERT_pr_ao (pr_ao);

	if (changed_obj) {
		pr_ao->is_changed = TRUE;
		nml_dbus_object_obj_changed_link (self, dbobj, NML_DBUS_OBJ_CHANGED_TYPE_NMOBJ);
	}

	if (changed_prop) {
		nm_clear_pointer (&pr_ao->arr, g_ptr_array_unref);
		_nm_client_queue_notify_object (self,
		                                pr_ao->owner_dbobj->nmobj,
		                                pr_ao->meta_iface->obj_properties[pr_ao->meta_iface->dbus_properties[pr_ao->dbus_property_idx].obj_properties_idx]);
	}

	return NML_DBUS_NOTIFY_UPDATE_PROP_FLAGS_NONE;
}

void
nml_dbus_property_ao_clear (NMLDBusPropertyAO *pr_ao,
                            NMClient *self)
{
	_ASSERT_pr_ao (pr_ao);

	if (!pr_ao->owner_dbobj) {
		nm_assert (pr_ao->n_not_ready == 0);
		nm_assert (   (!pr_ao->data_lst_head.next && !pr_ao->data_lst_head.prev)
		           || (pr_ao->data_lst_head.next == pr_ao->data_lst_head.prev));
		nm_assert (!pr_ao->hash);
		nm_assert (!pr_ao->meta_iface);
		nm_assert (pr_ao->dbus_property_idx == 0);
		nm_assert (!pr_ao->is_changed);
	} else {
		PropertyAOData *pr_ao_data;
		gboolean changed_prop = FALSE;

		nm_assert (NM_IS_CLIENT (self));
		nm_assert (pr_ao->data_lst_head.next);
		nm_assert (pr_ao->data_lst_head.prev);
		nm_assert (pr_ao->hash);
		nm_assert (pr_ao->meta_iface);

		while ((pr_ao_data = c_list_first_entry (&pr_ao->data_lst_head, PropertyAOData, data_lst))) {
			if (!pr_ao_data->is_ready) {
				nm_assert (pr_ao->n_not_ready > 0);
				pr_ao->n_not_ready--;
			} else {
				if (nml_dbus_property_ao_notify_changed_ao (pr_ao_data, self, FALSE))
					changed_prop = TRUE;
			}
			c_list_unlink (&pr_ao_data->data_lst);
			if (!g_hash_table_remove (pr_ao->hash, pr_ao_data))
				nm_assert_not_reached ();
			_dbobjs_obj_watcher_unregister (self, pr_ao_data);
		}

		nm_assert (c_list_is_empty (&pr_ao->data_lst_head));
		nm_assert (pr_ao->n_not_ready == 0);
		nm_assert (g_hash_table_size (pr_ao->hash) == 0);

		if (   changed_prop
		    && pr_ao->owner_dbobj->nmobj) {
			_nm_client_queue_notify_object (self,
			                                pr_ao->owner_dbobj->nmobj,
			                                pr_ao->meta_iface->obj_properties[pr_ao->meta_iface->dbus_properties[pr_ao->dbus_property_idx].obj_properties_idx]);
		}

		nm_assert (c_list_is_empty (&pr_ao->data_lst_head));
		nm_assert (pr_ao->n_not_ready == 0);
		nm_assert (g_hash_table_size (pr_ao->hash) == 0);
		nm_clear_pointer (&pr_ao->hash, g_hash_table_unref);
		pr_ao->owner_dbobj = NULL;
		pr_ao->meta_iface = NULL;
		pr_ao->dbus_property_idx = 0;
		pr_ao->data_lst_head.next = NULL;
		pr_ao->data_lst_head.prev = NULL;
		pr_ao->is_changed = FALSE;
	}

	nm_clear_pointer (&pr_ao->arr, g_ptr_array_unref);
}

void
nml_dbus_property_ao_clear_many (NMLDBusPropertyAO *pr_ao,
                                 guint len,
                                 NMClient *self)
{
	while (len-- > 0)
		nml_dbus_property_ao_clear (pr_ao++, self);
}

/*****************************************************************************/

NMLDBusNotifyUpdatePropFlags
_nml_dbus_notify_update_prop_ignore (NMClient *self,
                                     NMLDBusObject *dbobj,
                                     const NMLDBusMetaIface *meta_iface,
                                     guint dbus_property_idx,
                                     GVariant *value)
{
	return NML_DBUS_NOTIFY_UPDATE_PROP_FLAGS_NONE;
}

NMLDBusNotifyUpdatePropFlags
_nml_dbus_notify_update_prop_o (NMClient *self,
                                NMLDBusObject *dbobj,
                                const NMLDBusMetaIface *meta_iface,
                                guint dbus_property_idx,
                                GVariant *value)
{
	const char *path = NULL;
	NMRefString **p_property;

	if (value)
		path = g_variant_get_string (value, NULL);

	p_property = nml_dbus_object_get_property_location (dbobj,
	                                                    meta_iface,
	                                                    &meta_iface->dbus_properties[dbus_property_idx]);

	if (!nm_streq0 (nm_ref_string_get_str (*p_property), path)) {
		nm_ref_string_unref (*p_property);
		*p_property = nm_ref_string_new (path);
	}
	return NML_DBUS_NOTIFY_UPDATE_PROP_FLAGS_NOTIFY;
}

/*****************************************************************************/

static void
_obj_handle_dbus_prop_changes (NMClient *self,
                               NMLDBusObject *dbobj,
                               NMLDBusObjIfaceData *db_iface_data,
                               guint dbus_property_idx,
                               GVariant *value)
{
	const NMLDBusMetaIface *meta_iface = db_iface_data->dbus_iface.meta;
	const NMLDBusMetaProperty *meta_property = &meta_iface->dbus_properties[dbus_property_idx];
	gpointer p_property;
	const char *dbus_type_s;
	const GParamSpec *param_spec;
	NMLDBusNotifyUpdatePropFlags notify_update_prop_flags;

	nm_assert (G_IS_OBJECT (dbobj->nmobj));

	if (   value
	    && !g_variant_is_of_type (value, meta_property->dbus_type)) {
		NML_NMCLIENT_LOG_E (self, "[%s] property %s.%s expected of type \"%s\" but is \"%s\". Ignore",
		                    dbobj->dbus_path->str,
		                    meta_iface->dbus_iface_name,
		                    meta_property->dbus_property_name,
		                    (const char *) meta_property->dbus_type,
		                    (const char *) g_variant_get_type (value));
		value = NULL;
	}

	if (meta_property->use_notify_update_prop) {
		notify_update_prop_flags = meta_property->notify_update_prop (self,
		                                                              dbobj,
		                                                              meta_iface,
		                                                              dbus_property_idx,
		                                                              value);
		if (notify_update_prop_flags == NML_DBUS_NOTIFY_UPDATE_PROP_FLAGS_NONE)
			return;

		nm_assert (notify_update_prop_flags == NML_DBUS_NOTIFY_UPDATE_PROP_FLAGS_NOTIFY);
		nm_assert (G_IS_OBJECT (dbobj->nmobj));
		nm_assert (meta_iface->obj_properties);
		nm_assert (meta_property->obj_properties_idx > 0);
		param_spec = meta_iface->obj_properties[meta_property->obj_properties_idx];
		goto notify;
	}

	p_property = nml_dbus_object_get_property_location (dbobj, meta_iface, meta_property);

	dbus_type_s = (const char *) meta_property->dbus_type;

	nm_assert (G_IS_OBJECT (dbobj->nmobj));
	nm_assert (meta_iface->obj_properties);
	nm_assert (meta_property->obj_properties_idx > 0);
	param_spec = meta_iface->obj_properties[meta_property->obj_properties_idx];

	notify_update_prop_flags = NML_DBUS_NOTIFY_UPDATE_PROP_FLAGS_NOTIFY;

	switch (dbus_type_s[0]) {
	case 'b':
		nm_assert (dbus_type_s[1] == '\0');
		if (value)
			*((bool *) p_property) = g_variant_get_boolean (value);
		else if (param_spec->value_type == G_TYPE_BOOLEAN)
			*((bool *) p_property) = ((GParamSpecBoolean *) param_spec)->default_value;
		else {
			nm_assert_not_reached ();
			*((bool *) p_property) = FALSE;
		}
		break;
	case 'y':
		nm_assert (dbus_type_s[1] == '\0');
		if (value)
			*((guint8 *) p_property) = g_variant_get_byte (value);
		else {
			nm_assert (nm_utils_g_param_spec_is_default (param_spec));
			*((guint8 *) p_property) = 0;
		}
		break;
	case 'q':
		nm_assert (dbus_type_s[1] == '\0');
		if (value)
			*((guint16 *) p_property) = g_variant_get_uint16 (value);
		else {
			nm_assert (nm_utils_g_param_spec_is_default (param_spec));
			*((guint16 *) p_property) = 0;
		}
		break;
	case 'i':
		nm_assert (dbus_type_s[1] == '\0');
		if (value)
			*((gint32 *) p_property) = g_variant_get_int32 (value);
		else if (param_spec->value_type == G_TYPE_INT)
			*((gint32 *) p_property) = ((GParamSpecInt *) param_spec)->default_value;
		else {
			nm_assert (nm_utils_g_param_spec_is_default (param_spec));
			*((gint32 *) p_property) = 0;
		}
		break;
	case 'u':
		nm_assert (dbus_type_s[1] == '\0');
		if (value)
			*((guint32 *) p_property) = g_variant_get_uint32 (value);
		else {
			nm_assert (nm_utils_g_param_spec_is_default (param_spec));
			*((guint32 *) p_property) = 0;
		}
		break;
	case 'x':
		nm_assert (dbus_type_s[1] == '\0');
		if (value)
			*((gint64 *) p_property) = g_variant_get_int64 (value);
		else if (param_spec->value_type == G_TYPE_INT64)
			*((gint64 *) p_property) = ((GParamSpecInt64 *) param_spec)->default_value;
		else {
			nm_assert (nm_utils_g_param_spec_is_default (param_spec));
			*((gint64 *) p_property) = 0;
		}
		break;
	case 't':
		nm_assert (dbus_type_s[1] == '\0');
		if (value)
			*((guint64 *) p_property) = g_variant_get_uint64 (value);
		else {
			nm_assert (nm_utils_g_param_spec_is_default (param_spec));
			*((guint64 *) p_property) = 0;
		}
		break;
	case 's':
		nm_assert (dbus_type_s[1] == '\0');
		nm_clear_g_free ((char **) p_property);
		if (value)
			*((char **) p_property) = g_variant_dup_string (value, NULL);
		else {
			nm_assert (nm_utils_g_param_spec_is_default (param_spec));
			*((char **) p_property) = NULL;
		}
		break;
	case 'o':
		nm_assert (dbus_type_s[1] == '\0');
		notify_update_prop_flags = nml_dbus_property_o_notify (self,
		                                                       p_property,
		                                                       dbobj,
		                                                       meta_iface,
		                                                       dbus_property_idx,
		                                                       value);
		break;
	case 'a':
		switch (dbus_type_s[1]) {
		case 'y':
			nm_assert (dbus_type_s[2] == '\0');
			{
				gconstpointer v;
				gsize l;
				GBytes *b = NULL;

				if (value) {
					v = g_variant_get_fixed_array (value, &l, 1);

					if (l > 0) {
						/* empty arrays are coerced to NULL. */
						b = g_bytes_new (v, l);
					}
				}

				nm_clear_pointer ((GBytes **) p_property, g_bytes_unref);
				*((GBytes **) p_property) = b;
			}
			break;
		case 's':
			nm_assert (dbus_type_s[2] == '\0');
			nm_assert (param_spec->value_type == G_TYPE_STRV);

			g_strfreev (*((char ***) p_property));
			if (value)
				*((char ***) p_property) = g_variant_dup_strv (value, NULL);
			else
				*((char ***) p_property) = NULL;
			break;
		case 'o':
			nm_assert (dbus_type_s[2] == '\0');
			notify_update_prop_flags = nml_dbus_property_ao_notify (self,
			                                                        p_property,
			                                                        dbobj,
			                                                        meta_iface,
			                                                        dbus_property_idx,
			                                                        value);
			break;
		default:
			nm_assert_not_reached ();
		}
		break;
	default:
		nm_assert_not_reached ();
	}

notify:
	if (NM_FLAGS_HAS (notify_update_prop_flags, NML_DBUS_NOTIFY_UPDATE_PROP_FLAGS_NOTIFY))
		g_object_notify_by_pspec (dbobj->nmobj, (GParamSpec *) param_spec);
}

static void
_obj_handle_dbus_iface_changes (NMClient *self,
                                NMLDBusObject *dbobj,
                                NMLDBusObjIfaceData *db_iface_data)
{
	NMLDBusObjPropData *db_prop_data;
	gboolean is_self = (G_OBJECT (self) == dbobj->nmobj);
	gboolean is_removed;
	gboolean type_compatible;
	guint8 i_prop;

	nm_assert (NM_IS_CLIENT (self));
	nm_assert (is_self || NM_IS_OBJECT (dbobj->nmobj));

	if (G_UNLIKELY (!db_iface_data->nmobj_checked)) {
		db_iface_data->nmobj_checked = TRUE;
		type_compatible =    db_iface_data->dbus_iface.meta->get_type_fcn
		                  && g_type_is_a (G_OBJECT_TYPE (dbobj->nmobj), db_iface_data->dbus_iface.meta->get_type_fcn ());
		db_iface_data->nmobj_compatible = type_compatible;
	} else
		type_compatible = db_iface_data->nmobj_compatible;

	if (!type_compatible) {
		/* on D-Bus, we have this interface associate with the object, but apparently
		 * it is not compatible. This is either a bug, or NetworkManager exposed an
		 * unexpected interface on D-Bus object for which we create a certain NMObject
		 * type. */
		return;
	}

	is_removed = c_list_is_empty (&db_iface_data->iface_lst);

	nm_assert (   is_removed
	           || !c_list_is_empty (&db_iface_data->changed_prop_lst_head));

	_nm_client_queue_notify_object (self, dbobj->nmobj, NULL);

	if (is_removed) {
		for (i_prop = 0; i_prop < db_iface_data->dbus_iface.meta->n_dbus_properties; i_prop++) {
			_obj_handle_dbus_prop_changes (self,
			                               dbobj,
			                               db_iface_data,
			                               i_prop,
			                               NULL);
		}
	} else {
		while ((db_prop_data = c_list_first_entry (&db_iface_data->changed_prop_lst_head, NMLDBusObjPropData, changed_prop_lst))) {
			gs_unref_variant GVariant *prop_data_value = NULL;

			c_list_unlink (&db_prop_data->changed_prop_lst);

			nm_assert (db_prop_data >= db_iface_data->prop_datas);
			nm_assert (db_prop_data < &db_iface_data->prop_datas[db_iface_data->dbus_iface.meta->n_dbus_properties]);
			nm_assert (db_prop_data->prop_data_value);

			/* Currently NMLDBusObject forgets about the variant. Theoretically, it could cache
			 * it, but there is no need because we update the property in nmobj (which extracts and
			 * keeps the property value itself).
			 *
			 * Note that we only consume the variant here when we process it.
			 * That implies that we already created a NMObject for the dbobj
			 * instance. Unless that happens, we cache the last seen property values. */
			prop_data_value = g_steal_pointer (&db_prop_data->prop_data_value);

			i_prop = (db_prop_data - &db_iface_data->prop_datas[0]);
			_obj_handle_dbus_prop_changes (self,
			                               dbobj,
			                               db_iface_data,
			                               i_prop,
			                               prop_data_value);
		}
	}
}

static void
_obj_handle_dbus_changes (NMClient *self,
                          NMLDBusObject *dbobj)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (self);
	NMLDBusObjIfaceData *db_iface_data;
	NMLDBusObjIfaceData *db_iface_data_safe;
	gs_unref_object GObject *nmobj_unregistering = NULL;

	_ASSERT_dbobj (dbobj, self);

	/* In a first step we only remember all the changes that that a D-Bus message brings
	 * and queue the object to process them.
	 *
	 * Here (in step 2) we look at what changed on D-Bus and propagate those changes
	 * to the NMObject instance.
	 *
	 * Note that here we still must not emit any GObject signals. That follows later,
	 * and again if the object changes, we will just queue that we handle the changes
	 * later. */

	c_list_for_each_entry_safe (db_iface_data, db_iface_data_safe, &dbobj->iface_lst_head, iface_lst) {
		if (!db_iface_data->iface_removed)
			continue;
		c_list_unlink (&db_iface_data->iface_lst);
		if (   db_iface_data->dbus_iface_is_wellknown
		    && dbobj->nmobj)
			_obj_handle_dbus_iface_changes (self, dbobj, db_iface_data);
		nml_dbus_obj_iface_data_destroy (db_iface_data);
	}

	if (   G_UNLIKELY (!dbobj->nmobj)
	    && !c_list_is_empty (&dbobj->iface_lst_head)) {

		/* Try to create a NMObject for this D-Bus object. Note that we detect the type
		 * based on the interfaces that it has, and if we make a choice once, we don't
		 * change. That means, one D-Bus object can only be of one type. */

		if (NM_IN_SET (dbobj->dbus_path, _dbus_path_nm,
		                                 _dbus_path_settings,
		                                 _dbus_path_dns_manager)) {
			/* For the main types, we don't detect them based on the interfaces present,
			 * but on the path names. Of course, both should correspond anyway. */
			NML_NMCLIENT_LOG_T (self, "[%s]: register NMClient for D-Bus object",
			                    dbobj->dbus_path->str);
			dbobj->nmobj = G_OBJECT (self);
			if (dbobj->dbus_path == _dbus_path_nm) {
				nm_assert (!priv->dbobj_nm);
				priv->dbobj_nm = dbobj;
			} else if (dbobj->dbus_path == _dbus_path_settings) {
				nm_assert (!priv->dbobj_settings);
				priv->dbobj_settings = dbobj;
			} else {
				nm_assert (dbobj->dbus_path == _dbus_path_dns_manager);
				nm_assert (!priv->dbobj_dns_manager);
				priv->dbobj_dns_manager = dbobj;
			}
			nml_dbus_object_set_obj_state (dbobj, NML_DBUS_OBJ_STATE_WITH_NMOBJ_READY, self);
		} else {
			GType gtype = G_TYPE_NONE;
			NMLDBusMetaInteracePrio curr_prio = NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_LOW - 1;

			c_list_for_each_entry (db_iface_data, &dbobj->iface_lst_head, iface_lst) {
				nm_assert (!db_iface_data->iface_removed);
				if (!db_iface_data->dbus_iface_is_wellknown)
					break;
				if (db_iface_data->dbus_iface.meta->interface_prio <= curr_prio)
					continue;
				curr_prio = db_iface_data->dbus_iface.meta->interface_prio;
				gtype = db_iface_data->dbus_iface.meta->get_type_fcn ();
			}
			if (gtype != G_TYPE_NONE) {
				dbobj->nmobj = g_object_new (gtype, NULL);

				NML_NMCLIENT_LOG_T (self, "[%s]: register new NMObject "NM_HASH_OBFUSCATE_PTR_FMT" of type %s",
				                    dbobj->dbus_path->str,
				                    NM_HASH_OBFUSCATE_PTR (dbobj->nmobj),
				                    g_type_name (gtype));

				nm_assert (NM_IS_OBJECT (dbobj->nmobj));
				NM_OBJECT_GET_CLASS (dbobj->nmobj)->register_client (NM_OBJECT (dbobj->nmobj), self, dbobj);
				nml_dbus_object_set_obj_state (dbobj, NML_DBUS_OBJ_STATE_WITH_NMOBJ_NOT_READY, self);
			}
		}
	}

	c_list_for_each_entry (db_iface_data, &dbobj->iface_lst_head, iface_lst) {
		nm_assert (!db_iface_data->iface_removed);
		if (!db_iface_data->dbus_iface_is_wellknown)
			break;
		if (c_list_is_empty (&db_iface_data->changed_prop_lst_head))
			continue;
		if (dbobj->nmobj)
			_obj_handle_dbus_iface_changes (self, dbobj, db_iface_data);
	}

	if (   c_list_is_empty (&dbobj->iface_lst_head)
	    && dbobj->nmobj) {

		if (dbobj->nmobj == G_OBJECT (self)) {
			dbobj->nmobj = NULL;
			NML_NMCLIENT_LOG_T (self, "[%s]: unregister NMClient from D-Bus object",
			                    dbobj->dbus_path->str);
			if (dbobj->dbus_path == _dbus_path_nm) {
				nm_assert (priv->dbobj_nm == dbobj);
				priv->dbobj_nm = NULL;
				nml_dbus_property_o_clear_many (priv->nm.property_o, G_N_ELEMENTS (priv->nm.property_o), self);
				nml_dbus_property_ao_clear_many (priv->nm.property_ao, G_N_ELEMENTS (priv->nm.property_ao), self);
			} else if (dbobj->dbus_path == _dbus_path_settings) {
				nm_assert (priv->dbobj_settings == dbobj);
				priv->dbobj_settings = NULL;
				nml_dbus_property_ao_clear (&priv->settings.connections, self);
			} else {
				nm_assert (dbobj->dbus_path == _dbus_path_dns_manager);
				nm_assert (priv->dbobj_dns_manager == dbobj);
				priv->dbobj_dns_manager = NULL;
			}
		} else {
			nmobj_unregistering = g_steal_pointer (&dbobj->nmobj);
			nml_dbus_object_set_obj_state (dbobj, NML_DBUS_OBJ_STATE_WATCHED_ONLY, self);
			NML_NMCLIENT_LOG_T (self, "[%s]: unregister NMObject "NM_HASH_OBFUSCATE_PTR_FMT" of type %s",
			                    dbobj->dbus_path->str,
			                    NM_HASH_OBFUSCATE_PTR (nmobj_unregistering),
			                    g_type_name (G_OBJECT_TYPE (nmobj_unregistering)));
			NM_OBJECT_GET_CLASS (nmobj_unregistering)->unregister_client (NM_OBJECT (nmobj_unregistering), self, dbobj);
		}
	}

	nml_dbus_object_obj_changed_link (self, dbobj, NML_DBUS_OBJ_CHANGED_TYPE_NMOBJ);
}

/*****************************************************************************/

static void
_dbus_handle_obj_changed_nmobj (NMClient *self)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (self);
	NMLDBusObject *dbobj;
	CList obj_changed_tmp_lst_head = C_LIST_INIT (obj_changed_tmp_lst_head);

	nm_assert (!nml_dbus_object_obj_changed_any_linked (self, ~NML_DBUS_OBJ_CHANGED_TYPE_NMOBJ));

	/* First we notify all watchers that these objects changed. Note that we only do that
	 * here for the list before processing the changes below in a loop. That is, because
	 * processing changes can again enqueue changed objects, and we only want to want to
	 * notify watchers for the events that happened earlier (not repeatedly notify them). */
	c_list_splice (&obj_changed_tmp_lst_head, &priv->obj_changed_lst_head);
	while ((dbobj = c_list_first_entry (&obj_changed_tmp_lst_head, NMLDBusObject, obj_changed_lst))) {
		nm_c_list_move_tail (&priv->obj_changed_lst_head, &dbobj->obj_changed_lst);
		_dbobjs_notify_watchers_for_dbobj (self, dbobj);
	}

again:

	nm_assert (!nml_dbus_object_obj_changed_any_linked (self, ~NML_DBUS_OBJ_CHANGED_TYPE_NMOBJ));

	c_list_splice (&obj_changed_tmp_lst_head, &priv->obj_changed_lst_head);

	while ((dbobj = c_list_first_entry (&obj_changed_tmp_lst_head, NMLDBusObject, obj_changed_lst))) {

		if (!nml_dbus_object_obj_changed_consume (self, dbobj, NML_DBUS_OBJ_CHANGED_TYPE_NMOBJ)) {
			nm_assert_not_reached ();
			continue;
		}

		if (!dbobj->nmobj)
			continue;

		if (dbobj->nmobj == G_OBJECT (self)) {
			if (dbobj == priv->dbobj_nm) {
				nml_dbus_property_o_notify_changed_many (priv->nm.property_o, G_N_ELEMENTS (priv->nm.property_o), self);
				nml_dbus_property_ao_notify_changed_many (priv->nm.property_ao, G_N_ELEMENTS (priv->nm.property_ao), self);
			} else if (dbobj == priv->dbobj_settings)
				nml_dbus_property_ao_notify_changed (&priv->settings.connections, self);
			else
				nm_assert (dbobj == priv->dbobj_dns_manager);
		} else
			NM_OBJECT_GET_CLASS (dbobj->nmobj)->obj_changed_notify (NM_OBJECT (dbobj->nmobj));

		_dbobjs_check_dbobj_ready (self, dbobj);
	}

	if (!c_list_is_empty (&priv->obj_changed_lst_head)) {
		nm_assert (nml_dbus_object_obj_changed_any_linked (self, NML_DBUS_OBJ_CHANGED_TYPE_NMOBJ));
		/* we got new changes enqueued. Need to check again. */
		goto again;
	}
}

static void
_dbus_handle_obj_changed_dbus (NMClient *self,
                               const char *log_context)
{
	NMClientPrivate *priv;
	NMLDBusObject *dbobj;
	CList obj_changed_tmp_lst_head = C_LIST_INIT (obj_changed_tmp_lst_head);

	priv = NM_CLIENT_GET_PRIVATE (self);

	/* We move the changed list onto a temporary list and consume that.
	 * Note that nml_dbus_object_obj_changed_consume() will move the object
	 * back to the original list if there are changes of another type.
	 *
	 * This is done so that we can enqueue more changes while processing the
	 * change list. */
	c_list_splice (&obj_changed_tmp_lst_head, &priv->obj_changed_lst_head);

	while ((dbobj = c_list_first_entry (&obj_changed_tmp_lst_head, NMLDBusObject, obj_changed_lst))) {
		nm_auto_unref_nml_dbusobj NMLDBusObject *dbobj_unref = NULL;

		if (!nml_dbus_object_obj_changed_consume (self, dbobj, NML_DBUS_OBJ_CHANGED_TYPE_DBUS))
			continue;

		nm_assert (dbobj->obj_state >= NML_DBUS_OBJ_STATE_ON_DBUS);

		dbobj_unref = nml_dbus_object_ref (dbobj);

		_obj_handle_dbus_changes (self, dbobj);

		if (dbobj->obj_state == NML_DBUS_OBJ_STATE_UNLINKED)
			continue;

		if (   c_list_is_empty (&dbobj->iface_lst_head)
		    && c_list_is_empty (&dbobj->watcher_lst_head)) {
			NML_NMCLIENT_LOG_T (self, "[%s]: drop D-Bus instance", dbobj->dbus_path->str);
			nml_dbus_object_set_obj_state (dbobj, NML_DBUS_OBJ_STATE_UNLINKED, self);
			if (!g_hash_table_steal (priv->dbus_objects, dbobj))
				nm_assert_not_reached ();
			nml_dbus_object_unref (dbobj);
		}
	}

	/* D-Bus changes can only be enqueued in an earlier stage. We don't expect
	 * anymore changes of type D-Bus at this point. */
	nm_assert (!nml_dbus_object_obj_changed_any_linked (self, NML_DBUS_OBJ_CHANGED_TYPE_DBUS));
}

static void
_dbus_handle_changes_commit (NMClient *self,
                             gboolean allow_init_start_check_complete)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (self);
	nm_auto_pop_gmaincontext GMainContext *dbus_context = NULL;

	_dbus_handle_obj_changed_nmobj (self);

	dbus_context = nm_g_main_context_push_thread_default_if_necessary (priv->main_context);

	_nm_client_notify_event_emit (self);

	_set_nm_running (self);

	if (allow_init_start_check_complete)
		_init_start_check_complete (self);
}

static void
_dbus_handle_changes (NMClient *self,
                      const char *log_context,
                      gboolean allow_init_start_check_complete)
{
	_dbus_handle_obj_changed_dbus (self, log_context);
	_dbus_handle_changes_commit (self, allow_init_start_check_complete);
}

static gboolean
_dbus_handle_properties_changed (NMClient *self,
                                 const char *log_context,
                                 const char *object_path,
                                 const char *interface_name,
                                 gboolean allow_add_iface,
                                 GVariant *changed_properties,
                                 NMLDBusObject **inout_dbobj)
{
	NMLDBusObject *dbobj = NULL;
	NMLDBusObjIfaceData *db_iface_data = NULL;
	nm_auto_ref_string NMRefString *dbus_path = NULL;

	nm_assert (!changed_properties || g_variant_is_of_type (changed_properties, G_VARIANT_TYPE ("a{sv}")));

	{
		gs_free char *ss = NULL;

		NML_NMCLIENT_LOG_T (self, "[%s]: %s: properties changed for interface %s { %s }",
		                    object_path, log_context, interface_name,
		                    (ss = g_variant_print (changed_properties, TRUE)));
	}

	if (inout_dbobj) {
		dbobj = *inout_dbobj;
		nm_assert (!dbobj || nm_streq (object_path, dbobj->dbus_path->str));
	}
	if (!dbobj) {
		dbus_path = nm_ref_string_new (object_path);
		dbobj = _dbobjs_dbobj_get_r (self, dbus_path);
	}

	if (dbobj)
		db_iface_data = nml_dbus_object_iface_data_get (dbobj, interface_name, allow_add_iface);
	else if (allow_add_iface) {
		dbobj = _dbobjs_dbobj_create (self, g_steal_pointer (&dbus_path));
		nml_dbus_object_set_obj_state (dbobj, NML_DBUS_OBJ_STATE_ON_DBUS, self);
		db_iface_data = nml_dbus_object_iface_data_get (dbobj, interface_name, TRUE);
	}

	NM_SET_OUT (inout_dbobj, dbobj);

	if (!db_iface_data) {
		if (allow_add_iface)
			NML_NMCLIENT_LOG_E (self, "%s: [%s] too many interfaces on object. Something is very wrong", log_context, object_path);
		else
			NML_NMCLIENT_LOG_E (self, "%s: [%s] property changed signal for non existing interface %s", log_context, object_path, interface_name);
		nm_assert (   !dbobj
		           || dbobj->obj_state != NML_DBUS_OBJ_STATE_UNLINKED);
		return FALSE;
	}

	if (!db_iface_data->dbus_iface_is_wellknown)
		NML_NMCLIENT_LOG_W (self, "%s: [%s] ignore unknown interface %s", log_context, object_path, interface_name);
	else if (changed_properties) {
		GVariantIter iter_prop;
		const char *property_name;
		GVariant *property_value_tmp;

		g_variant_iter_init (&iter_prop, changed_properties);
		while (g_variant_iter_next (&iter_prop, "{&sv}", &property_name, &property_value_tmp)) {
			_nm_unused gs_unref_variant GVariant *property_value = property_value_tmp;
			const NMLDBusMetaProperty *meta_property;
			NMLDBusObjPropData *db_propdata;
			guint property_idx;

			meta_property = nml_dbus_meta_property_get (db_iface_data->dbus_iface.meta, property_name, &property_idx);
			if (!meta_property) {
				NML_NMCLIENT_LOG_W (self, "%s: [%s]: ignore unknown property %s.%s", log_context, object_path, interface_name, property_name);
				continue;
			}

			db_propdata = &db_iface_data->prop_datas[property_idx];

			NML_NMCLIENT_LOG_T (self, "[%s]: %s: %s property %s.%s",
			                    object_path, log_context,
			                    db_propdata->prop_data_value ? "update" : "set",
			                    interface_name, property_name);

			nm_g_variant_unref (db_propdata->prop_data_value);
			db_propdata->prop_data_value = g_steal_pointer (&property_value);
			nm_c_list_move_tail (&db_iface_data->changed_prop_lst_head, &db_propdata->changed_prop_lst);
		}
	}

	nml_dbus_object_obj_changed_link (self, dbobj, NML_DBUS_OBJ_CHANGED_TYPE_DBUS);
	return TRUE;
}

static gboolean
_dbus_handle_interface_added (NMClient *self,
                              const char *log_context,
                              const char *object_path,
                              GVariant *ifaces)
{
	gboolean changed = FALSE;
	const char *interface_name;
	GVariant *changed_properties;
	GVariantIter iter_ifaces;
	NMLDBusObject *dbobj = NULL;

	nm_assert (g_variant_is_of_type (ifaces, G_VARIANT_TYPE ("a{sa{sv}}")));

	g_variant_iter_init (&iter_ifaces, ifaces);
	while (g_variant_iter_next (&iter_ifaces, "{&s@a{sv}}", &interface_name, &changed_properties)) {
		_nm_unused gs_unref_variant GVariant *changed_properties_free = changed_properties;

		if (_dbus_handle_properties_changed (self, log_context, object_path, interface_name, TRUE, changed_properties, &dbobj))
			changed = TRUE;
	}

	return changed;
}

static gboolean
_dbus_handle_interface_removed (NMClient *self,
                                const char *log_context,
                                const char *object_path,
                                NMLDBusObject **inout_dbobj,
                                const char *const*removed_interfaces)
{
	gboolean changed = FALSE;
	NMLDBusObject *dbobj;
	gsize i;

	if (   inout_dbobj
	    && *inout_dbobj) {
		dbobj = *inout_dbobj;
		nm_assert (dbobj == _dbobjs_dbobj_get_s (self, object_path));
	} else {
		dbobj = _dbobjs_dbobj_get_s (self, object_path);
		if (!dbobj) {
			NML_NMCLIENT_LOG_E (self, "%s: [%s]: receive interface removed event for non existing object", log_context, object_path);
			return FALSE;
		}
		NM_SET_OUT (inout_dbobj, dbobj);
	}

	for (i = 0; removed_interfaces[i]; i++) {
		NMLDBusObjIfaceData *db_iface_data;
		const char *interface_name = removed_interfaces[i];

		db_iface_data = nml_dbus_object_iface_data_get (dbobj, interface_name, FALSE);
		if (!db_iface_data) {
			NML_NMCLIENT_LOG_E (self, "%s: [%s] receive interface remove event for unexpected interface %s", log_context, object_path, interface_name);
			continue;
		}

		NML_NMCLIENT_LOG_T (self, "%s: [%s] receive interface remove event for interface %s", log_context, object_path, interface_name);
		db_iface_data->iface_removed = TRUE;
		changed = TRUE;
	}

	if (changed)
		nml_dbus_object_obj_changed_link (self, dbobj, NML_DBUS_OBJ_CHANGED_TYPE_DBUS);

	return changed;
}

static void
_dbus_managed_objects_changed_cb (const char *object_path,
                                  GVariant *added_interfaces_and_properties,
                                  const char *const*removed_interfaces,
                                  gpointer user_data)
{
	NMClient *self = user_data;
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (self);
	const char *log_context;
	gboolean changed;

	if (priv->get_managed_objects_cancellable) {
		/* we still wait for the initial GetManagedObjects(). Ignore the event. */
		return;
	}

	if (!added_interfaces_and_properties) {
		log_context = "interfaces-removed";
		changed = _dbus_handle_interface_removed (self, log_context, object_path, NULL, removed_interfaces);
	} else {
		log_context = "interfaces-added";
		changed = _dbus_handle_interface_added (self, log_context, object_path, added_interfaces_and_properties);
	}

	if (changed)
		_dbus_handle_changes (self, log_context, TRUE);
}

static void
_dbus_properties_changed_cb (GDBusConnection *connection,
                             const char *sender_name,
                             const char *object_path,
                             const char *signal_interface_name,
                             const char *signal_name,
                             GVariant *parameters,
                             gpointer user_data)
{
	NMClient *self = user_data;
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (self);
	const char *interface_name;
	gs_unref_variant GVariant *changed_properties = NULL;
	gs_free const char **invalidated_properties = NULL;
	const char *log_context = "properties-changed";

	if (priv->get_managed_objects_cancellable) {
		/* we still wait for the initial GetManagedObjects(). Ignore the event. */
		return;
	}

	if (!g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(sa{sv}as)")))
		return;

	g_variant_get (parameters,
	               "(&s@a{sv}^a&s)",
	               &interface_name,
	               &changed_properties,
	               &invalidated_properties);

	if (invalidated_properties && invalidated_properties[0]) {
		NML_NMCLIENT_LOG_W (self, "%s: [%s] ignore invalidated properties on interface %s",
		                    log_context, object_path, interface_name);
	}

	if (_dbus_handle_properties_changed (self, log_context, object_path, interface_name, FALSE, changed_properties, NULL))
		_dbus_handle_changes (self, log_context, TRUE);
}

static void
_dbus_get_managed_objects_cb (GObject *source,
                              GAsyncResult *result,
                              gpointer user_data)
{
	NMClient *self;
	NMClientPrivate *priv;
	gs_unref_variant GVariant *ret = NULL;
	gs_unref_variant GVariant *managed_objects = NULL;
	gs_free_error GError *error = NULL;
	gs_unref_object GObject *context_busy_watcher = NULL;

	nm_utils_user_data_unpack (user_data, &self, &context_busy_watcher);

	ret = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source), result, &error);

	nm_assert ((!!ret) != (!!error));

	if (   !ret
	    && nm_utils_error_is_cancelled (error, FALSE))
		return;

	priv = NM_CLIENT_GET_PRIVATE (self);

	if (ret) {
		nm_assert (g_variant_is_of_type (ret, G_VARIANT_TYPE ("(a{oa{sa{sv}}})")));
		managed_objects = g_variant_get_child_value (ret, 0);
	}

	g_clear_object (&priv->get_managed_objects_cancellable);

	if (!managed_objects) {
		NML_NMCLIENT_LOG_D (self, "GetManagedObjects() call failed: %s", error->message);
		/* hm, now that's odd. Maybe NetworkManager just quit and we are about to get
		 * a name-owner changed signal soon. Treat this as if we got no managed objects at all. */
	} else
		NML_NMCLIENT_LOG_D (self, "GetManagedObjects() completed");

	if (managed_objects) {
		GVariantIter iter;
		const char *object_path;
		GVariant *ifaces_tmp;

		g_variant_iter_init (&iter, managed_objects);
		while (g_variant_iter_next (&iter, "{&o@a{sa{sv}}}", &object_path, &ifaces_tmp)) {
			gs_unref_variant GVariant *ifaces = ifaces_tmp;

			_dbus_handle_interface_added (self, "get-managed-objects", object_path, ifaces);
		}
	}

	/* always call _dbus_handle_changes(), even if nothing changed. We need this to complete
	 * initialization. */
	_dbus_handle_changes (self, "get-managed-objects", TRUE);
}

/*****************************************************************************/

static void
_nm_client_get_settings_call_cb (GObject *source, GAsyncResult *result, gpointer user_data)
{
	NMRemoteConnection *remote_connection;
	NMClient *self;
	gs_unref_variant GVariant *ret = NULL;
	gs_free_error GError *error = NULL;
	gs_unref_variant GVariant *settings = NULL;
	NMLDBusObject *dbobj;

	ret = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source), result, &error);
	if (   !ret
	    && nm_utils_error_is_cancelled (error, FALSE))
		return;

	remote_connection = user_data;

	self = _nm_object_get_client (remote_connection);

	dbobj = _nm_object_get_dbobj (remote_connection);

	_ASSERT_dbobj (dbobj, self);

	if (!ret) {
		NML_NMCLIENT_LOG_T (self, "[%s] GetSettings() completed with error: %s",
		                    dbobj->dbus_path->str,
		                    error->message);
	} else {
		NML_NMCLIENT_LOG_T (self, "[%s] GetSettings() completed with success",
		                    dbobj->dbus_path->str);
		g_variant_get (ret,
		               "(@a{sa{sv}})",
		               &settings);
	}

	_nm_remote_settings_get_settings_commit (remote_connection, settings);

	_dbus_handle_changes_commit (self, TRUE);
}

void
_nm_client_get_settings_call (NMClient *self,
                              NMLDBusObject *dbobj)
{
	GCancellable *cancellable;

	cancellable = _nm_remote_settings_get_settings_prepare (NM_REMOTE_CONNECTION (dbobj->nmobj));

	_nm_client_dbus_call_simple (self,
	                             cancellable,
	                             dbobj->dbus_path->str,
	                             NM_DBUS_INTERFACE_SETTINGS_CONNECTION,
	                             "GetSettings",
	                             g_variant_new ("()"),
	                             G_VARIANT_TYPE ("(a{sa{sv}})"),
	                             G_DBUS_CALL_FLAGS_NONE,
	                             NM_DBUS_DEFAULT_TIMEOUT_MSEC,
	                             _nm_client_get_settings_call_cb,
	                             dbobj->nmobj);
}

static void
_dbus_settings_updated_cb (GDBusConnection *connection,
                           const char *sender_name,
                           const char *object_path,
                           const char *signal_interface_name,
                           const char *signal_name,
                           GVariant *parameters,
                           gpointer user_data)
{
	NMClient *self = user_data;
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (self);
	const char *log_context = "settings-updated";
	NMLDBusObject *dbobj;

	if (priv->get_managed_objects_cancellable) {
		/* we still wait for the initial GetManagedObjects(). Ignore the event. */
		return;
	}

	if (!g_variant_is_of_type (parameters, G_VARIANT_TYPE ("()")))
		return;

	dbobj = _dbobjs_dbobj_get_s (self, object_path);

	if (   !dbobj
	    || !NM_IS_REMOTE_CONNECTION (dbobj->nmobj)) {
		NML_NMCLIENT_LOG_W (self, "%s: [%s] ignore Updated signal for non-existing setting",
		                    log_context, object_path);
		return;
	}

	NML_NMCLIENT_LOG_T (self, "%s: [%s] Updated signal received",
	                    log_context, object_path);

	_nm_client_get_settings_call (self, dbobj);
}

/*****************************************************************************/

static void
_dbus_nm_connection_active_state_changed_cb (GDBusConnection *connection,
                                             const char *sender_name,
                                             const char *object_path,
                                             const char *signal_interface_name,
                                             const char *signal_name,
                                             GVariant *parameters,
                                             gpointer user_data)
{
	NMClient *self = user_data;
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (self);
	const char *log_context = "active-connection-state-changed";
	NMLDBusObject *dbobj;
	guint32 state;
	guint32 reason;

	if (priv->get_managed_objects_cancellable) {
		/* we still wait for the initial GetManagedObjects(). Ignore the event. */
		return;
	}

	if (!g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(uu)"))) {
		NML_NMCLIENT_LOG_E (self, "%s: [%s] ignore StateChanged signal with unexpected signature",
		                    log_context, object_path);
		return;
	}

	dbobj = _dbobjs_dbobj_get_s (self, object_path);

	if (   !dbobj
	    || !NM_IS_ACTIVE_CONNECTION (dbobj->nmobj)) {
		NML_NMCLIENT_LOG_E (self, "%s: [%s] ignore StateChanged signal for non-existing active connection",
		                    log_context, object_path);
		return;
	}

	g_variant_get (parameters, "(uu)", &state, &reason);

	NML_NMCLIENT_LOG_T (self, "%s: [%s] StateChanged signal received",
	                    log_context, object_path);

	_nm_active_connection_state_changed_commit (NM_ACTIVE_CONNECTION (dbobj->nmobj),
	                                            state,
	                                            reason);

	_dbus_handle_changes_commit (self, TRUE);
}

/*****************************************************************************/

static void
_dbus_nm_vpn_connection_state_changed_cb (GDBusConnection *connection,
                                          const char *sender_name,
                                          const char *object_path,
                                          const char *signal_interface_name,
                                          const char *signal_name,
                                          GVariant *parameters,
                                          gpointer user_data)
{
	NMClient *self = user_data;
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (self);
	const char *log_context = "vpn-connection-state-changed";
	NMLDBusObject *dbobj;
	guint32 state;
	guint32 reason;

	if (priv->get_managed_objects_cancellable) {
		/* we still wait for the initial GetManagedObjects(). Ignore the event. */
		return;
	}

	if (!g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(uu)"))) {
		NML_NMCLIENT_LOG_E (self, "%s: [%s] ignore VpnStateChanged signal with unexpected signature",
		                    log_context, object_path);
		return;
	}

	dbobj = _dbobjs_dbobj_get_s (self, object_path);

	if (   !dbobj
	    || !NM_IS_VPN_CONNECTION (dbobj->nmobj)) {
		NML_NMCLIENT_LOG_E (self, "%s: [%s] ignore VpnStateChanged signal for non-existing vpn connection",
		                    log_context, object_path);
		return;
	}

	g_variant_get (parameters, "(uu)", &state, &reason);

	NML_NMCLIENT_LOG_T (self, "%s: [%s] VpnStateChanged signal received",
	                    log_context, object_path);

	_nm_vpn_connection_state_changed_commit (NM_VPN_CONNECTION (dbobj->nmobj),
	                                         state,
	                                         reason);

	_dbus_handle_changes_commit (self, TRUE);
}

/*****************************************************************************/

static void
_emit_permissions_changed (NMClient *self,
                           const guint8 *old_permissions,
                           const guint8 *permissions)
{
	int i;

	if (self->obj_base.is_disposing)
		return;

	if (old_permissions == permissions)
		return;

	for (i = 0; i < (int) G_N_ELEMENTS (nm_auth_permission_sorted); i++) {
		NMClientPermission perm = nm_auth_permission_sorted[i];
		NMClientPermissionResult perm_result = NM_CLIENT_PERMISSION_RESULT_UNKNOWN;
		NMClientPermissionResult perm_result_old = NM_CLIENT_PERMISSION_RESULT_UNKNOWN;

		if (permissions)
			perm_result = permissions[perm - 1];
		if (old_permissions)
			perm_result_old = old_permissions[perm - 1];

		if (perm_result == perm_result_old)
			continue;

		g_signal_emit (self,
		               signals[PERMISSION_CHANGED],
		               0,
		               (guint) perm,
		               (guint) perm_result);
	}
}


static void
_dbus_check_permissions_start_cb (GObject *source, GAsyncResult *result, gpointer user_data)
{
	nm_auto_pop_gmaincontext GMainContext *dbus_context = NULL;
	NMClient *self;
	NMClientPrivate *priv;
	gs_unref_variant GVariant *ret = NULL;
	nm_auto_free_variant_iter GVariantIter *v_permissions = NULL;
	gs_free guint8 *old_permissions = NULL;
	gs_free_error GError *error = NULL;
	const char *pkey;
	const char *pvalue;
	int i;

	ret = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source), result, &error);
	if (   !ret
	    && nm_utils_error_is_cancelled (error, FALSE))
		return;

	self = user_data;
	priv = NM_CLIENT_GET_PRIVATE (self);

	g_clear_object (&priv->permissions_cancellable);

	old_permissions = g_steal_pointer (&priv->permissions);

	if (!ret) {
		/* when the call completes, we always pretend success. Even a failure means
		 * that we fetched the permissions, however they are all unknown. */
		NML_NMCLIENT_LOG_T (self, "GetPermissions call failed: %s", error->message);
		goto out;
	}

	NML_NMCLIENT_LOG_T (self, "GetPermissions call finished with success");

	g_variant_get (ret, "(a{ss})", &v_permissions);
	while (g_variant_iter_next (v_permissions, "{&s&s}", &pkey, &pvalue)) {
		NMClientPermission perm;
		NMClientPermissionResult perm_result;

		perm = nm_auth_permission_from_string (pkey);
		if (perm == NM_CLIENT_PERMISSION_NONE)
			continue;

		perm_result = nm_client_permission_result_from_string (pvalue);

		if (!priv->permissions) {
			if (perm_result == NM_CLIENT_PERMISSION_RESULT_UNKNOWN)
				continue;
			priv->permissions = g_new (guint8, G_N_ELEMENTS (nm_auth_permission_sorted));
			for (i = 0; i < (int) G_N_ELEMENTS (nm_auth_permission_sorted); i++)
				priv->permissions[i] = NM_CLIENT_PERMISSION_RESULT_UNKNOWN;
		}
		priv->permissions[perm - 1] = perm_result;
	}

out:
	priv->permissions_state = NM_TERNARY_TRUE;

	dbus_context = nm_g_main_context_push_thread_default_if_necessary (priv->main_context);
	_emit_permissions_changed (self, old_permissions, priv->permissions);
	_notify (self, PROP_PERMISSIONS_STATE);
}

static void
_dbus_check_permissions_start (NMClient *self)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (self);
	gboolean fetch;

	fetch = !NM_FLAGS_HAS ((NMClientInstanceFlags) priv->instance_flags,
	                       NM_CLIENT_INSTANCE_FLAGS_NO_AUTO_FETCH_PERMISSIONS);

	nm_clear_g_cancellable (&priv->permissions_cancellable);

	if (fetch) {
		NML_NMCLIENT_LOG_T (self, "GetPermissions() call started...");

		priv->permissions_cancellable = g_cancellable_new ();
		_nm_client_dbus_call_simple (self,
		                             priv->permissions_cancellable,
		                             NM_DBUS_PATH,
		                             NM_DBUS_INTERFACE,
		                             "GetPermissions",
		                             g_variant_new ("()"),
		                             G_VARIANT_TYPE ("(a{ss})"),
		                             G_DBUS_CALL_FLAGS_NONE,
		                             NM_DBUS_DEFAULT_TIMEOUT_MSEC,
		                             _dbus_check_permissions_start_cb,
		                             self);
	}
}

static void
_dbus_nm_check_permissions_cb (GDBusConnection *connection,
                               const char *sender_name,
                               const char *object_path,
                               const char *signal_interface_name,
                               const char *signal_name,
                               GVariant *parameters,
                               gpointer user_data)
{
	NMClient *self = user_data;
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (self);

	if (!g_variant_is_of_type (parameters, G_VARIANT_TYPE ("()"))) {
		NML_NMCLIENT_LOG_E (self, "ignore CheckPermissions signal with unexpected signature %s",
		                    g_variant_get_type_string (parameters));
		return;
	}

	_dbus_check_permissions_start (self);

	if (priv->permissions_state == NM_TERNARY_TRUE)
		priv->permissions_state = NM_TERNARY_FALSE;
	_notify (self, PROP_PERMISSIONS_STATE);
}

/*****************************************************************************/

static void
_property_ao_notify_changed_connections_cb (NMLDBusPropertyAO *pr_ao,
                                            NMClient *self,
                                            NMObject *nmobj,
                                            gboolean is_added /* or else removed */)
{
	_nm_client_notify_event_queue_emit_obj_signal (self,
	                                               G_OBJECT (self),
	                                               nmobj,
	                                               is_added,
	                                               5,
	                                                 is_added
	                                               ? signals[CONNECTION_ADDED]
	                                               : signals[CONNECTION_REMOVED]);
}

static void
_property_ao_notify_changed_all_devices_cb (NMLDBusPropertyAO *pr_ao,
                                            NMClient *self,
                                            NMObject *nmobj,
                                            gboolean is_added /* or else removed */)
{
	_nm_client_notify_event_queue_emit_obj_signal (self,
	                                               G_OBJECT (self),
	                                               nmobj,
	                                               is_added,
	                                               6,
	                                                 is_added
	                                               ? signals[ANY_DEVICE_ADDED]
	                                               : signals[ANY_DEVICE_REMOVED]);
}

static void
_property_ao_notify_changed_devices_cb (NMLDBusPropertyAO *pr_ao,
                                        NMClient *self,
                                        NMObject *nmobj,
                                        gboolean is_added /* or else removed */)
{
	_nm_client_notify_event_queue_emit_obj_signal (self,
	                                               G_OBJECT (self),
	                                               nmobj,
	                                               is_added,
	                                               7,
	                                                 is_added
	                                               ? signals[DEVICE_ADDED]
	                                               : signals[DEVICE_REMOVED]);
}

static void
_property_ao_notify_changed_active_connections_cb (NMLDBusPropertyAO *pr_ao,
                                                  NMClient *self,
                                                  NMObject *nmobj,
                                                  gboolean is_added /* or else removed */)
{
	_nm_client_notify_event_queue_emit_obj_signal (self,
	                                               G_OBJECT (self),
	                                               nmobj,
	                                               is_added,
	                                               8,
	                                                 is_added
	                                               ? signals[ACTIVE_CONNECTION_ADDED]
	                                               : signals[ACTIVE_CONNECTION_REMOVED]);
}

/*****************************************************************************/

typedef struct {
	NMLDBusObjWatcherWithPtr *obj_watcher;
	const char *op_name;
	NMLDBusObject *dbobj;
	GTask *task;
	GVariant *extra_results;
	gpointer result;
	GType gtype;
	gulong cancellable_id;
} RequestWaitData;

static void
_request_wait_data_free (RequestWaitData *request_data)
{
	nm_assert (!request_data->obj_watcher);
	nm_assert (request_data->cancellable_id == 0);
	nm_assert (!request_data->task || G_IS_TASK (request_data->task));

	nm_g_object_unref (request_data->task);
	nm_g_object_unref (request_data->result);
	nm_g_variant_unref (request_data->extra_results);
	if (request_data->dbobj)
		nml_dbus_object_unref (request_data->dbobj);
	nm_g_slice_free (request_data);
}

static void
_request_wait_task_return (RequestWaitData *request_data)
{
	gs_unref_object GTask *task = NULL;

	nm_assert (request_data);
	nm_assert (G_IS_TASK (request_data->task));
	nm_assert (request_data->dbobj);
	nm_assert (NM_IS_OBJECT (request_data->dbobj->nmobj));
	nm_assert (!request_data->result);

	task = g_steal_pointer (&request_data->task);

	request_data->result = g_object_ref (request_data->dbobj->nmobj);
	nm_clear_g_signal_handler (g_task_get_cancellable (task), &request_data->cancellable_id);
	nm_clear_pointer (&request_data->dbobj, nml_dbus_object_unref);
	g_task_return_pointer (task, request_data, (GDestroyNotify) _request_wait_data_free);
}

static gboolean
_request_wait_complete (NMClient *self,
                        RequestWaitData *request_data,
                        gboolean force_complete)
{
	NMLDBusObject *dbobj;

	nm_assert (request_data);
	nm_assert (!request_data->result);
	nm_assert (!request_data->obj_watcher);
	nm_assert (request_data->dbobj);

	dbobj = request_data->dbobj;

	if (dbobj->obj_state == NML_DBUS_OBJ_STATE_WITH_NMOBJ_READY) {
		NML_NMCLIENT_LOG_D (self, "%s() succeeded with %s", request_data->op_name, dbobj->dbus_path->str);
		nm_assert (G_TYPE_CHECK_INSTANCE_TYPE (dbobj->nmobj, request_data->gtype));
		_request_wait_task_return (request_data);
		return TRUE;
	}

	if (   force_complete
	    || dbobj->obj_state != NML_DBUS_OBJ_STATE_WITH_NMOBJ_NOT_READY) {
		if (force_complete)
			NML_NMCLIENT_LOG_D (self, "%s() succeeded with %s but object is in an unsuitable state", request_data->op_name, dbobj->dbus_path->str);
		else
			NML_NMCLIENT_LOG_W (self, "%s() succeeded with %s but object is in an unsuitable state", request_data->op_name, dbobj->dbus_path->str);

		g_task_return_error (request_data->task, g_error_new (NM_CLIENT_ERROR,
		                                                      NM_CLIENT_ERROR_OBJECT_CREATION_FAILED,
		                                                      _("request succeeded with %s but object is in an unsuitable state"),
		                                                      dbobj->dbus_path->str));
		_request_wait_data_free (request_data);
		return TRUE;
	}

	return FALSE;
}

static void
_request_wait_complete_cb (NMClient *self,
                           NMClientNotifyEventWithPtr *notify_event)
{
	_request_wait_complete (self,
	                        notify_event->user_data,
	                        TRUE);
}

static void
_request_wait_obj_watcher_cb (NMClient *self,
                              gpointer obj_watcher_base)
{
	NMLDBusObjWatcherWithPtr *obj_watcher = obj_watcher_base;
	RequestWaitData *request_data = obj_watcher->user_data;
	NMLDBusObject *dbobj;

	dbobj = request_data->dbobj;

	if (dbobj->obj_state == NML_DBUS_OBJ_STATE_WITH_NMOBJ_NOT_READY)
		return;

	nm_assert (NM_IN_SET ((NMLDBusObjState) dbobj->obj_state, NML_DBUS_OBJ_STATE_WATCHED_ONLY,
	                                                          NML_DBUS_OBJ_STATE_ON_DBUS,
	                                                          NML_DBUS_OBJ_STATE_WITH_NMOBJ_READY));

	_dbobjs_obj_watcher_unregister (self, g_steal_pointer (&request_data->obj_watcher));

	nm_clear_g_signal_handler (g_task_get_cancellable (request_data->task), &request_data->cancellable_id);

	_nm_client_notify_event_queue_with_ptr (self,
	                                        NM_CLIENT_NOTIFY_EVENT_PRIO_AFTER + 30,
	                                        _request_wait_complete_cb,
	                                        request_data);
}

static void
_request_wait_cancelled_cb (GCancellable *cancellable,
                            gpointer user_data)
{
	RequestWaitData *request_data = user_data;
	NMClient *self;
	GError *error = NULL;

	nm_assert (cancellable == g_task_get_cancellable (request_data->task));

	nm_utils_error_set_cancelled (&error, FALSE, NULL);

	self = g_task_get_source_object (request_data->task);

	nm_clear_g_signal_handler (cancellable, &request_data->cancellable_id);

	_dbobjs_obj_watcher_unregister (self, g_steal_pointer (&request_data->obj_watcher));

	g_task_return_error (request_data->task, error);

	_request_wait_data_free (request_data);
}

static void
_request_wait_start (GTask *task_take,
                     const char *op_name,
                     GType gtype,
                     const char *dbus_path,
                     GVariant *extra_results_take)
{
	NMClient *self;
	gs_unref_object GTask *task = g_steal_pointer (&task_take);
	RequestWaitData *request_data;
	GCancellable *cancellable;
	NMLDBusObject *dbobj;

	nm_assert (G_IS_TASK (task));

	self = g_task_get_source_object (task);

	dbobj = _dbobjs_get_nmobj (self, dbus_path, gtype);

	if (!dbobj) {
		NML_NMCLIENT_LOG_E (self, "%s() succeeded with %s but object does not exist", op_name, dbus_path);
		g_task_return_error (task, g_error_new (NM_CLIENT_ERROR,
		                                        NM_CLIENT_ERROR_FAILED,
		                                        _("operation succeeded but object %s does not exist"),
		                                        dbus_path));
		return;
	}

	request_data = g_slice_new (RequestWaitData);
	*request_data = (RequestWaitData) {
		.task           = g_steal_pointer (&task),
		.op_name        = op_name,
		.gtype          = gtype,
		.dbobj          = nml_dbus_object_ref (dbobj),
		.obj_watcher    = NULL,
		.extra_results  = g_steal_pointer (&extra_results_take),
		.result         = NULL,
		.cancellable_id = 0,
	};

	if (_request_wait_complete (self, request_data, FALSE))
		return;

	NML_NMCLIENT_LOG_T (self, "%s() succeeded with %s. Wait for object to become ready", op_name, dbobj->dbus_path->str);

	request_data->obj_watcher = _dbobjs_obj_watcher_register_o (self,
	                                                            dbobj,
	                                                            _request_wait_obj_watcher_cb,
	                                                            sizeof (NMLDBusObjWatcherWithPtr));
	request_data->obj_watcher->user_data = request_data;

	cancellable = g_task_get_cancellable (request_data->task);
	if (cancellable) {
		gulong id;

		id = g_cancellable_connect (cancellable,
		                            G_CALLBACK (_request_wait_cancelled_cb),
		                            request_data,
		                            NULL);
		if (id == 0) {
			/* the callback was invoked synchronously, which destroyed @request_data.
			 * We must not touch @info anymore. */
		} else
			request_data->cancellable_id = id;
	}
}

static gpointer
_request_wait_finish (NMClient *client,
                      GAsyncResult *result,
                      gpointer source_tag,
                      GVariant **out_result,
                      GError **error)
{
	RequestWaitData *request_data = NULL;
	gpointer r;

	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);
	g_return_val_if_fail (nm_g_task_is_valid (result, client, source_tag), NULL);

	request_data = g_task_propagate_pointer (G_TASK (result), error);
	if (!request_data) {
		NM_SET_OUT (out_result, NULL);
		return NULL;
	}

	nm_assert (NM_IS_OBJECT (request_data->result));

	NM_SET_OUT (out_result, g_steal_pointer (&request_data->extra_results));
	r = g_steal_pointer (&request_data->result);

	nm_assert (NM_IS_OBJECT (r));

	_request_wait_data_free (request_data);
	return r;
}

/*****************************************************************************/

/**
 * nm_client_get_instance_flags:
 * @self: the #NMClient instance.
 *
 * Returns: the #NMClientInstanceFlags flags.
 *
 * Since: 1.24
 */
NMClientInstanceFlags
nm_client_get_instance_flags (NMClient *self)
{
	g_return_val_if_fail (NM_IS_CLIENT (self), NM_CLIENT_INSTANCE_FLAGS_NONE);

	return NM_CLIENT_GET_PRIVATE (self)->instance_flags;
}

/**
 * nm_client_get_dbus_connection:
 * @client: a #NMClient
 *
 * Gets the %GDBusConnection of the instance. This can be either passed when
 * constructing the instance (as "dbus-connection" property), or it will be
 * automatically initialized during async/sync init.
 *
 * Returns: (transfer none): the D-Bus connection of the client, or %NULL if none is set.
 *
 * Since: 1.22
 **/
GDBusConnection *
nm_client_get_dbus_connection (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);

	return NM_CLIENT_GET_PRIVATE (client)->dbus_connection;
}

/**
 * nm_client_get_dbus_name_owner:
 * @client: a #NMClient
 *
 * Returns: (transfer none): the current name owner of the D-Bus service of NetworkManager.
 *
 * Since: 1.22
 **/
const char *
nm_client_get_dbus_name_owner (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);

	return NM_CLIENT_GET_PRIVATE (client)->name_owner;
}

/**
 * nm_client_get_version:
 * @client: a #NMClient
 *
 * Gets NetworkManager version.
 *
 * Returns: string with the version (or %NULL if NetworkManager is not running)
 **/
const char *
nm_client_get_version (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);

	return NM_CLIENT_GET_PRIVATE (client)->nm.version;
}

/**
 * nm_client_get_state:
 * @client: a #NMClient
 *
 * Gets the current daemon state.
 *
 * Returns: the current %NMState
 **/
NMState
nm_client_get_state (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), NM_STATE_UNKNOWN);

	return NM_CLIENT_GET_PRIVATE (client)->nm.state;
}

/**
 * nm_client_get_startup:
 * @client: a #NMClient
 *
 * Tests whether the daemon is still in the process of activating
 * connections at startup.
 *
 * Returns: whether the daemon is still starting up
 **/
gboolean
nm_client_get_startup (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);

	return NM_CLIENT_GET_PRIVATE (client)->nm.startup;
}

static void
_set_nm_running (NMClient *self)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (self);
	gboolean nm_running;

	nm_running = priv->name_owner && !priv->get_managed_objects_cancellable;
	if (priv->nm_running != nm_running) {
		priv->nm_running = nm_running;
		_notify (self, PROP_NM_RUNNING);
	}
}

/**
 * nm_client_get_nm_running:
 * @client: a #NMClient
 *
 * Determines whether the daemon is running.
 *
 * Returns: %TRUE if the daemon is running
 **/
gboolean
nm_client_get_nm_running (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);

	return NM_CLIENT_GET_PRIVATE (client)->nm_running;
}

/**
 * nm_client_get_metered:
 * @client: a #NMClient
 *
 * Returns: whether the default route is metered.
 *
 * Since: 1.22
 */
NMMetered
nm_client_get_metered (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), NM_METERED_UNKNOWN);

	return NM_CLIENT_GET_PRIVATE (client)->nm.metered;
}

/**
 * nm_client_networking_get_enabled:
 * @client: a #NMClient
 *
 * Whether networking is enabled or disabled.
 *
 * Returns: %TRUE if networking is enabled, %FALSE if networking is disabled
 **/
gboolean
nm_client_networking_get_enabled (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);

	return NM_CLIENT_GET_PRIVATE (client)->nm.networking_enabled;
}

/**
 * nm_client_networking_set_enabled:
 * @client: a #NMClient
 * @enabled: %TRUE to set networking enabled, %FALSE to set networking disabled
 * @error: (allow-none): return location for a #GError, or %NULL
 *
 * Enables or disables networking.  When networking is disabled, all controlled
 * interfaces are disconnected and deactivated.  When networking is enabled,
 * all controlled interfaces are available for activation.
 *
 * Returns: %TRUE on success, %FALSE otherwise
 *
 * Deprecated: 1.22, use nm_client_networking_set_enabled_async() or GDBusConnection
 **/
gboolean
nm_client_networking_set_enabled (NMClient *client, gboolean enable, GError **error)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);

	/* FIXME(libnm-async-api): add nm_client_networking_set_enabled_async(). */

	return _nm_client_dbus_call_sync_void (client,
	                                       NULL,
	                                       NM_DBUS_PATH,
	                                       NM_DBUS_INTERFACE,
	                                       "Enable",
	                                       g_variant_new ("(b)", enable),
	                                       G_DBUS_CALL_FLAGS_NONE,
	                                       NM_DBUS_DEFAULT_TIMEOUT_MSEC,
	                                       TRUE,
	                                       error);
}

/**
 * nm_client_wireless_get_enabled:
 * @client: a #NMClient
 *
 * Determines whether the wireless is enabled.
 *
 * Returns: %TRUE if wireless is enabled
 **/
gboolean
nm_client_wireless_get_enabled (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);

	return NM_CLIENT_GET_PRIVATE (client)->nm.wireless_enabled;
}

/**
 * nm_client_wireless_set_enabled:
 * @client: a #NMClient
 * @enabled: %TRUE to enable wireless
 *
 * Enables or disables wireless devices.
 *
 * Deprecated: 1.22, use nm_client_wireless_set_enabled_async() or GDBusConnection
 */
void
nm_client_wireless_set_enabled (NMClient *client, gboolean enabled)
{
	g_return_if_fail (NM_IS_CLIENT (client));

	/* FIXME(libnm-async-api): add nm_client_wireless_set_enabled_async(). */

	_nm_client_set_property_sync_legacy (client,
	                                     NM_DBUS_PATH,
	                                     NM_DBUS_INTERFACE,
	                                     "WirelessEnabled",
	                                     "b",
	                                     enabled);
}

/**
 * nm_client_wireless_hardware_get_enabled:
 * @client: a #NMClient
 *
 * Determines whether the wireless hardware is enabled.
 *
 * Returns: %TRUE if the wireless hardware is enabled
 **/
gboolean
nm_client_wireless_hardware_get_enabled (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);

	return NM_CLIENT_GET_PRIVATE (client)->nm.wireless_hardware_enabled;
}

/**
 * nm_client_wwan_get_enabled:
 * @client: a #NMClient
 *
 * Determines whether WWAN is enabled.
 *
 * Returns: %TRUE if WWAN is enabled
 **/
gboolean
nm_client_wwan_get_enabled (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);

	return NM_CLIENT_GET_PRIVATE (client)->nm.wwan_enabled;
}

/**
 * nm_client_wwan_set_enabled:
 * @client: a #NMClient
 * @enabled: %TRUE to enable WWAN
 *
 * Enables or disables WWAN devices.
 **/
void
nm_client_wwan_set_enabled (NMClient *client, gboolean enabled)
{
	g_return_if_fail (NM_IS_CLIENT (client));

	/* FIXME(libnm-async-api): add nm_client_wwan_set_enabled_async(). */

	_nm_client_set_property_sync_legacy (client,
	                                     NM_DBUS_PATH,
	                                     NM_DBUS_INTERFACE,
	                                     "WwanEnabled",
	                                     "b",
	                                     enabled);
}

/**
 * nm_client_wwan_hardware_get_enabled:
 * @client: a #NMClient
 *
 * Determines whether the WWAN hardware is enabled.
 *
 * Returns: %TRUE if the WWAN hardware is enabled
 **/
gboolean
nm_client_wwan_hardware_get_enabled (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);

	return NM_CLIENT_GET_PRIVATE (client)->nm.wwan_hardware_enabled;
}

/**
 * nm_client_wimax_get_enabled:
 * @client: a #NMClient
 *
 * Determines whether WiMAX is enabled.
 *
 * Returns: %TRUE if WiMAX is enabled
 *
 * Deprecated: 1.22 This function always returns FALSE because WiMax is no longer supported
 **/
gboolean
nm_client_wimax_get_enabled (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);

	return FALSE;
}

/**
 * nm_client_wimax_set_enabled:
 * @client: a #NMClient
 * @enabled: %TRUE to enable WiMAX
 *
 * Enables or disables WiMAX devices.
 *
 * Deprecated: 1.22 This function does nothing because WiMax is no longer supported
 **/
void
nm_client_wimax_set_enabled (NMClient *client, gboolean enabled)
{
	g_return_if_fail (NM_IS_CLIENT (client));
}

/**
 * nm_client_wimax_hardware_get_enabled:
 * @client: a #NMClient
 *
 * Determines whether the WiMAX hardware is enabled.
 *
 * Returns: %TRUE if the WiMAX hardware is enabled
 *
 * Deprecated: 1.22 This function always returns FALSE because WiMax is no longer supported
 **/
gboolean
nm_client_wimax_hardware_get_enabled (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);

	return FALSE;
}

/**
 * nm_client_connectivity_check_get_available:
 * @client: a #NMClient
 *
 * Determine whether connectivity checking is available.  This
 * requires that the URI of a connectivity service has been set in the
 * configuration file.
 *
 * Returns: %TRUE if connectivity checking is available.
 *
 * Since: 1.10
 */
gboolean
nm_client_connectivity_check_get_available (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);

	return NM_CLIENT_GET_PRIVATE (client)->nm.connectivity_check_available;
}

/**
 * nm_client_connectivity_check_get_enabled:
 * @client: a #NMClient
 *
 * Determine whether connectivity checking is enabled.
 *
 * Returns: %TRUE if connectivity checking is enabled.
 *
 * Since: 1.10
 */
gboolean
nm_client_connectivity_check_get_enabled (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);

	return NM_CLIENT_GET_PRIVATE (client)->nm.connectivity_check_enabled;
}

/**
 * nm_client_connectivity_check_set_enabled:
 * @client: a #NMClient
 * @enabled: %TRUE to enable connectivity checking
 *
 * Enable or disable connectivity checking.  Note that if a
 * connectivity checking URI has not been configured, this will not
 * have any effect.
 *
 * Since: 1.10
 */
void
nm_client_connectivity_check_set_enabled (NMClient *client, gboolean enabled)
{
	g_return_if_fail (NM_IS_CLIENT (client));

	/* FIXME(libnm-async-api): add nm_client_wireless_set_enabled_async(). */

	_nm_client_set_property_sync_legacy (client,
	                                     NM_DBUS_PATH,
	                                     NM_DBUS_INTERFACE,
	                                     "ConnectivityCheckEnabled",
	                                     "b",
	                                     enabled);
}

/**
 * nm_client_connectivity_check_get_uri:
 * @client: a #NMClient
 *
 * Get the URI that will be queried to determine if there is internet
 * connectivity.
 *
 * Returns: (transfer none): the connectivity URI in use
 *
 * Since: 1.20
 */
const char *
nm_client_connectivity_check_get_uri (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);

	return NM_CLIENT_GET_PRIVATE (client)->nm.connectivity_check_uri;
}

/**
 * nm_client_get_logging:
 * @client: a #NMClient
 * @level: (allow-none): return location for logging level string
 * @domains: (allow-none): return location for log domains string. The string is
 *   a list of domains separated by ","
 * @error: (allow-none): return location for a #GError, or %NULL
 *
 * Gets NetworkManager current logging level and domains.
 *
 * Returns: %TRUE on success, %FALSE otherwise
 *
 * Deprecated: 1.22, use nm_client_get_logging_async() or GDBusConnection
 **/
gboolean
nm_client_get_logging (NMClient *client,
                       char **level,
                       char **domains,
                       GError **error)
{
	gs_unref_variant GVariant *ret = NULL;

	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);
	g_return_val_if_fail (level == NULL || *level == NULL, FALSE);
	g_return_val_if_fail (domains == NULL || *domains == NULL, FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	/* FIXME(libnm-async-api): add nm_client_get_logging_async(). */

	ret = _nm_client_dbus_call_sync (client,
	                                 NULL,
	                                 NM_DBUS_PATH,
	                                 NM_DBUS_INTERFACE,
	                                 "GetLogging",
	                                 g_variant_new ("()"),
	                                 G_VARIANT_TYPE ("(ss)"),
	                                 G_DBUS_CALL_FLAGS_NONE,
	                                 NM_DBUS_DEFAULT_TIMEOUT_MSEC,
	                                 TRUE,
	                                 error);
	if (!ret)
		return FALSE;

	g_variant_get (ret,
	               "(ss)",
	               level,
	               domains);
	return TRUE;
}

/**
 * nm_client_set_logging:
 * @client: a #NMClient
 * @level: (allow-none): logging level to set (%NULL or an empty string for no change)
 * @domains: (allow-none): logging domains to set. The string should be a list of log
 *   domains separated by ",". (%NULL or an empty string for no change)
 * @error: (allow-none): return location for a #GError, or %NULL
 *
 * Sets NetworkManager logging level and/or domains.
 *
 * Returns: %TRUE on success, %FALSE otherwise
 *
 * Deprecated: 1.22, use nm_client_set_logging_async() or GDBusConnection
 **/
gboolean
nm_client_set_logging (NMClient *client, const char *level, const char *domains, GError **error)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	/* FIXME(libnm-async-api): add nm_client_set_logging_async(). */

	return _nm_client_dbus_call_sync_void (client,
	                                       NULL,
	                                       NM_DBUS_PATH,
	                                       NM_DBUS_INTERFACE,
	                                       "SetLogging",
	                                       g_variant_new ("(ss)",
	                                                      level ?: "",
	                                                      domains ?: ""),
	                                       G_DBUS_CALL_FLAGS_NONE,
	                                       NM_DBUS_DEFAULT_TIMEOUT_MSEC,
	                                       TRUE,
	                                       error);
}

/**
 * nm_client_get_permission_result:
 * @client: a #NMClient
 * @permission: the permission for which to return the result, one of #NMClientPermission
 *
 * Requests the result of a specific permission, which indicates whether the
 * client can or cannot perform the action the permission represents
 *
 * Returns: the permission's result, one of #NMClientPermissionResult
 **/
NMClientPermissionResult
nm_client_get_permission_result (NMClient *client, NMClientPermission permission)
{
	NMClientPrivate *priv;
	NMClientPermissionResult result = NM_CLIENT_PERMISSION_RESULT_UNKNOWN;

	g_return_val_if_fail (NM_IS_CLIENT (client), NM_CLIENT_PERMISSION_RESULT_UNKNOWN);

	if (   permission > NM_CLIENT_PERMISSION_NONE
	    && permission <= NM_CLIENT_PERMISSION_LAST) {
		priv = NM_CLIENT_GET_PRIVATE (client);
		if (priv->permissions)
			result = priv->permissions[permission - 1];
	}

	return result;
}

/**
 * nm_client_get_permissions_state:
 * @self: the #NMClient instance
 *
 * Returns: the state of the cached permissions. %NM_TERNARY_DEFAULT
 *   means that no permissions result was yet received. All permissions
 *   are unknown. %NM_TERNARY_TRUE means that the permissions got received
 *   and are cached. %%NM_TERNARY_FALSE means that permissions are cached,
 *   but they are invalided as as "CheckPermissions" signal was received
 *   in the meantime.
 *
 * Since: 1.24
 */
NMTernary
nm_client_get_permissions_state (NMClient *self)
{
	g_return_val_if_fail (NM_IS_CLIENT (self), NM_TERNARY_DEFAULT);

	return NM_CLIENT_GET_PRIVATE (self)->permissions_state;
}

/**
 * nm_client_get_connectivity:
 * @client: an #NMClient
 *
 * Gets the current network connectivity state. Contrast
 * nm_client_check_connectivity() and
 * nm_client_check_connectivity_async(), which re-check the
 * connectivity state first before returning any information.
 *
 * Returns: the current connectivity state
 */
NMConnectivityState
nm_client_get_connectivity (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), NM_CONNECTIVITY_UNKNOWN);

	return NM_CLIENT_GET_PRIVATE (client)->nm.connectivity;
}

/**
 * nm_client_check_connectivity:
 * @client: an #NMClient
 * @cancellable: a #GCancellable
 * @error: return location for a #GError
 *
 * Updates the network connectivity state and returns the (new)
 * current state. Contrast nm_client_get_connectivity(), which returns
 * the most recent known state without re-checking.
 *
 * This is a blocking call; use nm_client_check_connectivity_async()
 * if you do not want to block.
 *
 * Returns: the (new) current connectivity state
 *
 * Deprecated: 1.22, use nm_client_check_connectivity_async() or GDBusConnection
 */
NMConnectivityState
nm_client_check_connectivity (NMClient *client,
                              GCancellable *cancellable,
                              GError **error)
{
	NMClientPrivate *priv;
	gs_unref_variant GVariant *ret = NULL;
	guint32 connectivity;

	g_return_val_if_fail (NM_IS_CLIENT (client), NM_CONNECTIVITY_UNKNOWN);

	ret = _nm_client_dbus_call_sync (client,
	                                 cancellable,
	                                 NM_DBUS_PATH,
	                                 NM_DBUS_INTERFACE,
	                                 "CheckConnectivity",
	                                 g_variant_new ("()"),
	                                 G_VARIANT_TYPE ("(u)"),
	                                 G_DBUS_CALL_FLAGS_NONE,
	                                 NM_DBUS_DEFAULT_TIMEOUT_MSEC,
	                                 TRUE,
	                                 error);
	if (!ret)
		return NM_CONNECTIVITY_UNKNOWN;

	g_variant_get (ret,
	               "(u)",
	               &connectivity);

	/* upon receiving the synchronous response, we hack the NMClient state
	 * and update the property outside the ordered D-Bus messages (like
	 * "PropertiesChanged" signals).
	 *
	 * This is really ugly, we shouldn't do this. */

	priv = NM_CLIENT_GET_PRIVATE (client);

	if (priv->nm.connectivity != connectivity) {
		priv->nm.connectivity = connectivity;
		_notify (client, PROP_CONNECTIVITY);
	}

	return connectivity;
}

/**
 * nm_client_check_connectivity_async:
 * @client: an #NMClient
 * @cancellable: a #GCancellable
 * @callback: callback to call with the result
 * @user_data: data for @callback.
 *
 * Asynchronously updates the network connectivity state and invokes
 * @callback when complete. Contrast nm_client_get_connectivity(),
 * which (immediately) returns the most recent known state without
 * re-checking, and nm_client_check_connectivity(), which blocks.
 */
void
nm_client_check_connectivity_async (NMClient *client,
                                    GCancellable *cancellable,
                                    GAsyncReadyCallback callback,
                                    gpointer user_data)
{
	g_return_if_fail (NM_IS_CLIENT (client));
	g_return_if_fail (!cancellable || G_IS_CANCELLABLE (cancellable));

	_nm_client_dbus_call (client,
	                      client,
	                      nm_client_check_connectivity_async,
	                      cancellable,
	                      callback,
	                      user_data,
	                      NM_DBUS_PATH,
	                      NM_DBUS_INTERFACE,
	                      "CheckConnectivity",
	                      g_variant_new ("()"),
	                      G_VARIANT_TYPE ("(u)"),
	                      G_DBUS_CALL_FLAGS_NONE,
	                      NM_DBUS_DEFAULT_TIMEOUT_MSEC,
	                      nm_dbus_connection_call_finish_variant_strip_dbus_error_cb);
}

/**
 * nm_client_check_connectivity_finish:
 * @client: an #NMClient
 * @result: the #GAsyncResult
 * @error: return location for a #GError
 *
 * Retrieves the result of an nm_client_check_connectivity_async()
 * call.
 *
 * Returns: the (new) current connectivity state
 */
NMConnectivityState
nm_client_check_connectivity_finish (NMClient *client,
                                     GAsyncResult *result,
                                     GError **error)
{
	gs_unref_variant GVariant *ret = NULL;
	guint32 connectivity;

	g_return_val_if_fail (NM_IS_CLIENT (client), NM_CONNECTIVITY_UNKNOWN);
	g_return_val_if_fail (nm_g_task_is_valid (client, result, nm_client_check_connectivity_async), NM_CONNECTIVITY_UNKNOWN);

	ret = g_task_propagate_pointer (G_TASK (result), error);
	if (!ret)
		return NM_CONNECTIVITY_UNKNOWN;

	g_variant_get (ret,
	               "(u)",
	               &connectivity);
	return connectivity;
}

/**
 * nm_client_save_hostname:
 * @client: the %NMClient
 * @hostname: (allow-none): the new persistent hostname to set, or %NULL to
 *   clear any existing persistent hostname
 * @cancellable: a #GCancellable, or %NULL
 * @error: return location for #GError
 *
 * Requests that the machine's persistent hostname be set to the specified value
 * or cleared.
 *
 * Returns: %TRUE if the request was successful, %FALSE if it failed
 *
 * Deprecated: 1.22, use nm_client_save_hostname_async() or GDBusConnection
 **/
gboolean
nm_client_save_hostname (NMClient *client,
                         const char *hostname,
                         GCancellable *cancellable,
                         GError **error)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);
	g_return_val_if_fail (!cancellable || G_IS_CANCELLABLE (cancellable), FALSE);

	return _nm_client_dbus_call_sync_void (client,
	                                       cancellable,
	                                       NM_DBUS_PATH_SETTINGS,
	                                       NM_DBUS_INTERFACE_SETTINGS,
	                                       "SaveHostname",
	                                       g_variant_new ("(s)", hostname ?: ""),
	                                       G_DBUS_CALL_FLAGS_NONE,
	                                       NM_DBUS_DEFAULT_TIMEOUT_MSEC,
	                                       TRUE,
	                                       error);
}

/**
 * nm_client_save_hostname_async:
 * @client: the %NMClient
 * @hostname: (allow-none): the new persistent hostname to set, or %NULL to
 *   clear any existing persistent hostname
 * @cancellable: a #GCancellable, or %NULL
 * @callback: (scope async): callback to be called when the operation completes
 * @user_data: (closure): caller-specific data passed to @callback
 *
 * Requests that the machine's persistent hostname be set to the specified value
 * or cleared.
 **/
void
nm_client_save_hostname_async (NMClient *client,
                               const char *hostname,
                               GCancellable *cancellable,
                               GAsyncReadyCallback callback,
                               gpointer user_data)
{
	g_return_if_fail (NM_IS_CLIENT (client));
	g_return_if_fail (!cancellable || G_IS_CANCELLABLE (cancellable));

	_nm_client_dbus_call (client,
	                      client,
	                      nm_client_save_hostname_async,
	                      cancellable,
	                      callback,
	                      user_data,
	                      NM_DBUS_PATH_SETTINGS,
	                      NM_DBUS_INTERFACE_SETTINGS,
	                      "SaveHostname",
	                      g_variant_new ("(s)", hostname ?: ""),
	                      G_VARIANT_TYPE ("()"),
	                      G_DBUS_CALL_FLAGS_NONE,
	                      NM_DBUS_DEFAULT_TIMEOUT_MSEC,
	                      nm_dbus_connection_call_finish_void_strip_dbus_error_cb);
}

/**
 * nm_client_save_hostname_finish:
 * @client: the %NMClient
 * @result: the result passed to the #GAsyncReadyCallback
 * @error: return location for #GError
 *
 * Gets the result of an nm_client_save_hostname_async() call.
 *
 * Returns: %TRUE if the request was successful, %FALSE if it failed
 **/
gboolean
nm_client_save_hostname_finish (NMClient *client,
                                GAsyncResult *result,
                                GError **error)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);
	g_return_val_if_fail (nm_g_task_is_valid (result, client, nm_client_save_hostname_async), FALSE);

	return g_task_propagate_boolean (G_TASK (result), error);
}

/*****************************************************************************/
/* Devices                                                                   */
/*****************************************************************************/

/**
 * nm_client_get_devices:
 * @client: a #NMClient
 *
 * Gets all the known network devices.  Use nm_device_get_type() or the
 * <literal>NM_IS_DEVICE_XXXX</literal> functions to determine what kind of
 * device member of the returned array is, and then you may use device-specific
 * methods such as nm_device_ethernet_get_hw_address().
 *
 * Returns: (transfer none) (element-type NMDevice): a #GPtrArray
 * containing all the #NMDevices.  The returned array is owned by the
 * #NMClient object and should not be modified.
 **/
const GPtrArray *
nm_client_get_devices (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);

	return nml_dbus_property_ao_get_objs_as_ptrarray (&NM_CLIENT_GET_PRIVATE (client)->nm.property_ao[PROPERTY_AO_IDX_DEVICES]);
}

/**
 * nm_client_get_all_devices:
 * @client: a #NMClient
 *
 * Gets both real devices and device placeholders (eg, software devices which
 * do not currently exist, but could be created automatically by NetworkManager
 * if one of their NMDevice::ActivatableConnections was activated).  Use
 * nm_device_is_real() to determine whether each device is a real device or
 * a placeholder.
 *
 * Use nm_device_get_type() or the NM_IS_DEVICE_XXXX() functions to determine
 * what kind of device each member of the returned array is, and then you may
 * use device-specific methods such as nm_device_ethernet_get_hw_address().
 *
 * Returns: (transfer none) (element-type NMDevice): a #GPtrArray
 * containing all the #NMDevices.  The returned array is owned by the
 * #NMClient object and should not be modified.
 *
 * Since: 1.2
 **/
const GPtrArray *
nm_client_get_all_devices (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);

	return nml_dbus_property_ao_get_objs_as_ptrarray (&NM_CLIENT_GET_PRIVATE (client)->nm.property_ao[PROPERTY_AO_IDX_ALL_DEVICES]);
}

/**
 * nm_client_get_device_by_path:
 * @client: a #NMClient
 * @object_path: the object path to search for
 *
 * Gets a #NMDevice from a #NMClient.
 *
 * Returns: (transfer none): the #NMDevice for the given @object_path or %NULL if none is found.
 **/
NMDevice *
nm_client_get_device_by_path (NMClient *client, const char *object_path)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);
	g_return_val_if_fail (object_path, NULL);

	return _dbobjs_get_nmobj_unpack_visible (client, object_path, NM_TYPE_DEVICE);
}

/**
 * nm_client_get_device_by_iface:
 * @client: a #NMClient
 * @iface: the interface name to search for
 *
 * Gets a #NMDevice from a #NMClient.
 *
 * Returns: (transfer none): the #NMDevice for the given @iface or %NULL if none is found.
 **/
NMDevice *
nm_client_get_device_by_iface (NMClient *client, const char *iface)
{
	const GPtrArray *devices;
	guint i;

	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);
	g_return_val_if_fail (iface, NULL);

	devices = nm_client_get_devices (client);
	for (i = 0; i < devices->len; i++) {
		NMDevice *candidate = g_ptr_array_index (devices, i);

		if (nm_streq0 (nm_device_get_iface (candidate), iface))
			return candidate;
	}

	return NULL;
}

/*****************************************************************************/
/* Active Connections                                           */
/*****************************************************************************/

/**
 * nm_client_get_active_connections:
 * @client: a #NMClient
 *
 * Gets the active connections.
 *
 * Returns: (transfer none) (element-type NMActiveConnection): a #GPtrArray
 *  containing all the active #NMActiveConnections.
 * The returned array is owned by the client and should not be modified.
 **/
const GPtrArray *
nm_client_get_active_connections (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);

	return nml_dbus_property_ao_get_objs_as_ptrarray (&NM_CLIENT_GET_PRIVATE (client)->nm.property_ao[PROPERTY_AO_IDX_ACTIVE_CONNECTIONS]);
}

/**
 * nm_client_get_primary_connection:
 * @client: an #NMClient
 *
 * Gets the #NMActiveConnection corresponding to the primary active
 * network device.
 *
 * In particular, when there is no VPN active, or the VPN does not
 * have the default route, this returns the active connection that has
 * the default route. If there is a VPN active with the default route,
 * then this function returns the active connection that contains the
 * route to the VPN endpoint.
 *
 * If there is no default route, or the default route is over a
 * non-NetworkManager-recognized device, this will return %NULL.
 *
 * Returns: (transfer none): the appropriate #NMActiveConnection, if
 * any
 */
NMActiveConnection *
nm_client_get_primary_connection (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);

	return nml_dbus_property_o_get_obj (&NM_CLIENT_GET_PRIVATE (client)->nm.property_o[PROPERTY_O_IDX_NM_PRIMAY_CONNECTION]);
}

/**
 * nm_client_get_activating_connection:
 * @client: an #NMClient
 *
 * Gets the #NMActiveConnection corresponding to a
 * currently-activating connection that is expected to become the new
 * #NMClient:primary-connection upon successful activation.
 *
 * Returns: (transfer none): the appropriate #NMActiveConnection, if
 * any.
 */
NMActiveConnection *
nm_client_get_activating_connection (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);

	return nml_dbus_property_o_get_obj (&NM_CLIENT_GET_PRIVATE (client)->nm.property_o[PROPERTY_O_IDX_NM_ACTIVATING_CONNECTION]);
}

/*****************************************************************************/

static void
activate_connection_cb (GObject *object,
                        GAsyncResult *result,
                        gpointer user_data)
{
	gs_unref_object GTask *task = user_data;
	gs_unref_variant GVariant *ret = NULL;
	const char *v_active_connection;
	GError *error = NULL;

	ret = g_dbus_connection_call_finish (G_DBUS_CONNECTION (object), result, &error);
	if (!ret) {
		if (!nm_utils_error_is_cancelled (error, FALSE))
			g_dbus_error_strip_remote_error (error);
		g_task_return_error (task, error);
		return;
	}

	g_variant_get (ret, "(&o)", &v_active_connection);

	_request_wait_start (g_steal_pointer (&task),
	                     "ActivateConnection",
	                     NM_TYPE_ACTIVE_CONNECTION,
	                     v_active_connection,
	                     NULL);
}

/**
 * nm_client_activate_connection_async:
 * @client: a #NMClient
 * @connection: (allow-none): an #NMConnection
 * @device: (allow-none): the #NMDevice
 * @specific_object: (allow-none): the object path of a connection-type-specific
 *   object this activation should use. This parameter is currently ignored for
 *   wired and mobile broadband connections, and the value of %NULL should be used
 *   (ie, no specific object).  For Wi-Fi or WiMAX connections, pass the object
 *   path of a #NMAccessPoint or #NMWimaxNsp owned by @device, which you can
 *   get using nm_object_get_path(), and which will be used to complete the
 *   details of the newly added connection.
 * @cancellable: a #GCancellable, or %NULL
 * @callback: callback to be called when the activation has started
 * @user_data: caller-specific data passed to @callback
 *
 * Asynchronously starts a connection to a particular network using the
 * configuration settings from @connection and the network device @device.
 * Certain connection types also take a "specific object" which is the object
 * path of a connection- specific object, like an #NMAccessPoint for Wi-Fi
 * connections, or an #NMWimaxNsp for WiMAX connections, to which you wish to
 * connect.  If the specific object is not given, NetworkManager can, in some
 * cases, automatically determine which network to connect to given the settings
 * in @connection.
 *
 * If @connection is not given for a device-based activation, NetworkManager
 * picks the best available connection for the device and activates it.
 *
 * Note that the callback is invoked when NetworkManager has started activating
 * the new connection, not when it finishes. You can use the returned
 * #NMActiveConnection object (in particular, #NMActiveConnection:state) to
 * track the activation to its completion.
 **/
void
nm_client_activate_connection_async (NMClient *client,
                                     NMConnection *connection,
                                     NMDevice *device,
                                     const char *specific_object,
                                     GCancellable *cancellable,
                                     GAsyncReadyCallback callback,
                                     gpointer user_data)
{
	const char *arg_connection = NULL;
	const char *arg_device = NULL;

	g_return_if_fail (NM_IS_CLIENT (client));

	if (connection) {
		g_return_if_fail (NM_IS_CONNECTION (connection));
		arg_connection = nm_connection_get_path (connection);
		g_return_if_fail (arg_connection);
	}

	if (device) {
		g_return_if_fail (NM_IS_DEVICE (device));
		arg_device = nm_object_get_path (NM_OBJECT (device));
		g_return_if_fail (arg_device);
	}

	NML_NMCLIENT_LOG_T (client, "ActivateConnection() for connection \"%s\", device \"%s\", specific_object \"%s",
	                    arg_connection ?: "/",
	                    arg_device ?: "/",
	                    specific_object ?: "/");

	_nm_client_dbus_call (client,
	                      client,
	                      nm_client_activate_connection_async,
	                      cancellable,
	                      callback,
	                      user_data,
	                      NM_DBUS_PATH,
	                      NM_DBUS_INTERFACE,
	                      "ActivateConnection",
	                      g_variant_new ("(ooo)",
	                                     arg_connection ?: "/",
	                                     arg_device ?: "/",
	                                     specific_object ?: "/"),
	                      G_VARIANT_TYPE ("(o)"),
	                      G_DBUS_CALL_FLAGS_NONE,
	                      NM_DBUS_DEFAULT_TIMEOUT_MSEC,
	                      activate_connection_cb);
}

/**
 * nm_client_activate_connection_finish:
 * @client: an #NMClient
 * @result: the result passed to the #GAsyncReadyCallback
 * @error: location for a #GError, or %NULL
 *
 * Gets the result of a call to nm_client_activate_connection_async().
 *
 * Returns: (transfer full): the new #NMActiveConnection on success, %NULL on
 *   failure, in which case @error will be set.
 **/
NMActiveConnection *
nm_client_activate_connection_finish (NMClient *client,
                                      GAsyncResult *result,
                                      GError **error)
{
	return NM_ACTIVE_CONNECTION (_request_wait_finish (client,
	                                                   result,
	                                                   nm_client_activate_connection_async,
	                                                   NULL,
	                                                   error));
}

/*****************************************************************************/

static void
_add_and_activate_connection_done (GObject *object,
                                   GAsyncResult *result,
                                   gboolean use_add_and_activate_v2,
                                   GTask *task_take)
{
	_nm_unused gs_unref_object GTask *task = task_take;
	gs_unref_variant GVariant *ret = NULL;
	GError *error = NULL;
	gs_unref_variant GVariant *v_result = NULL;
	const char *v_active_connection;
	const char *v_path;

	ret = g_dbus_connection_call_finish (G_DBUS_CONNECTION (object), result, &error);
	if (!ret) {
		if (!nm_utils_error_is_cancelled (error, FALSE))
			g_dbus_error_strip_remote_error (error);
		g_task_return_error (task, error);
		return;
	}

	if (use_add_and_activate_v2) {
		g_variant_get (ret,
		               "(&o&o@a{sv})",
		               &v_path,
		               &v_active_connection,
		               &v_result);
	} else {
		g_variant_get (ret,
		               "(&o&o)",
		               &v_path,
		               &v_active_connection);
	}

	_request_wait_start (g_steal_pointer (&task),
	                     "AddAndActivateConnection",
	                     NM_TYPE_ACTIVE_CONNECTION,
	                     v_active_connection,
	                     g_steal_pointer (&v_result));
}

static void
_add_and_activate_connection_v1_cb (GObject *object, GAsyncResult *result, gpointer user_data)
{
	_add_and_activate_connection_done (object, result, FALSE, user_data);
}

static void
_add_and_activate_connection_v2_cb (GObject *object, GAsyncResult *result, gpointer user_data)
{
	_add_and_activate_connection_done (object, result, TRUE, user_data);
}

static void
_add_and_activate_connection (NMClient *self,
                              gboolean is_v2,
                              NMConnection *partial,
                              NMDevice *device,
                              const char *specific_object,
                              GVariant *options,
                              GCancellable *cancellable,
                              GAsyncReadyCallback callback,
                              gpointer user_data)
{
	GVariant *arg_connection = NULL;
	gboolean use_add_and_activate_v2 = FALSE;
	const char *arg_device = NULL;
	gpointer source_tag;

	g_return_if_fail (NM_IS_CLIENT (self));
	g_return_if_fail (!partial || NM_IS_CONNECTION (partial));

	if (device) {
		g_return_if_fail (NM_IS_DEVICE (device));
		arg_device = nm_object_get_path (NM_OBJECT (device));
		g_return_if_fail (arg_device);
	}

	if (partial)
		arg_connection = nm_connection_to_dbus (partial, NM_CONNECTION_SERIALIZE_ALL);
	if (!arg_connection)
		arg_connection = g_variant_new_array (G_VARIANT_TYPE ("{sa{sv}}"), NULL, 0);

	if (is_v2) {
		if (!options)
			options = g_variant_new_array (G_VARIANT_TYPE ("{sv}"), NULL, 0);
		use_add_and_activate_v2 = TRUE;
		source_tag = nm_client_add_and_activate_connection2;
	} else {
		if (options) {
			if (g_variant_n_children (options) > 0)
				use_add_and_activate_v2 = TRUE;
			else
				nm_clear_pointer (&options, nm_g_variant_unref_floating);
		}
		source_tag = nm_client_add_and_activate_connection_async;
	}

	NML_NMCLIENT_LOG_D (self, "AddAndActivateConnection() started...");

	if (use_add_and_activate_v2) {
		_nm_client_dbus_call (self,
		                      self,
		                      source_tag,
		                      cancellable,
		                      callback,
		                      user_data,
		                      NM_DBUS_PATH,
		                      NM_DBUS_INTERFACE,
		                      "AddAndActivateConnection2",
		                      g_variant_new ("(@a{sa{sv}}oo@a{sv})",
		                                     arg_connection,
		                                     arg_device ?: "/",
		                                     specific_object ?: "/",
		                                     options),
		                      G_VARIANT_TYPE ("(ooa{sv})"),
		                      G_DBUS_CALL_FLAGS_NONE,
		                      NM_DBUS_DEFAULT_TIMEOUT_MSEC,
		                      _add_and_activate_connection_v2_cb);
	} else {
		_nm_client_dbus_call (self,
		                      self,
		                      source_tag,
		                      cancellable,
		                      callback,
		                      user_data,
		                      NM_DBUS_PATH,
		                      NM_DBUS_INTERFACE,
		                      "AddAndActivateConnection",
		                      g_variant_new ("(@a{sa{sv}}oo)",
		                                     arg_connection,
		                                     arg_device ?: "/",
		                                     specific_object ?: "/"),
		                      G_VARIANT_TYPE ("(oo)"),
		                      G_DBUS_CALL_FLAGS_NONE,
		                      NM_DBUS_DEFAULT_TIMEOUT_MSEC,
		                      _add_and_activate_connection_v1_cb);
	}
}

/**
 * nm_client_add_and_activate_connection_async:
 * @client: a #NMClient
 * @partial: (allow-none): an #NMConnection to add; the connection may be
 *   partially filled (or even %NULL) and will be completed by NetworkManager
 *   using the given @device and @specific_object before being added
 * @device: the #NMDevice
 * @specific_object: (allow-none): the object path of a connection-type-specific
 *   object this activation should use. This parameter is currently ignored for
 *   wired and mobile broadband connections, and the value of %NULL should be used
 *   (ie, no specific object).  For Wi-Fi or WiMAX connections, pass the object
 *   path of a #NMAccessPoint or #NMWimaxNsp owned by @device, which you can
 *   get using nm_object_get_path(), and which will be used to complete the
 *   details of the newly added connection.
 *   If the variant is floating, it will be consumed.
 * @cancellable: a #GCancellable, or %NULL
 * @callback: callback to be called when the activation has started
 * @user_data: caller-specific data passed to @callback
 *
 * Adds a new connection using the given details (if any) as a template,
 * automatically filling in missing settings with the capabilities of the given
 * device and specific object.  The new connection is then asynchronously
 * activated as with nm_client_activate_connection_async(). Cannot be used for
 * VPN connections at this time.
 *
 * Note that the callback is invoked when NetworkManager has started activating
 * the new connection, not when it finishes. You can used the returned
 * #NMActiveConnection object (in particular, #NMActiveConnection:state) to
 * track the activation to its completion.
 **/
void
nm_client_add_and_activate_connection_async (NMClient *client,
                                             NMConnection *partial,
                                             NMDevice *device,
                                             const char *specific_object,
                                             GCancellable *cancellable,
                                             GAsyncReadyCallback callback,
                                             gpointer user_data)
{
	_add_and_activate_connection (client,
	                              FALSE,
	                              partial,
	                              device,
	                              specific_object,
	                              NULL,
	                              cancellable,
	                              callback,
	                              user_data);
}

/**
 * nm_client_add_and_activate_connection_finish:
 * @client: an #NMClient
 * @result: the result passed to the #GAsyncReadyCallback
 * @error: location for a #GError, or %NULL
 *
 * Gets the result of a call to nm_client_add_and_activate_connection_async().
 *
 * You can call nm_active_connection_get_connection() on the returned
 * #NMActiveConnection to find the path of the created #NMConnection.
 *
 * Returns: (transfer full): the new #NMActiveConnection on success, %NULL on
 *   failure, in which case @error will be set.
 **/
NMActiveConnection *
nm_client_add_and_activate_connection_finish (NMClient *client,
                                              GAsyncResult *result,
                                              GError **error)
{
	return NM_ACTIVE_CONNECTION (_request_wait_finish (client,
	                                                   result,
	                                                   nm_client_add_and_activate_connection_async,
	                                                   NULL,
	                                                   error));
}

/**
 * nm_client_add_and_activate_connection2:
 * @client: a #NMClient
 * @partial: (allow-none): an #NMConnection to add; the connection may be
 *   partially filled (or even %NULL) and will be completed by NetworkManager
 *   using the given @device and @specific_object before being added
 * @device: the #NMDevice
 * @specific_object: (allow-none): the object path of a connection-type-specific
 *   object this activation should use. This parameter is currently ignored for
 *   wired and mobile broadband connections, and the value of %NULL should be used
 *   (ie, no specific object).  For Wi-Fi or WiMAX connections, pass the object
 *   path of a #NMAccessPoint or #NMWimaxNsp owned by @device, which you can
 *   get using nm_object_get_path(), and which will be used to complete the
 *   details of the newly added connection.
 * @options: a #GVariant containing a dictionary with options, or %NULL
 * @cancellable: a #GCancellable, or %NULL
 * @callback: callback to be called when the activation has started
 * @user_data: caller-specific data passed to @callback
 *
 * Adds a new connection using the given details (if any) as a template,
 * automatically filling in missing settings with the capabilities of the given
 * device and specific object.  The new connection is then asynchronously
 * activated as with nm_client_activate_connection_async(). Cannot be used for
 * VPN connections at this time.
 *
 * Note that the callback is invoked when NetworkManager has started activating
 * the new connection, not when it finishes. You can used the returned
 * #NMActiveConnection object (in particular, #NMActiveConnection:state) to
 * track the activation to its completion.
 *
 * This is identitcal to nm_client_add_and_activate_connection_async() but takes
 * a further @options parameter. Currently the following options are supported
 * by the daemon:
 *  * "persist": A string describing how the connection should be stored.
 *               The default is "disk", but it can be modified to "memory" (until
 *               the daemon quits) or "volatile" (will be deleted on disconnect).
 *  * "bind-activation": Bind the connection lifetime to something. The default is "none",
 *            meaning an explicit disconnect is needed. The value "dbus-client"
 *            means the connection will automatically be deactivated when the calling
 *            DBus client disappears from the system bus.
 *
 * Since: 1.16
 **/
void
nm_client_add_and_activate_connection2 (NMClient *client,
                                        NMConnection *partial,
                                        NMDevice *device,
                                        const char *specific_object,
                                        GVariant *options,
                                        GCancellable *cancellable,
                                        GAsyncReadyCallback callback,
                                        gpointer user_data)
{
	_add_and_activate_connection (client,
	                              TRUE,
	                              partial,
	                              device,
	                              specific_object,
	                              options,
	                              cancellable,
	                              callback,
	                              user_data);
}

/**
 * nm_client_add_and_activate_connection2_finish:
 * @client: an #NMClient
 * @result: the result passed to the #GAsyncReadyCallback
 * @error: location for a #GError, or %NULL
 * @out_result: (allow-none) (transfer full): the output result
 *   of type "a{sv}" returned by D-Bus' AddAndActivate2 call. Currently no
 *   output is implemented yet.
 *
 * Gets the result of a call to nm_client_add_and_activate_connection2().
 *
 * You can call nm_active_connection_get_connection() on the returned
 * #NMActiveConnection to find the path of the created #NMConnection.
 *
 * Returns: (transfer full): the new #NMActiveConnection on success, %NULL on
 *   failure, in which case @error will be set.
 **/
NMActiveConnection *
nm_client_add_and_activate_connection2_finish (NMClient *client,
                                               GAsyncResult *result,
                                               GVariant **out_result,
                                               GError **error)
{
	return NM_ACTIVE_CONNECTION (_request_wait_finish (client,
	                                                   result,
	                                                   nm_client_add_connection2,
	                                                   out_result,
	                                                   error));
}

/*****************************************************************************/

/**
 * nm_client_deactivate_connection:
 * @client: a #NMClient
 * @active: the #NMActiveConnection to deactivate
 * @cancellable: a #GCancellable, or %NULL
 * @error: location for a #GError, or %NULL
 *
 * Deactivates an active #NMActiveConnection.
 *
 * Returns: success or failure
 *
 * Deprecated: 1.22, use nm_client_deactivate_connection_async() or GDBusConnection
 **/
gboolean
nm_client_deactivate_connection (NMClient *client,
                                 NMActiveConnection *active,
                                 GCancellable *cancellable,
                                 GError **error)
{
	const char *active_path;

	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (active), FALSE);

	active_path = nm_object_get_path (NM_OBJECT (active));
	g_return_val_if_fail (active_path, FALSE);

	return _nm_client_dbus_call_sync_void (client,
	                                       cancellable,
	                                       NM_DBUS_PATH,
	                                       NM_DBUS_INTERFACE,
	                                       "DeactivateConnection",
	                                       g_variant_new ("(o)", active_path),
	                                       G_DBUS_CALL_FLAGS_NONE,
	                                       NM_DBUS_DEFAULT_TIMEOUT_MSEC,
	                                       TRUE,
	                                       error);
}

/**
 * nm_client_deactivate_connection_async:
 * @client: a #NMClient
 * @active: the #NMActiveConnection to deactivate
 * @cancellable: a #GCancellable, or %NULL
 * @callback: callback to be called when the deactivation has completed
 * @user_data: caller-specific data passed to @callback
 *
 * Asynchronously deactivates an active #NMActiveConnection.
 **/
void
nm_client_deactivate_connection_async (NMClient *client,
                                       NMActiveConnection *active,
                                       GCancellable *cancellable,
                                       GAsyncReadyCallback callback,
                                       gpointer user_data)
{
	const char *active_path;

	g_return_if_fail (NM_IS_CLIENT (client));
	g_return_if_fail (NM_IS_ACTIVE_CONNECTION (active));

	active_path = nm_object_get_path (NM_OBJECT (active));
	g_return_if_fail (active_path);

	_nm_client_dbus_call (client,
	                      client,
	                      nm_client_deactivate_connection_async,
	                      cancellable,
	                      callback,
	                      user_data,
	                      NM_DBUS_PATH,
	                      NM_DBUS_INTERFACE,
	                      "DeactivateConnection",
	                      g_variant_new ("(o)", active_path),
	                      G_VARIANT_TYPE ("()"),
	                      G_DBUS_CALL_FLAGS_NONE,
	                      NM_DBUS_DEFAULT_TIMEOUT_MSEC,
	                      nm_dbus_connection_call_finish_void_strip_dbus_error_cb);
}

/**
 * nm_client_deactivate_connection_finish:
 * @client: a #NMClient
 * @result: the result passed to the #GAsyncReadyCallback
 * @error: location for a #GError, or %NULL
 *
 * Gets the result of a call to nm_client_deactivate_connection_async().
 *
 * Returns: success or failure
 **/
gboolean
nm_client_deactivate_connection_finish (NMClient *client,
                                        GAsyncResult *result,
                                        GError **error)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);
	g_return_val_if_fail (nm_g_task_is_valid (result, client, nm_client_deactivate_connection_async), FALSE);

	return g_task_propagate_boolean (G_TASK (result), error);
}

/*****************************************************************************/
/* Connections                                                  */
/*****************************************************************************/

/**
 * nm_client_get_connections:
 * @client: the %NMClient
 *
 * Returns: (transfer none) (element-type NMRemoteConnection): an array
 * containing all connections provided by the remote settings service.  The
 * returned array is owned by the #NMClient object and should not be modified.
 *
 * The connections are as received from D-Bus and might not validate according
 * to nm_connection_verify().
 **/
const GPtrArray *
nm_client_get_connections (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);

	return nml_dbus_property_ao_get_objs_as_ptrarray (&NM_CLIENT_GET_PRIVATE (client)->settings.connections);
}

/**
 * nm_client_get_connection_by_id:
 * @client: the %NMClient
 * @id: the id of the remote connection
 *
 * Returns the first matching %NMRemoteConnection matching a given @id.
 *
 * Returns: (transfer none): the remote connection object on success, or %NULL if no
 *  matching object was found.
 *
 * The connection is as received from D-Bus and might not validate according
 * to nm_connection_verify().
 **/
NMRemoteConnection *
nm_client_get_connection_by_id (NMClient *client, const char *id)
{
	const GPtrArray *arr;
	guint i;

	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);
	g_return_val_if_fail (id, NULL);

	arr = nm_client_get_connections (client);
	for (i = 0; i < arr->len; i++) {
		NMRemoteConnection *c = NM_REMOTE_CONNECTION (arr->pdata[i]);

		if (nm_streq0 (id, nm_connection_get_id (NM_CONNECTION (c))))
			return c;
	}
	return NULL;
}

/**
 * nm_client_get_connection_by_path:
 * @client: the %NMClient
 * @path: the D-Bus object path of the remote connection
 *
 * Returns the %NMRemoteConnection representing the connection at @path.
 *
 * Returns: (transfer none): the remote connection object on success, or %NULL if the object was
 *  not known
 *
 * The connection is as received from D-Bus and might not validate according
 * to nm_connection_verify().
 **/
NMRemoteConnection *
nm_client_get_connection_by_path (NMClient *client, const char *path)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);
	g_return_val_if_fail (path != NULL, NULL);

	return _dbobjs_get_nmobj_unpack_visible (client, path, NM_TYPE_REMOTE_CONNECTION);
}

/**
 * nm_client_get_connection_by_uuid:
 * @client: the %NMClient
 * @uuid: the UUID of the remote connection
 *
 * Returns the %NMRemoteConnection identified by @uuid.
 *
 * Returns: (transfer none): the remote connection object on success, or %NULL if the object was
 *  not known
 *
 * The connection is as received from D-Bus and might not validate according
 * to nm_connection_verify().
 **/
NMRemoteConnection *
nm_client_get_connection_by_uuid (NMClient *client, const char *uuid)
{
	const GPtrArray *arr;
	guint i;

	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);
	g_return_val_if_fail (uuid, NULL);

	arr = nm_client_get_connections (client);
	for (i = 0; i < arr->len; i++) {
		NMRemoteConnection *c = NM_REMOTE_CONNECTION (arr->pdata[i]);

		if (nm_streq0 (uuid, nm_connection_get_uuid (NM_CONNECTION (c))))
			return c;
	}
	return NULL;
}

/*****************************************************************************/

static void
_add_connection_cb (GObject *source,
                    GAsyncResult *result,
                    gboolean with_extra_arg,
                    gpointer user_data)
{
	gs_unref_variant GVariant *ret = NULL;
	gs_unref_object GTask *task = user_data;
	gs_unref_variant GVariant *v_result = NULL;
	const char *v_path;
	GError *error = NULL;

	ret = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source), result, &error);
	if (!ret) {
		if (!nm_utils_error_is_cancelled (error, FALSE))
			g_dbus_error_strip_remote_error (error);
		g_task_return_error (task, error);
		return;
	}

	if (with_extra_arg) {
		g_variant_get (ret,
		               "(&o@a{sv})",
		               &v_path,
		               &v_result);
	} else {
		g_variant_get (ret,
		               "(&o)",
		               &v_path);
	}

	_request_wait_start (g_steal_pointer (&task),
	                     "AddConnection",
	                     NM_TYPE_REMOTE_CONNECTION,
	                     v_path,
	                     g_steal_pointer (&v_result));
}

static void
_add_connection_cb_without_extra_result (GObject *object, GAsyncResult *result, gpointer user_data)
{
	_add_connection_cb (object, result, FALSE, user_data);
}

static void
_add_connection_cb_with_extra_result (GObject *object, GAsyncResult *result, gpointer user_data)
{
	_add_connection_cb (object, result, TRUE, user_data);
}

static void
_add_connection_call (NMClient *self,
                      gpointer source_tag,
                      gboolean ignore_out_result,
                      GVariant *settings,
                      NMSettingsAddConnection2Flags flags,
                      GVariant *args,
                      GCancellable *cancellable,
                      GAsyncReadyCallback callback,
                      gpointer user_data)
{
	g_return_if_fail (NM_IS_CLIENT (self));
	g_return_if_fail (!settings || g_variant_is_of_type (settings, G_VARIANT_TYPE ("a{sa{sv}}")));
	g_return_if_fail (!args || g_variant_is_of_type (args, G_VARIANT_TYPE ("a{sv}")));

	NML_NMCLIENT_LOG_D (self, "AddConnection() started...");

	if (!settings)
		settings = g_variant_new_array (G_VARIANT_TYPE ("{sa{sv}}"), NULL, 0);

	/* Although AddConnection2() being capable to handle also AddConnection() and
	 * AddConnectionUnsaved() variants, we prefer to use the old D-Bus methods when
	 * they are sufficient. The reason is that libnm should avoid hard dependencies
	 * on 1.20 API whenever possible. */
	if (    ignore_out_result
	     && flags == NM_SETTINGS_ADD_CONNECTION2_FLAG_TO_DISK) {
		_nm_client_dbus_call (self,
		                      self,
		                      source_tag,
		                      cancellable,
		                      callback,
		                      user_data,
		                      NM_DBUS_PATH_SETTINGS,
		                      NM_DBUS_INTERFACE_SETTINGS,
		                      "AddConnection",
		                      g_variant_new ("(@a{sa{sv}})", settings),
		                      G_VARIANT_TYPE ("(o)"),
		                      G_DBUS_CALL_FLAGS_NONE,
		                      NM_DBUS_DEFAULT_TIMEOUT_MSEC,
		                      _add_connection_cb_without_extra_result);
	} else if (   ignore_out_result
	           && flags == NM_SETTINGS_ADD_CONNECTION2_FLAG_IN_MEMORY) {
		_nm_client_dbus_call (self,
		                      self,
		                      source_tag,
		                      cancellable,
		                      callback,
		                      user_data,
		                      NM_DBUS_PATH_SETTINGS,
		                      NM_DBUS_INTERFACE_SETTINGS,
		                      "AddConnectionUnsaved",
		                      g_variant_new ("(@a{sa{sv}})", settings),
		                      G_VARIANT_TYPE ("(o)"),
		                      G_DBUS_CALL_FLAGS_NONE,
		                      NM_DBUS_DEFAULT_TIMEOUT_MSEC,
		                      _add_connection_cb_without_extra_result);
	} else {
		_nm_client_dbus_call (self,
		                      self,
		                      source_tag,
		                      cancellable,
		                      callback,
		                      user_data,
		                      NM_DBUS_PATH_SETTINGS,
		                      NM_DBUS_INTERFACE_SETTINGS,
		                      "AddConnection2",
		                      g_variant_new ("(@a{sa{sv}}u@a{sv})",
		                                     settings,
		                                     (guint32) flags,
		                                        args
		                                     ?: g_variant_new_array (G_VARIANT_TYPE ("{sv}"), NULL, 0)),
		                      G_VARIANT_TYPE ("(oa{sv})"),
		                      G_DBUS_CALL_FLAGS_NONE,
		                      NM_DBUS_DEFAULT_TIMEOUT_MSEC,
		                      _add_connection_cb_with_extra_result);
	}
}

/**
 * nm_client_add_connection_async:
 * @client: the %NMClient
 * @connection: the connection to add. Note that this object's settings will be
 *   added, not the object itself
 * @save_to_disk: whether to immediately save the connection to disk
 * @cancellable: a #GCancellable, or %NULL
 * @callback: (scope async): callback to be called when the add operation completes
 * @user_data: (closure): caller-specific data passed to @callback
 *
 * Requests that the remote settings service add the given settings to a new
 * connection.  If @save_to_disk is %TRUE, the connection is immediately written
 * to disk; otherwise it is initially only stored in memory, but may be saved
 * later by calling the connection's nm_remote_connection_commit_changes()
 * method.
 *
 * @connection is untouched by this function and only serves as a template of
 * the settings to add.  The #NMRemoteConnection object that represents what
 * NetworkManager actually added is returned to @callback when the addition
 * operation is complete.
 *
 * Note that the #NMRemoteConnection returned in @callback may not contain
 * identical settings to @connection as NetworkManager may perform automatic
 * completion and/or normalization of connection properties.
 **/
void
nm_client_add_connection_async (NMClient *client,
                                NMConnection *connection,
                                gboolean save_to_disk,
                                GCancellable *cancellable,
                                GAsyncReadyCallback callback,
                                gpointer user_data)
{
	g_return_if_fail (NM_IS_CONNECTION (connection));

	_add_connection_call (client,
	                      nm_client_add_connection_async,
	                      TRUE,
	                      nm_connection_to_dbus (connection, NM_CONNECTION_SERIALIZE_ALL),
	                        save_to_disk
	                      ? NM_SETTINGS_ADD_CONNECTION2_FLAG_TO_DISK
	                      : NM_SETTINGS_ADD_CONNECTION2_FLAG_IN_MEMORY,
	                      NULL,
	                      cancellable,
	                      callback,
	                      user_data);
}

/**
 * nm_client_add_connection_finish:
 * @client: an #NMClient
 * @result: the result passed to the #GAsyncReadyCallback
 * @error: location for a #GError, or %NULL
 *
 * Gets the result of a call to nm_client_add_connection_async().
 *
 * Returns: (transfer full): the new #NMRemoteConnection on success, %NULL on
 *   failure, in which case @error will be set.
 **/
NMRemoteConnection *
nm_client_add_connection_finish (NMClient *client,
                                 GAsyncResult *result,
                                 GError **error)
{
	return NM_REMOTE_CONNECTION (_request_wait_finish (client,
	                                                   result,
	                                                   nm_client_add_connection_async,
	                                                   NULL,
	                                                   error));
}

/**
 * nm_client_add_connection2:
 * @client: the %NMClient
 * @settings: the "a{sa{sv}}" #GVariant with the content of the setting.
 * @flags: the %NMSettingsAddConnection2Flags argument.
 * @args: (allow-none): the "a{sv}" #GVariant with extra argument or %NULL
 *   for no extra arguments.
 * @ignore_out_result: this function wraps AddConnection2(), which has an
 *   additional result "a{sv}" output parameter. By setting this to %TRUE,
 *   you signal that you are not interested in that output parameter.
 *   This allows the function to fall back to AddConnection() and AddConnectionUnsaved(),
 *   which is interesting if you run against an older server version that does
 *   not yet provide AddConnection2(). By setting this to %FALSE, the function
 *   under the hood always calls AddConnection2().
 * @cancellable: a #GCancellable, or %NULL
 * @callback: (scope async): callback to be called when the add operation completes
 * @user_data: (closure): caller-specific data passed to @callback
 *
 * Call AddConnection2() D-Bus API asynchronously.
 *
 * Since: 1.20
 **/
void
nm_client_add_connection2 (NMClient *client,
                           GVariant *settings,
                           NMSettingsAddConnection2Flags flags,
                           GVariant *args,
                           gboolean ignore_out_result,
                           GCancellable *cancellable,
                           GAsyncReadyCallback callback,
                           gpointer user_data)
{
	_add_connection_call (client,
	                      nm_client_add_connection2,
	                      ignore_out_result,
	                      settings,
	                      flags,
	                      args,
	                      cancellable,
	                      callback,
	                      user_data);
}

/**
 * nm_client_add_connection2_finish:
 * @client: the #NMClient
 * @result: the #GAsyncResult
 * @out_result: (allow-none) (transfer full) (out): the output #GVariant
 *   from AddConnection2().
 *   If you care about the output result, then the "ignore_out_result"
 *   parameter of nm_client_add_connection2() must not be set to %TRUE.
 * @error: (allow-none): the error argument.
 *
 * Returns: (transfer full): on success, a pointer to the added
 *   #NMRemoteConnection.
 *
 * Since: 1.20
 */
NMRemoteConnection *
nm_client_add_connection2_finish (NMClient *client,
                                  GAsyncResult *result,
                                  GVariant **out_result,
                                  GError **error)
{
	return NM_REMOTE_CONNECTION (_request_wait_finish (client,
	                                                   result,
	                                                   nm_client_add_connection2,
	                                                   out_result,
	                                                   error));
}

/*****************************************************************************/

/**
 * nm_client_load_connections:
 * @client: the %NMClient
 * @filenames: (array zero-terminated=1): %NULL-terminated array of filenames to load
 * @failures: (out) (transfer full): on return, a %NULL-terminated array of
 *   filenames that failed to load
 * @cancellable: a #GCancellable, or %NULL
 * @error: return location for #GError
 *
 * Requests that the remote settings service load or reload the given files,
 * adding or updating the connections described within.
 *
 * The changes to the indicated files will not yet be reflected in
 * @client's connections array when the function returns.
 *
 * If all of the indicated files were successfully loaded, the
 * function will return %TRUE, and @failures will be set to %NULL. If
 * NetworkManager tried to load the files, but some (or all) failed,
 * then @failures will be set to a %NULL-terminated array of the
 * filenames that failed to load.
 *
 * Returns: %TRUE on success.
 *
 * Warning: before libnm 1.22, the boolean return value was inconsistent.
 *   That is made worse, because when running against certain server versions
 *   before 1.20, the server would return wrong values for success/failure.
 *   This means, if you use this function in libnm before 1.22, you are advised
 *   to ignore the boolean return value and only look at @failures and @error.
 *   With libnm >= 1.22, the boolean return value corresponds to whether @error was
 *   set. Note that even in the success case, you might have individual @failures.
 *   With 1.22, the return value is consistent with nm_client_load_connections_finish().
 *
 * Deprecated: 1.22, use nm_client_load_connections_async() or GDBusConnection
 **/
gboolean
nm_client_load_connections (NMClient *client,
                            char **filenames,
                            char ***failures,
                            GCancellable *cancellable,
                            GError **error)
{
	gs_unref_variant GVariant *ret = NULL;

	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);
	g_return_val_if_fail (!cancellable || G_IS_CANCELLABLE (cancellable), FALSE);

	ret = _nm_client_dbus_call_sync (client,
	                                 cancellable,
	                                 NM_DBUS_PATH_SETTINGS,
	                                 NM_DBUS_INTERFACE_SETTINGS,
	                                 "LoadConnections",
	                                 g_variant_new ("(^as)",
	                                                filenames ?: NM_PTRARRAY_EMPTY (char *)),
	                                 G_VARIANT_TYPE ("(bas)"),
	                                 G_DBUS_CALL_FLAGS_NONE,
	                                 NM_DBUS_DEFAULT_TIMEOUT_MSEC,
	                                 TRUE,
	                                 error);
	if (!ret) {
		*failures = NULL;
		return FALSE;
	}

	g_variant_get (ret,
	               "(b^as)",
	               NULL,
	               &failures);

	return TRUE;
}

/**
 * nm_client_load_connections_async:
 * @client: the %NMClient
 * @filenames: (array zero-terminated=1): %NULL-terminated array of filenames to load
 * @cancellable: a #GCancellable, or %NULL
 * @callback: (scope async): callback to be called when the operation completes
 * @user_data: (closure): caller-specific data passed to @callback
 *
 * Requests that the remote settings service asynchronously load or reload the
 * given files, adding or updating the connections described within.
 *
 * See nm_client_load_connections() for more details.
 **/
void
nm_client_load_connections_async (NMClient *client,
                                  char **filenames,
                                  GCancellable *cancellable,
                                  GAsyncReadyCallback callback,
                                  gpointer user_data)
{
	g_return_if_fail (NM_IS_CLIENT (client));
	g_return_if_fail (!cancellable || G_IS_CANCELLABLE (cancellable));

	_nm_client_dbus_call (client,
	                      client,
	                      nm_client_load_connections_async,
	                      cancellable,
	                      callback,
	                      user_data,
	                      NM_DBUS_PATH_SETTINGS,
	                      NM_DBUS_INTERFACE_SETTINGS,
	                      "LoadConnections",
	                      g_variant_new ("(^as)",
	                                     filenames ?: NM_PTRARRAY_EMPTY (char *)),
	                      G_VARIANT_TYPE ("(bas)"),
	                      G_DBUS_CALL_FLAGS_NONE,
	                      NM_DBUS_DEFAULT_TIMEOUT_MSEC,
	                      nm_dbus_connection_call_finish_variant_strip_dbus_error_cb);
}

/**
 * nm_client_load_connections_finish:
 * @client: the %NMClient
 * @failures: (out) (transfer full) (array zero-terminated=1): on return, a
 *    %NULL-terminated array of filenames that failed to load
 * @result: the result passed to the #GAsyncReadyCallback
 * @error: location for a #GError, or %NULL
 *
 * Gets the result of an nm_client_load_connections_async() call.

 * See nm_client_load_connections() for more details.
 *
 * Returns: %TRUE on success.
 *   Note that even in the success case, you might have individual @failures.
 **/
gboolean
nm_client_load_connections_finish (NMClient *client,
                                   char ***failures,
                                   GAsyncResult *result,
                                   GError **error)
{
	gs_unref_variant GVariant *ret = NULL;

	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);
	g_return_val_if_fail (nm_g_task_is_valid (result, client, nm_client_load_connections_async), FALSE);

	ret = g_task_propagate_pointer (G_TASK (result), error);
	if (!ret) {
		*failures = NULL;
		return FALSE;
	}

	g_variant_get (ret,
	               "(b^as)",
	               NULL,
	               &failures);

	return TRUE;
}

/**
 * nm_client_reload_connections:
 * @client: the #NMClient
 * @cancellable: a #GCancellable, or %NULL
 * @error: return location for #GError
 *
 * Requests that the remote settings service reload all connection
 * files from disk, adding, updating, and removing connections until
 * the in-memory state matches the on-disk state.
 *
 * Return value: %TRUE on success, %FALSE on failure
 *
 * Deprecated: 1.22, use nm_client_reload_connections_async() or GDBusConnection
 **/
gboolean
nm_client_reload_connections (NMClient *client,
                              GCancellable *cancellable,
                              GError **error)
{
	gs_unref_variant GVariant *ret = NULL;

	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);
	g_return_val_if_fail (!cancellable || G_IS_CANCELLABLE (cancellable), FALSE);

	ret = _nm_client_dbus_call_sync (client,
	                                 cancellable,
	                                 NM_DBUS_PATH_SETTINGS,
	                                 NM_DBUS_INTERFACE_SETTINGS,
	                                 "ReloadConnections",
	                                 g_variant_new ("()"),
	                                 G_VARIANT_TYPE ("(b)"),
	                                 G_DBUS_CALL_FLAGS_NONE,
	                                 NM_DBUS_DEFAULT_TIMEOUT_MSEC,
	                                 TRUE,
	                                 error);
	if (!ret)
		return FALSE;

	return TRUE;
}

/**
 * nm_client_reload_connections_async:
 * @client: the #NMClient
 * @cancellable: a #GCancellable, or %NULL
 * @callback: (scope async): callback to be called when the reload operation completes
 * @user_data: (closure): caller-specific data passed to @callback
 *
 * Requests that the remote settings service begin reloading all connection
 * files from disk, adding, updating, and removing connections until the
 * in-memory state matches the on-disk state.
 **/
void
nm_client_reload_connections_async (NMClient *client,
                                    GCancellable *cancellable,
                                    GAsyncReadyCallback callback,
                                    gpointer user_data)
{
	g_return_if_fail (NM_IS_CLIENT (client));
	g_return_if_fail (!cancellable || G_IS_CANCELLABLE (cancellable));

	_nm_client_dbus_call (client,
	                      client,
	                      nm_client_reload_connections_async,
	                      cancellable,
	                      callback,
	                      user_data,
	                      NM_DBUS_PATH_SETTINGS,
	                      NM_DBUS_INTERFACE_SETTINGS,
	                      "ReloadConnections",
	                      g_variant_new ("()"),
	                      G_VARIANT_TYPE ("(b)"),
	                      G_DBUS_CALL_FLAGS_NONE,
	                      NM_DBUS_DEFAULT_TIMEOUT_MSEC,
	                      nm_dbus_connection_call_finish_variant_strip_dbus_error_cb);
}

/**
 * nm_client_reload_connections_finish:
 * @client: the #NMClient
 * @result: the result passed to the #GAsyncReadyCallback
 * @error: return location for #GError
 *
 * Gets the result of an nm_client_reload_connections_async() call.
 *
 * Return value: %TRUE on success, %FALSE on failure
 **/
gboolean
nm_client_reload_connections_finish (NMClient *client,
                                     GAsyncResult *result,
                                     GError **error)
{
	gs_unref_variant GVariant *ret = NULL;

	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);
	g_return_val_if_fail (nm_g_task_is_valid (result, client, nm_client_reload_connections_async), FALSE);

	ret = g_task_propagate_pointer (G_TASK (result), error);
	if (!ret)
		return FALSE;

	return TRUE;
}

/*****************************************************************************/

/**
 * nm_client_get_dns_mode:
 * @client: the #NMClient
 *
 * Gets the current DNS processing mode.
 *
 * Return value: the DNS processing mode, or %NULL in case the
 *   value is not available.
 *
 * Since: 1.6
 **/
const char *
nm_client_get_dns_mode (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);

	return NM_CLIENT_GET_PRIVATE (client)->dns_manager.mode;
}

/**
 * nm_client_get_dns_rc_manager:
 * @client: the #NMClient
 *
 * Gets the current DNS resolv.conf manager.
 *
 * Return value: the resolv.conf manager or %NULL in case the
 *   value is not available.
 *
 * Since: 1.6
 **/
const char *
nm_client_get_dns_rc_manager (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);

	return NM_CLIENT_GET_PRIVATE (client)->dns_manager.rc_manager;
}

/**
 * nm_client_get_dns_configuration:
 * @client: a #NMClient
 *
 * Gets the current DNS configuration
 *
 * Returns: (transfer none) (element-type NMDnsEntry): a #GPtrArray
 * containing #NMDnsEntry elements or %NULL in case the value is not
 * available.  The returned array is owned by the #NMClient object
 * and should not be modified.
 *
 * Since: 1.6
 **/
const GPtrArray *
nm_client_get_dns_configuration (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);

	return NM_CLIENT_GET_PRIVATE (client)->dns_manager.configuration;
}

static NMLDBusNotifyUpdatePropFlags
_notify_update_prop_dns_manager_configuration (NMClient *self,
                                              NMLDBusObject *dbobj,
                                              const NMLDBusMetaIface *meta_iface,
                                              guint dbus_property_idx,
                                              GVariant *value)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (self);
	gs_unref_ptrarray GPtrArray *configuration_old = NULL;
	gs_unref_ptrarray GPtrArray *configuration_new = NULL;

	nm_assert (G_OBJECT (self) == dbobj->nmobj);

	if (value) {
		GVariant *entry_var_tmp;
		GVariantIter iter;
		GPtrArray *array;

		configuration_new = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_dns_entry_unref);

		g_variant_iter_init (&iter, value);
		while (g_variant_iter_next (&iter, "@a{sv}", &entry_var_tmp)) {
			gs_unref_variant GVariant *entry_var = entry_var_tmp;
			nm_auto_free_variant_iter GVariantIter *iterp_nameservers = NULL;
			nm_auto_free_variant_iter GVariantIter *iterp_domains = NULL;
			gs_free char **nameservers = NULL;
			gs_free char **domains = NULL;
			gboolean vpn = FALSE;
			NMDnsEntry *entry;
			char *interface = NULL;
			char *str;
			gint32 priority = 0;

			if (   !g_variant_lookup (entry_var, "nameservers", "as", &iterp_nameservers)
			    || !g_variant_lookup (entry_var, "priority", "i", &priority)) {
				g_warning ("Ignoring invalid DNS configuration");
				continue;
			}

			array = g_ptr_array_new ();
			while (g_variant_iter_next (iterp_nameservers, "&s", &str))
				g_ptr_array_add (array, str);
			g_ptr_array_add (array, NULL);
			nameservers = (char **) g_ptr_array_free (array, FALSE);

			if (g_variant_lookup (entry_var, "domains", "as", &iterp_domains)) {
				array = g_ptr_array_new ();
				while (g_variant_iter_next (iterp_domains, "&s", &str))
					g_ptr_array_add (array, str);
				g_ptr_array_add (array, NULL);
				domains = (char **) g_ptr_array_free (array, FALSE);
			}

			g_variant_lookup (entry_var, "interface", "&s", &interface);
			g_variant_lookup (entry_var, "vpn", "b", &vpn);

			entry = nm_dns_entry_new (interface,
			                          (const char *const*) nameservers,
			                          (const char *const*) domains,
			                          priority,
			                          vpn);
			if (!entry) {
				g_warning ("Ignoring invalid DNS entry");
				continue;
			}

			g_ptr_array_add (configuration_new, entry);
		}
	}

	configuration_old = priv->dns_manager.configuration;
	priv->dns_manager.configuration = g_steal_pointer (&configuration_new);

	return NML_DBUS_NOTIFY_UPDATE_PROP_FLAGS_NOTIFY;
}

/**
 * nm_client_get_capabilities:
 * @client: the #NMClient instance
 * @length: (out) (allow-none): the number of returned capabilities.
 *
 * Returns: (transfer none) (array length=length): the
 *   list of capabilities reported by the server or %NULL
 *   if the capabilities are unknown.
 *   The numeric values correspond to #NMCapability enum.
 *   The array is terminated by a numeric zero sentinel
 *   at position @length.
 *
 * Since: 1.24
 */
const guint32 *
nm_client_get_capabilities (NMClient *client,
                            gsize *length)
{
	NMClientPrivate *priv;

	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);
	g_return_val_if_fail (length, NULL);

	priv = NM_CLIENT_GET_PRIVATE (client);

	NM_SET_OUT (length, priv->nm.capabilities_len);
	return priv->nm.capabilities_arr;
}

static NMLDBusNotifyUpdatePropFlags
_notify_update_prop_nm_capabilities (NMClient *self,
                                     NMLDBusObject *dbobj,
                                     const NMLDBusMetaIface *meta_iface,
                                     guint dbus_property_idx,
                                     GVariant *value)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (self);

	nm_assert (G_OBJECT (self) == dbobj->nmobj);

	nm_clear_g_free (&priv->nm.capabilities_arr);
	priv->nm.capabilities_len = 0;

	if (value) {
		const guint32 *arr;
		gsize len;

		arr = g_variant_get_fixed_array (value, &len, sizeof (guint32));
		priv->nm.capabilities_len = len;
		priv->nm.capabilities_arr = g_new (guint32, len + 1);
		if (len > 0)
			memcpy (priv->nm.capabilities_arr, arr, len * sizeof (guint32));
		priv->nm.capabilities_arr[len] = 0;
	}

	return NML_DBUS_NOTIFY_UPDATE_PROP_FLAGS_NOTIFY;
}

/*****************************************************************************/

/**
 * nm_client_get_checkpoints:
 * @client: a #NMClient
 *
 * Gets all the active checkpoints.
 *
 * Returns: (transfer none) (element-type NMCheckpoint): a #GPtrArray
 * containing all the #NMCheckpoint.  The returned array is owned by the
 * #NMClient object and should not be modified.
 *
 * Since: 1.12
 **/
const GPtrArray *
nm_client_get_checkpoints (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);

	return nml_dbus_property_ao_get_objs_as_ptrarray (&NM_CLIENT_GET_PRIVATE (client)->nm.property_ao[PROPERTY_AO_IDX_CHECKPOINTS]);
}

static void
checkpoint_create_cb (GObject *object,
                      GAsyncResult *result,
                      gpointer user_data)
{
	gs_unref_object GTask *task = user_data;
	gs_unref_variant GVariant *ret = NULL;
	const char *v_checkpoint_path;
	GError *error = NULL;

	ret = g_dbus_connection_call_finish (G_DBUS_CONNECTION (object), result, &error);
	if (!ret) {
		if (!nm_utils_error_is_cancelled (error, FALSE))
			g_dbus_error_strip_remote_error (error);
		g_task_return_error (task, error);
		return;
	}

	g_variant_get (ret,
	               "(&o)",
	               &v_checkpoint_path);

	_request_wait_start (g_steal_pointer (&task),
	                     "CheckpointCreate",
	                     NM_TYPE_CHECKPOINT,
	                     v_checkpoint_path,
	                     NULL);
}

/**
 * nm_client_checkpoint_create:
 * @client: the %NMClient
 * @devices: (element-type NMDevice): a list of devices for which a
 *   checkpoint should be created.
 * @rollback_timeout: the rollback timeout in seconds
 * @flags: creation flags
 * @cancellable: a #GCancellable, or %NULL
 * @callback: (scope async): callback to be called when the add operation completes
 * @user_data: (closure): caller-specific data passed to @callback
 *
 * Creates a checkpoint of the current networking configuration
 * for given interfaces. An empty @devices argument means all
 * devices. If @rollback_timeout is not zero, a rollback is
 * automatically performed after the given timeout.
 *
 * Since: 1.12
 **/
void
nm_client_checkpoint_create (NMClient *client,
                             const GPtrArray *devices,
                             guint32 rollback_timeout,
                             NMCheckpointCreateFlags flags,
                             GCancellable *cancellable,
                             GAsyncReadyCallback callback,
                             gpointer user_data)
{
	gs_free const char **paths = NULL;
	guint i;

	g_return_if_fail (NM_IS_CLIENT (client));

	if (   devices
	    && devices->len > 0) {
		paths = g_new (const char *, devices->len + 1);
		for (i = 0; i < devices->len; i++)
			paths[i] = nm_object_get_path (NM_OBJECT (devices->pdata[i]));
		paths[i] = NULL;
	}

	_nm_client_dbus_call (client,
	                      client,
	                      nm_client_checkpoint_create,
	                      cancellable,
	                      callback,
	                      user_data,
	                      NM_DBUS_PATH,
	                      NM_DBUS_INTERFACE,
	                      "CheckpointCreate",
	                      g_variant_new ("(^aouu)",
	                                     paths ?: NM_PTRARRAY_EMPTY (const char *),
	                                     rollback_timeout,
	                                     flags),
	                      G_VARIANT_TYPE ("(o)"),
	                      G_DBUS_CALL_FLAGS_NONE,
	                      NM_DBUS_DEFAULT_TIMEOUT_MSEC,
	                      checkpoint_create_cb);
}

/**
 * nm_client_checkpoint_create_finish:
 * @client: the #NMClient
 * @result: the result passed to the #GAsyncReadyCallback
 * @error: location for a #GError, or %NULL
 *
 * Gets the result of a call to nm_client_checkpoint_create().
 *
 * Returns: (transfer full): the new #NMCheckpoint on success, %NULL on
 *   failure, in which case @error will be set.
 *
 * Since: 1.12
 **/
NMCheckpoint *
nm_client_checkpoint_create_finish (NMClient *client,
                                    GAsyncResult *result,
                                    GError **error)
{
	return NM_CHECKPOINT (_request_wait_finish (client,
	                                            result,
	                                            nm_client_checkpoint_create,
	                                            NULL,
	                                            error));
}

/**
 * nm_client_checkpoint_destroy:
 * @client: the %NMClient
 * @checkpoint_path: the D-Bus path for the checkpoint
 * @cancellable: a #GCancellable, or %NULL
 * @callback: (scope async): callback to be called when the add operation completes
 * @user_data: (closure): caller-specific data passed to @callback
 *
 * Destroys an existing checkpoint without performing a rollback.
 *
 * Since: 1.12
 **/
void
nm_client_checkpoint_destroy (NMClient *client,
                              const char *checkpoint_path,
                              GCancellable *cancellable,
                              GAsyncReadyCallback callback,
                              gpointer user_data)
{
	g_return_if_fail (NM_IS_CLIENT (client));
	g_return_if_fail (checkpoint_path && checkpoint_path[0] == '/');

	_nm_client_dbus_call (client,
	                      client,
	                      nm_client_checkpoint_destroy,
	                      cancellable,
	                      callback,
	                      user_data,
	                      NM_DBUS_PATH,
	                      NM_DBUS_INTERFACE,
	                      "CheckpointDestroy",
	                      g_variant_new ("(o)", checkpoint_path),
	                      G_VARIANT_TYPE ("()"),
	                      G_DBUS_CALL_FLAGS_NONE,
	                      NM_DBUS_DEFAULT_TIMEOUT_MSEC,
	                      nm_dbus_connection_call_finish_void_strip_dbus_error_cb);
}

/**
 * nm_client_checkpoint_destroy_finish:
 * @client: an #NMClient
 * @result: the result passed to the #GAsyncReadyCallback
 * @error: location for a #GError, or %NULL
 *
 * Gets the result of a call to nm_client_checkpoint_destroy().
 *
 * Returns: %TRUE on success or %FALSE on failure, in which case
 *   @error will be set.
 *
 * Since: 1.12
 **/
gboolean
nm_client_checkpoint_destroy_finish (NMClient *client,
                                     GAsyncResult *result,
                                     GError **error)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);
	g_return_val_if_fail (nm_g_task_is_valid (result, client, nm_client_checkpoint_destroy), FALSE);

	return g_task_propagate_boolean (G_TASK (result), error);
}

/**
 * nm_client_checkpoint_rollback:
 * @client: the %NMClient
 * @checkpoint_path: the D-Bus path to the checkpoint
 * @cancellable: a #GCancellable, or %NULL
 * @callback: (scope async): callback to be called when the add operation completes
 * @user_data: (closure): caller-specific data passed to @callback
 *
 * Performs the rollback of a checkpoint before the timeout is reached.
 *
 * Since: 1.12
 **/
void
nm_client_checkpoint_rollback (NMClient *client,
                               const char *checkpoint_path,
                               GCancellable *cancellable,
                               GAsyncReadyCallback callback,
                               gpointer user_data)
{
	g_return_if_fail (NM_IS_CLIENT (client));
	g_return_if_fail (checkpoint_path && checkpoint_path[0] == '/');

	_nm_client_dbus_call (client,
	                      client,
	                      nm_client_checkpoint_rollback,
	                      cancellable,
	                      callback,
	                      user_data,
	                      NM_DBUS_PATH,
	                      NM_DBUS_INTERFACE,
	                      "CheckpointRollback",
	                      g_variant_new ("(o)", checkpoint_path),
	                      G_VARIANT_TYPE ("(a{su})"),
	                      G_DBUS_CALL_FLAGS_NONE,
	                      NM_DBUS_DEFAULT_TIMEOUT_MSEC,
	                      nm_dbus_connection_call_finish_variant_strip_dbus_error_cb);
}

/**
 * nm_client_checkpoint_rollback_finish:
 * @client: an #NMClient
 * @result: the result passed to the #GAsyncReadyCallback
 * @error: location for a #GError, or %NULL
 *
 * Gets the result of a call to nm_client_checkpoint_rollback().
 *
 * Returns: (transfer full) (element-type utf8 guint32): an hash table of
 *   devices and results. Devices are represented by their original
 *   D-Bus path; each result is a #NMRollbackResult.
 *
 * Since: 1.12
 **/
GHashTable *
nm_client_checkpoint_rollback_finish (NMClient *client,
                                      GAsyncResult *result,
                                      GError **error)
{
	gs_unref_variant GVariant *ret = NULL;
	gs_unref_variant GVariant *v_result = NULL;
	GVariantIter iter;
	GHashTable *hash;
	const char *path;
	guint32 r;

	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);
	g_return_val_if_fail (nm_g_task_is_valid (result, client, nm_client_checkpoint_rollback), NULL);

	ret = g_task_propagate_pointer (G_TASK (result), error);
	if (!ret)
		return NULL;

	g_variant_get (ret,
	               "(@a{su})",
	               &v_result);

	hash = g_hash_table_new_full (nm_str_hash, g_str_equal, g_free, NULL);

	g_variant_iter_init (&iter, v_result);
	while (g_variant_iter_next (&iter, "{&su}", &path, &r))
		g_hash_table_insert (hash, g_strdup (path), GUINT_TO_POINTER (r));

	return hash;
}

/**
 * nm_client_checkpoint_adjust_rollback_timeout:
 * @client: the %NMClient
 * @checkpoint_path: a D-Bus path to a checkpoint
 * @add_timeout: the timeout in seconds counting from now.
 *   Set to zero, to disable the timeout.
 * @cancellable: a #GCancellable, or %NULL
 * @callback: (scope async): callback to be called when the add operation completes
 * @user_data: (closure): caller-specific data passed to @callback
 *
 * Resets the timeout for the checkpoint with path @checkpoint_path
 * to @timeout_add.
 *
 * Since: 1.12
 **/
void
nm_client_checkpoint_adjust_rollback_timeout (NMClient *client,
                                              const char *checkpoint_path,
                                              guint32 add_timeout,
                                              GCancellable *cancellable,
                                              GAsyncReadyCallback callback,
                                              gpointer user_data)
{
	g_return_if_fail (NM_IS_CLIENT (client));
	g_return_if_fail (checkpoint_path && checkpoint_path[0] == '/');

	_nm_client_dbus_call (client,
	                      client,
	                      nm_client_checkpoint_adjust_rollback_timeout,
	                      cancellable,
	                      callback,
	                      user_data,
	                      NM_DBUS_PATH,
	                      NM_DBUS_INTERFACE,
	                      "CheckpointAdjustRollbackTimeout",
	                      g_variant_new ("(ou)",
	                                     checkpoint_path,
	                                     add_timeout),
	                      G_VARIANT_TYPE ("()"),
	                      G_DBUS_CALL_FLAGS_NONE,
	                      NM_DBUS_DEFAULT_TIMEOUT_MSEC,
	                      nm_dbus_connection_call_finish_void_strip_dbus_error_cb);
}

/**
 * nm_client_checkpoint_adjust_rollback_timeout_finish:
 * @client: an #NMClient
 * @result: the result passed to the #GAsyncReadyCallback
 * @error: location for a #GError, or %NULL
 *
 * Gets the result of a call to nm_client_checkpoint_adjust_rollback_timeout().
 *
 * Returns: %TRUE on success or %FALSE on failure.
 *
 * Since: 1.12
 **/
gboolean
nm_client_checkpoint_adjust_rollback_timeout_finish (NMClient *client,
                                                     GAsyncResult *result,
                                                     GError **error)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);
	g_return_val_if_fail (nm_g_task_is_valid (result, client, nm_client_checkpoint_adjust_rollback_timeout), FALSE);

	return g_task_propagate_boolean (G_TASK (result), error);
}

/**
 * nm_client_reload:
 * @client: the %NMClient
 * @flags: flags indicating what to reload.
 * @cancellable: a #GCancellable, or %NULL
 * @callback: (scope async): callback to be called when the add operation completes
 * @user_data: (closure): caller-specific data passed to @callback
 *
 * Reload NetworkManager's configuration and perform certain updates, like
 * flushing caches or rewriting external state to disk. This is similar to
 * sending SIGHUP to NetworkManager but it allows for more fine-grained control
 * over what to reload (see @flags). It also allows non-root access via
 * PolicyKit and contrary to signals it is synchronous.
 *
 * Since: 1.22
 **/
void
nm_client_reload (NMClient *client,
                  NMManagerReloadFlags flags,
                  GCancellable *cancellable,
                  GAsyncReadyCallback callback,
                  gpointer user_data)
{
	g_return_if_fail (NM_IS_CLIENT (client));

	_nm_client_dbus_call (client,
	                      client,
	                      nm_client_reload,
	                      cancellable,
	                      callback,
	                      user_data,
	                      NM_DBUS_PATH,
	                      NM_DBUS_INTERFACE,
	                      "Reload",
	                      g_variant_new ("(u)", (guint32) flags),
	                      G_VARIANT_TYPE ("()"),
	                      G_DBUS_CALL_FLAGS_NONE,
	                      NM_DBUS_DEFAULT_TIMEOUT_MSEC,
	                      nm_dbus_connection_call_finish_void_strip_dbus_error_cb);
}

/**
 * nm_client_reload_finish:
 * @client: an #NMClient
 * @result: the result passed to the #GAsyncReadyCallback
 * @error: location for a #GError, or %NULL
 *
 * Gets the result of a call to nm_client_reload().
 *
 * Returns: %TRUE on success or %FALSE on failure.
 *
 * Since: 1.22
 **/
gboolean
nm_client_reload_finish (NMClient *client,
                         GAsyncResult *result,
                         GError **error)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);
	g_return_val_if_fail (nm_g_task_is_valid (result, client, nm_client_reload), FALSE);

	return g_task_propagate_boolean (G_TASK (result), error);
}

/*****************************************************************************/

static void
_init_fetch_all (NMClient *self)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (self);
	nm_auto_pop_gmaincontext GMainContext *dbus_context = NULL;

	dbus_context = nm_g_main_context_push_thread_default_if_necessary (priv->dbus_context);

	NML_NMCLIENT_LOG_D (self, "fetch all");

	nm_assert (!priv->get_managed_objects_cancellable);

	priv->get_managed_objects_cancellable = g_cancellable_new ();

	priv->dbsid_nm_object_manager = nm_dbus_connection_signal_subscribe_object_manager (priv->dbus_connection,
	                                                                                    priv->name_owner,
	                                                                                    "/org/freedesktop",
	                                                                                    _dbus_managed_objects_changed_cb,
	                                                                                    self,
	                                                                                    NULL);

	priv->dbsid_dbus_properties_properties_changed = nm_dbus_connection_signal_subscribe_properties_changed (priv->dbus_connection,
	                                                                                                         priv->name_owner,
	                                                                                                         NULL,
	                                                                                                         NULL,
	                                                                                                         _dbus_properties_changed_cb,
	                                                                                                         self,
	                                                                                                         NULL);

	priv->dbsid_nm_settings_connection_updated = g_dbus_connection_signal_subscribe (priv->dbus_connection,
	                                                                                 priv->name_owner,
	                                                                                 NM_DBUS_INTERFACE_SETTINGS_CONNECTION,
	                                                                                 "Updated",
	                                                                                 NULL,
	                                                                                 NULL,
	                                                                                 G_DBUS_SIGNAL_FLAGS_NONE,
	                                                                                 _dbus_settings_updated_cb,
	                                                                                 self,
	                                                                                 NULL);

	priv->dbsid_nm_connection_active_state_changed = g_dbus_connection_signal_subscribe (priv->dbus_connection,
	                                                                                     priv->name_owner,
	                                                                                     NM_DBUS_INTERFACE_ACTIVE_CONNECTION,
	                                                                                     "StateChanged",
	                                                                                     NULL,
	                                                                                     NULL,
	                                                                                     G_DBUS_SIGNAL_FLAGS_NONE,
	                                                                                     _dbus_nm_connection_active_state_changed_cb,
	                                                                                     self,
	                                                                                     NULL);

	priv->dbsid_nm_vpn_connection_state_changed = g_dbus_connection_signal_subscribe (priv->dbus_connection,
	                                                                                  priv->name_owner,
	                                                                                  NM_DBUS_INTERFACE_VPN_CONNECTION,
	                                                                                  "VpnStateChanged",
	                                                                                  NULL,
	                                                                                  NULL,
	                                                                                  G_DBUS_SIGNAL_FLAGS_NONE,
	                                                                                  _dbus_nm_vpn_connection_state_changed_cb,
	                                                                                  self,
	                                                                                  NULL);

	priv->dbsid_nm_check_permissions = g_dbus_connection_signal_subscribe (priv->dbus_connection,
	                                                                       priv->name_owner,
	                                                                       NM_DBUS_INTERFACE,
	                                                                       "CheckPermissions",
	                                                                       NULL,
	                                                                       NULL,
	                                                                       G_DBUS_SIGNAL_FLAGS_NONE,
	                                                                       _dbus_nm_check_permissions_cb,
	                                                                       self,
	                                                                       NULL);

	g_dbus_connection_call (priv->dbus_connection,
	                        priv->name_owner,
	                        "/org/freedesktop",
	                        DBUS_INTERFACE_OBJECT_MANAGER,
	                        "GetManagedObjects",
	                        NULL,
	                        G_VARIANT_TYPE ("(a{oa{sa{sv}}})"),
	                        G_DBUS_CALL_FLAGS_NO_AUTO_START,
	                        NM_DBUS_DEFAULT_TIMEOUT_MSEC,
	                        priv->get_managed_objects_cancellable,
	                        _dbus_get_managed_objects_cb,
	                        nm_utils_user_data_pack (self, g_object_ref (priv->context_busy_watcher)));

	_dbus_check_permissions_start (self);
}

static void
_init_release_all (NMClient *self)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (self);
	CList **dbus_objects_lst_heads;
	NMLDBusObject *dbobj;
	int i;
	gboolean permissions_state_changed = FALSE;

	NML_NMCLIENT_LOG_D (self, "release all");

	nm_clear_g_cancellable (&priv->permissions_cancellable);
	nm_clear_g_cancellable (&priv->get_managed_objects_cancellable);

	nm_clear_g_dbus_connection_signal (priv->dbus_connection,
	                                   &priv->dbsid_nm_object_manager);
	nm_clear_g_dbus_connection_signal (priv->dbus_connection,
	                                   &priv->dbsid_dbus_properties_properties_changed);
	nm_clear_g_dbus_connection_signal (priv->dbus_connection,
	                                   &priv->dbsid_nm_settings_connection_updated);
	nm_clear_g_dbus_connection_signal (priv->dbus_connection,
	                                   &priv->dbsid_nm_connection_active_state_changed);
	nm_clear_g_dbus_connection_signal (priv->dbus_connection,
	                                   &priv->dbsid_nm_vpn_connection_state_changed);
	nm_clear_g_dbus_connection_signal (priv->dbus_connection,
	                                   &priv->dbsid_nm_check_permissions);

	if (priv->permissions_state != NM_TERNARY_DEFAULT) {
		priv->permissions_state = NM_TERNARY_DEFAULT;
		permissions_state_changed = TRUE;
	}

	if (priv->permissions) {
		gs_free guint8 *old_permissions = g_steal_pointer (&priv->permissions);

		_emit_permissions_changed (self, old_permissions, NULL);
	}

	if (permissions_state_changed)
		_notify (self, PROP_PERMISSIONS_STATE);

	nm_assert (c_list_is_empty (&priv->obj_changed_lst_head));

	dbus_objects_lst_heads = ((CList *[]) {
		&priv->dbus_objects_lst_head_on_dbus,
		&priv->dbus_objects_lst_head_with_nmobj_not_ready,
		&priv->dbus_objects_lst_head_with_nmobj_ready,
		NULL,
	});
	for (i = 0; dbus_objects_lst_heads[i]; i++) {
		c_list_for_each_entry (dbobj, dbus_objects_lst_heads[i], dbus_objects_lst) {
			NMLDBusObjIfaceData *db_iface_data;

			nm_assert (c_list_is_empty (&dbobj->obj_changed_lst));
			c_list_for_each_entry (db_iface_data, &dbobj->iface_lst_head, iface_lst)
				db_iface_data->iface_removed = TRUE;
			nml_dbus_object_obj_changed_link (self, dbobj, NML_DBUS_OBJ_CHANGED_TYPE_DBUS);
		}
	}

	_dbus_handle_changes (self, "release-all", FALSE);

	/* We require that when we remove all D-Bus interfaces, that all object will go
	 * away. Note that a NMLDBusObject can be alive due to a NMLDBusObjWatcher, but
	 * even those should be all cleaned up. */
	nm_assert (c_list_is_empty (&priv->obj_changed_lst_head));
	nm_assert (c_list_is_empty (&priv->dbus_objects_lst_head_watched_only));
	nm_assert (c_list_is_empty (&priv->dbus_objects_lst_head_on_dbus));
	nm_assert (c_list_is_empty (&priv->dbus_objects_lst_head_with_nmobj_not_ready));
	nm_assert (c_list_is_empty (&priv->dbus_objects_lst_head_with_nmobj_ready));
	nm_assert (g_hash_table_size (priv->dbus_objects) == 0);
}

/*****************************************************************************/

static void
name_owner_changed (NMClient *self,
                    const char *name_owner)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (self);
	gboolean changed;
	gs_free char *old_name_owner_free = NULL;
	const char *old_name_owner;
	nm_auto_pop_gmaincontext GMainContext *dbus_context = NULL;

	name_owner = nm_str_not_empty (name_owner);

	changed = !nm_streq0 (priv->name_owner, name_owner);

	if (   !name_owner
	    && priv->main_context != priv->dbus_context) {
		gs_unref_object GObject *old_context_busy_watcher = NULL;

		NML_NMCLIENT_LOG_D (self, "resync main context as we have no name owner");

		nm_clear_g_dbus_connection_signal (priv->dbus_connection,
		                                   &priv->name_owner_changed_id);

		/* Our instance was initialized synchronously. Usually we must henceforth
		 * stick to a internal main context. But now we have no name-owner...
		 * at this point, we anyway are going to do a full resync. Swap the main
		 * contexts again. */

		old_context_busy_watcher = g_steal_pointer (&priv->context_busy_watcher);
		priv->context_busy_watcher = g_object_ref (g_object_get_qdata (old_context_busy_watcher,
		                                                               nm_context_busy_watcher_quark ()));

		g_main_context_ref (priv->main_context);
		g_main_context_unref (priv->dbus_context);
		priv->dbus_context = priv->main_context;

		dbus_context = nm_g_main_context_push_thread_default_if_necessary (priv->dbus_context);

		/* we need to sync again... */

		_assert_main_context_is_current_thread_default (self, dbus_context);

		priv->name_owner_changed_id = nm_dbus_connection_signal_subscribe_name_owner_changed (priv->dbus_connection,
		                                                                                      NM_DBUS_SERVICE,
		                                                                                      name_owner_changed_cb,
		                                                                                      self,
		                                                                                      NULL);
		name_owner_get_call (self);
	} else
		dbus_context = nm_g_main_context_push_thread_default_if_necessary (priv->dbus_context);

	if (changed) {
		NML_NMCLIENT_LOG_D (self, "name owner changed: %s%s%s -> %s%s%s",
		                    NM_PRINT_FMT_QUOTE_STRING (priv->name_owner),
		                    NM_PRINT_FMT_QUOTE_STRING (name_owner));
		old_name_owner_free = priv->name_owner;
		priv->name_owner = g_strdup (name_owner);
		old_name_owner = old_name_owner_free;
	} else
		old_name_owner = priv->name_owner;

	if (changed)
		_notify (self, PROP_DBUS_NAME_OWNER);

	if (   changed
	    && old_name_owner)
		_init_release_all (self);

	if (   changed
	    && priv->name_owner)
		_init_fetch_all (self);

	_set_nm_running (self);

	if (priv->init_data) {
		nm_auto_pop_gmaincontext GMainContext *main_context = NULL;

		if (priv->main_context != priv->dbus_context)
			main_context = nm_g_main_context_push_thread_default_if_necessary (priv->main_context);
		_init_start_check_complete (self);
	}
}

static void
name_owner_changed_cb (GDBusConnection *connection,
                       const char *sender_name,
                       const char *object_path,
                       const char *interface_name,
                       const char *signal_name,
                       GVariant *parameters,
                       gpointer user_data)
{
	NMClient *self = user_data;
	NMClientPrivate *priv;
	const char *new_owner;

	if (!g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(sss)")))
		return;

	priv = NM_CLIENT_GET_PRIVATE (self);
	if (priv->name_owner_get_cancellable)
		return;

	g_variant_get (parameters,
	               "(&s&s&s)",
	               NULL,
	               NULL,
	               &new_owner);

	name_owner_changed (self, new_owner);
}

static void
name_owner_get_cb (GObject *source,
                   GAsyncResult *result,
                   gpointer user_data)
{
	NMClient *self;
	NMClientPrivate *priv;
	gs_unref_object GObject *context_busy_watcher = NULL;
	gs_unref_variant GVariant *ret = NULL;
	gs_free_error GError *error = NULL;
	const char *name_owner = NULL;

	nm_utils_user_data_unpack (user_data, &self, &context_busy_watcher);

	ret = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source), result, &error);

	if (   !ret
	    && nm_utils_error_is_cancelled (error, FALSE))
		return;

	priv = NM_CLIENT_GET_PRIVATE (self);

	g_clear_object (&priv->name_owner_get_cancellable);

	if (ret)
		g_variant_get (ret, "(&s)", &name_owner);

	name_owner_changed (self, name_owner);
}

static void
name_owner_get_call (NMClient *self)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (self);

	nm_assert (!priv->name_owner_get_cancellable);
	priv->name_owner_get_cancellable = g_cancellable_new ();

	g_dbus_connection_call (priv->dbus_connection,
	                        DBUS_SERVICE_DBUS,
	                        DBUS_PATH_DBUS,
	                        DBUS_INTERFACE_DBUS,
	                        "GetNameOwner",
	                        g_variant_new ("(s)", NM_DBUS_SERVICE),
	                        G_VARIANT_TYPE ("(s)"),
	                        G_DBUS_CALL_FLAGS_NONE,
	                        NM_DBUS_DEFAULT_TIMEOUT_MSEC,
	                        priv->name_owner_get_cancellable,
	                        name_owner_get_cb,
	                        nm_utils_user_data_pack (self, g_object_ref (priv->context_busy_watcher)));
}

/*****************************************************************************/

static void
_init_start_complete (NMClient *self,
                      GError *error_take)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (self);
	NMLInitData *init_data;

	init_data = g_steal_pointer (&priv->init_data);

	NML_NMCLIENT_LOG_D (self, "%s init complete with %s%s%s",
	                   init_data->is_sync ? "sync" : "async",
	                   NM_PRINT_FMT_QUOTED (error_take, "error: ", error_take->message, "", "success"));

	nm_clear_pointer (&init_data->cancel_on_idle_source, nm_g_source_destroy_and_unref);
	nm_clear_g_signal_handler (init_data->cancellable, &init_data->cancelled_id);

	if (init_data->is_sync) {
		if (error_take)
			g_propagate_error (init_data->data.sync.error_location, error_take);
		g_main_loop_quit (init_data->data.sync.main_loop);
	} else {
		if (error_take)
			g_task_return_error (init_data->data.async.task, error_take);
		else
			g_task_return_boolean (init_data->data.async.task, TRUE);
		g_object_unref (init_data->data.async.task);
	}
	nm_g_object_unref (init_data->cancellable);
	nm_g_slice_free (init_data);
}

static void
_init_start_check_complete (NMClient *self)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (self);

	_assert_main_context_is_current_thread_default (self, main_context);

	if (!priv->init_data)
		return;

	if (priv->get_managed_objects_cancellable) {
		/* still initializing. Wait. */
		return;
	}

#if NM_MORE_ASSERTS > 10
	{
		NMLDBusObject *dbobj;

		c_list_for_each_entry (dbobj, &priv->dbus_objects_lst_head_with_nmobj_not_ready, dbus_objects_lst) {
			NML_NMCLIENT_LOG_T (self, "init-start waiting for %s", dbobj->dbus_path->str);
			break;
		}
	}
#endif

	if (!c_list_is_empty (&priv->dbus_objects_lst_head_with_nmobj_not_ready))
		return;

	_init_start_complete (self, NULL);
}

static void
_init_start_cancelled_cb (GCancellable *cancellable,
                          gpointer user_data)
{
	NMClient *self = user_data;
	GError *error;

	nm_assert (NM_IS_CLIENT (self));
	nm_assert (NM_CLIENT_GET_PRIVATE (self)->init_data);
	nm_assert (NM_CLIENT_GET_PRIVATE (self)->init_data->cancellable == cancellable);

	nm_utils_error_set_cancelled (&error, FALSE, NULL);
	_init_start_complete (self, error);
}

static gboolean
_init_start_cancel_on_idle_cb (gpointer user_data)
{
	NMClient *self = user_data;
	GError *error;

	nm_utils_error_set_cancelled (&error, FALSE, NULL);
	_init_start_complete (self, error);
	return G_SOURCE_CONTINUE;
}

static void
_init_start_with_bus (NMClient *self)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (self);

	if (priv->init_data->cancellable) {
		priv->init_data->cancelled_id = g_signal_connect (priv->init_data->cancellable,
		                                                  "cancelled",
		                                                  G_CALLBACK (_init_start_cancelled_cb),
		                                                  self);
		if (g_cancellable_is_cancelled (priv->init_data->cancellable)) {
			priv->init_data->cancel_on_idle_source = g_idle_source_new ();
			g_source_set_callback (priv->init_data->cancel_on_idle_source, _init_start_cancel_on_idle_cb, self, NULL);
			g_source_attach (priv->init_data->cancel_on_idle_source, priv->main_context);
			return;
		}
	}

	_assert_main_context_is_current_thread_default (self, dbus_context);

	priv->name_owner_changed_id = nm_dbus_connection_signal_subscribe_name_owner_changed (priv->dbus_connection,
	                                                                                      NM_DBUS_SERVICE,
	                                                                                      name_owner_changed_cb,
	                                                                                      self,
	                                                                                      NULL);
	name_owner_get_call (self);
}

static void
_init_start_bus_get_cb (GObject *source, GAsyncResult *result, gpointer user_data)
{
	NMClient *self = user_data;
	NMClientPrivate *priv;
	GDBusConnection *dbus_connection;
	GError *error = NULL;

	nm_assert (NM_IS_CLIENT (self));

	dbus_connection = g_bus_get_finish (result, &error);

	if (!dbus_connection) {
		_init_start_complete (self, error);
		return;
	}

	priv = NM_CLIENT_GET_PRIVATE (self);
	priv->dbus_connection = dbus_connection;

	_init_start_with_bus (self);

	_notify (self, PROP_DBUS_CONNECTION);
}

static void
_init_start (NMClient *self)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (self);

	NML_NMCLIENT_LOG_D (self, "starting %s initialization...",
	                    priv->init_data->is_sync ? "sync" : "async");

	if (!priv->dbus_connection) {
		g_bus_get (_nm_dbus_bus_type (),
		           priv->init_data->cancellable,
		           _init_start_bus_get_cb,
		           self);
		return;
	}

	_init_start_with_bus (self);
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMClient *self = NM_CLIENT (object);
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_INSTANCE_FLAGS:
		g_value_set_uint (value, priv->instance_flags);
		break;
	case PROP_DBUS_CONNECTION:
		g_value_set_object (value, priv->dbus_connection);
		break;
	case PROP_DBUS_NAME_OWNER:
		g_value_set_string (value, nm_client_get_dbus_name_owner (self));
		break;
	case PROP_NM_RUNNING:
		g_value_set_boolean (value, nm_client_get_nm_running (self));
		break;

	/* Manager properties. */
	case PROP_VERSION:
		g_value_set_string (value, nm_client_get_version (self));
		break;
	case PROP_STATE:
		g_value_set_enum (value, nm_client_get_state (self));
		break;
	case PROP_STARTUP:
		g_value_set_boolean (value, nm_client_get_startup (self));
		break;
	case PROP_NETWORKING_ENABLED:
		g_value_set_boolean (value, nm_client_networking_get_enabled (self));
		break;
	case PROP_WIRELESS_ENABLED:
		g_value_set_boolean (value, nm_client_wireless_get_enabled (self));
		break;
	case PROP_WIRELESS_HARDWARE_ENABLED:
		g_value_set_boolean (value, nm_client_wireless_hardware_get_enabled (self));
		break;
	case PROP_WWAN_ENABLED:
		g_value_set_boolean (value, nm_client_wwan_get_enabled (self));
		break;
	case PROP_WWAN_HARDWARE_ENABLED:
		g_value_set_boolean (value, nm_client_wwan_hardware_get_enabled (self));
		break;
	case PROP_WIMAX_ENABLED:
		g_value_set_boolean (value, FALSE);
		break;
	case PROP_WIMAX_HARDWARE_ENABLED:
		g_value_set_boolean (value, FALSE);
		break;
	case PROP_ACTIVE_CONNECTIONS:
		g_value_take_boxed (value, _nm_utils_copy_object_array (nm_client_get_active_connections (self)));
		break;
	case PROP_CONNECTIVITY:
		g_value_set_enum (value, nm_client_get_connectivity (self));
		break;
	case PROP_CONNECTIVITY_CHECK_AVAILABLE:
		g_value_set_boolean (value, nm_client_connectivity_check_get_available (self));
		break;
	case PROP_CONNECTIVITY_CHECK_ENABLED:
		g_value_set_boolean (value, nm_client_connectivity_check_get_enabled (self));
		break;
	case PROP_CONNECTIVITY_CHECK_URI:
		g_value_set_string (value, nm_client_connectivity_check_get_uri (self));
		break;
	case PROP_PRIMARY_CONNECTION:
		g_value_set_object (value, nm_client_get_primary_connection (self));
		break;
	case PROP_ACTIVATING_CONNECTION:
		g_value_set_object (value, nm_client_get_activating_connection (self));
		break;
	case PROP_DEVICES:
		g_value_take_boxed (value, _nm_utils_copy_object_array (nm_client_get_devices (self)));
		break;
	case PROP_METERED:
		g_value_set_uint (value, nm_client_get_metered (self));
		break;
	case PROP_ALL_DEVICES:
		g_value_take_boxed (value, _nm_utils_copy_object_array (nm_client_get_all_devices (self)));
		break;
	case PROP_CHECKPOINTS:
		g_value_take_boxed (value, _nm_utils_copy_object_array (nm_client_get_checkpoints (self)));
		break;
	case PROP_CAPABILITIES: {
			const guint32 *arr;
			GArray *out;
			gsize len;

			arr = nm_client_get_capabilities (self, &len);
			if (arr) {
				out = g_array_new (TRUE, FALSE, sizeof (guint32));
				g_array_append_vals (out, arr, len);
			} else
				out = NULL;
			g_value_take_boxed (value, out);
		}
		break;
	case PROP_PERMISSIONS_STATE:
		g_value_set_enum (value, priv->permissions_state);
		break;

	/* Settings properties. */
	case PROP_CONNECTIONS:
		g_value_take_boxed (value, _nm_utils_copy_object_array (nm_client_get_connections (self)));
		break;
	case PROP_HOSTNAME:
		g_value_set_string (value, priv->settings.hostname);
		break;
	case PROP_CAN_MODIFY:
		g_value_set_boolean (value, priv->settings.can_modify);
		break;

	/* DNS properties */
	case PROP_DNS_MODE:
		g_value_set_string (value, nm_client_get_dns_mode (self));
		break;
	case PROP_DNS_RC_MANAGER:
		g_value_set_string (value, nm_client_get_dns_rc_manager (self));
		break;
	case PROP_DNS_CONFIGURATION:
		g_value_take_boxed (value, _nm_utils_copy_array (nm_client_get_dns_configuration (self),
		                                                 (NMUtilsCopyFunc) nm_dns_entry_dup,
		                                                 (GDestroyNotify) nm_dns_entry_unref));
		break;

	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMClient *self = NM_CLIENT (object);
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (self);
	gboolean b;
	guint v_uint;

	switch (prop_id) {

	case PROP_INSTANCE_FLAGS:
		/* construct */

		v_uint = g_value_get_uint (value);
		g_return_if_fail (!NM_FLAGS_ANY (v_uint, ~((guint) NM_CLIENT_INSTANCE_FLAGS_ALL)));
		v_uint &= ((guint) NM_CLIENT_INSTANCE_FLAGS_ALL);

		if (!priv->instance_flags_constructed) {
			priv->instance_flags_constructed = TRUE;
			priv->instance_flags = v_uint;
			nm_assert ((guint) priv->instance_flags == v_uint);
		} else {
			NMClientInstanceFlags flags = v_uint;

			/* After object construction, we only allow to toggle certain flags and
			 * ignore all other flags. */

			if ((priv->instance_flags ^ flags) & NM_CLIENT_INSTANCE_FLAGS_NO_AUTO_FETCH_PERMISSIONS) {
				if (NM_FLAGS_HAS (flags, NM_CLIENT_INSTANCE_FLAGS_NO_AUTO_FETCH_PERMISSIONS))
					priv->instance_flags |= NM_CLIENT_INSTANCE_FLAGS_NO_AUTO_FETCH_PERMISSIONS;
				else
					priv->instance_flags &= ~NM_CLIENT_INSTANCE_FLAGS_NO_AUTO_FETCH_PERMISSIONS;
				if (priv->dbsid_nm_check_permissions != 0)
					_dbus_check_permissions_start (self);
			}
		}
		break;

	case PROP_DBUS_CONNECTION:
		/* construct-only */
		priv->dbus_connection = g_value_dup_object (value);
		break;

	case PROP_NETWORKING_ENABLED:
		b = g_value_get_boolean (value);
		if (priv->nm.networking_enabled != b) {
			nm_client_networking_set_enabled (self,
			                                  b,
			                                  NULL);
			/* Let the property value flip when we get the change signal from NM */
		}
		break;
	case PROP_WIRELESS_ENABLED:
		b = g_value_get_boolean (value);
		if (priv->nm.wireless_enabled != b) {
			nm_client_wireless_set_enabled (self, b);
			/* Let the property value flip when we get the change signal from NM */
		}
		break;
	case PROP_WWAN_ENABLED:
		b = g_value_get_boolean (value);
		if (priv->nm.wwan_enabled != b) {
			nm_client_wwan_set_enabled (self, b);
			/* Let the property value flip when we get the change signal from NM */
		}
		break;
	case PROP_CONNECTIVITY_CHECK_ENABLED:
		b = g_value_get_boolean (value);
		if (priv->nm.connectivity_check_enabled != b) {
			nm_client_connectivity_check_set_enabled (self, b);
			/* Let the property value flip when we get the change signal from NM */
		}
		break;
	case PROP_WIMAX_ENABLED:
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static gboolean
init_sync (GInitable *initable, GCancellable *cancellable, GError **error)
{
	gs_unref_object NMClient *self = NULL;
	NMClientPrivate *priv;
	GMainContext *dbus_context;
	GError *local_error = NULL;
	GMainLoop *main_loop;
	GObject *parent_context_busy_watcher;

	g_return_val_if_fail (NM_IS_CLIENT (initable), FALSE);

	self = g_object_ref (NM_CLIENT (initable)); /* keep instance alive. */

	priv = NM_CLIENT_GET_PRIVATE (self);

	g_return_val_if_fail (!priv->dbus_context, FALSE);

	/* when using init_sync(), we use a separate internal GMainContext for
	 * all D-Bus operations and use our regular async-init code. That means,
	 * also in sync-init, we don't actually block waiting for our D-Bus requests,
	 * instead, we only block (g_main_loop_run()) for the overall result.
	 *
	 * Doing this has a performance overhead. Also, we cannot ever fall back
	 * to the regular main-context (not unless we lose the main-owner and
	 * need to re-initialize). The reason is that we receive events on our
	 * dbus_context, and this cannot be brought in sync -- short of full
	 * reinitalizing. Therefor, using sync init not only is slower during
	 * construction of the object, but NMClient will stick to the dual GMainContext
	 * mode.
	 *
	 * Aside from this downside, the solution is good:
	 *
	 * - we don't duplicate the implementation of async-init.
	 * - we don't iterate the main-context of the caller while waiting for
	 *   initialization to happen
	 * - we still invoke all changes under the main_context of the caller.
	 * - all D-Bus events strictly go through dbus_context and are in order.
	 */

	dbus_context = g_main_context_new ();
	priv->dbus_context = g_main_context_ref (dbus_context);

	/* We have an inner context. Note that if we loose the name owner, we have a chance
	 * to resync and drop the inner context. That means, requests made against the inner
	 * context have a different lifetime. Hence, we create a separate tracking
	 * object. This "wraps" the outer context-busy-watcher and references it, so
	 * that the work together. Grep for nm_context_busy_watcher_quark() to
	 * see how this works. */
	parent_context_busy_watcher = g_steal_pointer (&priv->context_busy_watcher);
	priv->context_busy_watcher = g_object_new (G_TYPE_OBJECT, NULL);
	g_object_set_qdata_full (priv->context_busy_watcher,
	                         nm_context_busy_watcher_quark (),
	                         parent_context_busy_watcher,
	                         g_object_unref);

	g_main_context_push_thread_default (dbus_context);

	main_loop = g_main_loop_new (dbus_context, FALSE);

	priv->init_data = nml_init_data_new_sync (cancellable, main_loop, &local_error);

	_init_start (self);

	g_main_loop_run (main_loop);

	g_main_loop_unref (main_loop);

	g_main_context_pop_thread_default (dbus_context);

	if (priv->main_context != priv->dbus_context) {
		nm_context_busy_watcher_integrate_source (priv->main_context,
		                                          priv->dbus_context,
		                                          priv->context_busy_watcher);
	}

	g_main_context_unref (dbus_context);

	if (local_error) {
		g_propagate_error (error, local_error);
		return FALSE;
	}
	return TRUE;
}

/*****************************************************************************/

static void
init_async (GAsyncInitable *initable,
            int io_priority,
            GCancellable *cancellable,
            GAsyncReadyCallback callback,
            gpointer user_data)
{
	NMClientPrivate *priv;
	NMClient *self;
	nm_auto_pop_gmaincontext GMainContext *context = NULL;
	GTask *task;

	g_return_if_fail (NM_IS_CLIENT (initable));

	self = NM_CLIENT (initable);
	priv = NM_CLIENT_GET_PRIVATE (self);

	g_return_if_fail (!priv->dbus_context);

	priv->dbus_context = g_main_context_ref (priv->main_context);

	context = nm_g_main_context_push_thread_default_if_necessary (priv->main_context);

	task = nm_g_task_new (self, cancellable, init_async, callback, user_data);
	g_task_set_priority (task, io_priority);

	priv->init_data = nml_init_data_new_async (cancellable, g_steal_pointer (&task));

	_init_start (self);
}

static gboolean
init_finish (GAsyncInitable *initable, GAsyncResult *result, GError **error)
{
	g_return_val_if_fail (NM_IS_CLIENT (initable), FALSE);
	g_return_val_if_fail (nm_g_task_is_valid (result, initable, init_async), FALSE);

	return g_task_propagate_boolean (G_TASK (result), error);
}

/*****************************************************************************/

static void
nm_client_init (NMClient *self)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (self);

	priv->permissions_state = NM_TERNARY_DEFAULT;

	priv->context_busy_watcher = g_object_new (G_TYPE_OBJECT, NULL);

	c_list_init (&self->obj_base.queue_notify_lst);
	c_list_init (&priv->queue_notify_lst_head);
	c_list_init (&priv->notify_event_lst_head);

	priv->dbus_objects = g_hash_table_new (nm_pdirect_hash, nm_pdirect_equal);
	c_list_init (&priv->dbus_objects_lst_head_watched_only);
	c_list_init (&priv->dbus_objects_lst_head_on_dbus);
	c_list_init (&priv->dbus_objects_lst_head_with_nmobj_not_ready);
	c_list_init (&priv->dbus_objects_lst_head_with_nmobj_ready);
	c_list_init (&priv->obj_changed_lst_head);
}

/**
 * nm_client_new:
 * @cancellable: a #GCancellable, or %NULL
 * @error: location for a #GError, or %NULL
 *
 * Creates a new #NMClient.
 *
 * Note that this will do blocking D-Bus calls to initialize the
 * client. You can use nm_client_new_async() if you want to avoid
 * that.
 *
 * Returns: a new #NMClient or NULL on an error
 **/
NMClient *
nm_client_new (GCancellable  *cancellable,
               GError       **error)
{
	return g_initable_new (NM_TYPE_CLIENT, cancellable, error,
	                       NULL);
}

/**
 * nm_client_new_async:
 * @cancellable: a #GCancellable, or %NULL
 * @callback: callback to call when the client is created
 * @user_data: data for @callback
 *
 * Creates a new #NMClient and begins asynchronously initializing it.
 * @callback will be called when it is done; use
 * nm_client_new_finish() to get the result. Note that on an error,
 * the callback can be invoked with two first parameters as NULL.
 **/
void
nm_client_new_async (GCancellable *cancellable,
                     GAsyncReadyCallback callback,
                     gpointer user_data)
{
	g_async_initable_new_async (NM_TYPE_CLIENT,
	                            G_PRIORITY_DEFAULT,
	                            cancellable,
	                            callback,
	                            user_data,
	                            NULL);
}

/**
 * nm_client_new_finish:
 * @result: a #GAsyncResult
 * @error: location for a #GError, or %NULL
 *
 * Gets the result of an nm_client_new_async() call.
 *
 * Returns: a new #NMClient, or %NULL on error
 **/
NMClient *
nm_client_new_finish (GAsyncResult *result, GError **error)
{
	gs_unref_object GObject *source_object = NULL;
	GObject *object;

	source_object = g_async_result_get_source_object (result);
	g_return_val_if_fail (source_object, NULL);

	object = g_async_initable_new_finish (G_ASYNC_INITABLE (source_object),
	                                      result,
	                                      error);
	g_return_val_if_fail (!object || NM_IS_CLIENT (object), FALSE);

	return NM_CLIENT (object);
}

static void
constructed (GObject *object)
{
	NMClient *self = NM_CLIENT (object);
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (self);

	priv->main_context = g_main_context_ref_thread_default ();

	G_OBJECT_CLASS (nm_client_parent_class)->constructed (object);

	NML_NMCLIENT_LOG_D (self, "new NMClient instance");
}

static void
dispose (GObject *object)
{
	NMClient *self = NM_CLIENT (object);
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (self);

	nm_assert (!priv->init_data);

	self->obj_base.is_disposing = TRUE;

	nm_clear_g_cancellable (&priv->name_owner_get_cancellable);

	nm_clear_g_dbus_connection_signal (priv->dbus_connection,
	                                   &priv->name_owner_changed_id);

	nm_clear_g_free (&priv->name_owner);

	_init_release_all (self);

	nm_assert (c_list_is_empty (&priv->dbus_objects_lst_head_watched_only));
	nm_assert (c_list_is_empty (&priv->dbus_objects_lst_head_on_dbus));
	nm_assert (c_list_is_empty (&priv->dbus_objects_lst_head_with_nmobj_not_ready));
	nm_assert (c_list_is_empty (&priv->dbus_objects_lst_head_with_nmobj_ready));

	nm_assert (c_list_is_empty (&priv->queue_notify_lst_head));
	nm_assert (c_list_is_empty (&priv->notify_event_lst_head));
	nm_assert (c_list_is_empty (&self->obj_base.queue_notify_lst));
	nm_assert (!priv->dbus_objects || g_hash_table_size (priv->dbus_objects) == 0);

	nml_dbus_property_o_clear_many (priv->nm.property_o, G_N_ELEMENTS (priv->nm.property_o), NULL);
	nml_dbus_property_ao_clear_many (priv->nm.property_ao, G_N_ELEMENTS (priv->nm.property_ao), NULL);

	nm_clear_g_free (&priv->nm.connectivity_check_uri);
	nm_clear_g_free (&priv->nm.version);

	nml_dbus_property_ao_clear (&priv->settings.connections, NULL);
	nm_clear_g_free (&priv->settings.hostname);

	nm_clear_pointer (&priv->dns_manager.configuration, g_ptr_array_unref);
	nm_clear_g_free (&priv->dns_manager.mode);
	nm_clear_g_free (&priv->dns_manager.rc_manager);

	nm_clear_pointer (&priv->dbus_objects, g_hash_table_destroy);

	G_OBJECT_CLASS (nm_client_parent_class)->dispose (object);

	nm_clear_pointer (&priv->udev, udev_unref);

	nm_clear_pointer (&priv->dbus_context, g_main_context_unref);
	nm_clear_pointer (&priv->main_context, g_main_context_unref);

	nm_clear_g_free (&priv->permissions);

	g_clear_object (&priv->dbus_connection);

	g_clear_object (&priv->context_busy_watcher);

	nm_clear_g_free (&priv->name_owner);

	priv->nm.capabilities_len = 0;
	nm_clear_g_free (&priv->nm.capabilities_arr);

	NML_NMCLIENT_LOG_D (self, "disposed");
}

const NMLDBusMetaIface _nml_dbus_meta_iface_nm_agentmanager = NML_DBUS_META_IFACE_INIT (
	NM_DBUS_INTERFACE_AGENT_MANAGER,
	NULL,
	NML_DBUS_META_INTERFACE_PRIO_NONE,
);

const NMLDBusMetaIface _nml_dbus_meta_iface_nm = NML_DBUS_META_IFACE_INIT_PROP (
	NM_DBUS_INTERFACE,
	nm_client_get_type,
	NML_DBUS_META_INTERFACE_PRIO_NMCLIENT,
	NML_DBUS_META_IFACE_DBUS_PROPERTIES (
		NML_DBUS_META_PROPERTY_INIT_O_PROP  ("ActivatingConnection",       PROP_ACTIVATING_CONNECTION,        NMClient, _priv.nm.property_o[PROPERTY_O_IDX_NM_ACTIVATING_CONNECTION], nm_active_connection_get_type                                                                         ),
		NML_DBUS_META_PROPERTY_INIT_AO_PROP ("ActiveConnections",          PROP_ACTIVE_CONNECTIONS,           NMClient, _priv.nm.property_ao[PROPERTY_AO_IDX_ACTIVE_CONNECTIONS],     nm_active_connection_get_type, .notify_changed_ao = _property_ao_notify_changed_active_connections_cb ),
		NML_DBUS_META_PROPERTY_INIT_AO_PROP ("AllDevices",                 PROP_ALL_DEVICES,                  NMClient, _priv.nm.property_ao[PROPERTY_AO_IDX_ALL_DEVICES],            nm_device_get_type,            .notify_changed_ao = _property_ao_notify_changed_all_devices_cb        ),
		NML_DBUS_META_PROPERTY_INIT_FCN     ("Capabilities",               PROP_CAPABILITIES,                 "au",     _notify_update_prop_nm_capabilities,                                                                                                                                ),
		NML_DBUS_META_PROPERTY_INIT_AO_PROP ("Checkpoints",                PROP_CHECKPOINTS,                  NMClient, _priv.nm.property_ao[PROPERTY_AO_IDX_CHECKPOINTS],            nm_checkpoint_get_type                                                                                ),
		NML_DBUS_META_PROPERTY_INIT_U       ("Connectivity",               PROP_CONNECTIVITY,                 NMClient, _priv.nm.connectivity                                                                                                                                               ),
		NML_DBUS_META_PROPERTY_INIT_B       ("ConnectivityCheckAvailable", PROP_CONNECTIVITY_CHECK_AVAILABLE, NMClient, _priv.nm.connectivity_check_available                                                                                                                               ),
		NML_DBUS_META_PROPERTY_INIT_B       ("ConnectivityCheckEnabled",   PROP_CONNECTIVITY_CHECK_ENABLED,   NMClient, _priv.nm.connectivity_check_enabled                                                                                                                                 ),
		NML_DBUS_META_PROPERTY_INIT_S       ("ConnectivityCheckUri",       PROP_CONNECTIVITY_CHECK_URI,       NMClient, _priv.nm.connectivity_check_uri                                                                                                                                     ),
		NML_DBUS_META_PROPERTY_INIT_AO_PROP ("Devices",                    PROP_DEVICES,                      NMClient, _priv.nm.property_ao[PROPERTY_AO_IDX_DEVICES],                nm_device_get_type,            .notify_changed_ao = _property_ao_notify_changed_devices_cb            ),
		NML_DBUS_META_PROPERTY_INIT_IGNORE  ("GlobalDnsConfiguration",     "a{sv}"                                                                                                                                                                                                          ),
		NML_DBUS_META_PROPERTY_INIT_U       ("Metered",                    PROP_METERED,                      NMClient, _priv.nm.metered                                                                                                                                                    ),
		NML_DBUS_META_PROPERTY_INIT_B       ("NetworkingEnabled",          PROP_NETWORKING_ENABLED,           NMClient, _priv.nm.networking_enabled                                                                                                                                         ),
		NML_DBUS_META_PROPERTY_INIT_O_PROP  ("PrimaryConnection",          PROP_PRIMARY_CONNECTION,           NMClient, _priv.nm.property_o[PROPERTY_O_IDX_NM_PRIMAY_CONNECTION],     nm_active_connection_get_type                                                                         ),
		NML_DBUS_META_PROPERTY_INIT_IGNORE  ("PrimaryConnectionType",      "s"                                                                                                                                                                                                              ),
		NML_DBUS_META_PROPERTY_INIT_B       ("Startup",                    PROP_STARTUP,                      NMClient, _priv.nm.startup                                                                                                                                                    ),
		NML_DBUS_META_PROPERTY_INIT_U       ("State",                      PROP_STATE,                        NMClient, _priv.nm.state                                                                                                                                                      ),
		NML_DBUS_META_PROPERTY_INIT_S       ("Version",                    PROP_VERSION,                      NMClient, _priv.nm.version                                                                                                                                                    ),
		NML_DBUS_META_PROPERTY_INIT_IGNORE  ("WimaxEnabled",               "b"                                                                                                                                                                                                              ),
		NML_DBUS_META_PROPERTY_INIT_IGNORE  ("WimaxHardwareEnabled",       "b"                                                                                                                                                                                                              ),
		NML_DBUS_META_PROPERTY_INIT_B       ("WirelessEnabled",            PROP_WIRELESS_ENABLED,             NMClient, _priv.nm.wireless_enabled                                                                                                                                           ),
		NML_DBUS_META_PROPERTY_INIT_B       ("WirelessHardwareEnabled",    PROP_WIRELESS_HARDWARE_ENABLED,    NMClient, _priv.nm.wireless_hardware_enabled                                                                                                                                  ),
		NML_DBUS_META_PROPERTY_INIT_B       ("WwanEnabled",                PROP_WWAN_ENABLED,                 NMClient, _priv.nm.wwan_enabled                                                                                                                                               ),
		NML_DBUS_META_PROPERTY_INIT_B       ("WwanHardwareEnabled",        PROP_WWAN_HARDWARE_ENABLED,        NMClient, _priv.nm.wwan_hardware_enabled                                                                                                                                      ),
	),
);

const NMLDBusMetaIface _nml_dbus_meta_iface_nm_settings = NML_DBUS_META_IFACE_INIT_PROP (
	NM_DBUS_INTERFACE_SETTINGS,
	nm_client_get_type,
	NML_DBUS_META_INTERFACE_PRIO_NMCLIENT,
	NML_DBUS_META_IFACE_DBUS_PROPERTIES (
		NML_DBUS_META_PROPERTY_INIT_B       ("CanModify",   PROP_CAN_MODIFY,  NMClient, _priv.settings.can_modify                                                                                                                                                                                          ),
		NML_DBUS_META_PROPERTY_INIT_AO_PROP ("Connections", PROP_CONNECTIONS, NMClient, _priv.settings.connections, nm_remote_connection_get_type, .notify_changed_ao = _property_ao_notify_changed_connections_cb, .check_nmobj_visible_fcn = (gboolean (*) (GObject *)) nm_remote_connection_get_visible ),
		NML_DBUS_META_PROPERTY_INIT_S       ("Hostname",    PROP_HOSTNAME,    NMClient, _priv.settings.hostname                                                                                                                                                                                            ),
	),
);

const NMLDBusMetaIface _nml_dbus_meta_iface_nm_dnsmanager = NML_DBUS_META_IFACE_INIT_PROP (
	NM_DBUS_INTERFACE_DNS_MANAGER,
	nm_client_get_type,
	NML_DBUS_META_INTERFACE_PRIO_NMCLIENT,
	NML_DBUS_META_IFACE_DBUS_PROPERTIES (
		NML_DBUS_META_PROPERTY_INIT_FCN ("Configuration", PROP_DNS_CONFIGURATION, "aa{sv}", _notify_update_prop_dns_manager_configuration ),
		NML_DBUS_META_PROPERTY_INIT_S   ("Mode",          PROP_DNS_MODE,          NMClient, _priv.dns_manager.mode                        ),
		NML_DBUS_META_PROPERTY_INIT_S   ("RcManager",     PROP_DNS_RC_MANAGER,    NMClient, _priv.dns_manager.rc_manager                  ),
	),
);

static void
nm_client_class_init (NMClientClass *client_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (client_class);

	_dbus_path_nm          = nm_ref_string_new (NM_DBUS_PATH);
	_dbus_path_settings    = nm_ref_string_new (NM_DBUS_PATH_SETTINGS);
	_dbus_path_dns_manager = nm_ref_string_new (NM_DBUS_PATH_DNS_MANAGER);

	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->constructed  = constructed;
	object_class->dispose      = dispose;

	/**
	 * NMClient:dbus-connection:
	 *
	 * The #GDBusConnection to use.
	 *
	 * If this is not set during object construction, the D-Bus connection will
	 * automatically be chosen during async/sync initalization via g_bus_get().
	 *
	 * Since: 1.22
	 */
	obj_properties[PROP_DBUS_CONNECTION] =
	    g_param_spec_object (NM_CLIENT_DBUS_CONNECTION, "", "",
	                         G_TYPE_DBUS_CONNECTION,
	                         G_PARAM_READABLE |
	                         G_PARAM_WRITABLE |
	                         G_PARAM_CONSTRUCT_ONLY |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMClient:instance-flags:
	 *
	 * #NMClientInstanceFlags for the instance. These affect behavior of #NMClient.
	 * This is a construct property and you may only set most flags only during
	 * construction.
	 *
	 * The flag %NM_CLIENT_INSTANCE_FLAGS_NO_AUTO_FETCH_PERMISSIONS can be toggled any time,
	 * even after constructing the instance. Note that you may want to watch NMClient:permissions-state
	 * property to know whether permissions are ready. Note that permissions are only fetched
	 * when NMClient has a D-Bus name owner.
	 *
	 * Since: 1.24
	 */
	obj_properties[PROP_INSTANCE_FLAGS] =
	    g_param_spec_uint (NM_CLIENT_INSTANCE_FLAGS, "", "",
	                       0,
	                       G_MAXUINT32,
	                       0,
	                       G_PARAM_READABLE |
	                       G_PARAM_WRITABLE |
	                       G_PARAM_CONSTRUCT |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMClient:dbus-name-owner:
	 *
	 * The name owner of the NetworkManager D-Bus service.
	 *
	 * Since: 1.22
	 **/
	obj_properties[PROP_DBUS_NAME_OWNER] =
	    g_param_spec_string (NM_CLIENT_DBUS_NAME_OWNER, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMClient:version:
	 *
	 * The NetworkManager version.
	 **/
	obj_properties[PROP_VERSION] =
	    g_param_spec_string (NM_CLIENT_VERSION, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMClient:state:
	 *
	 * The current daemon state.
	 **/
	obj_properties[PROP_STATE] =
	    g_param_spec_enum (NM_CLIENT_STATE, "", "",
	                       NM_TYPE_STATE,
	                       NM_STATE_UNKNOWN,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMClient:startup:
	 *
	 * Whether the daemon is still starting up.
	 **/
	obj_properties[PROP_STARTUP] =
	    g_param_spec_boolean (NM_CLIENT_STARTUP, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMClient:nm-running:
	 *
	 * Whether the daemon is running.
	 **/
	obj_properties[PROP_NM_RUNNING] =
	    g_param_spec_boolean (NM_CLIENT_NM_RUNNING, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMClient:networking-enabled:
	 *
	 * Whether networking is enabled.
	 *
	 * The property setter is a synchronous D-Bus call. This is deprecated since 1.22.
	 */
	obj_properties[PROP_NETWORKING_ENABLED] =
	    g_param_spec_boolean (NM_CLIENT_NETWORKING_ENABLED, "", "",
	                          FALSE,
	                          G_PARAM_READWRITE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMClient:wireless-enabled:
	 *
	 * Whether wireless is enabled.
	 *
	 * The property setter is a synchronous D-Bus call. This is deprecated since 1.22.
	 **/
	obj_properties[PROP_WIRELESS_ENABLED] =
	    g_param_spec_boolean (NM_CLIENT_WIRELESS_ENABLED, "", "",
	                          FALSE,
	                          G_PARAM_READWRITE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMClient:wireless-hardware-enabled:
	 *
	 * Whether the wireless hardware is enabled.
	 **/
	obj_properties[PROP_WIRELESS_HARDWARE_ENABLED] =
	    g_param_spec_boolean (NM_CLIENT_WIRELESS_HARDWARE_ENABLED, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMClient:wwan-enabled:
	 *
	 * Whether WWAN functionality is enabled.
	 *
	 * The property setter is a synchronous D-Bus call. This is deprecated since 1.22.
	 */
	obj_properties[PROP_WWAN_ENABLED] =
	    g_param_spec_boolean (NM_CLIENT_WWAN_ENABLED, "", "",
	                          FALSE,
	                          G_PARAM_READWRITE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMClient:wwan-hardware-enabled:
	 *
	 * Whether the WWAN hardware is enabled.
	 **/
	obj_properties[PROP_WWAN_HARDWARE_ENABLED] =
	    g_param_spec_boolean (NM_CLIENT_WWAN_HARDWARE_ENABLED, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMClient:wimax-enabled:
	 *
	 * Whether WiMAX functionality is enabled.
	 *
	 * Deprecated: 1.22: WiMAX is no longer supported and this always returns FALSE. The setter has no effect.
	 */
	obj_properties[PROP_WIMAX_ENABLED] =
	    g_param_spec_boolean (NM_CLIENT_WIMAX_ENABLED, "", "",
	                          FALSE,
	                          G_PARAM_READWRITE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMClient:wimax-hardware-enabled:
	 *
	 * Whether the WiMAX hardware is enabled.
	 *
	 * Deprecated: 1.22: WiMAX is no longer supported and this always returns FALSE.
	 **/
	obj_properties[PROP_WIMAX_HARDWARE_ENABLED] =
	    g_param_spec_boolean (NM_CLIENT_WIMAX_HARDWARE_ENABLED, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMClient:active-connections: (type GPtrArray(NMActiveConnection))
	 *
	 * The active connections.
	 **/
	obj_properties[PROP_ACTIVE_CONNECTIONS] =
	    g_param_spec_boxed (NM_CLIENT_ACTIVE_CONNECTIONS, "", "",
	                        G_TYPE_PTR_ARRAY,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMClient:connectivity:
	 *
	 * The network connectivity state.
	 */
	obj_properties[PROP_CONNECTIVITY] =
	    g_param_spec_enum (NM_CLIENT_CONNECTIVITY, "", "",
	                       NM_TYPE_CONNECTIVITY_STATE,
	                       NM_CONNECTIVITY_UNKNOWN,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMClient::connectivity-check-available
	 *
	 * Whether a connectivity checking service has been configured.
	 *
	 * Since: 1.10
	 */
	obj_properties[PROP_CONNECTIVITY_CHECK_AVAILABLE] =
	    g_param_spec_boolean (NM_CLIENT_CONNECTIVITY_CHECK_AVAILABLE, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMClient::connectivity-check-enabled
	 *
	 * Whether a connectivity checking service has been enabled.
	 *
	 * Since: 1.10
	 *
	 * The property setter is a synchronous D-Bus call. This is deprecated since 1.22.
	 */
	obj_properties[PROP_CONNECTIVITY_CHECK_ENABLED] =
	    g_param_spec_boolean (NM_CLIENT_CONNECTIVITY_CHECK_ENABLED, "", "",
	                          FALSE,
	                          G_PARAM_READWRITE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMClient:connectivity-check-uri:
	 *
	 * The used URI for connectivity checking.
	 *
	 * Since: 1.22
	 **/
	obj_properties[PROP_CONNECTIVITY_CHECK_URI] =
	    g_param_spec_string (NM_CLIENT_CONNECTIVITY_CHECK_URI, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMClient:primary-connection:
	 *
	 * The #NMActiveConnection of the device with the default route;
	 * see nm_client_get_primary_connection() for more details.
	 **/
	obj_properties[PROP_PRIMARY_CONNECTION] =
	    g_param_spec_object (NM_CLIENT_PRIMARY_CONNECTION, "", "",
	                         NM_TYPE_ACTIVE_CONNECTION,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMClient:activating-connection:
	 *
	 * The #NMActiveConnection of the activating connection that is
	 * likely to become the new #NMClient:primary-connection.
	 **/
	obj_properties[PROP_ACTIVATING_CONNECTION] =
	    g_param_spec_object (NM_CLIENT_ACTIVATING_CONNECTION, "", "",
	                         NM_TYPE_ACTIVE_CONNECTION,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMClient:devices: (type GPtrArray(NMDevice))
	 *
	 * List of real network devices.  Does not include placeholder devices.
	 **/
	obj_properties[PROP_DEVICES] =
	    g_param_spec_boxed (NM_CLIENT_DEVICES, "", "",
	                        G_TYPE_PTR_ARRAY,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMClient:all-devices: (type GPtrArray(NMDevice))
	 *
	 * List of both real devices and device placeholders.
	 * Since: 1.2
	 **/
	obj_properties[PROP_ALL_DEVICES] =
	    g_param_spec_boxed (NM_CLIENT_ALL_DEVICES, "", "",
	                        G_TYPE_PTR_ARRAY,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMClient:connections: (type GPtrArray(NMRemoteConnection))
	 *
	 * The list of configured connections that are available to the user. (Note
	 * that this differs from the underlying D-Bus property, which may also
	 * contain the object paths of connections that the user does not have
	 * permission to read the details of.)
	 */
	obj_properties[PROP_CONNECTIONS] =
	    g_param_spec_boxed (NM_CLIENT_CONNECTIONS, "", "",
	                        G_TYPE_PTR_ARRAY,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMClient:hostname:
	 *
	 * The machine hostname stored in persistent configuration. This can be
	 * modified by calling nm_client_save_hostname().
	 */
	obj_properties[PROP_HOSTNAME] =
	    g_param_spec_string (NM_CLIENT_HOSTNAME, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMClient:can-modify:
	 *
	 * If %TRUE, adding and modifying connections is supported.
	 */
	obj_properties[PROP_CAN_MODIFY] =
	    g_param_spec_boolean (NM_CLIENT_CAN_MODIFY, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMClient:metered:
	 *
	 * Whether the connectivity is metered.
	 *
	 * Since: 1.2
	 **/
	obj_properties[PROP_METERED] =
	    g_param_spec_uint (NM_CLIENT_METERED, "", "",
	                       0, G_MAXUINT32, NM_METERED_UNKNOWN,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMClient:dns-mode:
	 *
	 * The current DNS processing mode.
	 *
	 * Since: 1.6
	 **/
	obj_properties[PROP_DNS_MODE] =
	    g_param_spec_string (NM_CLIENT_DNS_MODE, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMClient:dns-rc-manager:
	 *
	 * The current resolv.conf management mode.
	 *
	 * Since: 1.6
	 **/
	obj_properties[PROP_DNS_RC_MANAGER] =
	    g_param_spec_string (NM_CLIENT_DNS_RC_MANAGER, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMClient:dns-configuration: (type GPtrArray(NMDnsEntry))
	 *
	 * The current DNS configuration, represented as an array
	 * of #NMDnsEntry objects.
	 *
	 * Since: 1.6
	 **/
	obj_properties[PROP_DNS_CONFIGURATION] =
	    g_param_spec_boxed (NM_CLIENT_DNS_CONFIGURATION, "", "",
	                        G_TYPE_PTR_ARRAY,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMClient:checkpoints: (type GPtrArray(NMCheckpoint))
	 *
	 * The list of active checkpoints.
	 *
	 * Since: 1.12
	 */
	obj_properties[PROP_CHECKPOINTS] =
	    g_param_spec_boxed (NM_CLIENT_CHECKPOINTS, "", "",
	                        G_TYPE_PTR_ARRAY,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMClient:capabilities: (type GArray(guint32))
	 *
	 * The list of capabilities numbers as guint32 or %NULL if
	 * there are no capabitilies. The numeric value correspond
	 * to %NMCapability enum.
	 *
	 * Since: 1.24
	 */
	obj_properties[PROP_CAPABILITIES] =
	    g_param_spec_boxed (NM_CLIENT_CAPABILITIES, "", "",
	                        G_TYPE_ARRAY,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMClient:permissions-state:
	 *
	 * The state of the cached permissions. The value %NM_TERNARY_DEFAULT
	 * means that no permissions are yet received (or not yet requested).
	 * %NM_TERNARY_TRUE means that permissions are received, cached and up
	 * to date. %NM_TERNARY_FALSE means that permissions were received and are
	 * cached, but in the meantime a "CheckPermissions" signal was received
	 * that invalidated the cached permissions.
	 * Note that NMClient will always emit a notify::permissions-state signal
	 * when a "CheckPermissions" signal got received or after new permissions
	 * got received (that is regardless whether the value of the permission state
	 * actually changed). With this you can watch the permissions-state property
	 * to know whether the permissions are ready. Note that while NMClient has
	 * no D-Bus name owner, no permissions are fetched (and this property won't
	 * change).
	 *
	 * Since: 1.24
	 */
	obj_properties[PROP_PERMISSIONS_STATE] =
	    g_param_spec_enum (NM_CLIENT_PERMISSIONS_STATE, "", "",
	                       NM_TYPE_TERNARY,
	                       NM_TERNARY_DEFAULT,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);

	_nml_dbus_meta_class_init_with_properties (object_class, &_nml_dbus_meta_iface_nm,
	                                                         &_nml_dbus_meta_iface_nm_settings,
	                                                         &_nml_dbus_meta_iface_nm_dnsmanager);

	/**
	 * NMClient::device-added:
	 * @client: the client that received the signal
	 * @device: (type NMDevice): the new device
	 *
	 * Notifies that a #NMDevice is added.  This signal is not emitted for
	 * placeholder devices.
	 **/
	signals[DEVICE_ADDED] =
	    g_signal_new (NM_CLIENT_DEVICE_ADDED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 1,
	                  G_TYPE_OBJECT);

	/**
	 * NMClient::device-removed:
	 * @client: the client that received the signal
	 * @device: (type NMDevice): the removed device
	 *
	 * Notifies that a #NMDevice is removed.  This signal is not emitted for
	 * placeholder devices.
	 **/
	signals[DEVICE_REMOVED] =
	    g_signal_new (NM_CLIENT_DEVICE_REMOVED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 1,
	                  G_TYPE_OBJECT);

	/**
	 * NMClient::any-device-added:
	 * @client: the client that received the signal
	 * @device: (type NMDevice): the new device
	 *
	 * Notifies that a #NMDevice is added.  This signal is emitted for both
	 * regular devices and placeholder devices.
	 **/
	signals[ANY_DEVICE_ADDED] =
	    g_signal_new (NM_CLIENT_ANY_DEVICE_ADDED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 1,
	                  G_TYPE_OBJECT);

	/**
	 * NMClient::any-device-removed:
	 * @client: the client that received the signal
	 * @device: (type NMDevice): the removed device
	 *
	 * Notifies that a #NMDevice is removed.  This signal is emitted for both
	 * regular devices and placeholder devices.
	 **/
	signals[ANY_DEVICE_REMOVED] =
	    g_signal_new (NM_CLIENT_ANY_DEVICE_REMOVED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 1,
	                  G_TYPE_OBJECT);

	/**
	 * NMClient::permission-changed:
	 * @client: the client that received the signal
	 * @permission: a permission from #NMClientPermission
	 * @result: the permission's result, one of #NMClientPermissionResult
	 *
	 * Notifies that a permission has changed
	 **/
	signals[PERMISSION_CHANGED] =
	    g_signal_new (NM_CLIENT_PERMISSION_CHANGED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 2, G_TYPE_UINT, G_TYPE_UINT);
	/**
	 * NMClient::connection-added:
	 * @client: the settings object that received the signal
	 * @connection: the new connection
	 *
	 * Notifies that a #NMConnection has been added.
	 **/
	signals[CONNECTION_ADDED] =
	    g_signal_new (NM_CLIENT_CONNECTION_ADDED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 1,
	                  NM_TYPE_REMOTE_CONNECTION);

	/**
	 * NMClient::connection-removed:
	 * @client: the settings object that received the signal
	 * @connection: the removed connection
	 *
	 * Notifies that a #NMConnection has been removed.
	 **/
	signals[CONNECTION_REMOVED] =
	    g_signal_new (NM_CLIENT_CONNECTION_REMOVED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 1,
	                  NM_TYPE_REMOTE_CONNECTION);

	/**
	 * NMClient::active-connection-added:
	 * @client: the settings object that received the signal
	 * @active_connection: the new active connection
	 *
	 * Notifies that a #NMActiveConnection has been added.
	 **/
	signals[ACTIVE_CONNECTION_ADDED] =
	    g_signal_new (NM_CLIENT_ACTIVE_CONNECTION_ADDED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 1,
	                  NM_TYPE_ACTIVE_CONNECTION);

	/**
	 * NMClient::active-connection-removed:
	 * @client: the settings object that received the signal
	 * @active_connection: the removed active connection
	 *
	 * Notifies that a #NMActiveConnection has been removed.
	 **/
	signals[ACTIVE_CONNECTION_REMOVED] =
	    g_signal_new (NM_CLIENT_ACTIVE_CONNECTION_REMOVED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 1,
	                  NM_TYPE_ACTIVE_CONNECTION);
}

static void
nm_client_initable_iface_init (GInitableIface *iface)
{
	iface->init = init_sync;
}

static void
nm_client_async_initable_iface_init (GAsyncInitableIface *iface)
{
	iface->init_async = init_async;
	iface->init_finish = init_finish;
}

/*****************************************************************************
 * Backported symbols. Usually, new API is only added in new major versions
 * of NetworkManager (that is, on "master" branch). Sometimes however, we might
 * have to backport some API to an older stable branch. In that case, we backport
 * the symbols with a different version corresponding to the minor API.
 *
 * To allow upgrading from such a extended minor-release, "master" contains these
 * backported symbols too.
 *
 * For example, 1.2.0 added nm_setting_connection_autoconnect_slaves_get_type.
 * This was backported for 1.0.4 as nm_setting_connection_autoconnect_slaves_get_type@libnm_1_0_4
 * To allow an application that was linked against 1.0.4 to seamlessly upgrade to
 * a newer major version, the same symbols is also exposed on "master". Note, that
 * a user can only seamlessly upgrade to a newer major version, that is released
 * *after* 1.0.4 is out. In this example, 1.2.0 was released after 1.4.0, and thus
 * a 1.0.4 user can upgrade to 1.2.0 ABI.
 *****************************************************************************/

NM_BACKPORT_SYMBOL (libnm_1_0_4, NMSettingConnectionAutoconnectSlaves, nm_setting_connection_get_autoconnect_slaves, (NMSettingConnection *setting), (setting));

NM_BACKPORT_SYMBOL (libnm_1_0_4, GType, nm_setting_connection_autoconnect_slaves_get_type, (void), ());

NM_BACKPORT_SYMBOL (libnm_1_0_6, NMMetered, nm_setting_connection_get_metered, (NMSettingConnection *setting), (setting));

NM_BACKPORT_SYMBOL (libnm_1_0_6, GType, nm_metered_get_type, (void), ());

NM_BACKPORT_SYMBOL (libnm_1_0_6, NMSettingWiredWakeOnLan, nm_setting_wired_get_wake_on_lan,
                    (NMSettingWired *setting), (setting));

NM_BACKPORT_SYMBOL (libnm_1_0_6, const char *, nm_setting_wired_get_wake_on_lan_password,
                    (NMSettingWired *setting), (setting));

NM_BACKPORT_SYMBOL (libnm_1_0_6, GType, nm_setting_wired_wake_on_lan_get_type, (void), ());

NM_BACKPORT_SYMBOL (libnm_1_0_6, const guint *, nm_utils_wifi_2ghz_freqs, (void), ());

NM_BACKPORT_SYMBOL (libnm_1_0_6, const guint *, nm_utils_wifi_5ghz_freqs, (void), ());

NM_BACKPORT_SYMBOL (libnm_1_0_6, char *, nm_utils_enum_to_str,
                    (GType type, int value), (type, value));

NM_BACKPORT_SYMBOL (libnm_1_0_6, gboolean, nm_utils_enum_from_str,
                    (GType type, const char *str, int *out_value, char **err_token),
                    (type, str, out_value, err_token));

NM_BACKPORT_SYMBOL (libnm_1_2_4, int, nm_setting_ip_config_get_dns_priority, (NMSettingIPConfig *setting), (setting));

NM_BACKPORT_SYMBOL (libnm_1_10_14, NMSettingConnectionMdns, nm_setting_connection_get_mdns,
                    (NMSettingConnection *setting), (setting));
NM_BACKPORT_SYMBOL (libnm_1_10_14, GType, nm_setting_connection_mdns_get_type, (void), ());
