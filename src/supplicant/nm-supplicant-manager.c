// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2006 - 2010 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#include "nm-default.h"

#include "nm-supplicant-manager.h"

#include "nm-core-internal.h"
#include "nm-dbus-manager.h"
#include "nm-glib-aux/nm-dbus-aux.h"
#include "nm-glib-aux/nm-ref-string.h"
#include "nm-supplicant-interface.h"
#include "nm-supplicant-types.h"
#include "platform/nm-platform.h"

/*****************************************************************************/

#define CREATE_IFACE_TRY_COUNT_MAX 7u

struct _NMSupplMgrCreateIfaceHandle {
	NMSupplicantManager *self;
	CList create_iface_lst;
	GCancellable *cancellable;
	NMSupplicantManagerCreateInterfaceCb callback;
	gpointer callback_user_data;
	NMShutdownWaitObjHandle *shutdown_handle;
	NMRefString *name_owner;
	GError *fail_on_idle_error;
	NMSupplicantDriver driver;
	int ifindex;
	guint fail_on_idle_id;
	guint create_iface_try_count:5;
};

enum {
	AVAILABLE_CHANGED,
	LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = { 0 };

typedef struct {
	GDBusConnection *dbus_connection;

	NMRefString *name_owner;

	GCancellable *get_name_owner_cancellable;
	GCancellable *get_capabilities_cancellable;
	GCancellable *poke_name_owner_cancellable;

	GHashTable *supp_ifaces;
	CList supp_lst_head;

	CList create_iface_lst_head;

	NMSupplCapMask capabilities;

	guint name_owner_changed_id;
	guint interface_removed_id;
	guint poke_name_owner_timeout_id;
	guint available_reset_id;

	/* see nm_supplicant_manager_get_available(). */
	NMTernary available:2;

} NMSupplicantManagerPrivate;

struct _NMSupplicantManager {
	GObject parent;
	NMSupplicantManagerPrivate _priv;
};

struct _NMSupplicantManagerClass {
	GObjectClass parent;
};

G_DEFINE_TYPE (NMSupplicantManager, nm_supplicant_manager, G_TYPE_OBJECT)

#define NM_SUPPLICANT_MANAGER_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMSupplicantManager, NM_IS_SUPPLICANT_MANAGER)

NM_DEFINE_SINGLETON_GETTER (NMSupplicantManager, nm_supplicant_manager_get, NM_TYPE_SUPPLICANT_MANAGER);

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_SUPPLICANT
#define _NMLOG(level, ...) __NMLOG_DEFAULT (level, _NMLOG_DOMAIN, "supplicant", __VA_ARGS__)

/*****************************************************************************/

NM_CACHED_QUARK_FCN ("nm-supplicant-error-quark", nm_supplicant_error_quark)

/*****************************************************************************/

static void _create_iface_proceed_all (NMSupplicantManager *self,
                                       GError *error);
static void _supp_iface_add (NMSupplicantManager *self,
                             NMRefString *iface_path,
                             NMSupplicantInterface *supp_iface);
static void _supp_iface_remove_one (NMSupplicantManager *self,
                                    NMSupplicantInterface *supp_iface,
                                    gboolean force_remove_from_supplicant,
                                    const char *reason);
static void _create_iface_dbus_call_get_interface (NMSupplicantManager *self,
                                                   NMSupplMgrCreateIfaceHandle *handle,
                                                   const char *ifname);
static void _create_iface_dbus_call_create_interface (NMSupplicantManager *self,
                                                      NMSupplMgrCreateIfaceHandle *handle,
                                                      const char *ifname);
static gboolean _create_iface_fail_on_idle_cb (gpointer user_data);

static gboolean _available_reset_cb (gpointer user_data);

/*****************************************************************************/

NM_UTILS_LOOKUP_STR_DEFINE (nm_supplicant_driver_to_string, NMSupplicantDriver,
	NM_UTILS_LOOKUP_DEFAULT_WARN (NULL),
	NM_UTILS_LOOKUP_ITEM    (NM_SUPPLICANT_DRIVER_UNKNOWN,  "???"),
	NM_UTILS_LOOKUP_ITEM    (NM_SUPPLICANT_DRIVER_WIRELESS, NM_WPAS_DEFAULT_WIFI_DRIVER),
	NM_UTILS_LOOKUP_ITEM    (NM_SUPPLICANT_DRIVER_WIRED,    "wired"),
	NM_UTILS_LOOKUP_ITEM    (NM_SUPPLICANT_DRIVER_MACSEC,   "macsec_linux"),
);

/*****************************************************************************/

NMTernary
nm_supplicant_manager_is_available (NMSupplicantManager *self)
{
	g_return_val_if_fail (NM_IS_SUPPLICANT_MANAGER (self), NM_TERNARY_FALSE);

	return NM_SUPPLICANT_MANAGER_GET_PRIVATE (self)->available;
}

NMRefString *
nm_supplicant_manager_get_dbus_name_owner (NMSupplicantManager *self)
{
	g_return_val_if_fail (NM_IS_SUPPLICANT_MANAGER (self), NULL);

	return NM_SUPPLICANT_MANAGER_GET_PRIVATE (self)->name_owner;
}

GDBusConnection *nm_supplicant_manager_get_dbus_connection (NMSupplicantManager *self)
{
	g_return_val_if_fail (NM_IS_SUPPLICANT_MANAGER (self), NULL);

	return NM_SUPPLICANT_MANAGER_GET_PRIVATE (self)->dbus_connection;
}

NMSupplCapMask
nm_supplicant_manager_get_global_capabilities (NMSupplicantManager *self)
{
	g_return_val_if_fail (NM_IS_SUPPLICANT_MANAGER (self), NM_SUPPL_CAP_MASK_NONE);

	return NM_SUPPLICANT_MANAGER_GET_PRIVATE (self)->capabilities;
}

/*****************************************************************************/

static void
_caps_set (NMSupplicantManagerPrivate *priv,
           NMSupplCapType type,
           NMTernary value)
{
	priv->capabilities = NM_SUPPL_CAP_MASK_SET (priv->capabilities, type, value);
}

static char
_caps_to_char (NMSupplicantManagerPrivate *priv,
               NMSupplCapType type)
{
	NMTernary val;

	val = NM_SUPPL_CAP_MASK_GET (priv->capabilities, type);
	if (val == NM_TERNARY_TRUE)
		return '+';
	if (val == NM_TERNARY_FALSE)
		return '-';
	return '?';
}

/*****************************************************************************/

static void
_dbus_call_remove_interface (GDBusConnection *dbus_connection,
                             const char *name_owner,
                             const char *iface_path)
{
	nm_assert (G_IS_DBUS_CONNECTION (dbus_connection));
	nm_assert (name_owner);
	nm_assert (iface_path);

	g_dbus_connection_call (dbus_connection,
	                        name_owner,
	                        NM_WPAS_DBUS_PATH,
	                        NM_WPAS_DBUS_INTERFACE,
	                        "RemoveInterface",
	                        g_variant_new ("(o)", iface_path),
	                        G_VARIANT_TYPE ("()"),
	                        G_DBUS_CALL_FLAGS_NO_AUTO_START,
	                        10000,
	                        NULL,
	                        NULL,
	                        NULL);
}

void
_nm_supplicant_manager_dbus_call_remove_interface (NMSupplicantManager *self,
                                                   const char *name_owner,
                                                   const char *iface_path)
{
	_dbus_call_remove_interface (NM_SUPPLICANT_MANAGER_GET_PRIVATE (self)->dbus_connection,
	                             name_owner,
	                             iface_path);
}

/*****************************************************************************/

static void
on_supplicant_wfd_ies_set (GObject *source_object,
                           GAsyncResult *result,
                           gpointer user_data)
{
	gs_unref_variant GVariant *res = NULL;
	gs_free_error GError *error = NULL;

	res = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source_object), result, &error);
	if (!res)
		_LOGD ("failed to set WFD IEs on wpa_supplicant: %s", error->message);
}

/**
 * nm_supplicant_manager_set_wfd_ies:
 * @self: the #NMSupplicantManager
 * @wfd_ies: a #GBytes with the WFD IEs or %NULL
 *
 * This function sets the global WFD IEs on wpa_supplicant. Note that
 * it would make more sense if this was per-device, but wpa_supplicant
 * simply does not work that way.
 * */
void
nm_supplicant_manager_set_wfd_ies (NMSupplicantManager *self,
                                   GBytes *wfd_ies)
{
	NMSupplicantManagerPrivate *priv;
	GVariantBuilder params;

	g_return_if_fail (NM_IS_SUPPLICANT_MANAGER (self));

	priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);

	if (!priv->name_owner)
		return;

	_LOGD ("setting WFD IEs for P2P operation on %s", priv->name_owner->str);

	g_variant_builder_init (&params, G_VARIANT_TYPE ("(ssv)"));

	g_variant_builder_add (&params, "s", NM_WPAS_DBUS_INTERFACE);
	g_variant_builder_add (&params, "s", "WFDIEs");
	g_variant_builder_add_value (&params,
	                             g_variant_new_variant (nm_utils_gbytes_to_variant_ay (wfd_ies)));

	g_dbus_connection_call (priv->dbus_connection,
	                        priv->name_owner->str,
	                        NM_WPAS_DBUS_PATH,
	                        DBUS_INTERFACE_PROPERTIES,
	                        "Set",
	                        g_variant_builder_end (&params),
	                        G_VARIANT_TYPE ("()"),
	                        G_DBUS_CALL_FLAGS_NO_AUTO_START,
	                        3000,
	                        NULL,
	                        on_supplicant_wfd_ies_set,
	                        NULL);
}

/*****************************************************************************/

static gboolean
_poke_name_owner_timeout_cb (gpointer user_data)
{
	NMSupplicantManager *self = user_data;
	NMSupplicantManagerPrivate *priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);
	gs_free_error GError *error = NULL;
	gboolean available_changed = FALSE;

	nm_assert (!priv->name_owner);

	priv->poke_name_owner_timeout_id = 0;
	nm_clear_g_cancellable (&priv->poke_name_owner_cancellable);

	_LOGT ("poke service \"%s\" failed for good with timeout%s",
	       NM_WPAS_DBUS_SERVICE,
	         (priv->available == NM_TERNARY_DEFAULT)
	       ? " (set as not available)"
	       : "");

	if (priv->available == NM_TERNARY_DEFAULT) {
		/* the available flag usually only changes together with the name-owner.
		 * However, if we tries to poke the service but failed to start it (with
		 * timeout), was also set it as (hard) not available. */
		priv->available = NM_TERNARY_FALSE;
		nm_clear_g_source (&priv->available_reset_id);
		priv->available_reset_id = g_timeout_add_seconds (60,
		                                                  _available_reset_cb,
		                                                  self);
		available_changed = TRUE;
	}

	nm_utils_error_set (&error,
	                    NM_UTILS_ERROR_UNKNOWN,
	                    "Failed to D-Bus activate wpa_supplicant service");

	_create_iface_proceed_all (self, error);

	if (available_changed) {
		/* We delay the emitting of the notification after aborting all
		 * create-iface handles. */
		g_signal_emit (self, signals[AVAILABLE_CHANGED], 0);
	}

	return G_SOURCE_REMOVE;
}

static void
_poke_name_owner_cb (GObject *source,
                     GAsyncResult *result,
                     gpointer user_data)
{
	gs_unref_variant GVariant *res = NULL;
	gs_free_error GError *error = NULL;

	res = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source), result, &error);
	if (nm_utils_error_is_cancelled (error))
		return;

	if (!res)
		_LOGT ("poke service \"%s\" failed: %s", NM_WPAS_DBUS_SERVICE, error->message);
	else
		_LOGT ("poke service \"%s\" succeeded", NM_WPAS_DBUS_SERVICE);

	/* in both cases, we react the same: we wait for the name owner to appear
	 * or hit the timeout. */
}

static void
_poke_name_owner (NMSupplicantManager *self)
{
	NMSupplicantManagerPrivate *priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);

	if (priv->poke_name_owner_cancellable)
		return;

	_LOGT ("poke service \"%s\"...", NM_WPAS_DBUS_SERVICE);

	priv->poke_name_owner_cancellable = g_cancellable_new ();
	priv->poke_name_owner_timeout_id = g_timeout_add (3000,
	                                                  _poke_name_owner_timeout_cb,
	                                                  self);
	nm_dbus_connection_call_start_service_by_name (priv->dbus_connection,
	                                               NM_WPAS_DBUS_SERVICE,
	                                               5000,
	                                               priv->poke_name_owner_cancellable,
	                                               _poke_name_owner_cb,
	                                               self);
}

/*****************************************************************************/

static void
_create_iface_complete (NMSupplMgrCreateIfaceHandle *handle,
                        NMSupplicantInterface *supp_iface,
                        GError *error)
{
	nm_assert (!supp_iface || NM_IS_SUPPLICANT_INTERFACE (supp_iface));
	nm_assert ((!!supp_iface) != (!!error));

	c_list_unlink (&handle->create_iface_lst);

	nm_clear_g_source (&handle->fail_on_idle_id);

	if (handle->callback) {
		NMSupplicantManagerCreateInterfaceCb callback;

		nm_assert (NM_IS_SUPPLICANT_MANAGER (handle->self));

		callback = handle->callback;
		handle->callback = NULL;
		callback (handle->self,
		          handle,
		          supp_iface,
		          error,
		          handle->callback_user_data);
	}

	g_clear_error (&handle->fail_on_idle_error);

	g_clear_object (&handle->self);

	if (handle->shutdown_handle) {
		/* we have a pending CreateInterface request. We keep the handle
		 * instance alive. This is to remove the device again, once the
		 * request completes. */
		return;
	}

	nm_clear_g_cancellable (&handle->cancellable);
	nm_ref_string_unref (handle->name_owner);

	nm_g_slice_free_fcn (handle);
}

static void
_create_iface_add (NMSupplicantManager *self,
                   NMSupplMgrCreateIfaceHandle *handle,
                   const char *iface_path_str,
                   gboolean created_by_us)
{
	NMSupplicantManagerPrivate *priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);
	nm_auto_ref_string NMRefString *iface_path = NULL;
	gs_unref_object NMSupplicantInterface *supp_iface = NULL;

	iface_path = nm_ref_string_new (iface_path_str);

	supp_iface = g_hash_table_lookup (priv->supp_ifaces, iface_path);
	if (supp_iface) {
		/* Now this is odd... Reuse the same interface. */
		g_object_ref (supp_iface);
		_LOGT ("create-iface["NM_HASH_OBFUSCATE_PTR_FMT"]: interface %s on %s created (already existing)",
		       NM_HASH_OBFUSCATE_PTR (handle),
		       iface_path_str,
		       priv->name_owner->str);
		_create_iface_complete (handle, supp_iface, NULL);
		return;
	}

	_LOGT ("create-iface["NM_HASH_OBFUSCATE_PTR_FMT"]: interface %s on %s created%s",
	       NM_HASH_OBFUSCATE_PTR (handle),
	       iface_path_str,
	       priv->name_owner->str,
	       created_by_us ? " (created by us)" : "");

	supp_iface = nm_supplicant_interface_new (self,
	                                          iface_path,
	                                          handle->ifindex,
	                                          handle->driver);

	_supp_iface_add (self, iface_path, supp_iface);

	_create_iface_complete (handle, supp_iface, NULL);
}

static void
_create_iface_dbus_call_get_interface_cb (GObject *source,
                                          GAsyncResult *result,
                                          gpointer user_data)
{
	GDBusConnection *dbus_connection = G_DBUS_CONNECTION (source);
	NMSupplMgrCreateIfaceHandle *handle;
	NMSupplicantManager *self;
	NMSupplicantManagerPrivate *priv;
	gs_unref_variant GVariant *res = NULL;
	gs_free_error GError *error = NULL;
	const char *iface_path_str;

	res = g_dbus_connection_call_finish (dbus_connection, result, &error);

	if (nm_utils_error_is_cancelled (error))
		return;

	handle = user_data;
	nm_assert (handle->callback);

	self = handle->self;
	priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);

	nm_assert (handle->name_owner == priv->name_owner);

	if (!res) {
		char ifname[NMP_IFNAMSIZ];

		if (   handle->create_iface_try_count < CREATE_IFACE_TRY_COUNT_MAX
		    && _nm_dbus_error_has_name (error, NM_WPAS_ERROR_UNKNOWN_IFACE)
		    && nm_platform_if_indextoname (NM_PLATFORM_GET, handle->ifindex, ifname)) {
			/* Before, supplicant told us the interface existed. Was there a race?
			 * Try again. */
			_LOGT ("create-iface["NM_HASH_OBFUSCATE_PTR_FMT"]: D-Bus call failed to get interface. Try to create it again (ifname \"%s\")",
			       NM_HASH_OBFUSCATE_PTR (handle),
			       ifname);
			_create_iface_dbus_call_create_interface (self, handle, ifname);
			return;
		}

		g_clear_object (&handle->cancellable);
		_LOGT ("create-iface["NM_HASH_OBFUSCATE_PTR_FMT"]: D-Bus call to get interface failed: %s",
		       NM_HASH_OBFUSCATE_PTR (handle),
		       error->message);
		_create_iface_complete (handle, NULL, error);
		return;
	}

	g_clear_object (&handle->cancellable);

	g_variant_get (res, "(&o)", &iface_path_str);

	_create_iface_add (self, handle, iface_path_str, FALSE);
}

static void
_create_iface_dbus_call_create_interface_cb (GObject *source,
                                             GAsyncResult *result,
                                             gpointer user_data)
{
	GDBusConnection *dbus_connection = G_DBUS_CONNECTION (source);
	NMSupplMgrCreateIfaceHandle *handle = user_data;
	NMSupplicantManager *self;
	NMSupplicantManagerPrivate *priv;
	gs_unref_variant GVariant *res = NULL;
	gs_free_error GError *error = NULL;
	const char *iface_path_str;
	char ifname[NMP_IFNAMSIZ];

	res = g_dbus_connection_call_finish (dbus_connection, result, &error);

	nm_shutdown_wait_obj_unregister (g_steal_pointer (&handle->shutdown_handle));

	if (!res) {
		if (   handle->callback
		    && ({ nm_assert (handle->self); TRUE; })
		    && _nm_dbus_error_has_name (error, NM_WPAS_ERROR_EXISTS_ERROR)
		    && nm_platform_if_indextoname (NM_PLATFORM_GET, handle->ifindex, ifname)) {
			self = handle->self;
			_LOGT ("create-iface["NM_HASH_OBFUSCATE_PTR_FMT"]: D-Bus call failed to create interface. Try to get existing interface (ifname \"%s\")",
			       NM_HASH_OBFUSCATE_PTR (handle),
			       ifname);
			_create_iface_dbus_call_get_interface (self, handle, ifname);
			return;
		}
		g_clear_object (&handle->cancellable);
		_LOGT ("create-iface["NM_HASH_OBFUSCATE_PTR_FMT"]: D-Bus call failed: %s",
		       NM_HASH_OBFUSCATE_PTR (handle),
		       error->message);
		_create_iface_complete (handle, NULL, error);
		return;
	}

	g_clear_object (&handle->cancellable);

	self = handle->self;
	priv =   self
	       ? NM_SUPPLICANT_MANAGER_GET_PRIVATE (self)
	       : NULL;

	g_variant_get (res, "(&o)", &iface_path_str);

	if (   !handle->callback
	    || priv->name_owner != handle->name_owner) {
		if (!handle->callback) {
			_LOGT ("create-iface["NM_HASH_OBFUSCATE_PTR_FMT"]: request already cancelled but still remove interface %s in %s",
			       NM_HASH_OBFUSCATE_PTR (handle),
			       iface_path_str,
			       handle->name_owner->str);
		} else {
			_LOGT ("create-iface["NM_HASH_OBFUSCATE_PTR_FMT"]: name owner changed, still remove interface %s in %s",
			       NM_HASH_OBFUSCATE_PTR (handle),
			       iface_path_str,
			       handle->name_owner->str);
			nm_utils_error_set (&error,
			                    NM_UTILS_ERROR_UNKNOWN,
			                    "The name owner changed since creating the interface");
		}
		_dbus_call_remove_interface (dbus_connection,
		                             handle->name_owner->str,
		                             iface_path_str);
		_create_iface_complete (handle, NULL, error);
		return;
	}

	_create_iface_add (self, handle, iface_path_str, TRUE);
}

static void
_create_iface_dbus_call_get_interface (NMSupplicantManager *self,
                                       NMSupplMgrCreateIfaceHandle *handle,
                                       const char *ifname)
{
	NMSupplicantManagerPrivate *priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);

	nm_assert (handle->cancellable);
	nm_assert (!handle->shutdown_handle);

	g_dbus_connection_call (priv->dbus_connection,
	                        priv->name_owner->str,
	                        NM_WPAS_DBUS_PATH,
	                        NM_WPAS_DBUS_INTERFACE,
	                        "GetInterface",
	                        g_variant_new ("(s)", ifname),
	                        G_VARIANT_TYPE ("(o)"),
	                        G_DBUS_CALL_FLAGS_NONE,
	                        5000,
	                        handle->cancellable,
	                        _create_iface_dbus_call_get_interface_cb,
	                        handle);
}

static void
_create_iface_dbus_call_create_interface (NMSupplicantManager *self,
                                          NMSupplMgrCreateIfaceHandle *handle,
                                          const char *ifname)
{
	NMSupplicantManagerPrivate *priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);
	GVariantBuilder builder;

	nm_assert (priv->name_owner == handle->name_owner);
	nm_assert (handle->cancellable);
	nm_assert (!handle->shutdown_handle);
	nm_assert (handle->create_iface_try_count <= CREATE_IFACE_TRY_COUNT_MAX);

	g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add (&builder,
	                       "{sv}",
	                       "Driver",
	                       g_variant_new_string (nm_supplicant_driver_to_string (handle->driver)));
	g_variant_builder_add (&builder,
	                       "{sv}",
	                       "Ifname",
	                       g_variant_new_string (ifname));

	handle->shutdown_handle = nm_shutdown_wait_obj_register_cancellable_full (handle->cancellable,
	                                                                          g_strdup_printf ("wpas-create-" NM_HASH_OBFUSCATE_PTR_FMT,
	                                                                                           NM_HASH_OBFUSCATE_PTR (handle)),
	                                                                          TRUE);
	handle->create_iface_try_count++;
	g_dbus_connection_call (priv->dbus_connection,
	                        handle->name_owner->str,
	                        NM_WPAS_DBUS_PATH,
	                        NM_WPAS_DBUS_INTERFACE,
	                        "CreateInterface",
	                        g_variant_new ("(a{sv})", &builder),
	                        G_VARIANT_TYPE ("(o)"),
	                        G_DBUS_CALL_FLAGS_NONE,
	                        5000,
	                        handle->cancellable,
	                        _create_iface_dbus_call_create_interface_cb,
	                        handle);
}

static void
_create_iface_dbus_start (NMSupplicantManager *self,
                          NMSupplMgrCreateIfaceHandle *handle)
{
	NMSupplicantManagerPrivate *priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);
	char ifname[NMP_IFNAMSIZ];

	nm_assert (priv->name_owner);
	nm_assert (!handle->cancellable);

	if (!nm_platform_if_indextoname (NM_PLATFORM_GET, handle->ifindex, ifname)) {
		nm_utils_error_set (&handle->fail_on_idle_error,
		                    NM_UTILS_ERROR_UNKNOWN,
		                    "Cannot find interface %d",
		                    handle->ifindex);
		_LOGT ("create-iface["NM_HASH_OBFUSCATE_PTR_FMT"]: creating interface fails to find interface name for ifindex %d",
		       NM_HASH_OBFUSCATE_PTR (handle),
		       handle->ifindex);
		handle->fail_on_idle_id = g_idle_add (_create_iface_fail_on_idle_cb, handle);
		return;
	}

	/* Our handle keeps @self alive. That means, when NetworkManager shall shut
	 * down, it's the responsibility of the callers to cancel the handles,
	 * to initiate coordinated shutdown.
	 *
	 * However, we now issue a CreateInterface call. Even if the handle gets cancelled
	 * (because of shutdown, or because the caller is no longer interested in the
	 * result), we don't want to cancel this request. Instead, we want to get
	 * the interface path and remove it right away.
	 *
	 * That means, the D-Bus call cannot be cancelled (because we always care about
	 * the result). Only the @handle can be cancelled, but parts of the handle will
	 * stick around to complete the task.
	 *
	 * See also handle->shutdown_handle.
	 */
	handle->name_owner = nm_ref_string_ref (priv->name_owner);
	handle->cancellable = g_cancellable_new ();
	_LOGT ("create-iface["NM_HASH_OBFUSCATE_PTR_FMT"]: creating interface (ifname \"%s\")...",
	       NM_HASH_OBFUSCATE_PTR (handle),
	       ifname);
	_create_iface_dbus_call_create_interface (self, handle, ifname);
}

static gboolean
_create_iface_fail_on_idle_cb (gpointer user_data)
{
	NMSupplMgrCreateIfaceHandle *handle = user_data;

	handle->fail_on_idle_id = 0;

	_LOGT ("create-iface["NM_HASH_OBFUSCATE_PTR_FMT"]: fail with internal error: %s",
	       NM_HASH_OBFUSCATE_PTR (handle),
	       handle->fail_on_idle_error->message);

	_create_iface_complete (handle, NULL, handle->fail_on_idle_error);
	return G_SOURCE_REMOVE;
}

NMSupplMgrCreateIfaceHandle *
nm_supplicant_manager_create_interface (NMSupplicantManager *self,
                                        int ifindex,
                                        NMSupplicantDriver driver,
                                        NMSupplicantManagerCreateInterfaceCb callback,
                                        gpointer user_data)
{
	NMSupplicantManagerPrivate *priv;
	NMSupplMgrCreateIfaceHandle *handle;

	g_return_val_if_fail (NM_IS_SUPPLICANT_MANAGER (self), NULL);
	g_return_val_if_fail (ifindex > 0, NULL);
	g_return_val_if_fail (callback, NULL);
	nm_assert (nm_supplicant_driver_to_string (driver));

	priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);

	handle = g_slice_new (NMSupplMgrCreateIfaceHandle);
	*handle = (NMSupplMgrCreateIfaceHandle) {
		.self               = g_object_ref (self),
		.callback           = callback,
		.callback_user_data = user_data,
		.driver             = driver,
		.ifindex            = ifindex,
	};
	c_list_link_tail (&priv->create_iface_lst_head, &handle->create_iface_lst);

	if (!priv->dbus_connection) {
		_LOGT ("create-iface["NM_HASH_OBFUSCATE_PTR_FMT"]: new request interface %d (driver %s). Fail bacause no D-Bus connection to talk to wpa_supplicant...",
		       NM_HASH_OBFUSCATE_PTR (handle),
		       ifindex,
		       nm_supplicant_driver_to_string (driver));
		nm_utils_error_set (&handle->fail_on_idle_error,
		                    NM_UTILS_ERROR_UNKNOWN,
		                    "No D-Bus connection to talk to wpa_supplicant");
		handle->fail_on_idle_id = g_idle_add (_create_iface_fail_on_idle_cb, handle);
		return handle;
	}

	if (!priv->name_owner) {
		_LOGT ("create-iface["NM_HASH_OBFUSCATE_PTR_FMT"]: new request interface %d (driver %s). %s",
		       NM_HASH_OBFUSCATE_PTR (handle),
		       ifindex,
		       nm_supplicant_driver_to_string (driver),
		         priv->poke_name_owner_cancellable
		       ? "Waiting for supplicant..."
		       : "Poke supplicant...");
		_poke_name_owner (self);
		return handle;
	}

	if (priv->get_capabilities_cancellable) {
		_LOGT ("create-iface["NM_HASH_OBFUSCATE_PTR_FMT"]: new request interface %d (driver %s). Waiting to fetch capabilities for %s...",
		       NM_HASH_OBFUSCATE_PTR (handle),
		       ifindex,
		       nm_supplicant_driver_to_string (driver),
		       priv->name_owner->str);
		return handle;
	}

	_LOGT ("create-iface["NM_HASH_OBFUSCATE_PTR_FMT"]: new request interface %d (driver %s). create interface on %s...",
	       NM_HASH_OBFUSCATE_PTR (handle),
	       ifindex,
	       nm_supplicant_driver_to_string (driver),
	       priv->name_owner->str);

	_create_iface_dbus_start (self, handle);
	return handle;
}

static void
_create_iface_proceed_all (NMSupplicantManager *self,
                           GError *error)
{
	NMSupplicantManagerPrivate *priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);
	NMSupplMgrCreateIfaceHandle *handle;

	nm_assert (error || priv->name_owner);
	nm_assert (error || !priv->get_capabilities_cancellable);

	if (c_list_is_empty (&priv->create_iface_lst_head))
		return;

	if (error) {
		CList alt_list;

		/* we move the handles we want to proceed to a alternative list.
		 * That is, because we invoke callbacks to the caller, who might
		 * create another request right away. We don't want to proceed
		 * that one. */
		c_list_init (&alt_list);
		c_list_splice (&alt_list, &priv->create_iface_lst_head);

		while ((handle = c_list_last_entry (&alt_list, NMSupplMgrCreateIfaceHandle, create_iface_lst))) {
			/* We don't need to keep @self alive. Every handle holds a reference already. */
			_LOGT ("create-iface["NM_HASH_OBFUSCATE_PTR_FMT"]: create interface failed: %s",
			       NM_HASH_OBFUSCATE_PTR (handle),
			       error->message);
			_create_iface_complete (handle, NULL, error);
		}
		return;
	}

	/* start all the handles. This does not invoke callbacks, so the list of handles
	 * cannot be modified while we iterate it. */
	c_list_for_each_entry (handle, &priv->create_iface_lst_head, create_iface_lst) {
		_LOGT ("create-iface["NM_HASH_OBFUSCATE_PTR_FMT"]: create interface on %s...",
		       NM_HASH_OBFUSCATE_PTR (handle),
		       priv->name_owner->str);
		_create_iface_dbus_start (self, handle);
	}
}

void
nm_supplicant_manager_create_interface_cancel (NMSupplMgrCreateIfaceHandle *handle)
{
	gs_free_error GError *error = NULL;

	if (!handle)
		return;

	g_return_if_fail (NM_IS_SUPPLICANT_MANAGER (handle->self));
	g_return_if_fail (handle->callback);
	nm_assert (!c_list_is_empty (&handle->create_iface_lst));

	nm_utils_error_set_cancelled (&error, FALSE, NULL);
	_create_iface_complete (handle, NULL, error);
}

NMSupplicantInterface *
nm_supplicant_manager_create_interface_from_path (NMSupplicantManager *self,
                                                  const char *object_path)
{
	NMSupplicantManagerPrivate *priv;
	NMSupplicantInterface *supp_iface;
	nm_auto_ref_string NMRefString *iface_path = NULL;

	g_return_val_if_fail (NM_IS_SUPPLICANT_MANAGER (self), NULL);
	g_return_val_if_fail (object_path, NULL);

	priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);

	iface_path = nm_ref_string_new (object_path);

	supp_iface = g_hash_table_lookup (priv->supp_ifaces, iface_path);

	if (supp_iface)
		return g_object_ref (supp_iface);

	supp_iface = nm_supplicant_interface_new (self,
	                                          iface_path,
	                                          0,
	                                          NM_SUPPLICANT_DRIVER_UNKNOWN);

	_supp_iface_add (self, iface_path, supp_iface);

	return supp_iface;
}

/*****************************************************************************/

static void
_dbus_interface_removed_cb (GDBusConnection *connection,
                            const char *sender_name,
                            const char *object_path,
                            const char *signal_interface_name,
                            const char *signal_name,
                            GVariant *parameters,
                            gpointer user_data)
{
	NMSupplicantManager *self = user_data;
	NMSupplicantManagerPrivate *priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);
	NMSupplicantInterface *supp_iface;
	const char *iface_path_str;
	nm_auto_ref_string NMRefString *iface_path = NULL;

	nm_assert (nm_streq (sender_name, priv->name_owner->str));

	if (!g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(o)")))
		return;

	g_variant_get (parameters, "(&o)", &iface_path_str);

	iface_path = nm_ref_string_new (iface_path_str);

	supp_iface = g_hash_table_lookup (priv->supp_ifaces, iface_path);
	if (!supp_iface)
		return;

	_supp_iface_remove_one (self, supp_iface, FALSE, "InterfaceRemoved signal from wpa_supplicant");
}

/*****************************************************************************/

static void
_dbus_get_capabilities_cb (GVariant *res,
                           GError *error,
                           gpointer user_data)
{
	NMSupplicantManager *self;
	NMSupplicantManagerPrivate *priv;

	if (nm_utils_error_is_cancelled (error))
		return;

	self = user_data;
	priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);

	g_clear_object (&priv->get_capabilities_cancellable);

	/* The supplicant only advertises global capabilities if the following
	 * commit has been applied:
	 *
	 * commit 1634ac0654eba8d458640a115efc0a6cde3bac4d
	 * Author: Dan Williams <dcbw@redhat.com>
	 * Date:   Sat Sep 29 19:06:30 2012 +0300
	 *
	 * dbus: Add global capabilities property
	 */
	_caps_set (priv, NM_SUPPL_CAP_TYPE_AP,     NM_TERNARY_DEFAULT);
	_caps_set (priv, NM_SUPPL_CAP_TYPE_PMF,    NM_TERNARY_DEFAULT);
	_caps_set (priv, NM_SUPPL_CAP_TYPE_FILS,   NM_TERNARY_DEFAULT);

	/* Support for the following is newer than the capabilities property */
	_caps_set (priv, NM_SUPPL_CAP_TYPE_P2P,    NM_TERNARY_FALSE);
	_caps_set (priv, NM_SUPPL_CAP_TYPE_FT,     NM_TERNARY_FALSE);
	_caps_set (priv, NM_SUPPL_CAP_TYPE_SHA384, NM_TERNARY_FALSE);
	_caps_set (priv, NM_SUPPL_CAP_TYPE_MESH,   NM_TERNARY_FALSE);
	_caps_set (priv, NM_SUPPL_CAP_TYPE_FAST,   NM_TERNARY_FALSE);
	_caps_set (priv, NM_SUPPL_CAP_TYPE_WFD,    NM_TERNARY_FALSE);

	if (res) {
		nm_auto_free_variant_iter GVariantIter *res_iter = NULL;
		const char *res_key;
		GVariant *res_val;

		g_variant_get (res, "(a{sv})", &res_iter);
		while (g_variant_iter_loop (res_iter, "{&sv}", &res_key, &res_val)) {
			if (nm_streq (res_key, "Capabilities")) {
				if (g_variant_is_of_type (res_val, G_VARIANT_TYPE_STRING_ARRAY)) {
					gs_free const char **array = NULL;
					const char **a;

					array = g_variant_get_strv (res_val, NULL);
					_caps_set (priv, NM_SUPPL_CAP_TYPE_AP,   NM_TERNARY_FALSE);
					_caps_set (priv, NM_SUPPL_CAP_TYPE_PMF,  NM_TERNARY_FALSE);
					_caps_set (priv, NM_SUPPL_CAP_TYPE_FILS, NM_TERNARY_FALSE);
					if (array) {
						for (a = array; *a; a++) {
							if (nm_streq (*a, "ap"))     { _caps_set (priv, NM_SUPPL_CAP_TYPE_AP,     NM_TERNARY_TRUE); continue; }
							if (nm_streq (*a, "pmf"))    { _caps_set (priv, NM_SUPPL_CAP_TYPE_PMF,    NM_TERNARY_TRUE); continue; }
							if (nm_streq (*a, "fils"))   { _caps_set (priv, NM_SUPPL_CAP_TYPE_FILS,   NM_TERNARY_TRUE); continue; }
							if (nm_streq (*a, "p2p"))    { _caps_set (priv, NM_SUPPL_CAP_TYPE_P2P,    NM_TERNARY_TRUE); continue; }
							if (nm_streq (*a, "ft"))     { _caps_set (priv, NM_SUPPL_CAP_TYPE_FT,     NM_TERNARY_TRUE); continue; }
							if (nm_streq (*a, "sha384")) { _caps_set (priv, NM_SUPPL_CAP_TYPE_SHA384, NM_TERNARY_TRUE); continue; }
							if (nm_streq (*a, "mesh"))   { _caps_set (priv, NM_SUPPL_CAP_TYPE_MESH,   NM_TERNARY_TRUE); continue; }
						}
					}
				}
				continue;
			}
			if (nm_streq (res_key, "EapMethods")) {
				if (g_variant_is_of_type (res_val, G_VARIANT_TYPE_STRING_ARRAY)) {
					gs_free const char **array = NULL;
					const char **a;

					array = g_variant_get_strv (res_val, NULL);
					if (array) {
						for (a = array; *a; a++) {
							if (g_ascii_strcasecmp (*a, "FAST") == 0) {
								_caps_set (priv, NM_SUPPL_CAP_TYPE_FAST, NM_TERNARY_TRUE);
								break;
							}
						}
					}
				}
				continue;
			}
			if (nm_streq (res_key, "WFDIEs")) {
				_caps_set (priv, NM_SUPPL_CAP_TYPE_WFD, NM_TERNARY_TRUE);
				continue;
			}
		}
	}

	_LOGD ("supported features:"
	       " AP%c"
	       " PMF%c"
	       " FILS%c"
	       " P2P%c"
	       " FT%c"
	       " SHA384%c"
	       " MESH%c"
	       " FAST%c"
	       " WFD%c"
	       "",
	       _caps_to_char (priv, NM_SUPPL_CAP_TYPE_AP),
	       _caps_to_char (priv, NM_SUPPL_CAP_TYPE_PMF),
	       _caps_to_char (priv, NM_SUPPL_CAP_TYPE_FILS),
	       _caps_to_char (priv, NM_SUPPL_CAP_TYPE_P2P),
	       _caps_to_char (priv, NM_SUPPL_CAP_TYPE_FT),
	       _caps_to_char (priv, NM_SUPPL_CAP_TYPE_SHA384),
	       _caps_to_char (priv, NM_SUPPL_CAP_TYPE_MESH),
	       _caps_to_char (priv, NM_SUPPL_CAP_TYPE_FAST),
	       _caps_to_char (priv, NM_SUPPL_CAP_TYPE_WFD));

	nm_assert (g_hash_table_size (priv->supp_ifaces) == 0);
	nm_assert (c_list_is_empty (&priv->supp_lst_head));

	_create_iface_proceed_all (self, NULL);
}

/*****************************************************************************/

void
_nm_supplicant_manager_unregister_interface (NMSupplicantManager *self,
                                             NMSupplicantInterface *supp_iface)
{
	NMSupplicantManagerPrivate *priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);

	nm_assert (NM_IS_SUPPLICANT_INTERFACE (supp_iface));
	nm_assert (c_list_contains (&NM_SUPPLICANT_MANAGER_GET_PRIVATE (self)->supp_lst_head, &supp_iface->supp_lst));

	c_list_unlink (&supp_iface->supp_lst);
	if (!g_hash_table_remove (priv->supp_ifaces, nm_supplicant_interface_get_object_path (supp_iface)))
		nm_assert_not_reached ();
}

static void
_supp_iface_add (NMSupplicantManager *self,
                 NMRefString *iface_path,
                 NMSupplicantInterface *supp_iface)
{
	NMSupplicantManagerPrivate *priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);

	c_list_link_tail (&priv->supp_lst_head, &supp_iface->supp_lst);
	if (!g_hash_table_insert (priv->supp_ifaces, iface_path, supp_iface))
		nm_assert_not_reached ();
}

static void
_supp_iface_remove_one (NMSupplicantManager *self,
                        NMSupplicantInterface *supp_iface,
                        gboolean force_remove_from_supplicant,
                        const char *reason)
{
#if NM_MORE_ASSERTS
	_nm_unused gs_unref_object NMSupplicantInterface *supp_iface_keep_alive = g_object_ref (supp_iface);
#endif

	nm_assert (NM_IS_SUPPLICANT_MANAGER (self));
	nm_assert (NM_IS_SUPPLICANT_INTERFACE (supp_iface));
	nm_assert (c_list_contains (&NM_SUPPLICANT_MANAGER_GET_PRIVATE (self)->supp_lst_head, &supp_iface->supp_lst));

	_nm_supplicant_interface_set_state_down (supp_iface, force_remove_from_supplicant, reason);

	nm_assert (c_list_is_empty (&supp_iface->supp_lst));
}

static void
_supp_iface_remove_all (NMSupplicantManager *self,
                        gboolean force_remove_from_supplicant,
                        const char *reason)
{
	NMSupplicantManagerPrivate *priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);
	NMSupplicantInterface *supp_iface;

	while ((supp_iface = c_list_first_entry (&priv->supp_lst_head, NMSupplicantInterface, supp_lst)))
		_supp_iface_remove_one (self, supp_iface, force_remove_from_supplicant, reason);
}

/*****************************************************************************/

static gboolean
_available_reset_cb (gpointer user_data)
{
	NMSupplicantManager *self = user_data;
	NMSupplicantManagerPrivate *priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);

	priv->available_reset_id = 0;
	nm_assert (priv->available == NM_TERNARY_FALSE);
	priv->available = NM_TERNARY_DEFAULT;
	g_signal_emit (self, signals[AVAILABLE_CHANGED], 0);
	return G_SOURCE_REMOVE;
}

/*****************************************************************************/

static void
name_owner_changed (NMSupplicantManager *self,
                    const char *name_owner,
                    gboolean first_time)
{
	NMSupplicantManagerPrivate *priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);
	NMTernary available;
	gboolean available_changed = FALSE;

	nm_assert (!priv->get_name_owner_cancellable);
	nm_assert (   !name_owner
	           || name_owner[0]);
	nm_assert (   (   first_time
	               && !priv->name_owner)
	           || (   !first_time
	               && (!!priv->name_owner) != (!!name_owner)));

	if (first_time) {
		_LOGD ("wpa_supplicant name owner %s%s%s (%srunning)",
		       NM_PRINT_FMT_QUOTE_STRING (name_owner),
		       name_owner ? "" : "not ");
	} else {
		_LOGD ("wpa_supplicant name owner \"%s\" %s (%srunning)",
		       name_owner ?: priv->name_owner->str,
		       name_owner ? "disappeared" : "appeared",
		       name_owner ? "" : "not ");
	}

	nm_ref_string_unref (priv->name_owner);
	priv->name_owner = nm_ref_string_new (name_owner);

	nm_clear_g_dbus_connection_signal (priv->dbus_connection,
	                                   &priv->interface_removed_id);

	if (name_owner) {
		if (nm_clear_g_source (&priv->poke_name_owner_timeout_id))
			_LOGT ("poke service \"%s\" completed with name owner change", NM_WPAS_DBUS_SERVICE);
		nm_clear_g_cancellable (&priv->poke_name_owner_cancellable);
	}

	nm_clear_g_cancellable (&priv->get_capabilities_cancellable);

	priv->capabilities = NM_SUPPL_CAP_MASK_NONE;
	if (priv->name_owner) {
		priv->get_capabilities_cancellable = g_cancellable_new ();
		nm_dbus_connection_call_get_all (priv->dbus_connection,
		                                 priv->name_owner->str,
		                                 NM_WPAS_DBUS_PATH,
		                                 NM_WPAS_DBUS_INTERFACE,
		                                 5000,
		                                 priv->get_capabilities_cancellable,
		                                 _dbus_get_capabilities_cb,
		                                 self);
		priv->interface_removed_id = g_dbus_connection_signal_subscribe (priv->dbus_connection,
		                                                                 priv->name_owner->str,
		                                                                 NM_WPAS_DBUS_INTERFACE,
		                                                                 "InterfaceRemoved",
		                                                                 NULL,
		                                                                 NULL,
		                                                                 G_DBUS_SIGNAL_FLAGS_NONE,
		                                                                 _dbus_interface_removed_cb,
		                                                                 self,
		                                                                 NULL);
	}

	/* if supplicant is running (has a name owner), we may use it.
	 * If this is the first time, and supplicant is not running, we
	 * may also use it (and assume that we probably could D-Bus activate
	 * it).
	 *
	 * Otherwise, somebody else stopped supplicant. It's no longer useable to
	 * us and we block auto starting it. The user has to start the service...
	 *
	 * Actually, below we reset the hard block after a short timeout. This
	 * causes the caller to notify that supplicant may now by around and
	 * retry to D-Bus activate it. */
	if (priv->name_owner)
		available = NM_TERNARY_TRUE;
	else if (first_time)
		available = NM_TERNARY_DEFAULT;
	else
		available = NM_TERNARY_FALSE;

	if (priv->available != available) {
		priv->available = available;
		_LOGD ("supplicant is now %savailable",
		         available == FALSE
		       ? "not "
		       : (  available == TRUE
		          ? ""
		          : "maybe "));
		available_changed = TRUE;

		nm_clear_g_source (&priv->available_reset_id);
		if (available == NM_TERNARY_FALSE) {
			/* reset the availability from a hard "no" to a "maybe" in a bit. */
			priv->available_reset_id = g_timeout_add_seconds (60,
			                                                  _available_reset_cb,
			                                                  self);
		}
	}

	_supp_iface_remove_all (self, TRUE, "name-owner changed");

	if (!priv->name_owner) {
		if (priv->poke_name_owner_timeout_id) {
			/* we are still poking for the service to start. Don't cancel
			 * the pending create requests just yet. */
		} else {
			gs_free_error GError *local_error = NULL;

			/* When we loose the name owner, we fail all pending creation requests. */
			nm_utils_error_set (&local_error,
			                    NM_UTILS_ERROR_UNKNOWN,
			                    "Name owner lost");
			_create_iface_proceed_all (self, local_error);
		}
	} else {
		/* We got a name-owner, but we don't do anything. Instead let
		 * _dbus_get_capabilities_cb() complete and kick of the create-iface
		 * handles.
		 *
		 * Note that before the first name-owner change, all create-iface
		 * requests fail right away. So we don't have to handle them here
		 * (by starting to poke the service). */
	}

	if (available_changed)
		g_signal_emit (self, signals[AVAILABLE_CHANGED], 0);
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
	gs_unref_object NMSupplicantManager *self = g_object_ref (user_data);
	NMSupplicantManagerPrivate *priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);
	const char *name_owner;

	if (!g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(sss)")))
		return;

	if (priv->get_name_owner_cancellable)
		return;

	g_variant_get (parameters,
	               "(&s&s&s)",
	               NULL,
	               NULL,
	               &name_owner);

	name_owner = nm_str_not_empty (name_owner);

	if (nm_streq0 (name_owner, nm_ref_string_get_str (priv->name_owner)))
		return;

	if (   name_owner
	    && priv->name_owner) {
		/* odd, we directly switch from one name owner to the next. Can't allow that.
		 * First clear the name owner before resetting. */
		name_owner_changed (self, NULL, FALSE);
	}
	name_owner_changed (user_data, name_owner, FALSE);
}

static void
get_name_owner_cb (const char *name_owner,
                   GError *error,
                   gpointer user_data)
{
	NMSupplicantManager *self = user_data;
	NMSupplicantManagerPrivate *priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);

	if (   !name_owner
	    && nm_utils_error_is_cancelled (error))
		return;

	self = user_data;
	priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);

	g_clear_object (&priv->get_name_owner_cancellable);

	name_owner_changed (self, nm_str_not_empty (name_owner), TRUE);
}

/*****************************************************************************/

static void
nm_supplicant_manager_init (NMSupplicantManager *self)
{
	NMSupplicantManagerPrivate *priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);

	nm_assert (priv->capabilities == NM_SUPPL_CAP_MASK_NONE);
	nm_assert (priv->available == NM_TERNARY_FALSE);

	priv->supp_ifaces = g_hash_table_new (nm_direct_hash, NULL);
	c_list_init (&priv->supp_lst_head);
	c_list_init (&priv->create_iface_lst_head);

	priv->dbus_connection = nm_g_object_ref (NM_MAIN_DBUS_CONNECTION_GET);

	if (!priv->dbus_connection) {
		_LOGI ("no D-Bus connection to talk to wpa_supplicant");
		return;
	}

	priv->name_owner_changed_id = nm_dbus_connection_signal_subscribe_name_owner_changed (priv->dbus_connection,
	                                                                                      NM_WPAS_DBUS_SERVICE,
	                                                                                      name_owner_changed_cb,
	                                                                                      self,
	                                                                                      NULL);
	priv->get_name_owner_cancellable = g_cancellable_new ();
	nm_dbus_connection_call_get_name_owner (priv->dbus_connection,
	                                        NM_WPAS_DBUS_SERVICE,
	                                        -1,
	                                        priv->get_name_owner_cancellable,
	                                        get_name_owner_cb,
	                                        self);
}

static void
dispose (GObject *object)
{
	NMSupplicantManager *self = (NMSupplicantManager *) object;
	NMSupplicantManagerPrivate *priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);

	_supp_iface_remove_all (self, TRUE, "NMSupplicantManager is disposing");

	nm_assert (c_list_is_empty (&priv->create_iface_lst_head));

	nm_clear_g_source (&priv->available_reset_id);

	priv->available = NM_TERNARY_FALSE;
	nm_clear_pointer (&priv->name_owner, nm_ref_string_unref);

	nm_clear_g_source (&priv->poke_name_owner_timeout_id);
	nm_clear_g_cancellable (&priv->poke_name_owner_cancellable);

	nm_clear_g_dbus_connection_signal (priv->dbus_connection,
	                                   &priv->interface_removed_id);
	nm_clear_g_dbus_connection_signal (priv->dbus_connection,
	                                   &priv->name_owner_changed_id);

	nm_clear_g_cancellable (&priv->get_name_owner_cancellable);
	nm_clear_g_cancellable (&priv->get_capabilities_cancellable);

	G_OBJECT_CLASS (nm_supplicant_manager_parent_class)->dispose (object);

	g_clear_object (&priv->dbus_connection);

	nm_clear_pointer (&priv->supp_ifaces, g_hash_table_destroy);
}

static void
nm_supplicant_manager_class_init (NMSupplicantManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->dispose = dispose;

	signals[AVAILABLE_CHANGED] =
	    g_signal_new (NM_SUPPLICANT_MANAGER_AVAILABLE_CHANGED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 0);
}
