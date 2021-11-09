/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2014 Red Hat, Inc.
 */

#ifndef __NM_CLIENT_H__
#define __NM_CLIENT_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-types.h"

G_BEGIN_DECLS

/**
 * NMClientInstanceFlags:
 * @NM_CLIENT_INSTANCE_FLAGS_NONE: special value to indicate no flags.
 * @NM_CLIENT_INSTANCE_FLAGS_NO_AUTO_FETCH_PERMISSIONS: by default, NMClient
 *   will fetch the permissions via "GetPermissions" and refetch them when
 *   "CheckPermissions" signal gets received. By setting this flag, this behavior
 *   can be disabled. You can toggle this flag to enable and disable automatic
 *   fetching of the permissions. Watch also nm_client_get_permissions_state()
 *   to know whether the permissions are up to date.
 *
 * Since: 1.24
 */
typedef enum { /*< flags >*/
               NM_CLIENT_INSTANCE_FLAGS_NONE                      = 0,
               NM_CLIENT_INSTANCE_FLAGS_NO_AUTO_FETCH_PERMISSIONS = 1,
} NMClientInstanceFlags;

#define NM_TYPE_CLIENT            (nm_client_get_type())
#define NM_CLIENT(obj)            (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_CLIENT, NMClient))
#define NM_CLIENT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_CLIENT, NMClientClass))
#define NM_IS_CLIENT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_CLIENT))
#define NM_IS_CLIENT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_CLIENT))
#define NM_CLIENT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_CLIENT, NMClientClass))

#define NM_CLIENT_VERSION         "version"
#define NM_CLIENT_STATE           "state"
#define NM_CLIENT_STARTUP         "startup"
#define NM_CLIENT_NM_RUNNING      "nm-running"
#define NM_CLIENT_DBUS_CONNECTION "dbus-connection"
#define NM_CLIENT_DBUS_NAME_OWNER "dbus-name-owner"
#define NM_CLIENT_INSTANCE_FLAGS  "instance-flags"

_NM_DEPRECATED_SYNC_WRITABLE_PROPERTY
#define NM_CLIENT_NETWORKING_ENABLED "networking-enabled"

_NM_DEPRECATED_SYNC_WRITABLE_PROPERTY
#define NM_CLIENT_WIRELESS_ENABLED "wireless-enabled"
_NM_DEPRECATED_SYNC_WRITABLE_PROPERTY
#define NM_CLIENT_WWAN_ENABLED "wwan-enabled"
_NM_DEPRECATED_SYNC_WRITABLE_PROPERTY
#define NM_CLIENT_WIMAX_ENABLED "wimax-enabled"

#define NM_CLIENT_WIRELESS_HARDWARE_ENABLED "wireless-hardware-enabled"
#define NM_CLIENT_WWAN_HARDWARE_ENABLED     "wwan-hardware-enabled"
#define NM_CLIENT_WIMAX_HARDWARE_ENABLED    "wimax-hardware-enabled"

#define NM_CLIENT_ACTIVE_CONNECTIONS           "active-connections"
#define NM_CLIENT_CONNECTIVITY                 "connectivity"
#define NM_CLIENT_CONNECTIVITY_CHECK_URI       "connectivity-check-uri"
#define NM_CLIENT_CONNECTIVITY_CHECK_AVAILABLE "connectivity-check-available"

_NM_DEPRECATED_SYNC_WRITABLE_PROPERTY
#define NM_CLIENT_CONNECTIVITY_CHECK_ENABLED "connectivity-check-enabled"

#define NM_CLIENT_PRIMARY_CONNECTION    "primary-connection"
#define NM_CLIENT_ACTIVATING_CONNECTION "activating-connection"
#define NM_CLIENT_DEVICES               "devices"
#define NM_CLIENT_ALL_DEVICES           "all-devices"
#define NM_CLIENT_CONNECTIONS           "connections"
#define NM_CLIENT_HOSTNAME              "hostname"
#define NM_CLIENT_CAN_MODIFY            "can-modify"
#define NM_CLIENT_METERED               "metered"
#define NM_CLIENT_DNS_MODE              "dns-mode"
#define NM_CLIENT_DNS_RC_MANAGER        "dns-rc-manager"
#define NM_CLIENT_DNS_CONFIGURATION     "dns-configuration"
#define NM_CLIENT_CHECKPOINTS           "checkpoints"
#define NM_CLIENT_CAPABILITIES          "capabilities"
#define NM_CLIENT_PERMISSIONS_STATE     "permissions-state"

#define NM_CLIENT_DEVICE_ADDED              "device-added"
#define NM_CLIENT_DEVICE_REMOVED            "device-removed"
#define NM_CLIENT_ANY_DEVICE_ADDED          "any-device-added"
#define NM_CLIENT_ANY_DEVICE_REMOVED        "any-device-removed"
#define NM_CLIENT_PERMISSION_CHANGED        "permission-changed"
#define NM_CLIENT_CONNECTION_ADDED          "connection-added"
#define NM_CLIENT_CONNECTION_REMOVED        "connection-removed"
#define NM_CLIENT_ACTIVE_CONNECTION_ADDED   "active-connection-added"
#define NM_CLIENT_ACTIVE_CONNECTION_REMOVED "active-connection-removed"

/**
 * NMClientError:
 * @NM_CLIENT_ERROR_FAILED: unknown or unclassified error
 * @NM_CLIENT_ERROR_MANAGER_NOT_RUNNING: an operation that requires NetworkManager
 *   failed because NetworkManager is not running
 * @NM_CLIENT_ERROR_OBJECT_CREATION_FAILED: NetworkManager claimed that an
 *   operation succeeded, but the object that was allegedly created (eg,
 *   #NMRemoteConnection, #NMActiveConnection) was apparently destroyed before
 *   #NMClient could create a representation of it.
 *
 * Describes errors that may result from operations involving a #NMClient.
 *
 * D-Bus operations may also return errors from other domains, including
 * #NMManagerError, #NMSettingsError, #NMAgentManagerError, and #NMConnectionError.
 **/
typedef enum {
    NM_CLIENT_ERROR_FAILED = 0,
    NM_CLIENT_ERROR_MANAGER_NOT_RUNNING,
    NM_CLIENT_ERROR_OBJECT_CREATION_FAILED,
} NMClientError;

#define NM_CLIENT_ERROR nm_client_error_quark()
GQuark nm_client_error_quark(void);

/* DNS stuff */

typedef struct NMDnsEntry NMDnsEntry;

NM_AVAILABLE_IN_1_6
GType nm_dns_entry_get_type(void);
NM_AVAILABLE_IN_1_6
void nm_dns_entry_unref(NMDnsEntry *entry);
NM_AVAILABLE_IN_1_6
const char *nm_dns_entry_get_interface(NMDnsEntry *entry);
NM_AVAILABLE_IN_1_6
const char *const *nm_dns_entry_get_nameservers(NMDnsEntry *entry);
NM_AVAILABLE_IN_1_6
const char *const *nm_dns_entry_get_domains(NMDnsEntry *entry);
NM_AVAILABLE_IN_1_6
int nm_dns_entry_get_priority(NMDnsEntry *entry);
NM_AVAILABLE_IN_1_6
gboolean nm_dns_entry_get_vpn(NMDnsEntry *entry);

/**
 * NMClient:
 *
 * NMClient contains a cache of the objects of NetworkManager's D-Bus API.
 * It uses #GMainContext and #GDBusConnection for that and registers to
 * D-Bus signals. That means, when iterating the associated #GMainContext,
 * D-Bus signals gets processed and the #NMClient instance updates and
 * emits #GObject signals.
 */
typedef struct _NMClientClass NMClientClass;

GType nm_client_get_type(void);

NMClient *nm_client_new(GCancellable *cancellable, GError **error);

void
nm_client_new_async(GCancellable *cancellable, GAsyncReadyCallback callback, gpointer user_data);
NMClient *nm_client_new_finish(GAsyncResult *result, GError **error);

NM_AVAILABLE_IN_1_24
NMClientInstanceFlags nm_client_get_instance_flags(NMClient *self);

NM_AVAILABLE_IN_1_22
GDBusConnection *nm_client_get_dbus_connection(NMClient *client);

NM_AVAILABLE_IN_1_22
GMainContext *nm_client_get_main_context(NMClient *self);

NM_AVAILABLE_IN_1_22
GObject *nm_client_get_context_busy_watcher(NMClient *self);

NM_AVAILABLE_IN_1_22
const char *nm_client_get_dbus_name_owner(NMClient *client);

const char *nm_client_get_version(NMClient *client);
NMState     nm_client_get_state(NMClient *client);
gboolean    nm_client_get_startup(NMClient *client);
gboolean    nm_client_get_nm_running(NMClient *client);

NMObject *nm_client_get_object_by_path(NMClient *client, const char *dbus_path);

NM_AVAILABLE_IN_1_22
NMMetered nm_client_get_metered(NMClient *client);

gboolean nm_client_networking_get_enabled(NMClient *client);

NM_AVAILABLE_IN_1_24
const guint32 *nm_client_get_capabilities(NMClient *client, gsize *length);

_NM_DEPRECATED_SYNC_METHOD
gboolean nm_client_networking_set_enabled(NMClient *client, gboolean enabled, GError **error);

gboolean nm_client_wireless_get_enabled(NMClient *client);

_NM_DEPRECATED_SYNC_METHOD
void nm_client_wireless_set_enabled(NMClient *client, gboolean enabled);

gboolean nm_client_wireless_hardware_get_enabled(NMClient *client);

gboolean nm_client_wwan_get_enabled(NMClient *client);

_NM_DEPRECATED_SYNC_METHOD
void nm_client_wwan_set_enabled(NMClient *client, gboolean enabled);

gboolean nm_client_wwan_hardware_get_enabled(NMClient *client);

NM_DEPRECATED_IN_1_22
gboolean nm_client_wimax_get_enabled(NMClient *client);

NM_DEPRECATED_IN_1_22
_NM_DEPRECATED_SYNC_METHOD
void nm_client_wimax_set_enabled(NMClient *client, gboolean enabled);

NM_DEPRECATED_IN_1_22
gboolean nm_client_wimax_hardware_get_enabled(NMClient *client);

NM_AVAILABLE_IN_1_10
gboolean nm_client_connectivity_check_get_available(NMClient *client);

NM_AVAILABLE_IN_1_10
gboolean nm_client_connectivity_check_get_enabled(NMClient *client);

NM_AVAILABLE_IN_1_10
_NM_DEPRECATED_SYNC_METHOD
void nm_client_connectivity_check_set_enabled(NMClient *client, gboolean enabled);

NM_AVAILABLE_IN_1_20
const char *nm_client_connectivity_check_get_uri(NMClient *client);

_NM_DEPRECATED_SYNC_METHOD
gboolean nm_client_get_logging(NMClient *client, char **level, char **domains, GError **error);

_NM_DEPRECATED_SYNC_METHOD
gboolean
nm_client_set_logging(NMClient *client, const char *level, const char *domains, GError **error);

NMClientPermissionResult nm_client_get_permission_result(NMClient          *client,
                                                         NMClientPermission permission);

NM_AVAILABLE_IN_1_24
NMTernary nm_client_get_permissions_state(NMClient *self);

NMConnectivityState nm_client_get_connectivity(NMClient *client);

_NM_DEPRECATED_SYNC_METHOD
NM_DEPRECATED_IN_1_22
NMConnectivityState
nm_client_check_connectivity(NMClient *client, GCancellable *cancellable, GError **error);

void nm_client_check_connectivity_async(NMClient           *client,
                                        GCancellable       *cancellable,
                                        GAsyncReadyCallback callback,
                                        gpointer            user_data);
NMConnectivityState
nm_client_check_connectivity_finish(NMClient *client, GAsyncResult *result, GError **error);

_NM_DEPRECATED_SYNC_METHOD
gboolean nm_client_save_hostname(NMClient     *client,
                                 const char   *hostname,
                                 GCancellable *cancellable,
                                 GError      **error);

void     nm_client_save_hostname_async(NMClient           *client,
                                       const char         *hostname,
                                       GCancellable       *cancellable,
                                       GAsyncReadyCallback callback,
                                       gpointer            user_data);
gboolean nm_client_save_hostname_finish(NMClient *client, GAsyncResult *result, GError **error);

/* Devices */

const GPtrArray *nm_client_get_devices(NMClient *client);
NM_AVAILABLE_IN_1_2
const GPtrArray *nm_client_get_all_devices(NMClient *client);
NMDevice        *nm_client_get_device_by_path(NMClient *client, const char *object_path);
NMDevice        *nm_client_get_device_by_iface(NMClient *client, const char *iface);

/* Active Connections */

const GPtrArray *nm_client_get_active_connections(NMClient *client);

NMActiveConnection *nm_client_get_primary_connection(NMClient *client);
NMActiveConnection *nm_client_get_activating_connection(NMClient *client);

void nm_client_activate_connection_async(NMClient           *client,
                                         NMConnection       *connection,
                                         NMDevice           *device,
                                         const char         *specific_object,
                                         GCancellable       *cancellable,
                                         GAsyncReadyCallback callback,
                                         gpointer            user_data);
NMActiveConnection *
nm_client_activate_connection_finish(NMClient *client, GAsyncResult *result, GError **error);

void                nm_client_add_and_activate_connection_async(NMClient           *client,
                                                                NMConnection       *partial,
                                                                NMDevice           *device,
                                                                const char         *specific_object,
                                                                GCancellable       *cancellable,
                                                                GAsyncReadyCallback callback,
                                                                gpointer            user_data);
NMActiveConnection *nm_client_add_and_activate_connection_finish(NMClient     *client,
                                                                 GAsyncResult *result,
                                                                 GError      **error);

NM_AVAILABLE_IN_1_16
void nm_client_add_and_activate_connection2(NMClient           *client,
                                            NMConnection       *partial,
                                            NMDevice           *device,
                                            const char         *specific_object,
                                            GVariant           *options,
                                            GCancellable       *cancellable,
                                            GAsyncReadyCallback callback,
                                            gpointer            user_data);
NM_AVAILABLE_IN_1_16
NMActiveConnection *nm_client_add_and_activate_connection2_finish(NMClient     *client,
                                                                  GAsyncResult *result,
                                                                  GVariant    **out_result,
                                                                  GError      **error);

_NM_DEPRECATED_SYNC_METHOD
gboolean nm_client_deactivate_connection(NMClient           *client,
                                         NMActiveConnection *active,
                                         GCancellable       *cancellable,
                                         GError            **error);

void nm_client_deactivate_connection_async(NMClient           *client,
                                           NMActiveConnection *active,
                                           GCancellable       *cancellable,
                                           GAsyncReadyCallback callback,
                                           gpointer            user_data);
gboolean
nm_client_deactivate_connection_finish(NMClient *client, GAsyncResult *result, GError **error);

/* Connections */

const GPtrArray *nm_client_get_connections(NMClient *client);

NMRemoteConnection *nm_client_get_connection_by_id(NMClient *client, const char *id);
NMRemoteConnection *nm_client_get_connection_by_path(NMClient *client, const char *path);
NMRemoteConnection *nm_client_get_connection_by_uuid(NMClient *client, const char *uuid);

void nm_client_add_connection_async(NMClient           *client,
                                    NMConnection       *connection,
                                    gboolean            save_to_disk,
                                    GCancellable       *cancellable,
                                    GAsyncReadyCallback callback,
                                    gpointer            user_data);
NMRemoteConnection *
nm_client_add_connection_finish(NMClient *client, GAsyncResult *result, GError **error);

NM_AVAILABLE_IN_1_20
void nm_client_add_connection2(NMClient                     *client,
                               GVariant                     *settings,
                               NMSettingsAddConnection2Flags flags,
                               GVariant                     *args,
                               gboolean                      ignore_out_result,
                               GCancellable                 *cancellable,
                               GAsyncReadyCallback           callback,
                               gpointer                      user_data);

NM_AVAILABLE_IN_1_20
NMRemoteConnection *nm_client_add_connection2_finish(NMClient     *client,
                                                     GAsyncResult *result,
                                                     GVariant    **out_result,
                                                     GError      **error);

_NM_DEPRECATED_SYNC_METHOD
gboolean nm_client_load_connections(NMClient     *client,
                                    char        **filenames,
                                    char       ***failures,
                                    GCancellable *cancellable,
                                    GError      **error);

void     nm_client_load_connections_async(NMClient           *client,
                                          char              **filenames,
                                          GCancellable       *cancellable,
                                          GAsyncReadyCallback callback,
                                          gpointer            user_data);
gboolean nm_client_load_connections_finish(NMClient     *client,
                                           char       ***failures,
                                           GAsyncResult *result,
                                           GError      **error);

_NM_DEPRECATED_SYNC_METHOD
gboolean nm_client_reload_connections(NMClient *client, GCancellable *cancellable, GError **error);

void nm_client_reload_connections_async(NMClient           *client,
                                        GCancellable       *cancellable,
                                        GAsyncReadyCallback callback,
                                        gpointer            user_data);
gboolean
nm_client_reload_connections_finish(NMClient *client, GAsyncResult *result, GError **error);

NM_AVAILABLE_IN_1_6
const char *nm_client_get_dns_mode(NMClient *client);
NM_AVAILABLE_IN_1_6
const char *nm_client_get_dns_rc_manager(NMClient *client);
NM_AVAILABLE_IN_1_6
const GPtrArray *nm_client_get_dns_configuration(NMClient *client);

NM_AVAILABLE_IN_1_12
const GPtrArray *nm_client_get_checkpoints(NMClient *client);

NM_AVAILABLE_IN_1_12
void nm_client_checkpoint_create(NMClient               *client,
                                 const GPtrArray        *devices,
                                 guint32                 rollback_timeout,
                                 NMCheckpointCreateFlags flags,
                                 GCancellable           *cancellable,
                                 GAsyncReadyCallback     callback,
                                 gpointer                user_data);
NM_AVAILABLE_IN_1_12
NMCheckpoint *
nm_client_checkpoint_create_finish(NMClient *client, GAsyncResult *result, GError **error);

NM_AVAILABLE_IN_1_12
void nm_client_checkpoint_destroy(NMClient           *client,
                                  const char         *checkpoint_path,
                                  GCancellable       *cancellable,
                                  GAsyncReadyCallback callback,
                                  gpointer            user_data);
NM_AVAILABLE_IN_1_12
gboolean
nm_client_checkpoint_destroy_finish(NMClient *client, GAsyncResult *result, GError **error);

NM_AVAILABLE_IN_1_12
void nm_client_checkpoint_rollback(NMClient           *client,
                                   const char         *checkpoint_path,
                                   GCancellable       *cancellable,
                                   GAsyncReadyCallback callback,
                                   gpointer            user_data);
NM_AVAILABLE_IN_1_12
GHashTable *
nm_client_checkpoint_rollback_finish(NMClient *client, GAsyncResult *result, GError **error);

NM_AVAILABLE_IN_1_12
void nm_client_checkpoint_adjust_rollback_timeout(NMClient           *client,
                                                  const char         *checkpoint_path,
                                                  guint32             add_timeout,
                                                  GCancellable       *cancellable,
                                                  GAsyncReadyCallback callback,
                                                  gpointer            user_data);

NM_AVAILABLE_IN_1_12
gboolean nm_client_checkpoint_adjust_rollback_timeout_finish(NMClient     *client,
                                                             GAsyncResult *result,
                                                             GError      **error);

NM_AVAILABLE_IN_1_22
void nm_client_reload(NMClient            *client,
                      NMManagerReloadFlags flags,
                      GCancellable        *cancellable,
                      GAsyncReadyCallback  callback,
                      gpointer             user_data);
NM_AVAILABLE_IN_1_22
gboolean nm_client_reload_finish(NMClient *client, GAsyncResult *result, GError **error);

/*****************************************************************************/

NM_AVAILABLE_IN_1_24
void nm_client_dbus_call(NMClient           *client,
                         const char         *object_path,
                         const char         *interface_name,
                         const char         *method_name,
                         GVariant           *parameters,
                         const GVariantType *reply_type,
                         int                 timeout_msec,
                         GCancellable       *cancellable,
                         GAsyncReadyCallback callback,
                         gpointer            user_data);

NM_AVAILABLE_IN_1_24
GVariant *nm_client_dbus_call_finish(NMClient *client, GAsyncResult *result, GError **error);

NM_AVAILABLE_IN_1_24
void nm_client_dbus_set_property(NMClient           *client,
                                 const char         *object_path,
                                 const char         *interface_name,
                                 const char         *property_name,
                                 GVariant           *value,
                                 int                 timeout_msec,
                                 GCancellable       *cancellable,
                                 GAsyncReadyCallback callback,
                                 gpointer            user_data);

NM_AVAILABLE_IN_1_24
gboolean nm_client_dbus_set_property_finish(NMClient *client, GAsyncResult *result, GError **error);

/*****************************************************************************/

NM_AVAILABLE_IN_1_30
void nm_utils_print(int output_mode, const char *msg);

G_END_DECLS

#endif /* __NM_CLIENT_H__ */
