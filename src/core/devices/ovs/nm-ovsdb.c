/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-ovsdb.h"

#include <gmodule.h>
#include <gio/gunixsocketaddress.h>

#include "libnm-glib-aux/nm-jansson.h"
#include "libnm-glib-aux/nm-str-buf.h"
#include "libnm-glib-aux/nm-io-utils.h"
#include "nm-core-utils.h"
#include "libnm-core-intern/nm-core-internal.h"
#include "devices/nm-device.h"
#include "nm-manager.h"
#include "nm-setting-ovs-external-ids.h"
#include "nm-setting-ovs-other-config.h"
#include "nm-priv-helper-call.h"
#include "libnm-platform/nm-platform.h"

/*****************************************************************************/

#define OVSDB_MAX_FAILURES 3

#define OTHER_CONFIG_HWADDR "hwaddr"

/*****************************************************************************/

#if JANSSON_VERSION_HEX < 0x020400
#warning "requires at least libjansson 2.4"
#endif

typedef enum {
    STRDICT_TYPE_EXTERNAL_IDS,
    STRDICT_TYPE_OTHER_CONFIG,
} StrdictType;

typedef struct {
    char      *port_uuid;
    char      *name;
    char      *connection_uuid;
    GPtrArray *interfaces; /* interface uuids */
    GArray    *external_ids;
    GArray    *other_config;
} OpenvswitchPort;

typedef struct {
    char      *bridge_uuid;
    char      *name;
    char      *connection_uuid;
    GPtrArray *ports; /* port uuids */
    GArray    *external_ids;
    GArray    *other_config;
} OpenvswitchBridge;

typedef struct {
    char   *interface_uuid;
    char   *name;
    char   *type;
    char   *connection_uuid;
    GArray *external_ids;
    GArray *other_config;
} OpenvswitchInterface;

/*****************************************************************************/

typedef void (*OvsdbMethodCallback)(NMOvsdb *self,
                                    json_t  *response,
                                    GError  *error,
                                    gpointer user_data);

typedef enum {
    OVSDB_MONITOR,
    OVSDB_ADD_INTERFACE,
    OVSDB_DEL_INTERFACE,
    OVSDB_SET_INTERFACE_MTU,
    OVSDB_SET_REAPPLY,
} OvsdbCommand;

#define CALL_ID_UNSPEC G_MAXUINT64

typedef union {
    struct {
    } monitor;
    struct {
        NMConnection *bridge;
        NMConnection *port;
        NMConnection *interface;
        NMDevice     *bridge_device;
        NMDevice     *interface_device;
    } add_interface;
    struct {
        char *ifname;
    } del_interface;
    struct {
        char   *ifname;
        guint32 mtu;
    } set_interface_mtu;
    struct {
        NMDeviceType device_type;
        char        *ifname;
        char        *connection_uuid;
        GHashTable  *external_ids_old;
        GHashTable  *external_ids_new;
        GHashTable  *other_config_old;
        GHashTable  *other_config_new;
    } set_reapply;
} OvsdbMethodPayload;

typedef struct {
    NMOvsdb            *self;
    CList               calls_lst;
    guint64             call_id;
    OvsdbCommand        command;
    OvsdbMethodCallback callback;
    gpointer            user_data;
    OvsdbMethodPayload  payload;
    GObject            *shutdown_wait_obj;
} OvsdbMethodCall;

/*****************************************************************************/

enum {
    DEVICE_ADDED,
    DEVICE_REMOVED,
    INTERFACE_FAILED,
    READY,
    LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = {0};

typedef struct {
    NMPlatform   *platform;
    int           conn_fd;
    GSource      *conn_fd_in_source;
    GSource      *conn_fd_out_source;
    GCancellable *conn_cancellable;

    NMStrBuf input_buf;
    NMStrBuf output_buf;

    GSource *input_timeout_source;

    guint64 call_id_counter;

    CList calls_lst_head;

    GHashTable *interfaces; /* interface uuid => OpenvswitchInterface */
    GHashTable *ports;      /* port uuid => OpenvswitchPort */
    GHashTable *bridges;    /* bridge uuid => OpenvswitchBridge */
    char       *db_uuid;
    guint       num_failures;
    bool        ready : 1;
    struct {
        GPtrArray *interfaces;      /* Interface names we are waiting to go away */
        GSource   *timeout_source;  /* After all deletions complete, wait this
                                    * timeout for interfaces to disappear */
        gulong     link_changed_id; /* Platform link-changed signal handle */
        guint      num_pending_del; /* Number of ovsdb deletions pending */
    } cleanup;
} NMOvsdbPrivate;

struct _NMOvsdb {
    GObject        parent;
    NMOvsdbPrivate _priv;
};

struct _NMOvsdbClass {
    GObjectClass parent;
};

G_DEFINE_TYPE(NMOvsdb, nm_ovsdb, G_TYPE_OBJECT)

#define NM_OVSDB_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMOvsdb, NM_IS_OVSDB)

NM_DEFINE_SINGLETON_GETTER(NMOvsdb, nm_ovsdb_get, NM_TYPE_OVSDB);

/*****************************************************************************/

static void     ovsdb_try_connect(NMOvsdb *self);
static void     ovsdb_disconnect(NMOvsdb *self, gboolean retry, gboolean is_disposing);
static void     ovsdb_read(NMOvsdb *self);
static void     ovsdb_write_try(NMOvsdb *self);
static gboolean ovsdb_write_cb(int fd, GIOCondition condition, gpointer user_data);
static void     ovsdb_next_command(NMOvsdb *self);
static void     cleanup_check_ready(NMOvsdb *self);

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_DEVICE
#define _NMLOG(level, ...) __NMLOG_DEFAULT(level, _NMLOG_DOMAIN, "ovsdb", __VA_ARGS__)

#define _NMLOG_call(level, call, ...)                                                  \
    _NMLOG((level),                                                                    \
           "call[" NM_HASH_OBFUSCATE_PTR_FMT "]: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
           NM_HASH_OBFUSCATE_PTR((call)) _NM_UTILS_MACRO_REST(__VA_ARGS__))

#define _LOGT_call(call, ...) _NMLOG_call(LOGL_TRACE, (call), __VA_ARGS__)

/*****************************************************************************/

#define OVSDB_METHOD_PAYLOAD_MONITOR() \
    (&((const OvsdbMethodPayload){     \
        .monitor = {},                 \
    }))

#define OVSDB_METHOD_PAYLOAD_ADD_INTERFACE(xbridge,           \
                                           xport,             \
                                           xinterface,        \
                                           xbridge_device,    \
                                           xinterface_device) \
    (&((const OvsdbMethodPayload){                            \
        .add_interface =                                      \
            {                                                 \
                .bridge           = (xbridge),                \
                .port             = (xport),                  \
                .interface        = (xinterface),             \
                .bridge_device    = (xbridge_device),         \
                .interface_device = (xinterface_device),      \
            },                                                \
    }))

#define OVSDB_METHOD_PAYLOAD_DEL_INTERFACE(xifname)               \
    (&((const OvsdbMethodPayload){                                \
        .del_interface =                                          \
            {                                                     \
                .ifname = (char *) NM_CONSTCAST(char, (xifname)), \
            },                                                    \
    }))

#define OVSDB_METHOD_PAYLOAD_SET_INTERFACE_MTU(xifname, xmtu)     \
    (&((const OvsdbMethodPayload){                                \
        .set_interface_mtu =                                      \
            {                                                     \
                .ifname = (char *) NM_CONSTCAST(char, (xifname)), \
                .mtu    = (xmtu),                                 \
            },                                                    \
    }))

#define OVSDB_METHOD_PAYLOAD_SET_REAPPLY(xdevice_type,                               \
                                         xifname,                                    \
                                         xconnection_uuid,                           \
                                         xexternal_ids_old,                          \
                                         xexternal_ids_new,                          \
                                         xother_config_old,                          \
                                         xother_config_new)                          \
    (&((const OvsdbMethodPayload){                                                   \
        .set_reapply =                                                               \
            {                                                                        \
                .device_type      = xdevice_type,                                    \
                .ifname           = (char *) NM_CONSTCAST(char, (xifname)),          \
                .connection_uuid  = (char *) NM_CONSTCAST(char, (xconnection_uuid)), \
                .external_ids_old = (xexternal_ids_old),                             \
                .external_ids_new = (xexternal_ids_new),                             \
                .other_config_old = (xother_config_old),                             \
                .other_config_new = (xother_config_new),                             \
            },                                                                       \
    }))

/*****************************************************************************/

static NM_UTILS_LOOKUP_STR_DEFINE(_device_type_to_table,
                                  NMDeviceType,
                                  NM_UTILS_LOOKUP_DEFAULT_NM_ASSERT(NULL),
                                  NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_TYPE_OVS_BRIDGE, "Bridge"),
                                  NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_TYPE_OVS_PORT, "Port"),
                                  NM_UTILS_LOOKUP_STR_ITEM(NM_DEVICE_TYPE_OVS_INTERFACE,
                                                           "Interface"),
                                  NM_UTILS_LOOKUP_ITEM_IGNORE_OTHER(), );

/*****************************************************************************/

static void
_call_complete(OvsdbMethodCall *call, json_t *response, GError *error)
{
    g_clear_object(&call->shutdown_wait_obj);

    if (response) {
        gs_free char *str = NULL;

        str = json_dumps(response, 0);
        if (error)
            _LOGT_call(call, "completed: %s ; error: %s", str, error->message);
        else
            _LOGT_call(call, "completed: %s", str);
    } else {
        nm_assert(error);
        _LOGT_call(call, "completed: error: %s", error->message);
    }

    c_list_unlink_stale(&call->calls_lst);

    if (call->callback)
        call->callback(call->self, response, error, call->user_data);

    switch (call->command) {
    case OVSDB_MONITOR:
        break;
    case OVSDB_ADD_INTERFACE:
        g_clear_object(&call->payload.add_interface.bridge);
        g_clear_object(&call->payload.add_interface.port);
        g_clear_object(&call->payload.add_interface.interface);
        g_clear_object(&call->payload.add_interface.bridge_device);
        g_clear_object(&call->payload.add_interface.interface_device);
        break;
    case OVSDB_DEL_INTERFACE:
        nm_clear_g_free(&call->payload.del_interface.ifname);
        break;
    case OVSDB_SET_INTERFACE_MTU:
        nm_clear_g_free(&call->payload.set_interface_mtu.ifname);
        break;
    case OVSDB_SET_REAPPLY:
        nm_clear_g_free(&call->payload.set_reapply.ifname);
        nm_clear_g_free(&call->payload.set_reapply.connection_uuid);
        nm_clear_pointer(&call->payload.set_reapply.external_ids_old, g_hash_table_destroy);
        nm_clear_pointer(&call->payload.set_reapply.external_ids_new, g_hash_table_destroy);
        nm_clear_pointer(&call->payload.set_reapply.other_config_old, g_hash_table_destroy);
        nm_clear_pointer(&call->payload.set_reapply.other_config_new, g_hash_table_destroy);
        break;
    }

    nm_g_slice_free(call);
}

/*****************************************************************************/

static void
_free_bridge(OpenvswitchBridge *ovs_bridge)
{
    g_free(ovs_bridge->bridge_uuid);
    g_free(ovs_bridge->name);
    g_free(ovs_bridge->connection_uuid);
    g_ptr_array_free(ovs_bridge->ports, TRUE);
    nm_g_array_unref(ovs_bridge->external_ids);
    nm_g_array_unref(ovs_bridge->other_config);
    nm_g_slice_free(ovs_bridge);
}

static void
_free_port(OpenvswitchPort *ovs_port)
{
    g_free(ovs_port->port_uuid);
    g_free(ovs_port->name);
    g_free(ovs_port->connection_uuid);
    g_ptr_array_free(ovs_port->interfaces, TRUE);
    nm_g_array_unref(ovs_port->external_ids);
    nm_g_array_unref(ovs_port->other_config);
    nm_g_slice_free(ovs_port);
}

static void
_free_interface(OpenvswitchInterface *ovs_interface)
{
    g_free(ovs_interface->interface_uuid);
    g_free(ovs_interface->name);
    g_free(ovs_interface->connection_uuid);
    g_free(ovs_interface->type);
    nm_g_array_unref(ovs_interface->external_ids);
    nm_g_array_unref(ovs_interface->other_config);
    nm_g_slice_free(ovs_interface);
}

/*****************************************************************************/

static void
_signal_emit_device_added(NMOvsdb     *self,
                          const char  *name,
                          NMDeviceType device_type,
                          const char  *device_subtype)
{
    g_signal_emit(self, signals[DEVICE_ADDED], 0, name, (guint) device_type, device_subtype);
}

static void
_signal_emit_device_removed(NMOvsdb     *self,
                            const char  *name,
                            NMDeviceType device_type,
                            const char  *device_subtype)
{
    g_signal_emit(self, signals[DEVICE_REMOVED], 0, name, (guint) device_type, device_subtype);
}

static void
_signal_emit_interface_failed(NMOvsdb    *self,
                              const char *name,
                              const char *connection_uuid,
                              const char *error)
{
    g_signal_emit(self, signals[INTERFACE_FAILED], 0, name, connection_uuid, error);
}

/*****************************************************************************/

/**
 * ovsdb_call_method:
 *
 * Queues the ovsdb command. Eventually fires the command right away if
 * there's no command pending completion.
 */
static void
ovsdb_call_method(NMOvsdb                  *self,
                  OvsdbMethodCallback       callback,
                  gpointer                  user_data,
                  gboolean                  add_first,
                  OvsdbCommand              command,
                  const OvsdbMethodPayload *payload)
{
    NMOvsdbPrivate  *priv = NM_OVSDB_GET_PRIVATE(self);
    OvsdbMethodCall *call;

    /* FIXME(shutdown): this function should accept a cancellable to
     * interrupt the operation. */

    /* Ensure we're not unsynchronized before we queue the method call. */
    ovsdb_try_connect(self);

    call  = g_slice_new(OvsdbMethodCall);
    *call = (OvsdbMethodCall){
        .self              = self,
        .call_id           = CALL_ID_UNSPEC,
        .command           = command,
        .callback          = callback,
        .user_data         = user_data,
        .shutdown_wait_obj = g_object_new(G_TYPE_OBJECT, NULL),
    };
    nm_shutdown_wait_obj_register_object(call->shutdown_wait_obj, "ovsdb-call");

    if (add_first)
        c_list_link_front(&priv->calls_lst_head, &call->calls_lst);
    else
        c_list_link_tail(&priv->calls_lst_head, &call->calls_lst);

    /* Migrate the arguments from @payload to @call->payload. Technically,
     * this is not a plain copy, because
     * - call->payload is not initialized (thus no need to free the previous data).
     * - payload does not own the data. It is merely initialized using the
     *   OVSDB_METHOD_PAYLOAD_*() macros. */
    switch (command) {
    case OVSDB_MONITOR:
        _LOGT_call(call, "new: monitor");
        break;
    case OVSDB_ADD_INTERFACE:
        /* FIXME(applied-connection-immutable): we should not modify the applied
         *   connection, consequently there is no need to clone the connections. */
        call->payload.add_interface.bridge =
            nm_simple_connection_new_clone(payload->add_interface.bridge);
        call->payload.add_interface.port =
            nm_simple_connection_new_clone(payload->add_interface.port);
        call->payload.add_interface.interface =
            nm_simple_connection_new_clone(payload->add_interface.interface);
        call->payload.add_interface.bridge_device =
            g_object_ref(payload->add_interface.bridge_device);
        call->payload.add_interface.interface_device =
            g_object_ref(payload->add_interface.interface_device);
        _LOGT_call(call,
                   "new: add-interface bridge=%s port=%s interface=%s",
                   nm_connection_get_interface_name(call->payload.add_interface.bridge),
                   nm_connection_get_interface_name(call->payload.add_interface.port),
                   nm_connection_get_interface_name(call->payload.add_interface.interface));
        break;
    case OVSDB_DEL_INTERFACE:
        call->payload.del_interface.ifname = g_strdup(payload->del_interface.ifname);
        _LOGT_call(call, "new: del-interface interface=%s", call->payload.del_interface.ifname);
        break;
    case OVSDB_SET_INTERFACE_MTU:
        call->payload.set_interface_mtu.ifname = g_strdup(payload->set_interface_mtu.ifname);
        call->payload.set_interface_mtu.mtu    = payload->set_interface_mtu.mtu;
        _LOGT_call(call,
                   "new: set-interface-mtu interface=%s mtu=%u",
                   call->payload.set_interface_mtu.ifname,
                   call->payload.set_interface_mtu.mtu);
        break;
    case OVSDB_SET_REAPPLY:
        call->payload.set_reapply.device_type     = payload->set_reapply.device_type;
        call->payload.set_reapply.ifname          = g_strdup(payload->set_reapply.ifname);
        call->payload.set_reapply.connection_uuid = g_strdup(payload->set_reapply.connection_uuid);
        call->payload.set_reapply.external_ids_old =
            nm_g_hash_table_ref(payload->set_reapply.external_ids_old);
        call->payload.set_reapply.external_ids_new =
            nm_g_hash_table_ref(payload->set_reapply.external_ids_new);
        call->payload.set_reapply.other_config_old =
            nm_g_hash_table_ref(payload->set_reapply.other_config_old);
        call->payload.set_reapply.other_config_new =
            nm_g_hash_table_ref(payload->set_reapply.other_config_new);
        _LOGT_call(call,
                   "new: set external-ids/other-config con-uuid=%s, interface=%s",
                   call->payload.set_reapply.connection_uuid,
                   call->payload.set_reapply.ifname);
        break;
    }

    ovsdb_next_command(self);
}

/*****************************************************************************/

/* Create and process the JSON-RPC messages from ovsdb. */

/**
 * _expect_ovs_bridges:
 *
 * Return a command that will fail the transaction if the actual set of
 * bridges doesn't match @bridges. This is a way of detecting race conditions
 * with other ovsdb clients that might be adding or removing bridges
 * at the same time.
 */
static void
_expect_ovs_bridges(json_t *params, const char *db_uuid, json_t *bridges)
{
    json_array_append_new(
        params,
        json_pack("{s:s, s:s, s:i, s:[s], s:s, s:[{s:[s, O]}], s:[[s, s, [s, s]]]}",
                  "op",
                  "wait",
                  "table",
                  "Open_vSwitch",
                  "timeout",
                  0,
                  "columns",
                  "bridges",
                  "until",
                  "==",
                  "rows",
                  "bridges",
                  "set",
                  bridges,
                  "where",
                  "_uuid",
                  "==",
                  "uuid",
                  db_uuid));
}

/**
 * _set_ovs_bridges:
 *
 * Return a command that will update the list of bridges in @db_uuid
 * database to @new_bridges.
 */
static void
_set_ovs_bridges(json_t *params, const char *db_uuid, json_t *new_bridges)
{
    json_array_append_new(params,
                          json_pack("{s:s, s:s, s:{s:[s, O]}, s:[[s, s, [s, s]]]}",
                                    "op",
                                    "update",
                                    "table",
                                    "Open_vSwitch",
                                    "row",
                                    "bridges",
                                    "set",
                                    new_bridges,
                                    "where",
                                    "_uuid",
                                    "==",
                                    "uuid",
                                    db_uuid));
}

/**
 * _expect_bridge_ports:
 *
 * Return a command that will fail the transaction if the actual set of
 * ports in bridge @ifname doesn't match @ports. This is a way of detecting
 * race conditions with other ovsdb clients that might be adding or removing
 * bridge ports at the same time.
 */
static void
_expect_bridge_ports(json_t *params, const char *ifname, json_t *ports)
{
    json_array_append_new(params,
                          json_pack("{s:s, s:s, s:i, s:[s], s:s, s:[{s:[s, O]}], s:[[s, s, s]]}",
                                    "op",
                                    "wait",
                                    "table",
                                    "Bridge",
                                    "timeout",
                                    0,
                                    "columns",
                                    "ports",
                                    "until",
                                    "==",
                                    "rows",
                                    "ports",
                                    "set",
                                    ports,
                                    "where",
                                    "name",
                                    "==",
                                    ifname));
}

/**
 * _set_bridge_ports:
 *
 * Return a command that will update the list of ports of bridge
 * @ifname to @new_ports.
 */
static void
_set_bridge_ports(json_t *params, const char *ifname, json_t *new_ports)
{
    json_array_append_new(params,
                          json_pack("{s:s, s:s, s:{s:[s, O]}, s:[[s, s, s]]}",
                                    "op",
                                    "update",
                                    "table",
                                    "Bridge",
                                    "row",
                                    "ports",
                                    "set",
                                    new_ports,
                                    "where",
                                    "name",
                                    "==",
                                    ifname));
}

static void
_set_bridge_mac(json_t *params, const char *ifname, const char *mac)
{
    json_array_append_new(
        params,
        json_pack("{s:s, s:s, s:[[s, s, [s, [s]]], [s, s, [s, [[s, s]]]]], s:[[s, s, s]]}",
                  "op",
                  "mutate",
                  "table",
                  "Bridge",
                  "mutations",

                  "other_config",
                  "delete",
                  "set",
                  OTHER_CONFIG_HWADDR,

                  "other_config",
                  "insert",
                  "map",
                  OTHER_CONFIG_HWADDR,
                  mac,

                  "where",
                  "name",
                  "==",
                  ifname));
}

/**
 * _expect_port_interfaces:
 *
 * Return a command that will fail the transaction if the actual set of
 * interfaces in port @ifname doesn't match @interfaces. This is a way of
 * detecting race conditions with other ovsdb clients that might be adding
 * or removing port interfaces at the same time.
 */
static void
_expect_port_interfaces(json_t *params, const char *ifname, json_t *interfaces)
{
    json_array_append_new(params,
                          json_pack("{s:s, s:s, s:i, s:[s], s:s, s:[{s:[s, O]}], s:[[s, s, s]]}",
                                    "op",
                                    "wait",
                                    "table",
                                    "Port",
                                    "timeout",
                                    0,
                                    "columns",
                                    "interfaces",
                                    "until",
                                    "==",
                                    "rows",
                                    "interfaces",
                                    "set",
                                    interfaces,
                                    "where",
                                    "name",
                                    "==",
                                    ifname));
}

/**
 * _set_port_interfaces:
 *
 * Return a command that will update the list of interfaces of port @ifname
 * to @new_interfaces.
 */
static void
_set_port_interfaces(json_t *params, const char *ifname, json_t *new_interfaces)
{
    json_array_append_new(params,
                          json_pack("{s:s, s:s, s:{s:[s, O]}, s:[[s, s, s]]}",
                                    "op",
                                    "update",
                                    "table",
                                    "Port",
                                    "row",
                                    "interfaces",
                                    "set",
                                    new_interfaces,
                                    "where",
                                    "name",
                                    "==",
                                    ifname));
}

static json_t *
_j_create_strdict_new(NMConnection *connection,
                      StrdictType   strdict_type,
                      const char   *other_config_hwaddr)
{
    NMSettingOvsOtherConfig *s_other_config = NULL;
    NMSettingOvsExternalIDs *s_external_ids = NULL;
    json_t                  *array;
    const char *const       *strv   = NULL;
    guint                    n_strv = 0;
    guint                    i;
    const char              *uuid;

    nm_assert(NM_IS_CONNECTION(connection));
    nm_assert(NM_IN_SET(strdict_type, STRDICT_TYPE_EXTERNAL_IDS, STRDICT_TYPE_OTHER_CONFIG));

    array = json_array();

    if (strdict_type == STRDICT_TYPE_EXTERNAL_IDS) {
        uuid = nm_connection_get_uuid(connection);
        nm_assert(uuid);
        json_array_append_new(array,
                              json_pack("[s, s]", NM_OVS_EXTERNAL_ID_NM_CONNECTION_UUID, uuid));
    } else {
        if (other_config_hwaddr) {
            json_array_append_new(array,
                                  json_pack("[s, s]", OTHER_CONFIG_HWADDR, other_config_hwaddr));
        }
    }

    if (strdict_type == STRDICT_TYPE_EXTERNAL_IDS) {
        s_external_ids = _nm_connection_get_setting(connection, NM_TYPE_SETTING_OVS_EXTERNAL_IDS);
        if (s_external_ids)
            strv = nm_setting_ovs_external_ids_get_data_keys(s_external_ids, &n_strv);
    } else {
        s_other_config = _nm_connection_get_setting(connection, NM_TYPE_SETTING_OVS_OTHER_CONFIG);
        if (s_other_config)
            strv = nm_setting_ovs_other_config_get_data_keys(s_other_config, &n_strv);
    }

    for (i = 0; i < n_strv; i++) {
        const char *k = strv[i];

        if (strdict_type == STRDICT_TYPE_OTHER_CONFIG && other_config_hwaddr
            && nm_streq(k, OTHER_CONFIG_HWADDR)) {
            /* "hwaddr" is explicitly overwritten. */
            continue;
        }

        json_array_append_new(
            array,
            json_pack("[s, s]",
                      k,
                      strdict_type == STRDICT_TYPE_EXTERNAL_IDS
                          ? nm_setting_ovs_external_ids_get_data(s_external_ids, k)
                          : nm_setting_ovs_other_config_get_data(s_other_config, k)));
    }

    return json_pack("[s, o]", "map", array);
}

static void
_j_create_strv_array_update(json_t     *mutations,
                            StrdictType strdict_type,
                            const char *connection_uuid,
                            GHashTable *hash_old,
                            GHashTable *hash_new)
{
    GHashTableIter iter;
    json_t        *array;
    const char    *key;
    const char    *val;

    /* This is called during reapply. We accept reapplying all settings,
     * except other_config:hwaddr. That one cannot change and is specially
     * handled below. The reason is that we knew the correct "hwaddr" during
     * _j_create_strdict_new(), but we don't do now. At least not easily,
     * and it's not clear that reapply of the MAC address is really useful. */

    nm_assert((!!connection_uuid) == (strdict_type == STRDICT_TYPE_EXTERNAL_IDS));
    nm_assert(NM_IN_SET(strdict_type, STRDICT_TYPE_EXTERNAL_IDS, STRDICT_TYPE_OTHER_CONFIG));

    array = NULL;
    if (hash_old) {
        g_hash_table_iter_init(&iter, hash_old);
        while (g_hash_table_iter_next(&iter, (gpointer *) &key, NULL)) {
            if (strdict_type == STRDICT_TYPE_OTHER_CONFIG && nm_streq(key, OTHER_CONFIG_HWADDR))
                continue;
            if (!array)
                array = json_array();
            json_array_append_new(array, json_string(key));
        }
    }
    if (hash_new) {
        g_hash_table_iter_init(&iter, hash_new);
        while (g_hash_table_iter_next(&iter, (gpointer *) &key, NULL)) {
            if (strdict_type == STRDICT_TYPE_OTHER_CONFIG && nm_streq(key, OTHER_CONFIG_HWADDR))
                continue;
            if (nm_g_hash_table_contains(hash_old, key))
                continue;
            if (!array)
                array = json_array();
            json_array_append_new(array, json_string(key));
        }
    }
    if (strdict_type == STRDICT_TYPE_EXTERNAL_IDS) {
        if (!nm_g_hash_table_contains(hash_old, NM_OVS_EXTERNAL_ID_NM_PREFIX)
            && !nm_g_hash_table_contains(hash_new, NM_OVS_EXTERNAL_ID_NM_PREFIX)) {
            if (!array)
                array = json_array();
            json_array_append_new(array, json_string(NM_OVS_EXTERNAL_ID_NM_PREFIX));
        }
    }
    if (array) {
        json_array_append_new(
            mutations,
            json_pack("[s, s, [s, o]]",
                      strdict_type == STRDICT_TYPE_EXTERNAL_IDS ? "external_ids" : "other_config",
                      "delete",
                      "set",
                      array));
    }

    array = json_array();

    if (strdict_type == STRDICT_TYPE_EXTERNAL_IDS) {
        json_array_append_new(
            array,
            json_pack("[s, s]", NM_OVS_EXTERNAL_ID_NM_CONNECTION_UUID, connection_uuid));
    }
    if (hash_new) {
        g_hash_table_iter_init(&iter, hash_new);
        while (g_hash_table_iter_next(&iter, (gpointer *) &key, (gpointer *) &val)) {
            if (strdict_type == STRDICT_TYPE_EXTERNAL_IDS) {
                if (NM_STR_HAS_PREFIX(key, NM_OVS_EXTERNAL_ID_NM_PREFIX))
                    continue;
            }
            if (strdict_type == STRDICT_TYPE_OTHER_CONFIG && nm_streq(key, OTHER_CONFIG_HWADDR))
                continue;
            json_array_append_new(array, json_pack("[s, s]", key, val));
        }
    }

    json_array_append_new(
        mutations,
        json_pack("[s, s, [s, o]]",
                  strdict_type == STRDICT_TYPE_EXTERNAL_IDS ? "external_ids" : "other_config",
                  "insert",
                  "map",
                  array));
}

/**
 * _insert_interface:
 *
 * Returns a command that adds new interface from a given connection.
 */
static void
_insert_interface(json_t       *params,
                  NMConnection *interface,
                  NMDevice     *interface_device,
                  const char   *cloned_mac)
{
    const char            *type = NULL;
    NMSettingOvsInterface *s_ovs_iface;
    NMSettingOvsDpdk      *s_ovs_dpdk;
    char                   sbuf[64];
    json_t                *dpdk_array;
    NMSettingOvsPatch     *s_ovs_patch;
    json_t                *options = json_array();
    json_t                *row;
    guint32                mtu            = 0;
    guint32                ofport_request = 0;

    s_ovs_iface = nm_connection_get_setting_ovs_interface(interface);
    if (s_ovs_iface) {
        type           = nm_setting_ovs_interface_get_interface_type(s_ovs_iface);
        ofport_request = nm_setting_ovs_interface_get_ofport_request(s_ovs_iface);
    }

    if (nm_streq0(type, "internal")) {
        NMSettingWired *s_wired;

        s_wired = _nm_connection_get_setting(interface, NM_TYPE_SETTING_WIRED);
        if (s_wired)
            mtu = nm_setting_wired_get_mtu(s_wired);
    }

    json_array_append_new(options, json_string("map"));

    s_ovs_dpdk =
        (NMSettingOvsDpdk *) nm_connection_get_setting(interface, NM_TYPE_SETTING_OVS_DPDK);
    if (!s_ovs_dpdk)
        s_ovs_patch = nm_connection_get_setting_ovs_patch(interface);

    if (s_ovs_dpdk) {
        const char *devargs;
        guint32     n_rxq;
        guint32     n_rxq_desc;
        guint32     n_txq_desc;

        devargs    = nm_setting_ovs_dpdk_get_devargs(s_ovs_dpdk);
        n_rxq      = nm_setting_ovs_dpdk_get_n_rxq(s_ovs_dpdk);
        n_rxq_desc = nm_setting_ovs_dpdk_get_n_rxq_desc(s_ovs_dpdk);
        n_txq_desc = nm_setting_ovs_dpdk_get_n_txq_desc(s_ovs_dpdk);

        dpdk_array = json_array();

        if (devargs)
            json_array_append_new(dpdk_array, json_pack("[s,s]", "dpdk-devargs", devargs));

        if (n_rxq != 0) {
            json_array_append_new(dpdk_array,
                                  json_pack("[s,s]", "n_rxq", nm_sprintf_buf(sbuf, "%u", n_rxq)));
        }
        if (n_rxq_desc != 0) {
            json_array_append_new(
                dpdk_array,
                json_pack("[s,s]", "n_rxq_desc", nm_sprintf_buf(sbuf, "%u", n_rxq_desc)));
        }
        if (n_txq_desc != 0) {
            json_array_append_new(
                dpdk_array,
                json_pack("[s,s]", "n_txq_desc", nm_sprintf_buf(sbuf, "%u", n_txq_desc)));
        }

        json_array_append_new(options, dpdk_array);

    } else if (s_ovs_patch) {
        json_array_append_new(
            options,
            json_pack("[[s, s]]", "peer", nm_setting_ovs_patch_get_peer(s_ovs_patch)));
    } else {
        json_array_append_new(options, json_array());
    }

    row = json_pack("{s:s, s:s, s:o, s:o, s:o}",
                    "name",
                    nm_connection_get_interface_name(interface),
                    "type",
                    type ?: "",
                    "options",
                    options,
                    "external_ids",
                    _j_create_strdict_new(interface, STRDICT_TYPE_EXTERNAL_IDS, NULL),
                    "other_config",
                    _j_create_strdict_new(interface, STRDICT_TYPE_OTHER_CONFIG, NULL));

    if (cloned_mac)
        json_object_set_new(row, "mac", json_string(cloned_mac));

    if (mtu != 0)
        json_object_set_new(row, "mtu_request", json_integer(mtu));

    if (ofport_request != 0)
        json_object_set_new(row, "ofport_request", json_integer(ofport_request));

    json_array_append_new(params,
                          json_pack("{s:s, s:s, s:o, s:s}",
                                    "op",
                                    "insert",
                                    "table",
                                    "Interface",
                                    "row",
                                    row,
                                    "uuid-name",
                                    "rowInterface"));
}

/**
 * _insert_port:
 *
 * Returns an commands that adds new port from a given connection.
 */
static void
_insert_port(json_t *params, NMConnection *port, json_t *new_interfaces)
{
    NMSettingOvsPort *s_ovs_port;
    const char       *vlan_mode      = NULL;
    json_t           *trunks         = NULL;
    guint             tag            = 0;
    const char       *lacp           = NULL;
    const char       *bond_mode      = NULL;
    guint             bond_updelay   = 0;
    guint             bond_downdelay = 0;
    json_t           *row;

    s_ovs_port = nm_connection_get_setting_ovs_port(port);

    row = json_object();

    if (s_ovs_port) {
        const GPtrArray *ranges;
        guint            i;
        guint64          start;
        guint64          end;

        vlan_mode      = nm_setting_ovs_port_get_vlan_mode(s_ovs_port);
        tag            = nm_setting_ovs_port_get_tag(s_ovs_port);
        lacp           = nm_setting_ovs_port_get_lacp(s_ovs_port);
        bond_mode      = nm_setting_ovs_port_get_bond_mode(s_ovs_port);
        bond_updelay   = nm_setting_ovs_port_get_bond_updelay(s_ovs_port);
        bond_downdelay = nm_setting_ovs_port_get_bond_downdelay(s_ovs_port);

        ranges = _nm_setting_ovs_port_get_trunks_arr(s_ovs_port);
        for (i = 0; i < ranges->len; i++) {
            if (!trunks)
                trunks = json_array();
            nm_range_get_range(ranges->pdata[i], &start, &end);
            for (; start <= end; start++)
                json_array_append_new(trunks, json_integer(start));
        }
    }

    if (vlan_mode)
        json_object_set_new(row, "vlan_mode", json_string(vlan_mode));
    if (tag)
        json_object_set_new(row, "tag", json_integer(tag));
    if (trunks)
        json_object_set_new(row, "trunks", json_pack("[s, o]", "set", trunks));
    if (lacp)
        json_object_set_new(row, "lacp", json_string(lacp));
    if (bond_mode)
        json_object_set_new(row, "bond_mode", json_string(bond_mode));
    if (bond_updelay)
        json_object_set_new(row, "bond_updelay", json_integer(bond_updelay));
    if (bond_downdelay)
        json_object_set_new(row, "bond_downdelay", json_integer(bond_downdelay));

    json_object_set_new(row, "name", json_string(nm_connection_get_interface_name(port)));
    json_object_set_new(row, "interfaces", json_pack("[s, O]", "set", new_interfaces));
    json_object_set_new(row,
                        "external_ids",
                        _j_create_strdict_new(port, STRDICT_TYPE_EXTERNAL_IDS, NULL));
    json_object_set_new(row,
                        "other_config",
                        _j_create_strdict_new(port, STRDICT_TYPE_OTHER_CONFIG, NULL));

    /* Create a new one. */
    json_array_append_new(params,
                          json_pack("{s:s, s:s, s:o, s:s}",
                                    "op",
                                    "insert",
                                    "table",
                                    "Port",
                                    "row",
                                    row,
                                    "uuid-name",
                                    "rowPort"));
}

/**
 * _insert_bridge:
 *
 * Returns an commands that adds new bridge from a given connection.
 */
static void
_insert_bridge(json_t       *params,
               NMConnection *bridge,
               NMDevice     *bridge_device,
               json_t       *new_ports,
               const char   *cloned_mac)
{
    NMSettingOvsBridge *s_ovs_bridge;
    const char         *fail_mode             = NULL;
    gboolean            mcast_snooping_enable = FALSE;
    gboolean            rstp_enable           = FALSE;
    gboolean            stp_enable            = FALSE;
    const char         *datapath_type         = NULL;
    json_t             *row;

    s_ovs_bridge = nm_connection_get_setting_ovs_bridge(bridge);

    row = json_object();

    if (s_ovs_bridge) {
        fail_mode             = nm_setting_ovs_bridge_get_fail_mode(s_ovs_bridge);
        mcast_snooping_enable = nm_setting_ovs_bridge_get_mcast_snooping_enable(s_ovs_bridge);
        rstp_enable           = nm_setting_ovs_bridge_get_rstp_enable(s_ovs_bridge);
        stp_enable            = nm_setting_ovs_bridge_get_stp_enable(s_ovs_bridge);
        datapath_type         = nm_setting_ovs_bridge_get_datapath_type(s_ovs_bridge);
    }

    if (fail_mode)
        json_object_set_new(row, "fail_mode", json_string(fail_mode));
    if (mcast_snooping_enable)
        json_object_set_new(row, "mcast_snooping_enable", json_boolean(mcast_snooping_enable));
    if (rstp_enable)
        json_object_set_new(row, "rstp_enable", json_boolean(rstp_enable));
    if (stp_enable)
        json_object_set_new(row, "stp_enable", json_boolean(stp_enable));
    if (datapath_type)
        json_object_set_new(row, "datapath_type", json_string(datapath_type));

    json_object_set_new(row, "name", json_string(nm_connection_get_interface_name(bridge)));
    json_object_set_new(row, "ports", json_pack("[s, O]", "set", new_ports));
    json_object_set_new(row,
                        "external_ids",
                        _j_create_strdict_new(bridge, STRDICT_TYPE_EXTERNAL_IDS, NULL));
    json_object_set_new(row,
                        "other_config",
                        _j_create_strdict_new(bridge, STRDICT_TYPE_OTHER_CONFIG, cloned_mac));

    /* Create a new one. */
    json_array_append_new(params,
                          json_pack("{s:s, s:s, s:o, s:s}",
                                    "op",
                                    "insert",
                                    "table",
                                    "Bridge",
                                    "row",
                                    row,
                                    "uuid-name",
                                    "rowBridge"));
}

/**
 * _inc_next_cfg:
 *
 * Returns an mutate command that bumps next_cfg upon successful completion
 * of the transaction it is in.
 */
static json_t *
_inc_next_cfg(const char *db_uuid)
{
    return json_pack("{s:s, s:s, s:[[s, s, i]], s:[[s, s, [s, s]]]}",
                     "op",
                     "mutate",
                     "table",
                     "Open_vSwitch",
                     "mutations",
                     "next_cfg",
                     "+=",
                     1,
                     "where",
                     "_uuid",
                     "==",
                     "uuid",
                     db_uuid);
}

/**
 * _add_interface:
 *
 * Adds an interface as specified by @interface connection, optionally creating
 * a parent @port and @bridge if needed.
 */
static void
_add_interface(NMOvsdb      *self,
               json_t       *params,
               NMConnection *bridge,
               NMConnection *port,
               NMConnection *interface,
               NMDevice     *bridge_device,
               NMDevice     *interface_device)
{
    NMOvsdbPrivate             *priv = NM_OVSDB_GET_PRIVATE(self);
    GHashTableIter              iter;
    const char                 *port_uuid;
    const char                 *interface_uuid;
    const char                 *bridge_name;
    const char                 *port_name;
    const char                 *interface_name;
    OpenvswitchBridge          *ovs_bridge     = NULL;
    OpenvswitchPort            *ovs_port       = NULL;
    OpenvswitchInterface       *ovs_interface  = NULL;
    nm_auto_decref_json json_t *bridges        = NULL;
    nm_auto_decref_json json_t *new_bridges    = NULL;
    nm_auto_decref_json json_t *ports          = NULL;
    nm_auto_decref_json json_t *new_ports      = NULL;
    nm_auto_decref_json json_t *interfaces     = NULL;
    nm_auto_decref_json json_t *new_interfaces = NULL;
    gboolean                    has_interface  = FALSE;
    gboolean                    interface_is_local;
    gs_free char               *bridge_cloned_mac    = NULL;
    gs_free char               *interface_cloned_mac = NULL;
    GError                     *error                = NULL;
    int                         pi;
    int                         ii;

    bridges        = json_array();
    ports          = json_array();
    interfaces     = json_array();
    new_bridges    = json_array();
    new_ports      = json_array();
    new_interfaces = json_array();

    bridge_name        = nm_connection_get_interface_name(bridge);
    port_name          = nm_connection_get_interface_name(port);
    interface_name     = nm_connection_get_interface_name(interface);
    interface_is_local = nm_streq0(bridge_name, interface_name);

    /* Determine cloned MAC addresses */
    if (!nm_device_hw_addr_get_cloned(bridge_device,
                                      bridge,
                                      FALSE,
                                      &bridge_cloned_mac,
                                      NULL,
                                      &error)) {
        _LOGW("Cannot determine cloned MAC for OVS %s '%s': %s",
              "bridge",
              bridge_name,
              error->message);
        g_clear_error(&error);
    }

    if (!nm_device_hw_addr_get_cloned(interface_device,
                                      interface,
                                      FALSE,
                                      &interface_cloned_mac,
                                      NULL,
                                      &error)) {
        _LOGW("Cannot determine cloned MAC for OVS %s '%s': %s",
              "interface",
              interface_name,
              error->message);
        g_clear_error(&error);
    }

    /* For local interfaces, ovs complains if it finds a
     * MAC address in the Interface table because it only takes
     * the MAC from the Bridge table.
     * Set any cloned MAC present in a local interface connection
     * into the Bridge table, unless conflicting with the bridge MAC. */
    if (interface_is_local && interface_cloned_mac) {
        if (bridge_cloned_mac && !nm_streq(interface_cloned_mac, bridge_cloned_mac)) {
            _LOGW("Cloned MAC '%s' of local ovs-interface '%s' conflicts with MAC '%s' of bridge "
                  "'%s'",
                  interface_cloned_mac,
                  interface_name,
                  bridge_cloned_mac,
                  bridge_name);
            nm_clear_g_free(&interface_cloned_mac);
        } else {
            nm_clear_g_free(&bridge_cloned_mac);
            bridge_cloned_mac = g_steal_pointer(&interface_cloned_mac);
            _LOGT("'%s' is a local ovs-interface, the MAC will be set on ovs-bridge '%s'",
                  interface_name,
                  bridge_name);
        }
    }

    g_hash_table_iter_init(&iter, priv->bridges);
    while (g_hash_table_iter_next(&iter, (gpointer) &ovs_bridge, NULL)) {
        json_array_append_new(bridges, json_pack("[s, s]", "uuid", ovs_bridge->bridge_uuid));

        if (!nm_streq0(ovs_bridge->name, bridge_name)
            || !nm_streq0(ovs_bridge->connection_uuid, nm_connection_get_uuid(bridge)))
            continue;

        for (pi = 0; pi < ovs_bridge->ports->len; pi++) {
            port_uuid = g_ptr_array_index(ovs_bridge->ports, pi);
            ovs_port  = g_hash_table_lookup(priv->ports, &port_uuid);

            json_array_append_new(ports, json_pack("[s, s]", "uuid", port_uuid));

            if (!ovs_port) {
                /* This would be a violation of ovsdb's reference integrity (a bug). */
                _LOGW("Unknown port '%s' in bridge '%s'", port_uuid, ovs_bridge->bridge_uuid);
                continue;
            }

            if (!nm_streq(ovs_port->name, port_name)
                || !nm_streq0(ovs_port->connection_uuid, nm_connection_get_uuid(port)))
                continue;

            for (ii = 0; ii < ovs_port->interfaces->len; ii++) {
                interface_uuid = g_ptr_array_index(ovs_port->interfaces, ii);
                ovs_interface  = g_hash_table_lookup(priv->interfaces, &interface_uuid);

                json_array_append_new(interfaces, json_pack("[s, s]", "uuid", interface_uuid));

                if (!ovs_interface) {
                    /* This would be a violation of ovsdb's reference integrity (a bug). */
                    _LOGW("Unknown interface '%s' in port '%s'", interface_uuid, port_uuid);
                    continue;
                }
                if (nm_streq(ovs_interface->name, interface_name)
                    && nm_streq0(ovs_interface->connection_uuid, nm_connection_get_uuid(interface)))
                    has_interface = TRUE;
            }

            break;
        }

        break;
    }

    json_array_extend(new_bridges, bridges);
    json_array_extend(new_ports, ports);
    json_array_extend(new_interfaces, interfaces);

    if (json_array_size(interfaces) == 0) {
        /* Need to create a port. */
        if (json_array_size(ports) == 0) {
            /* Need to create a bridge. */
            _expect_ovs_bridges(params, priv->db_uuid, bridges);
            json_array_append_new(new_bridges, json_pack("[s, s]", "named-uuid", "rowBridge"));
            _set_ovs_bridges(params, priv->db_uuid, new_bridges);
            _insert_bridge(params, bridge, bridge_device, new_ports, bridge_cloned_mac);
        } else {
            /* Bridge already exists. */
            g_return_if_fail(ovs_bridge);
            _expect_bridge_ports(params, ovs_bridge->name, ports);
            _set_bridge_ports(params, bridge_name, new_ports);
            if (bridge_cloned_mac && interface_is_local)
                _set_bridge_mac(params, bridge_name, bridge_cloned_mac);
        }

        json_array_append_new(new_ports, json_pack("[s, s]", "named-uuid", "rowPort"));
        _insert_port(params, port, new_interfaces);
    } else {
        /* Port already exists */
        g_return_if_fail(ovs_port);
        _expect_port_interfaces(params, ovs_port->name, interfaces);
        _set_port_interfaces(params, port_name, new_interfaces);
    }

    if (!has_interface) {
        _insert_interface(params, interface, interface_device, interface_cloned_mac);
        json_array_append_new(new_interfaces, json_pack("[s, s]", "named-uuid", "rowInterface"));
    }
}

/**
 * _delete_interface:
 *
 * Removes an interface of @ifname name, collecting empty ports and bridge
 * if last item is removed from them.
 */
static void
_delete_interface(NMOvsdb *self, json_t *params, const char *ifname)
{
    NMOvsdbPrivate             *priv = NM_OVSDB_GET_PRIVATE(self);
    GHashTableIter              iter;
    char                       *port_uuid;
    char                       *interface_uuid;
    OpenvswitchBridge          *ovs_bridge;
    OpenvswitchPort            *ovs_port;
    OpenvswitchInterface       *ovs_interface;
    nm_auto_decref_json json_t *bridges     = NULL;
    nm_auto_decref_json json_t *new_bridges = NULL;
    gboolean                    bridges_changed;
    gboolean                    ports_changed;
    gboolean                    interfaces_changed;
    int                         pi;
    int                         ii;

    bridges         = json_array();
    new_bridges     = json_array();
    bridges_changed = FALSE;

    g_hash_table_iter_init(&iter, priv->bridges);
    while (g_hash_table_iter_next(&iter, (gpointer) &ovs_bridge, NULL)) {
        nm_auto_decref_json json_t *ports     = NULL;
        nm_auto_decref_json json_t *new_ports = NULL;

        ports         = json_array();
        new_ports     = json_array();
        ports_changed = FALSE;

        json_array_append_new(bridges, json_pack("[s,s]", "uuid", ovs_bridge->bridge_uuid));

        for (pi = 0; pi < ovs_bridge->ports->len; pi++) {
            nm_auto_decref_json json_t *interfaces     = NULL;
            nm_auto_decref_json json_t *new_interfaces = NULL;

            interfaces     = json_array();
            new_interfaces = json_array();
            port_uuid      = g_ptr_array_index(ovs_bridge->ports, pi);
            ovs_port       = g_hash_table_lookup(priv->ports, &port_uuid);

            json_array_append_new(ports, json_pack("[s,s]", "uuid", port_uuid));

            interfaces_changed = FALSE;

            if (!ovs_port) {
                /* This would be a violation of ovsdb's reference integrity (a bug). */
                _LOGW("Unknown port '%s' in bridge '%s'", port_uuid, ovs_bridge->bridge_uuid);
                continue;
            }

            for (ii = 0; ii < ovs_port->interfaces->len; ii++) {
                interface_uuid = g_ptr_array_index(ovs_port->interfaces, ii);
                ovs_interface  = g_hash_table_lookup(priv->interfaces, &interface_uuid);

                json_array_append_new(interfaces, json_pack("[s,s]", "uuid", interface_uuid));

                if (ovs_interface) {
                    if (nm_streq(ovs_interface->name, ifname)) {
                        /* skip the interface */
                        interfaces_changed = TRUE;
                        continue;
                    }
                } else {
                    /* This would be a violation of ovsdb's reference integrity (a bug). */
                    _LOGW("Unknown interface '%s' in port '%s'", interface_uuid, port_uuid);
                }

                json_array_append_new(new_interfaces, json_pack("[s,s]", "uuid", interface_uuid));
            }

            if (json_array_size(new_interfaces) == 0) {
                ports_changed = TRUE;
            } else {
                if (interfaces_changed) {
                    _expect_port_interfaces(params, ovs_port->name, interfaces);
                    _set_port_interfaces(params, ovs_port->name, new_interfaces);
                }
                json_array_append_new(new_ports, json_pack("[s,s]", "uuid", port_uuid));
            }
        }

        if (json_array_size(new_ports) == 0) {
            bridges_changed = TRUE;
        } else {
            if (ports_changed) {
                _expect_bridge_ports(params, ovs_bridge->name, ports);
                _set_bridge_ports(params, ovs_bridge->name, new_ports);
            }
            json_array_append_new(new_bridges, json_pack("[s,s]", "uuid", ovs_bridge->bridge_uuid));
        }
    }

    if (bridges_changed) {
        _expect_ovs_bridges(params, priv->db_uuid, bridges);
        _set_ovs_bridges(params, priv->db_uuid, new_bridges);
    }
}

/**
 * ovsdb_next_command:
 *
 * Translates a higher level operation (add/remove bridge/port) to a RFC 7047
 * command serialized into JSON ands sends it over to the database.

 * Only called when no command is waiting for a response, since the serialized
 * command might depend on result of a previous one (add and remove need to
 * include an up to date bridge list in their transactions to rule out races).
 */
static void
ovsdb_next_command(NMOvsdb *self)
{
    NMOvsdbPrivate             *priv = NM_OVSDB_GET_PRIVATE(self);
    OvsdbMethodCall            *call;
    nm_auto_free char          *cmd = NULL;
    nm_auto_decref_json json_t *msg = NULL;

    if (priv->conn_fd < 0)
        return;

    if (c_list_is_empty(&priv->calls_lst_head))
        return;

    call = c_list_first_entry(&priv->calls_lst_head, OvsdbMethodCall, calls_lst);
    if (call->call_id != CALL_ID_UNSPEC)
        return;

    call->call_id = ++priv->call_id_counter;

    switch (call->command) {
    case OVSDB_MONITOR:
        msg = json_pack("{s:I, s:s, s:[s, n, {"
                        "  s:[{s:[s, s, s, s]}],"
                        "  s:[{s:[s, s, s, s]}],"
                        "  s:[{s:[s, s, s, s, s]}],"
                        "  s:[{s:[]}]"
                        "}]}",
                        "id",
                        (json_int_t) call->call_id,
                        "method",
                        "monitor",
                        "params",
                        "Open_vSwitch",
                        "Bridge",
                        "columns",
                        "name",
                        "ports",
                        "external_ids",
                        "other_config",
                        "Port",
                        "columns",
                        "name",
                        "interfaces",
                        "external_ids",
                        "other_config",
                        "Interface",
                        "columns",
                        "name",
                        "type",
                        "external_ids",
                        "other_config",
                        "error",
                        "Open_vSwitch",
                        "columns");
        break;
    default:
    {
        json_t *params = NULL;

        params = json_array();
        json_array_append_new(params, json_string("Open_vSwitch"));
        json_array_append_new(params, _inc_next_cfg(priv->db_uuid));

        switch (call->command) {
        case OVSDB_ADD_INTERFACE:
            _add_interface(self,
                           params,
                           call->payload.add_interface.bridge,
                           call->payload.add_interface.port,
                           call->payload.add_interface.interface,
                           call->payload.add_interface.bridge_device,
                           call->payload.add_interface.interface_device);
            break;
        case OVSDB_DEL_INTERFACE:
            _delete_interface(self, params, call->payload.del_interface.ifname);
            break;
        case OVSDB_SET_INTERFACE_MTU:
            json_array_append_new(params,
                                  json_pack("{s:s, s:s, s:{s: I}, s:[[s, s, s]]}",
                                            "op",
                                            "update",
                                            "table",
                                            "Interface",
                                            "row",
                                            "mtu_request",
                                            (json_int_t) call->payload.set_interface_mtu.mtu,
                                            "where",
                                            "name",
                                            "==",
                                            call->payload.set_interface_mtu.ifname));
            break;
        case OVSDB_SET_REAPPLY:
        {
            json_t *mutations;

            mutations = json_array();

            _j_create_strv_array_update(mutations,
                                        STRDICT_TYPE_EXTERNAL_IDS,
                                        call->payload.set_reapply.connection_uuid,
                                        call->payload.set_reapply.external_ids_old,
                                        call->payload.set_reapply.external_ids_new);
            _j_create_strv_array_update(mutations,
                                        STRDICT_TYPE_OTHER_CONFIG,
                                        NULL,
                                        call->payload.set_reapply.other_config_old,
                                        call->payload.set_reapply.other_config_new);

            json_array_append_new(
                params,
                json_pack("{s:s, s:s, s:o, s:[[s, s, s]]}",
                          "op",
                          "mutate",
                          "table",
                          _device_type_to_table(call->payload.set_reapply.device_type),
                          "mutations",
                          mutations,
                          "where",
                          "name",
                          "==",
                          call->payload.set_reapply.ifname));
            break;
        }

        default:
            nm_assert_not_reached();
            break;
        }

        msg = json_pack("{s:I, s:s, s:o}",
                        "id",
                        (json_int_t) call->call_id,
                        "method",
                        "transact",
                        "params",
                        params);
        break;
    }
    }

    g_return_if_fail(msg);

    cmd = json_dumps(msg, 0);
    _LOGT_call(call, "send: call-id=%" G_GUINT64_FORMAT ", %s", call->call_id, cmd);
    nm_str_buf_append(&priv->output_buf, cmd);

    ovsdb_write_try(self);
}

/**
 * _uuids_to_array:
 *
 * This tidies up the somewhat non-straightforward way ovsdb represents an array
 * of UUID elements. The single element is a tuple (called <atom> in RFC7047),
 *
 *   [ "uuid", "aa095ffb-e1f1-0fc4-8038-82c1ea7e4797" ]
 *
 * while the list of multiple UUIDs are turned into a set of such tuples ("atoms"):
 *
 *   [ "set", [ [ "uuid", "aa095ffb-e1f1-0fc4-8038-82c1ea7e4797" ],
 *              [ "uuid", "185c93f6-0b39-424e-8587-77d074aa7ce0" ], ... ] ]
 */
static void
_uuids_to_array_inplace(GPtrArray *array, const json_t *items)
{
    const char *key;
    json_t     *value;
    size_t      index = 0;
    json_t     *set_value;
    size_t      set_index;

    while (index < json_array_size(items)) {
        key = json_string_value(json_array_get(items, index));
        index++;
        value = json_array_get(items, index);
        index++;

        if (!value || !key)
            return;

        if (nm_streq(key, "uuid")) {
            if (json_is_string(value))
                g_ptr_array_add(array, g_strdup(json_string_value(value)));
            continue;
        }
        if (nm_streq(key, "set")) {
            if (json_is_array(value)) {
                json_array_foreach (value, set_index, set_value)
                    _uuids_to_array_inplace(array, set_value);
            }
            continue;
        }
    }
}

static GPtrArray *
_uuids_to_array(const json_t *items)
{
    GPtrArray *array;

    array = g_ptr_array_new_with_free_func(g_free);
    _uuids_to_array_inplace(array, items);
    return array;
}

static void
_strdict_extract(json_t *strdict, GArray **out_array)
{
    json_t *array;
    json_t *value;
    gsize   index;

    nm_assert(out_array && !*out_array);

    if (!nm_streq0("map", json_string_value(json_array_get(strdict, 0))))
        return;

    array = json_array_get(strdict, 1);

    json_array_foreach (array, index, value) {
        const char        *key = json_string_value(json_array_get(value, 0));
        const char        *val = json_string_value(json_array_get(value, 1));
        NMUtilsNamedValue *v;

        if (!key || !val)
            continue;

        if (!*out_array) {
            *out_array = g_array_new(FALSE, FALSE, sizeof(NMUtilsNamedValue));
            g_array_set_clear_func(*out_array,
                                   (GDestroyNotify) nm_utils_named_value_clear_with_g_free);
        }

        v  = nm_g_array_append_new(*out_array, NMUtilsNamedValue);
        *v = (NMUtilsNamedValue){
            .name      = g_strdup(key),
            .value_str = g_strdup(val),
        };
    }
}

static const char *
_strdict_find_key(GArray *array, const char *key)
{
    gssize idx;

    idx = nm_utils_named_value_list_find(nm_g_array_first_p(array, NMUtilsNamedValue),
                                         nm_g_array_len(array),
                                         key,
                                         FALSE);
    if (idx < 0)
        return NULL;

    return nm_g_array_index(array, NMUtilsNamedValue, idx).value_str;
}

static gboolean
_strdict_equals(const GArray *arr1, const GArray *arr2)
{
    guint n;
    guint i;

    n = nm_g_array_len(arr1);

    if (n != nm_g_array_len(arr2))
        return FALSE;
    for (i = 0; i < n; i++) {
        const NMUtilsNamedValue *n1 = &nm_g_array_index(arr1, NMUtilsNamedValue, i);
        const NMUtilsNamedValue *n2 = &nm_g_array_index(arr2, NMUtilsNamedValue, i);

        if (!nm_streq(n1->name, n2->name))
            return FALSE;
        if (!nm_streq(n1->value_str, n2->value_str))
            return FALSE;
    }
    return TRUE;
}

static char *
_strdict_to_string(const GArray *arr)
{
    NMStrBuf strbuf;
    guint    i;

    if (!arr)
        return g_strdup("empty");

    strbuf = NM_STR_BUF_INIT(NM_UTILS_GET_NEXT_REALLOC_SIZE_104, FALSE);
    nm_str_buf_append(&strbuf, "[");
    for (i = 0; i < arr->len; i++) {
        const NMUtilsNamedValue *n = &nm_g_array_index(arr, NMUtilsNamedValue, i);

        if (i > 0)
            nm_str_buf_append_c(&strbuf, ',');
        nm_str_buf_append_printf(&strbuf, " \"%s\" = \"%s\" ", n->name, n->value_str);
    }
    nm_str_buf_append(&strbuf, "]");

    return nm_str_buf_finalize(&strbuf, NULL);
}

/*****************************************************************************/

/**
 * ovsdb_got_update:
 *
 * Called when we've got an "update" method call (we asked for it with the monitor
 * command). We use it to maintain a consistent view of bridge list regardless of
 * whether the changes are done by us or externally.
 */
static void
ovsdb_got_update(NMOvsdb *self, json_t *msg)
{
    NMOvsdbPrivate *priv      = NM_OVSDB_GET_PRIVATE(self);
    json_t         *ovs       = NULL;
    json_t         *bridge    = NULL;
    json_t         *port      = NULL;
    json_t         *interface = NULL;
    json_t         *items;
    json_t         *external_ids;
    json_t         *other_config;
    json_error_t    json_error = {
        0,
    };
    void       *iter;
    const char *name;
    const char *key;
    const char *type;
    json_t     *value;

    if (json_unpack_ex(msg,
                       &json_error,
                       0,
                       "{s?:o, s?:o, s?:o, s?:o}",
                       "Open_vSwitch",
                       &ovs,
                       "Bridge",
                       &bridge,
                       "Port",
                       &port,
                       "Interface",
                       &interface)
        == -1) {
        /* This doesn't really have to be an error; the key might
         * be missing if there really are no bridges present. */
        _LOGD("Bad update: %s", json_error.text);
    }

    if (ovs) {
        const char *s;

        iter = json_object_iter(ovs);
        s    = json_object_iter_key(iter);
        if (s)
            nm_strdup_reset(&priv->db_uuid, s);
    }

    json_object_foreach (interface, key, value) {
        OpenvswitchInterface  *ovs_interface;
        gs_unref_array GArray *external_ids_arr = NULL;
        gs_unref_array GArray *other_config_arr = NULL;
        const char            *connection_uuid  = NULL;
        json_t                *error            = NULL;
        int                    r;

        r = json_unpack(value,
                        "{s:{s:s, s:s, s?:o, s:o, s:o}}",
                        "new",
                        "name",
                        &name,
                        "type",
                        &type,
                        "error",
                        &error,
                        "external_ids",
                        &external_ids,
                        "other_config",
                        &other_config);
        if (r != 0) {
            gpointer unused;

            r = json_unpack(value, "{s:{}}", "old");
            if (r != 0)
                continue;

            if (!g_hash_table_steal_extended(priv->interfaces,
                                             &key,
                                             (gpointer *) &ovs_interface,
                                             &unused))
                continue;

            _LOGT("obj[iface:%s]: removed an '%s' interface: %s%s%s",
                  key,
                  ovs_interface->type,
                  ovs_interface->name,
                  NM_PRINT_FMT_QUOTED2(ovs_interface->connection_uuid,
                                       ", ",
                                       ovs_interface->connection_uuid,
                                       ""));
            _signal_emit_device_removed(self,
                                        ovs_interface->name,
                                        NM_DEVICE_TYPE_OVS_INTERFACE,
                                        ovs_interface->type);
            _free_interface(ovs_interface);
            continue;
        }

        ovs_interface = g_hash_table_lookup(priv->interfaces, &key);

        if (ovs_interface
            && (!nm_streq0(ovs_interface->name, name) || !nm_streq0(ovs_interface->type, type))) {
            if (!g_hash_table_steal(priv->interfaces, ovs_interface))
                nm_assert_not_reached();
            _signal_emit_device_removed(self,
                                        ovs_interface->name,
                                        NM_DEVICE_TYPE_OVS_INTERFACE,
                                        ovs_interface->type);
            nm_clear_pointer(&ovs_interface, _free_interface);
        }

        _strdict_extract(external_ids, &external_ids_arr);
        connection_uuid =
            _strdict_find_key(external_ids_arr, NM_OVS_EXTERNAL_ID_NM_CONNECTION_UUID);
        _strdict_extract(other_config, &other_config_arr);

        if (ovs_interface) {
            gboolean changed = FALSE;

            nm_assert(nm_streq0(ovs_interface->name, name));

            changed |= nm_strdup_reset(&ovs_interface->type, type);
            changed |= nm_strdup_reset(&ovs_interface->connection_uuid, connection_uuid);
            if (!_strdict_equals(ovs_interface->external_ids, external_ids_arr)) {
                NM_SWAP(&ovs_interface->external_ids, &external_ids_arr);
                changed = TRUE;
            }
            if (!_strdict_equals(ovs_interface->other_config, other_config_arr)) {
                NM_SWAP(&ovs_interface->other_config, &other_config_arr);
                changed = TRUE;
            }
            if (changed) {
                gs_free char *strtmp1 = NULL;
                gs_free char *strtmp2 = NULL;

                _LOGT("obj[iface:%s]: changed an '%s' interface: %s%s%s, external-ids=%s, "
                      "other-config=%s",
                      key,
                      type,
                      ovs_interface->name,
                      NM_PRINT_FMT_QUOTED2(ovs_interface->connection_uuid,
                                           ", ",
                                           ovs_interface->connection_uuid,
                                           ""),
                      (strtmp1 = _strdict_to_string(ovs_interface->external_ids)),
                      (strtmp2 = _strdict_to_string(ovs_interface->other_config)));
            }
        } else {
            gs_free char *strtmp1 = NULL;
            gs_free char *strtmp2 = NULL;

            ovs_interface  = g_slice_new(OpenvswitchInterface);
            *ovs_interface = (OpenvswitchInterface){
                .interface_uuid  = g_strdup(key),
                .name            = g_strdup(name),
                .type            = g_strdup(type),
                .connection_uuid = g_strdup(connection_uuid),
                .external_ids    = g_steal_pointer(&external_ids_arr),
                .other_config    = g_steal_pointer(&other_config_arr),
            };
            g_hash_table_add(priv->interfaces, ovs_interface);
            _LOGT(
                "obj[iface:%s]: added an '%s' interface: %s%s%s, external-ids=%s, other-config=%s",
                key,
                ovs_interface->type,
                ovs_interface->name,
                NM_PRINT_FMT_QUOTED2(ovs_interface->connection_uuid,
                                     ", ",
                                     ovs_interface->connection_uuid,
                                     ""),
                (strtmp1 = _strdict_to_string(ovs_interface->external_ids)),
                (strtmp2 = _strdict_to_string(ovs_interface->other_config)));
            _signal_emit_device_added(self,
                                      ovs_interface->name,
                                      NM_DEVICE_TYPE_OVS_INTERFACE,
                                      ovs_interface->type);
        }

        /* The error is a string. No error is indicated by an empty set,
         * Why not: [ "set": [] ] ? */
        if (error && json_is_string(error)) {
            _signal_emit_interface_failed(self,
                                          ovs_interface->name,
                                          ovs_interface->connection_uuid,
                                          json_string_value(error));
        }
    }

    json_object_foreach (port, key, value) {
        gs_unref_ptrarray GPtrArray *interfaces = NULL;
        OpenvswitchPort             *ovs_port;
        gs_unref_array GArray       *external_ids_arr = NULL;
        gs_unref_array GArray       *other_config_arr = NULL;
        const char                  *connection_uuid  = NULL;
        int                          r;

        r = json_unpack(value,
                        "{s:{s:s, s:o, s:o, s:o}}",
                        "new",
                        "name",
                        &name,
                        "external_ids",
                        &external_ids,
                        "other_config",
                        &other_config,
                        "interfaces",
                        &items);
        if (r != 0) {
            gpointer unused;

            r = json_unpack(value, "{s:{}}", "old");
            if (r != 0)
                continue;

            if (!g_hash_table_steal_extended(priv->ports, &key, (gpointer *) &ovs_port, &unused))
                continue;

            _LOGT("obj[port:%s]: removed a port: %s%s%s",
                  key,
                  ovs_port->name,
                  NM_PRINT_FMT_QUOTED2(ovs_port->connection_uuid,
                                       ", ",
                                       ovs_port->connection_uuid,
                                       ""));
            _signal_emit_device_removed(self, ovs_port->name, NM_DEVICE_TYPE_OVS_PORT, NULL);
            _free_port(ovs_port);
            continue;
        }

        ovs_port = g_hash_table_lookup(priv->ports, &key);

        if (ovs_port && !nm_streq0(ovs_port->name, name)) {
            if (!g_hash_table_steal(priv->ports, ovs_port))
                nm_assert_not_reached();
            _signal_emit_device_removed(self, ovs_port->name, NM_DEVICE_TYPE_OVS_PORT, NULL);
            nm_clear_pointer(&ovs_port, _free_port);
        }

        _strdict_extract(external_ids, &external_ids_arr);
        connection_uuid =
            _strdict_find_key(external_ids_arr, NM_OVS_EXTERNAL_ID_NM_CONNECTION_UUID);
        _strdict_extract(other_config, &other_config_arr);

        interfaces = _uuids_to_array(items);

        if (ovs_port) {
            gboolean changed = FALSE;

            nm_assert(nm_streq0(ovs_port->name, name));

            changed |= nm_strdup_reset(&ovs_port->name, name);
            changed |= nm_strdup_reset(&ovs_port->connection_uuid, connection_uuid);
            if (nm_strv_ptrarray_cmp(ovs_port->interfaces, interfaces) != 0) {
                NM_SWAP(&ovs_port->interfaces, &interfaces);
                changed = TRUE;
            }
            if (!_strdict_equals(ovs_port->external_ids, external_ids_arr)) {
                NM_SWAP(&ovs_port->external_ids, &external_ids_arr);
                changed = TRUE;
            }
            if (!_strdict_equals(ovs_port->other_config, other_config_arr)) {
                NM_SWAP(&ovs_port->other_config, &other_config_arr);
                changed = TRUE;
            }
            if (changed) {
                gs_free char *strtmp1 = NULL;
                gs_free char *strtmp2 = NULL;

                _LOGT("obj[port:%s]: changed a port: %s%s%s, external-ids=%s, other-config=%s",
                      key,
                      ovs_port->name,
                      NM_PRINT_FMT_QUOTED2(ovs_port->connection_uuid,
                                           ", ",
                                           ovs_port->connection_uuid,
                                           ""),
                      (strtmp1 = _strdict_to_string(ovs_port->external_ids)),
                      (strtmp2 = _strdict_to_string(ovs_port->other_config)));
            }
        } else {
            gs_free char *strtmp1 = NULL;
            gs_free char *strtmp2 = NULL;

            ovs_port  = g_slice_new(OpenvswitchPort);
            *ovs_port = (OpenvswitchPort){
                .port_uuid       = g_strdup(key),
                .name            = g_strdup(name),
                .connection_uuid = g_strdup(connection_uuid),
                .interfaces      = g_steal_pointer(&interfaces),
                .external_ids    = g_steal_pointer(&external_ids_arr),
                .other_config    = g_steal_pointer(&other_config_arr),
            };
            g_hash_table_add(priv->ports, ovs_port);
            _LOGT("obj[port:%s]: added a port: %s%s%s, external-ids=%s, other-config=%s",
                  key,
                  ovs_port->name,
                  NM_PRINT_FMT_QUOTED2(ovs_port->connection_uuid,
                                       ", ",
                                       ovs_port->connection_uuid,
                                       ""),
                  (strtmp1 = _strdict_to_string(ovs_port->external_ids)),
                  (strtmp2 = _strdict_to_string(ovs_port->other_config)));
            _signal_emit_device_added(self, ovs_port->name, NM_DEVICE_TYPE_OVS_PORT, NULL);
        }
    }

    json_object_foreach (bridge, key, value) {
        gs_unref_ptrarray GPtrArray *ports = NULL;
        OpenvswitchBridge           *ovs_bridge;
        gs_unref_array GArray       *external_ids_arr = NULL;
        gs_unref_array GArray       *other_config_arr = NULL;
        const char                  *connection_uuid  = NULL;
        int                          r;

        r = json_unpack(value,
                        "{s:{s:s, s:o, s:o, s:o}}",
                        "new",
                        "name",
                        &name,
                        "external_ids",
                        &external_ids,
                        "other_config",
                        &other_config,
                        "ports",
                        &items);

        if (r != 0) {
            gpointer unused;

            r = json_unpack(value, "{s:{}}", "old");
            if (r != 0)
                continue;

            if (!g_hash_table_steal_extended(priv->bridges,
                                             &key,
                                             (gpointer *) &ovs_bridge,
                                             &unused))
                continue;

            _LOGT("obj[bridge:%s]: removed a bridge: %s%s%s",
                  key,
                  ovs_bridge->name,
                  NM_PRINT_FMT_QUOTED2(ovs_bridge->connection_uuid,
                                       ", ",
                                       ovs_bridge->connection_uuid,
                                       ""));
            _signal_emit_device_removed(self, ovs_bridge->name, NM_DEVICE_TYPE_OVS_BRIDGE, NULL);
            _free_bridge(ovs_bridge);
            continue;
        }

        ovs_bridge = g_hash_table_lookup(priv->bridges, &key);

        if (ovs_bridge && !nm_streq0(ovs_bridge->name, name)) {
            if (!g_hash_table_steal(priv->bridges, ovs_bridge))
                nm_assert_not_reached();
            _signal_emit_device_removed(self, ovs_bridge->name, NM_DEVICE_TYPE_OVS_BRIDGE, NULL);
            nm_clear_pointer(&ovs_bridge, _free_bridge);
        }

        _strdict_extract(external_ids, &external_ids_arr);
        connection_uuid =
            _strdict_find_key(external_ids_arr, NM_OVS_EXTERNAL_ID_NM_CONNECTION_UUID);
        _strdict_extract(other_config, &other_config_arr);

        ports = _uuids_to_array(items);

        if (ovs_bridge) {
            gboolean changed = FALSE;

            nm_assert(nm_streq0(ovs_bridge->name, name));

            changed = nm_strdup_reset(&ovs_bridge->name, name);
            changed = nm_strdup_reset(&ovs_bridge->connection_uuid, connection_uuid);
            if (nm_strv_ptrarray_cmp(ovs_bridge->ports, ports) != 0) {
                NM_SWAP(&ovs_bridge->ports, &ports);
                changed = TRUE;
            }
            if (!_strdict_equals(ovs_bridge->external_ids, external_ids_arr)) {
                NM_SWAP(&ovs_bridge->external_ids, &external_ids_arr);
                changed = TRUE;
            }
            if (!_strdict_equals(ovs_bridge->other_config, other_config_arr)) {
                NM_SWAP(&ovs_bridge->other_config, &other_config_arr);
                changed = TRUE;
            }
            if (changed) {
                gs_free char *strtmp1 = NULL;
                gs_free char *strtmp2 = NULL;

                _LOGT("obj[bridge:%s]: changed a bridge: %s%s%s, external-ids=%s, other-config=%s",
                      key,
                      ovs_bridge->name,
                      NM_PRINT_FMT_QUOTED2(ovs_bridge->connection_uuid,
                                           ", ",
                                           ovs_bridge->connection_uuid,
                                           ""),
                      (strtmp1 = _strdict_to_string(ovs_bridge->external_ids)),
                      (strtmp2 = _strdict_to_string(ovs_bridge->external_ids)));
            }
        } else {
            gs_free char *strtmp1 = NULL;
            gs_free char *strtmp2 = NULL;

            ovs_bridge  = g_slice_new(OpenvswitchBridge);
            *ovs_bridge = (OpenvswitchBridge){
                .bridge_uuid     = g_strdup(key),
                .name            = g_strdup(name),
                .connection_uuid = g_strdup(connection_uuid),
                .ports           = g_steal_pointer(&ports),
                .external_ids    = g_steal_pointer(&external_ids_arr),
                .other_config    = g_steal_pointer(&other_config_arr),
            };
            g_hash_table_add(priv->bridges, ovs_bridge);
            _LOGT("obj[bridge:%s]: added a bridge: %s%s%s, external-ids=%s, other-config=%s",
                  key,
                  ovs_bridge->name,
                  NM_PRINT_FMT_QUOTED2(ovs_bridge->connection_uuid,
                                       ", ",
                                       ovs_bridge->connection_uuid,
                                       ""),
                  (strtmp1 = _strdict_to_string(ovs_bridge->external_ids)),
                  (strtmp2 = _strdict_to_string(ovs_bridge->other_config)));
            _signal_emit_device_added(self, ovs_bridge->name, NM_DEVICE_TYPE_OVS_BRIDGE, NULL);
        }
    }
}

/**
 * ovsdb_got_echo:
 *
 * Only implemented because the specification mandates it. Actual ovsdb hasn't been
 * seen doing this.
 */
static void
ovsdb_got_echo(NMOvsdb *self, json_int_t id, json_t *data)
{
    NMOvsdbPrivate             *priv  = NM_OVSDB_GET_PRIVATE(self);
    nm_auto_decref_json json_t *msg   = NULL;
    nm_auto_free char          *reply = NULL;

    msg   = json_pack("{s:I, s:O}", "id", id, "result", data);
    reply = json_dumps(msg, 0);

    _LOGT("send: echo: %s", reply);

    nm_str_buf_append(&priv->output_buf, reply);

    ovsdb_write_try(self);
}

/**
 * ovsdb_got_msg::
 *
 * Called when a complete JSON object was seen and unmarshalled.
 * Either finishes a method call or processes a method call.
 */
static void
ovsdb_got_msg(NMOvsdb *self, json_t *msg)
{
    NMOvsdbPrivate *priv       = NM_OVSDB_GET_PRIVATE(self);
    json_error_t    json_error = {
        0,
    };
    json_t     *json_id = NULL;
    json_int_t  id      = (json_int_t) -1;
    const char *method  = NULL;
    json_t     *params  = NULL;
    json_t     *result  = NULL;
    json_t     *error   = NULL;

    if (json_unpack_ex(msg,
                       &json_error,
                       0,
                       "{s?:o, s?:s, s?:o, s?:o, s?:o}",
                       "id",
                       &json_id,
                       "method",
                       &method,
                       "params",
                       &params,
                       "result",
                       &result,
                       "error",
                       &error)
        == -1) {
        _LOGW("couldn't grok the message: %s", json_error.text);
        ovsdb_disconnect(self, FALSE, FALSE);
        return;
    }

    if (json_is_number(json_id))
        id = json_integer_value(json_id);

    if (method) {
        /* It's a method call! */
        if (!params) {
            _LOGW("a method call with no params: '%s'", method);
            ovsdb_disconnect(self, FALSE, FALSE);
            return;
        }

        if (nm_streq0(method, "update")) {
            /* This is a update method call. */
            ovsdb_got_update(self, json_array_get(params, 1));
        } else if (nm_streq0(method, "echo")) {
            /* This is an echo request. */
            ovsdb_got_echo(self, id, params);
        } else {
            _LOGW("got an unknown method call: '%s'", method);
        }
        return;
    }

    if (id >= 0) {
        OvsdbMethodCall      *call;
        gs_free_error GError *local      = NULL;
        gs_free char         *msg_as_str = NULL;

        /* This is a response to a method call. */
        if (c_list_is_empty(&priv->calls_lst_head)) {
            _LOGW("there are no queued calls expecting response %" G_GUINT64_FORMAT, (guint64) id);
            ovsdb_disconnect(self, FALSE, FALSE);
            return;
        }
        call = c_list_first_entry(&priv->calls_lst_head, OvsdbMethodCall, calls_lst);
        if (call->call_id != id) {
            _LOGW("expected a response to call %" G_GUINT64_FORMAT ", not %" G_GUINT64_FORMAT,
                  call->call_id,
                  (guint64) id);
            ovsdb_disconnect(self, FALSE, FALSE);
            return;
        }
        /* Cool, we found a corresponding call. Finish it. */

        _LOGT_call(call, "response: %s", (msg_as_str = json_dumps(msg, 0)));

        if (!json_is_null(error)) {
            /* The response contains an error. */
            g_set_error(&local,
                        G_IO_ERROR,
                        G_IO_ERROR_FAILED,
                        "Error call to OVSDB returned an error: %s",
                        json_string_value(error));
        }

        _call_complete(call, result, local);

        priv->num_failures = 0;

        /* Don't progress further commands in case the callback hit an error
         * and disconnected us. */
        if (priv->conn_fd < 0)
            return;

        /* Now we're free to serialize and send the next command, if any. */
        ovsdb_next_command(self);

        return;
    }

    /* This is a message we are not interested in. */
    _LOGW("got an unknown message, ignoring");
}

/*****************************************************************************/

typedef struct {
    gsize     bufp;
    NMStrBuf *input;
} JsonReadMsgData;

/* Lower level marshalling and demarshalling of the JSON-RPC traffic on the
 * ovsdb socket. */

static size_t
_json_read_msg_cb(void *buffer, size_t buflen, void *user_data)
{
    JsonReadMsgData *data = user_data;

    nm_assert(buffer);
    nm_assert(buflen > 0);

    if (data->bufp == data->input->len) {
        /* No more bytes buffered for decoding. */
        return 0;
    }

    /* Pass one more byte to the JSON decoder. */
    *(char *) buffer = nm_str_buf_get_char(data->input, data->bufp);
    data->bufp++;
    return 1;
}

static json_t *
_json_read_msg(NMOvsdb *self, NMStrBuf *input)
{
    gs_free char   *ss   = NULL;
    JsonReadMsgData data = {
        .bufp  = 0,
        .input = input,
    };
    json_error_t json_error = {
        0,
    };
    json_t *msg;

    /* The callback always eats up only up to a single byte. This makes it
     * possible for us to identify complete JSON objects in spite of us not
     * knowing the length in advance. */
    msg = json_load_callback(_json_read_msg_cb, &data, JSON_DISABLE_EOF_CHECK, &json_error);
    if (!msg)
        return NULL;

    nm_assert(data.bufp > 0);

    _LOGT("json: parse %zu bytes: \"%s\"",
          data.bufp,
          (ss = g_strndup(nm_str_buf_get_str_at_unsafe(input, 0), data.bufp)));

    nm_str_buf_erase(input, 0, data.bufp, FALSE);
    return msg;
}

static gboolean
_ovsdb_read_input_timeout_cb(gpointer user_data)
{
    NMOvsdb        *self = user_data;
    NMOvsdbPrivate *priv = NM_OVSDB_GET_PRIVATE(self);

    _LOGW("invalid/incomplete data in receive buffer. Reset");
    priv->num_failures++;
    ovsdb_disconnect(self, priv->num_failures <= OVSDB_MAX_FAILURES, FALSE);
    return G_SOURCE_CONTINUE;
}

static void
ovsdb_read(NMOvsdb *self)
{
    NMOvsdbPrivate *priv = NM_OVSDB_GET_PRIVATE(self);
    gssize          size;

again:
    size = nm_utils_fd_read(priv->conn_fd, &priv->input_buf);

    if (size <= 0) {
        if (size == -EAGAIN) {
            if (priv->input_buf.len == 0)
                nm_clear_g_source_inst(&priv->input_timeout_source);
            else if (!priv->input_timeout_source) {
                /* We have data in the buffer but nothing further to read. Schedule a timer,
                 * if we don't get the rest within timeout, it means that the buffer
                 * content is broken (_json_read_msg() cannot extract any data) and
                 * we disconnect. */
                priv->input_timeout_source =
                    nm_g_timeout_add_seconds_source(5, _ovsdb_read_input_timeout_cb, NULL);
            }
            return;
        }

        /* ovsdb-server was possibly restarted */
        _LOGW("short read from ovsdb: %s", nm_strerror_native(-size));
        priv->num_failures++;
        ovsdb_disconnect(self, priv->num_failures <= OVSDB_MAX_FAILURES, FALSE);
        return;
    }

    nm_assert(priv->input_buf.len > 0);

    while (TRUE) {
        nm_auto_decref_json json_t *msg = NULL;

        msg = _json_read_msg(self, &priv->input_buf);
        if (!msg)
            break;

        nm_clear_g_source_inst(&priv->input_timeout_source);
        ovsdb_got_msg(self, msg);

        if (priv->input_buf.len == 0)
            break;
    }

    if (priv->input_buf.len > 0) {
        if (priv->input_buf.len > 50 * 1024 * 1024) {
            _LOGW("received too much data from ovsdb that is not valid JSON");
            priv->num_failures++;
            ovsdb_disconnect(self, priv->num_failures <= OVSDB_MAX_FAILURES, FALSE);
            return;
        }
        /* We have an incomplete message in the message buffer. Don't wait for another round
         * of "poll", instead try to read it again. */
        goto again;
    }

    nm_clear_g_source_inst(&priv->input_timeout_source);
}

static gboolean
ovsdb_read_cb(int fd, GIOCondition condition, gpointer user_data)
{
    ovsdb_read(user_data);
    return G_SOURCE_CONTINUE;
}

static void
ovsdb_write(NMOvsdb *self)
{
    NMOvsdbPrivate *priv = NM_OVSDB_GET_PRIVATE(self);
    gssize          n;

again:
    if (priv->output_buf.len == 0) {
        nm_clear_g_source_inst(&priv->conn_fd_out_source);
        return;
    }

    n = write(priv->conn_fd,
              nm_str_buf_get_str_at_unsafe(&priv->output_buf, 0),
              priv->output_buf.len);

    if (n < 0)
        n = -NM_ERRNO_NATIVE(errno);

    if (n == -EAGAIN) {
        if (!priv->conn_fd_out_source) {
            priv->conn_fd_out_source =
                nm_g_unix_fd_add_source(priv->conn_fd, G_IO_OUT, ovsdb_write_cb, self);
        }
        return;
    }

    if (n <= 0) {
        /* ovsdb-server was possibly restarted */
        _LOGW("short write to ovsdb: %s", nm_strerror_native(-n));
        priv->num_failures++;
        ovsdb_disconnect(self, priv->num_failures <= OVSDB_MAX_FAILURES, FALSE);
        return;
    }

    nm_str_buf_erase(&priv->output_buf, 0, n, FALSE);
    goto again;
}

static void
ovsdb_write_try(NMOvsdb *self)
{
    NMOvsdbPrivate *priv = NM_OVSDB_GET_PRIVATE(self);

    if (priv->conn_fd >= 0 && !priv->conn_fd_out_source)
        ovsdb_write(self);
}

static gboolean
ovsdb_write_cb(int fd, GIOCondition condition, gpointer user_data)
{
    ovsdb_write(user_data);
    return G_SOURCE_CONTINUE;
}

/*****************************************************************************/

/* Routines to maintain the ovsdb connection. */

/**
 * ovsdb_disconnect:
 *
 * Clean up the internal state to the point equivalent to before connecting.
 * Apart from clean shutdown this is a good response to unexpected trouble,
 * since the next method call attempt a will trigger reconnect which hopefully
 * puts us back in sync.
 */
static void
ovsdb_disconnect(NMOvsdb *self, gboolean retry, gboolean is_disposing)
{
    NMOvsdbPrivate  *priv = NM_OVSDB_GET_PRIVATE(self);
    OvsdbMethodCall *call;

    nm_assert(!retry || !is_disposing);

    if (priv->conn_fd < 0 && !priv->conn_cancellable)
        return;

    _LOGD("disconnecting from ovsdb, retry %d", retry);

    /* FIXME(shutdown): NMOvsdb should process the pending calls before
     * shutting down, and cancel the remaining calls after the timeout. */

    if (retry) {
        if (!c_list_is_empty(&priv->calls_lst_head)) {
            call          = c_list_first_entry(&priv->calls_lst_head, OvsdbMethodCall, calls_lst);
            call->call_id = CALL_ID_UNSPEC;
        }
    } else {
        gs_free_error GError *error = NULL;

        if (is_disposing)
            nm_utils_error_set_cancelled(&error, is_disposing, "NMOvsdb");
        else
            nm_utils_error_set(&error, NM_UTILS_ERROR_NOT_READY, "disconnected from ovsdb");
        while ((call = c_list_last_entry(&priv->calls_lst_head, OvsdbMethodCall, calls_lst)))
            _call_complete(call, NULL, error);
    }

    nm_str_buf_reset(&priv->input_buf);
    nm_str_buf_reset(&priv->output_buf);
    nm_clear_fd(&priv->conn_fd);
    nm_clear_g_source_inst(&priv->conn_fd_in_source);
    nm_clear_g_source_inst(&priv->conn_fd_out_source);
    nm_clear_g_source_inst(&priv->input_timeout_source);
    nm_clear_g_free(&priv->db_uuid);
    nm_clear_g_cancellable(&priv->conn_cancellable);

    if (retry)
        ovsdb_try_connect(self);
}

static void
cleanup_emit_ready(NMOvsdb *self, const char *reason)
{
    NMOvsdbPrivate *priv = NM_OVSDB_GET_PRIVATE(self);

    _LOGT("cleanup: ready (%s)", reason);

    nm_clear_pointer(&priv->cleanup.interfaces, g_ptr_array_unref);
    nm_clear_g_source_inst(&priv->cleanup.timeout_source);
    nm_clear_g_signal_handler(priv->platform, &priv->cleanup.link_changed_id);

    priv->ready = TRUE;
    g_signal_emit(self, signals[READY], 0);
    nm_manager_unblock_failed_ovs_interfaces(nm_manager_get());
}

static gboolean
cleanup_timeout(NMOvsdb *self)
{
    cleanup_emit_ready(self, "timeout");
    return G_SOURCE_CONTINUE;
}

static void
cleanup_link_cb(NMPlatform     *platform,
                int             obj_type_i,
                int             ifindex,
                NMPlatformLink *plink,
                int             change_type_i,
                gpointer        user_data)
{
    const NMPlatformSignalChangeType change_type = change_type_i;

    if (change_type != NM_PLATFORM_SIGNAL_REMOVED)
        return;

    cleanup_check_ready(user_data);
}

static void
cleanup_check_ready(NMOvsdb *self)
{
    NMOvsdbPrivate *priv = NM_OVSDB_GET_PRIVATE(self);
    guint           i    = 0;

    nm_assert(!priv->ready);

    if (priv->cleanup.num_pending_del > 0)
        return;

    /* After we have deleted an interface from ovsdb, the link will stay
     * in platform until ovs-vswitch removes it. To avoid race conditions,
     * we need to wait until the link goes away; otherwise, after adding the
     * interface again, these race conditions can happen:
     * 1) we see the link in platform, and proceed with activation. But after
     *    that, ovs-vswitchd reads the updates from ovsdb-server and deletes/recreates
     *    the link.
     * 2) ovs-vswitch combines the delete/insert of the interface to a no-op. NM sees
     *    the link staying in platform, but doesn't know whether the link is ready
     *    or we are again in case 1)
     * In other words, it's necessary to wait that the link goes away before inserting
     * the interface again.
     */
    while (i < nm_g_ptr_array_len(priv->cleanup.interfaces)) {
        const char                  *ifname;
        const NMDedupMultiHeadEntry *pl_links_head_entry;
        NMDedupMultiIter             pliter;
        const NMPlatformLink        *link;
        gboolean                     found = FALSE;

        ifname              = priv->cleanup.interfaces->pdata[i];
        pl_links_head_entry = nm_platform_lookup_link_by_ifname(priv->platform, ifname);
        nmp_cache_iter_for_each_link (&pliter, pl_links_head_entry, &link) {
            if (link->type == NM_LINK_TYPE_OPENVSWITCH
                && nmp_object_is_visible(NMP_OBJECT_UP_CAST(link))) {
                found = TRUE;
                break;
            }
        }

        if (!found) {
            g_ptr_array_remove_index_fast(priv->cleanup.interfaces, i);
            continue;
        }
        i++;
    }

    if (nm_g_ptr_array_len(priv->cleanup.interfaces) == 0) {
        cleanup_emit_ready(self, "all interfaces deleted");
        return;
    }

    _LOGT("cleanup: still waiting for %d interfaces", priv->cleanup.interfaces->len);

    if (priv->cleanup.timeout_source) {
        /* We already registered the timeout/change-callback */
        return;
    }

    priv->cleanup.timeout_source =
        nm_g_timeout_add_seconds_source(6, G_SOURCE_FUNC(cleanup_timeout), self);
    priv->cleanup.link_changed_id = g_signal_connect(priv->platform,
                                                     NM_PLATFORM_SIGNAL_LINK_CHANGED,
                                                     G_CALLBACK(cleanup_link_cb),
                                                     self);
}

static void
cleanup_del_iface_cb(GError *error, gpointer user_data)
{
    NMOvsdb        *self;
    gs_free char   *ifname = NULL;
    NMOvsdbPrivate *priv;

    nm_utils_user_data_unpack(user_data, &self, &ifname);

    if (nm_utils_error_is_cancelled_or_disposing(error))
        return;

    priv = NM_OVSDB_GET_PRIVATE(self);
    nm_assert(priv->cleanup.num_pending_del > 0);
    priv->cleanup.num_pending_del--;

    _LOGD("cleanup: deleted interface '%s': %s %s%s%s, pending %u",
          ifname,
          error ? "error" : "success",
          error ? "(" : "",
          error ? error->message : "",
          error ? ")" : "",
          priv->cleanup.num_pending_del);

    cleanup_check_ready(self);
}

static void
ovsdb_cleanup_initial_interfaces(NMOvsdb *self)
{
    NMOvsdbPrivate             *priv = NM_OVSDB_GET_PRIVATE(self);
    const OpenvswitchInterface *interface;
    NMUtilsUserData            *data;
    GHashTableIter              iter;

    if (priv->ready || priv->cleanup.num_pending_del > 0 || priv->cleanup.interfaces)
        return;

    /* Delete OVS interfaces added by NM. Bridges and ports and
     * not considered because they are deleted automatically
     * when no interface is present. */
    g_hash_table_iter_init(&iter, self->_priv.interfaces);
    while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &interface)) {
        if (!interface->connection_uuid) {
            /* not created by NM, ignore */
            continue;
        }

        if (!priv->cleanup.interfaces)
            priv->cleanup.interfaces = g_ptr_array_new_with_free_func(g_free);
        g_ptr_array_add(priv->cleanup.interfaces, g_strdup(interface->name));

        _LOGD("cleanup: deleting interface '%s'", interface->name);
        priv->cleanup.num_pending_del++;
        data = nm_utils_user_data_pack(self, g_strdup(interface->name));
        nm_ovsdb_del_interface(self, interface->name, cleanup_del_iface_cb, data);
    }

    cleanup_check_ready(self);
}

static void
_monitor_bridges_cb(NMOvsdb *self, json_t *result, GError *error, gpointer user_data)
{
    if (error) {
        if (!nm_utils_error_is_cancelled_or_disposing(error)) {
            _LOGI("%s", error->message);
            ovsdb_disconnect(self, FALSE, FALSE);
        }
        return;
    }

    /* Treat the first response the same as the subsequent "update"
     * messages we eventually get. */
    ovsdb_got_update(self, result);

    ovsdb_cleanup_initial_interfaces(self);
}

static void
_ovsdb_connect_complete_with_fd(NMOvsdb *self, int fd_take)
{
    NMOvsdbPrivate          *priv   = NM_OVSDB_GET_PRIVATE(self);
    gs_unref_object GSocket *socket = NULL;
    gs_free_error GError    *error  = NULL;

    nm_clear_g_cancellable(&priv->conn_cancellable);

    nm_io_fcntl_setfl_update_nonblock(fd_take);

    priv->conn_fd           = nm_steal_fd(&fd_take);
    priv->conn_fd_in_source = nm_g_unix_fd_add_source(priv->conn_fd, G_IO_IN, ovsdb_read_cb, self);

    ovsdb_read(self);
    ovsdb_next_command(self);
}

static void
_ovsdb_connect_priv_helper_cb(int fd_take, GError *error, gpointer user_data)
{
    nm_auto_close int fd = fd_take;
    NMOvsdb          *self;

    if (nm_utils_error_is_cancelled(error))
        return;

    self = user_data;

    if (error) {
        _LOGT("connect: failure to get FD from nm-priv-helper: %s", error->message);
        ovsdb_disconnect(self, FALSE, FALSE);
        return;
    }

    _LOGT("connect: connected successfully with FD from nm-priv-helper");
    _ovsdb_connect_complete_with_fd(self, nm_steal_fd(&fd));
}

static void
_ovsdb_connect_idle(gpointer user_data, GCancellable *cancellable)
{
    NMOvsdb              *self;
    NMOvsdbPrivate       *priv;
    nm_auto_close int     fd    = -1;
    gs_free_error GError *error = NULL;

    if (g_cancellable_is_cancelled(cancellable))
        return;

    self = user_data;
    priv = NM_OVSDB_GET_PRIVATE(self);

    fd = nm_priv_helper_utils_open_fd(NM_PRIV_HELPER_GET_FD_TYPE_OVSDB_SOCKET, &error);
    if (fd == -ENOENT) {
        _LOGT("connect: opening %s failed (\"%s\")", NM_OVSDB_SOCKET, error->message);
        ovsdb_disconnect(self, FALSE, FALSE);
        return;
    }
    if (fd < 0) {
        _LOGT("connect: opening %s failed (\"%s\"). Retry with nm-priv-helper",
              NM_OVSDB_SOCKET,
              error->message);
        nm_priv_helper_call_get_fd(NM_PRIV_HELPER_GET_FD_TYPE_OVSDB_SOCKET,
                                   priv->conn_cancellable,
                                   _ovsdb_connect_priv_helper_cb,
                                   self);
        return;
    }

    _LOGT("connect: opening %s succeeded", NM_OVSDB_SOCKET);
    _ovsdb_connect_complete_with_fd(self, nm_steal_fd(&fd));
}

/**
 * ovsdb_try_connect:
 *
 * Establish a connection to ovsdb unless it's already established or being
 * established. Queues a monitor command as a very first one so that we're in
 * sync when other commands are issued.
 */
static void
ovsdb_try_connect(NMOvsdb *self)
{
    NMOvsdbPrivate *priv = NM_OVSDB_GET_PRIVATE(self);

    if (priv->conn_fd >= 0 || priv->conn_cancellable)
        return;

    _LOGT("connect: start connecting socket %s on idle", NM_OVSDB_SOCKET);
    priv->conn_cancellable = g_cancellable_new();
    nm_utils_invoke_on_idle(priv->conn_cancellable, _ovsdb_connect_idle, self);

    /* Queue a monitor call before any other command, ensuring that we have an up
     * to date view of existing bridged that we need for add and remove ops. */
    ovsdb_call_method(self,
                      _monitor_bridges_cb,
                      NULL,
                      TRUE,
                      OVSDB_MONITOR,
                      OVSDB_METHOD_PAYLOAD_MONITOR());
}

/*****************************************************************************/

/* Public functions useful for NMDeviceOpenvswitch to maintain the life cycle of
 * their ovsdb entries without having to deal with ovsdb complexities themselves. */

typedef struct {
    NMOvsdbCallback callback;
    gpointer        user_data;
} OvsdbCall;

static void
_transact_cb(NMOvsdb *self, json_t *result, GError *error, gpointer user_data)
{
    OvsdbCall            *call  = user_data;
    gs_free_error GError *local = NULL;
    const char           *err;
    const char           *err_details;
    size_t                index;
    json_t               *value;

    if (!error) {
        json_array_foreach (result, index, value) {
            if (json_unpack(value, "{s:s, s:s}", "error", &err, "details", &err_details) == 0) {
                local = g_error_new(G_IO_ERROR,
                                    G_IO_ERROR_FAILED,
                                    "Error running the transaction: %s: %s",
                                    err,
                                    err_details);
                break;
            }
        }
    }

    call->callback(local ?: error, call->user_data);
    nm_g_slice_free(call);
}

static OvsdbCall *
ovsdb_call_new(NMOvsdbCallback callback, gpointer user_data)
{
    OvsdbCall *call;

    call  = g_slice_new(OvsdbCall);
    *call = (OvsdbCall){
        .callback  = callback,
        .user_data = user_data,
    };
    return call;
}

gboolean
nm_ovsdb_is_ready(NMOvsdb *self)
{
    NMOvsdbPrivate *priv = NM_OVSDB_GET_PRIVATE(self);

    return priv->ready;
}

void
nm_ovsdb_add_interface(NMOvsdb        *self,
                       NMConnection   *bridge,
                       NMConnection   *port,
                       NMConnection   *interface,
                       NMDevice       *bridge_device,
                       NMDevice       *interface_device,
                       NMOvsdbCallback callback,
                       gpointer        user_data)
{
    ovsdb_call_method(self,
                      _transact_cb,
                      ovsdb_call_new(callback, user_data),
                      FALSE,
                      OVSDB_ADD_INTERFACE,
                      OVSDB_METHOD_PAYLOAD_ADD_INTERFACE(bridge,
                                                         port,
                                                         interface,
                                                         bridge_device,
                                                         interface_device));
}

void
nm_ovsdb_del_interface(NMOvsdb        *self,
                       const char     *ifname,
                       NMOvsdbCallback callback,
                       gpointer        user_data)
{
    ovsdb_call_method(self,
                      _transact_cb,
                      ovsdb_call_new(callback, user_data),
                      FALSE,
                      OVSDB_DEL_INTERFACE,
                      OVSDB_METHOD_PAYLOAD_DEL_INTERFACE(ifname));
}

void
nm_ovsdb_set_interface_mtu(NMOvsdb        *self,
                           const char     *ifname,
                           guint32         mtu,
                           NMOvsdbCallback callback,
                           gpointer        user_data)
{
    ovsdb_call_method(self,
                      _transact_cb,
                      ovsdb_call_new(callback, user_data),
                      FALSE,
                      OVSDB_SET_INTERFACE_MTU,
                      OVSDB_METHOD_PAYLOAD_SET_INTERFACE_MTU(ifname, mtu));
}

void
nm_ovsdb_set_reapply(NMOvsdb                 *self,
                     NMDeviceType             device_type,
                     const char              *ifname,
                     const char              *connection_uuid,
                     NMSettingOvsExternalIDs *s_external_ids_old,
                     NMSettingOvsExternalIDs *s_external_ids_new,
                     NMSettingOvsOtherConfig *s_other_config_old,
                     NMSettingOvsOtherConfig *s_other_config_new)
{
    gs_unref_hashtable GHashTable *external_ids_old = NULL;
    gs_unref_hashtable GHashTable *external_ids_new = NULL;
    gs_unref_hashtable GHashTable *other_config_old = NULL;
    gs_unref_hashtable GHashTable *other_config_new = NULL;

    external_ids_old =
        s_external_ids_old
            ? nm_strdict_clone(_nm_setting_ovs_external_ids_get_data(s_external_ids_old))
            : NULL;
    external_ids_new =
        s_external_ids_new
            ? nm_strdict_clone(_nm_setting_ovs_external_ids_get_data(s_external_ids_new))
            : NULL;

    other_config_old =
        s_other_config_old
            ? nm_strdict_clone(_nm_setting_ovs_other_config_get_data(s_other_config_old))
            : NULL;
    other_config_new =
        s_other_config_new
            ? nm_strdict_clone(_nm_setting_ovs_other_config_get_data(s_other_config_new))
            : NULL;

    ovsdb_call_method(self,
                      NULL,
                      NULL,
                      FALSE,
                      OVSDB_SET_REAPPLY,
                      OVSDB_METHOD_PAYLOAD_SET_REAPPLY(device_type,
                                                       ifname,
                                                       connection_uuid,
                                                       external_ids_old,
                                                       external_ids_new,
                                                       other_config_old,
                                                       other_config_new));
}

/*****************************************************************************/

static void
nm_ovsdb_init(NMOvsdb *self)
{
    NMOvsdbPrivate *priv = NM_OVSDB_GET_PRIVATE(self);

    priv->conn_fd = -1;

    priv->input_buf  = NM_STR_BUF_INIT(0, FALSE);
    priv->output_buf = NM_STR_BUF_INIT(0, FALSE);

    c_list_init(&priv->calls_lst_head);

    priv->platform = g_object_ref(NM_PLATFORM_GET);

    priv->bridges =
        g_hash_table_new_full(nm_pstr_hash, nm_pstr_equal, (GDestroyNotify) _free_bridge, NULL);
    priv->ports =
        g_hash_table_new_full(nm_pstr_hash, nm_pstr_equal, (GDestroyNotify) _free_port, NULL);
    priv->interfaces =
        g_hash_table_new_full(nm_pstr_hash, nm_pstr_equal, (GDestroyNotify) _free_interface, NULL);

    ovsdb_try_connect(self);
}

static void
dispose(GObject *object)
{
    NMOvsdb        *self = NM_OVSDB(object);
    NMOvsdbPrivate *priv = NM_OVSDB_GET_PRIVATE(self);

    ovsdb_disconnect(self, FALSE, TRUE);

    nm_assert(c_list_is_empty(&priv->calls_lst_head));

    nm_str_buf_destroy(&priv->input_buf);
    nm_str_buf_destroy(&priv->output_buf);

    g_clear_object(&priv->platform);
    nm_clear_pointer(&priv->bridges, g_hash_table_destroy);
    nm_clear_pointer(&priv->ports, g_hash_table_destroy);
    nm_clear_pointer(&priv->interfaces, g_hash_table_destroy);

    G_OBJECT_CLASS(nm_ovsdb_parent_class)->dispose(object);
}

static void
nm_ovsdb_class_init(NMOvsdbClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS(klass);

    object_class->dispose = dispose;

    signals[DEVICE_ADDED] = g_signal_new(NM_OVSDB_DEVICE_ADDED,
                                         G_OBJECT_CLASS_TYPE(object_class),
                                         G_SIGNAL_RUN_LAST,
                                         0,
                                         NULL,
                                         NULL,
                                         NULL,
                                         G_TYPE_NONE,
                                         3,
                                         G_TYPE_STRING,
                                         G_TYPE_UINT,
                                         G_TYPE_STRING);

    signals[DEVICE_REMOVED] = g_signal_new(NM_OVSDB_DEVICE_REMOVED,
                                           G_OBJECT_CLASS_TYPE(object_class),
                                           G_SIGNAL_RUN_LAST,
                                           0,
                                           NULL,
                                           NULL,
                                           NULL,
                                           G_TYPE_NONE,
                                           3,
                                           G_TYPE_STRING,
                                           G_TYPE_UINT,
                                           G_TYPE_STRING);

    signals[INTERFACE_FAILED] = g_signal_new(NM_OVSDB_INTERFACE_FAILED,
                                             G_OBJECT_CLASS_TYPE(object_class),
                                             G_SIGNAL_RUN_LAST,
                                             0,
                                             NULL,
                                             NULL,
                                             NULL,
                                             G_TYPE_NONE,
                                             3,
                                             G_TYPE_STRING,
                                             G_TYPE_STRING,
                                             G_TYPE_STRING);

    signals[READY] = g_signal_new(NM_OVSDB_READY,
                                  G_OBJECT_CLASS_TYPE(object_class),
                                  G_SIGNAL_RUN_LAST,
                                  0,
                                  NULL,
                                  NULL,
                                  NULL,
                                  G_TYPE_NONE,
                                  0);
}
