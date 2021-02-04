/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-ovsdb.h"

#include <gmodule.h>
#include <gio/gunixsocketaddress.h>

#include "nm-glib-aux/nm-jansson.h"
#include "nm-glib-aux/nm-str-buf.h"
#include "nm-core-utils.h"
#include "nm-core-internal.h"
#include "devices/nm-device.h"
#include "nm-manager.h"
#include "nm-setting-ovs-external-ids.h"

/*****************************************************************************/

#define OVSDB_MAX_FAILURES 3

/*****************************************************************************/

#if JANSSON_VERSION_HEX < 0x020400
    #warning "requires at least libjansson 2.4"
#endif

typedef struct {
    char *     port_uuid;
    char *     name;
    char *     connection_uuid;
    GPtrArray *interfaces; /* interface uuids */
    GArray *   external_ids;
} OpenvswitchPort;

typedef struct {
    char *     bridge_uuid;
    char *     name;
    char *     connection_uuid;
    GPtrArray *ports; /* port uuids */
    GArray *   external_ids;
} OpenvswitchBridge;

typedef struct {
    char *  interface_uuid;
    char *  name;
    char *  type;
    char *  connection_uuid;
    GArray *external_ids;
} OpenvswitchInterface;

/*****************************************************************************/

typedef void (*OvsdbMethodCallback)(NMOvsdb *self,
                                    json_t * response,
                                    GError * error,
                                    gpointer user_data);

typedef enum {
    OVSDB_MONITOR,
    OVSDB_ADD_INTERFACE,
    OVSDB_DEL_INTERFACE,
    OVSDB_SET_INTERFACE_MTU,
    OVSDB_SET_EXTERNAL_IDS,
} OvsdbCommand;

#define CALL_ID_UNSPEC G_MAXUINT64

typedef union {
    struct {
    } monitor;
    struct {
        NMConnection *bridge;
        NMConnection *port;
        NMConnection *interface;
        NMDevice *    bridge_device;
        NMDevice *    interface_device;
    } add_interface;
    struct {
        char *ifname;
    } del_interface;
    struct {
        char *  ifname;
        guint32 mtu;
    } set_interface_mtu;
    struct {
        NMDeviceType device_type;
        char *       ifname;
        char *       connection_uuid;
        GHashTable * exid_old;
        GHashTable * exid_new;
    } set_external_ids;
} OvsdbMethodPayload;

typedef struct {
    NMOvsdb *           self;
    CList               calls_lst;
    guint64             call_id;
    OvsdbCommand        command;
    OvsdbMethodCallback callback;
    gpointer            user_data;
    OvsdbMethodPayload  payload;
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
    GSocketClient *    client;
    GSocketConnection *conn;
    GCancellable *     cancellable;
    char               buf[4096]; /* Input buffer */
    size_t             bufp;      /* Last decoded byte in the input buffer. */
    GString *          input;     /* JSON stream waiting for decoding. */
    GString *          output;    /* JSON stream to be sent. */
    guint64            call_id_counter;

    CList calls_lst_head;

    GHashTable *interfaces; /* interface uuid => OpenvswitchInterface */
    GHashTable *ports;      /* port uuid => OpenvswitchPort */
    GHashTable *bridges;    /* bridge uuid => OpenvswitchBridge */
    char *      db_uuid;
    guint       num_failures;
    guint       num_pending_deletions;
    bool        ready : 1;
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

static void ovsdb_try_connect(NMOvsdb *self);
static void ovsdb_disconnect(NMOvsdb *self, gboolean retry, gboolean is_disposing);
static void ovsdb_read(NMOvsdb *self);
static void ovsdb_write(NMOvsdb *self);
static void ovsdb_next_command(NMOvsdb *self);

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

#define OVSDB_METHOD_PAYLOAD_SET_EXTERNAL_IDS(xdevice_type,                         \
                                              xifname,                              \
                                              xconnection_uuid,                     \
                                              xexid_old,                            \
                                              xexid_new)                            \
    (&((const OvsdbMethodPayload){                                                  \
        .set_external_ids =                                                         \
            {                                                                       \
                .device_type     = xdevice_type,                                    \
                .ifname          = (char *) NM_CONSTCAST(char, (xifname)),          \
                .connection_uuid = (char *) NM_CONSTCAST(char, (xconnection_uuid)), \
                .exid_old        = (xexid_old),                                     \
                .exid_new        = (xexid_new),                                     \
            },                                                                      \
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
    case OVSDB_SET_EXTERNAL_IDS:
        nm_clear_g_free(&call->payload.set_external_ids.ifname);
        nm_clear_g_free(&call->payload.set_external_ids.connection_uuid);
        nm_clear_pointer(&call->payload.set_external_ids.exid_old, g_hash_table_destroy);
        nm_clear_pointer(&call->payload.set_external_ids.exid_new, g_hash_table_destroy);
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
    nm_g_slice_free(ovs_interface);
}

/*****************************************************************************/

static void
_signal_emit_device_added(NMOvsdb *    self,
                          const char * name,
                          NMDeviceType device_type,
                          const char * device_subtype)
{
    g_signal_emit(self, signals[DEVICE_ADDED], 0, name, (guint) device_type, device_subtype);
}

static void
_signal_emit_device_removed(NMOvsdb *    self,
                            const char * name,
                            NMDeviceType device_type,
                            const char * device_subtype)
{
    g_signal_emit(self, signals[DEVICE_REMOVED], 0, name, (guint) device_type, device_subtype);
}

static void
_signal_emit_interface_failed(NMOvsdb *   self,
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
ovsdb_call_method(NMOvsdb *                 self,
                  OvsdbMethodCallback       callback,
                  gpointer                  user_data,
                  gboolean                  add_first,
                  OvsdbCommand              command,
                  const OvsdbMethodPayload *payload)
{
    NMOvsdbPrivate * priv = NM_OVSDB_GET_PRIVATE(self);
    OvsdbMethodCall *call;

    /* Ensure we're not unsynchronized before we queue the method call. */
    ovsdb_try_connect(self);

    call  = g_slice_new(OvsdbMethodCall);
    *call = (OvsdbMethodCall){
        .self      = self,
        .call_id   = CALL_ID_UNSPEC,
        .command   = command,
        .callback  = callback,
        .user_data = user_data,
    };

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
    case OVSDB_SET_EXTERNAL_IDS:
        call->payload.set_external_ids.device_type = payload->set_external_ids.device_type;
        call->payload.set_external_ids.ifname      = g_strdup(payload->set_external_ids.ifname);
        call->payload.set_external_ids.connection_uuid =
            g_strdup(payload->set_external_ids.connection_uuid);
        call->payload.set_external_ids.exid_old =
            nm_g_hash_table_ref(payload->set_external_ids.exid_old);
        call->payload.set_external_ids.exid_new =
            nm_g_hash_table_ref(payload->set_external_ids.exid_new);
        _LOGT_call(call,
                   "new: set-external-ids con-uuid=%s, interface=%s",
                   call->payload.set_external_ids.connection_uuid,
                   call->payload.set_external_ids.ifname);
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
    json_array_append_new(params,
                          json_pack("{s:s, s:s, s:{s:[s, [[s, s]]]}, s:[[s, s, s]]}",
                                    "op",
                                    "update",
                                    "table",
                                    "Bridge",
                                    "row",
                                    "other_config",
                                    "map",
                                    "hwaddr",
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
_j_create_external_ids_array_new(NMConnection *connection)
{
    json_t *                 array;
    const char *const *      external_ids   = NULL;
    guint                    n_external_ids = 0;
    guint                    i;
    const char *             uuid;
    NMSettingOvsExternalIDs *s_exid;

    nm_assert(NM_IS_CONNECTION(connection));

    array = json_array();

    uuid = nm_connection_get_uuid(connection);
    nm_assert(uuid);
    json_array_append_new(array, json_pack("[s, s]", NM_OVS_EXTERNAL_ID_NM_CONNECTION_UUID, uuid));

    s_exid = _nm_connection_get_setting(connection, NM_TYPE_SETTING_OVS_EXTERNAL_IDS);
    if (s_exid)
        external_ids = nm_setting_ovs_external_ids_get_data_keys(s_exid, &n_external_ids);
    for (i = 0; i < n_external_ids; i++) {
        const char *k = external_ids[i];

        json_array_append_new(
            array,
            json_pack("[s, s]", k, nm_setting_ovs_external_ids_get_data(s_exid, k)));
    }

    return json_pack("[s, o]", "map", array);
}

static json_t *
_j_create_external_ids_array_update(const char *connection_uuid,
                                    GHashTable *exid_old,
                                    GHashTable *exid_new)
{
    GHashTableIter iter;
    json_t *       mutations;
    json_t *       array;
    const char *   key;
    const char *   val;

    nm_assert(connection_uuid);

    mutations = json_array();

    if (exid_old) {
        array = NULL;
        g_hash_table_iter_init(&iter, exid_old);
        while (g_hash_table_iter_next(&iter, (gpointer *) &key, NULL)) {
            if (nm_g_hash_table_contains(exid_new, key))
                continue;
            if (NM_STR_HAS_PREFIX(key, NM_OVS_EXTERNAL_ID_NM_PREFIX))
                continue;

            if (!array)
                array = json_array();

            json_array_append_new(array, json_string(key));
        }
        if (array) {
            json_array_append_new(
                mutations,
                json_pack("[s, s, [s, o]]", "external_ids", "delete", "set", array));
        }
    }

    array = json_array();

    json_array_append_new(
        array,
        json_pack("[s, s]", NM_OVS_EXTERNAL_ID_NM_CONNECTION_UUID, connection_uuid));

    if (exid_new) {
        g_hash_table_iter_init(&iter, exid_new);
        while (g_hash_table_iter_next(&iter, (gpointer *) &key, (gpointer *) &val)) {
            if (NM_STR_HAS_PREFIX(key, NM_OVS_EXTERNAL_ID_NM_PREFIX))
                continue;
            json_array_append_new(array, json_pack("[s, s]", key, val));
        }
    }

    json_array_append_new(mutations,
                          json_pack("[s, s, [s, o]]", "external_ids", "insert", "map", array));
    return mutations;
}

/**
 * _insert_interface:
 *
 * Returns an commands that adds new interface from a given connection.
 */
static void
_insert_interface(json_t *      params,
                  NMConnection *interface,
                  NMDevice *    interface_device,
                  const char *  cloned_mac)
{
    const char *           type = NULL;
    NMSettingOvsInterface *s_ovs_iface;
    NMSettingOvsDpdk *     s_ovs_dpdk;
    NMSettingOvsPatch *    s_ovs_patch;
    json_t *               options = json_array();
    json_t *               row;
    guint32                mtu = 0;

    s_ovs_iface = nm_connection_get_setting_ovs_interface(interface);
    if (s_ovs_iface)
        type = nm_setting_ovs_interface_get_interface_type(s_ovs_iface);

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
        json_array_append_new(
            options,
            json_pack("[[s, s]]", "dpdk-devargs", nm_setting_ovs_dpdk_get_devargs(s_ovs_dpdk)));
    } else if (s_ovs_patch) {
        json_array_append_new(
            options,
            json_pack("[[s, s]]", "peer", nm_setting_ovs_patch_get_peer(s_ovs_patch)));
    } else {
        json_array_append_new(options, json_array());
    }

    row = json_pack("{s:s, s:s, s:o, s:o}",
                    "name",
                    nm_connection_get_interface_name(interface),
                    "type",
                    type ?: "",
                    "options",
                    options,
                    "external_ids",
                    _j_create_external_ids_array_new(interface));

    if (cloned_mac)
        json_object_set_new(row, "mac", json_string(cloned_mac));

    if (mtu != 0)
        json_object_set_new(row, "mtu_request", json_integer(mtu));

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
    const char *      vlan_mode      = NULL;
    guint             tag            = 0;
    const char *      lacp           = NULL;
    const char *      bond_mode      = NULL;
    guint             bond_updelay   = 0;
    guint             bond_downdelay = 0;
    json_t *          row;

    s_ovs_port = nm_connection_get_setting_ovs_port(port);

    row = json_object();

    if (s_ovs_port) {
        vlan_mode      = nm_setting_ovs_port_get_vlan_mode(s_ovs_port);
        tag            = nm_setting_ovs_port_get_tag(s_ovs_port);
        lacp           = nm_setting_ovs_port_get_lacp(s_ovs_port);
        bond_mode      = nm_setting_ovs_port_get_bond_mode(s_ovs_port);
        bond_updelay   = nm_setting_ovs_port_get_bond_updelay(s_ovs_port);
        bond_downdelay = nm_setting_ovs_port_get_bond_downdelay(s_ovs_port);
    }

    if (vlan_mode)
        json_object_set_new(row, "vlan_mode", json_string(vlan_mode));
    if (tag)
        json_object_set_new(row, "tag", json_integer(tag));
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
    json_object_set_new(row, "external_ids", _j_create_external_ids_array_new(port));

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
_insert_bridge(json_t *      params,
               NMConnection *bridge,
               NMDevice *    bridge_device,
               json_t *      new_ports,
               const char *  cloned_mac)
{
    NMSettingOvsBridge *s_ovs_bridge;
    const char *        fail_mode             = NULL;
    gboolean            mcast_snooping_enable = FALSE;
    gboolean            rstp_enable           = FALSE;
    gboolean            stp_enable            = FALSE;
    const char *        datapath_type         = NULL;
    json_t *            row;

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
    json_object_set_new(row, "external_ids", _j_create_external_ids_array_new(bridge));

    if (cloned_mac) {
        json_object_set_new(row,
                            "other_config",
                            json_pack("[s, [[s, s]]]", "map", "hwaddr", cloned_mac));
    }

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
_add_interface(NMOvsdb *     self,
               json_t *      params,
               NMConnection *bridge,
               NMConnection *port,
               NMConnection *interface,
               NMDevice *    bridge_device,
               NMDevice *    interface_device)
{
    NMOvsdbPrivate *      priv = NM_OVSDB_GET_PRIVATE(self);
    GHashTableIter        iter;
    const char *          port_uuid;
    const char *          interface_uuid;
    const char *          bridge_name;
    const char *          port_name;
    const char *          interface_name;
    OpenvswitchBridge *   ovs_bridge           = NULL;
    OpenvswitchPort *     ovs_port             = NULL;
    OpenvswitchInterface *ovs_interface        = NULL;
    nm_auto_decref_json json_t *bridges        = NULL;
    nm_auto_decref_json json_t *new_bridges    = NULL;
    nm_auto_decref_json json_t *ports          = NULL;
    nm_auto_decref_json json_t *new_ports      = NULL;
    nm_auto_decref_json json_t *interfaces     = NULL;
    nm_auto_decref_json json_t *new_interfaces = NULL;
    gboolean                    has_interface  = FALSE;
    gboolean                    interface_is_local;
    gs_free char *              bridge_cloned_mac    = NULL;
    gs_free char *              interface_cloned_mac = NULL;
    GError *                    error                = NULL;
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
    NMOvsdbPrivate *      priv = NM_OVSDB_GET_PRIVATE(self);
    GHashTableIter        iter;
    char *                port_uuid;
    char *                interface_uuid;
    OpenvswitchBridge *   ovs_bridge;
    OpenvswitchPort *     ovs_port;
    OpenvswitchInterface *ovs_interface;
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
    NMOvsdbPrivate *    priv = NM_OVSDB_GET_PRIVATE(self);
    OvsdbMethodCall *   call;
    char *              cmd;
    nm_auto_decref_json json_t *msg = NULL;

    if (!priv->conn)
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
                        "  s:[{s:[s, s, s]}],"
                        "  s:[{s:[s, s, s]}],"
                        "  s:[{s:[s, s, s, s]}],"
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
                        "Port",
                        "columns",
                        "name",
                        "interfaces",
                        "external_ids",
                        "Interface",
                        "columns",
                        "name",
                        "type",
                        "external_ids",
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
        case OVSDB_SET_EXTERNAL_IDS:
            json_array_append_new(
                params,
                json_pack("{s:s, s:s, s:o, s:[[s, s, s]]}",
                          "op",
                          "mutate",
                          "table",
                          _device_type_to_table(call->payload.set_external_ids.device_type),
                          "mutations",
                          _j_create_external_ids_array_update(
                              call->payload.set_external_ids.connection_uuid,
                              call->payload.set_external_ids.exid_old,
                              call->payload.set_external_ids.exid_new),
                          "where",
                          "name",
                          "==",
                          call->payload.set_external_ids.ifname));
            break;

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
    g_string_append(priv->output, cmd);
    free(cmd);

    ovsdb_write(self);
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
    json_t *    value;
    size_t      index = 0;
    json_t *    set_value;
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
_external_ids_extract(json_t *external_ids, GArray **out_array, const char **out_connection_uuid)
{
    json_t *array;
    json_t *value;
    gsize   index;

    nm_assert(out_array && !*out_array);
    nm_assert(!out_connection_uuid || !*out_connection_uuid);

    if (!nm_streq0("map", json_string_value(json_array_get(external_ids, 0))))
        return;

    array = json_array_get(external_ids, 1);

    json_array_foreach (array, index, value) {
        const char *       key = json_string_value(json_array_get(value, 0));
        const char *       val = json_string_value(json_array_get(value, 1));
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

        if (out_connection_uuid && nm_streq(v->name, NM_OVS_EXTERNAL_ID_NM_CONNECTION_UUID)) {
            *out_connection_uuid = v->value_str;
            out_connection_uuid  = NULL;
        }
    }
}

static gboolean
_external_ids_equal(const GArray *arr1, const GArray *arr2)
{
    guint n;
    guint i;

    n = nm_g_array_len(arr1);

    if (n != nm_g_array_len(arr2))
        return FALSE;
    for (i = 0; i < n; i++) {
        const NMUtilsNamedValue *n1 = &g_array_index(arr1, NMUtilsNamedValue, i);
        const NMUtilsNamedValue *n2 = &g_array_index(arr2, NMUtilsNamedValue, i);

        if (!nm_streq0(n1->name, n2->name))
            return FALSE;
        if (!nm_streq0(n1->value_str, n2->value_str))
            return FALSE;
    }
    return TRUE;
}

static char *
_external_ids_to_string(const GArray *arr)
{
    NMStrBuf strbuf;
    guint    i;

    if (!arr)
        return g_strdup("empty");

    nm_str_buf_init(&strbuf, NM_UTILS_GET_NEXT_REALLOC_SIZE_104, FALSE);
    nm_str_buf_append(&strbuf, "[");
    for (i = 0; i < arr->len; i++) {
        const NMUtilsNamedValue *n = &g_array_index(arr, NMUtilsNamedValue, i);

        if (i > 0)
            nm_str_buf_append_c(&strbuf, ',');
        nm_str_buf_append_printf(&strbuf, " \"%s\" = \"%s\"]", n->name, n->value_str);
    }
    nm_str_buf_append(&strbuf, " ]");

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
    json_t *        ovs       = NULL;
    json_t *        bridge    = NULL;
    json_t *        port      = NULL;
    json_t *        interface = NULL;
    json_t *        items;
    json_t *        external_ids;
    json_error_t    json_error = {
        0,
    };
    void *      iter;
    const char *name;
    const char *key;
    const char *type;
    json_t *    value;

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
            nm_utils_strdup_reset(&priv->db_uuid, s);
    }

    json_object_foreach (interface, key, value) {
        OpenvswitchInterface *ovs_interface;
        gs_unref_array GArray *external_ids_arr = NULL;
        const char *           connection_uuid  = NULL;
        json_t *               error            = NULL;
        int                    r;

        r = json_unpack(value,
                        "{s:{s:s, s:s, s?:o, s:o}}",
                        "new",
                        "name",
                        &name,
                        "type",
                        &type,
                        "error",
                        &error,
                        "external_ids",
                        &external_ids);
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

        _external_ids_extract(external_ids, &external_ids_arr, &connection_uuid);

        if (ovs_interface) {
            gboolean changed = FALSE;

            nm_assert(nm_streq0(ovs_interface->name, name));

            changed |= nm_utils_strdup_reset(&ovs_interface->type, type);
            changed |= nm_utils_strdup_reset(&ovs_interface->connection_uuid, connection_uuid);
            if (!_external_ids_equal(ovs_interface->external_ids, external_ids_arr)) {
                NM_SWAP(&ovs_interface->external_ids, &external_ids_arr);
                changed = TRUE;
            }
            if (changed) {
                gs_free char *strtmp = NULL;

                _LOGT("obj[iface:%s]: changed an '%s' interface: %s%s%s, external-ids=%s",
                      key,
                      type,
                      ovs_interface->name,
                      NM_PRINT_FMT_QUOTED2(ovs_interface->connection_uuid,
                                           ", ",
                                           ovs_interface->connection_uuid,
                                           ""),
                      (strtmp = _external_ids_to_string(ovs_interface->external_ids)));
            }
        } else {
            gs_free char *strtmp = NULL;

            ovs_interface  = g_slice_new(OpenvswitchInterface);
            *ovs_interface = (OpenvswitchInterface){
                .interface_uuid  = g_strdup(key),
                .name            = g_strdup(name),
                .type            = g_strdup(type),
                .connection_uuid = g_strdup(connection_uuid),
                .external_ids    = g_steal_pointer(&external_ids_arr),
            };
            g_hash_table_add(priv->interfaces, ovs_interface);
            _LOGT("obj[iface:%s]: added an '%s' interface: %s%s%s, external-ids=%s",
                  key,
                  ovs_interface->type,
                  ovs_interface->name,
                  NM_PRINT_FMT_QUOTED2(ovs_interface->connection_uuid,
                                       ", ",
                                       ovs_interface->connection_uuid,
                                       ""),
                  (strtmp = _external_ids_to_string(ovs_interface->external_ids)));
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
        OpenvswitchPort *            ovs_port;
        gs_unref_array GArray *external_ids_arr = NULL;
        const char *           connection_uuid  = NULL;
        int                    r;

        r = json_unpack(value,
                        "{s:{s:s, s:o, s:o}}",
                        "new",
                        "name",
                        &name,
                        "external_ids",
                        &external_ids,
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

        _external_ids_extract(external_ids, &external_ids_arr, &connection_uuid);
        interfaces = _uuids_to_array(items);

        if (ovs_port) {
            gboolean changed = FALSE;

            nm_assert(nm_streq0(ovs_port->name, name));

            changed |= nm_utils_strdup_reset(&ovs_port->name, name);
            changed |= nm_utils_strdup_reset(&ovs_port->connection_uuid, connection_uuid);
            if (nm_strv_ptrarray_cmp(ovs_port->interfaces, interfaces) != 0) {
                NM_SWAP(&ovs_port->interfaces, &interfaces);
                changed = TRUE;
            }
            if (!_external_ids_equal(ovs_port->external_ids, external_ids_arr)) {
                NM_SWAP(&ovs_port->external_ids, &external_ids_arr);
                changed = TRUE;
            }
            if (changed) {
                gs_free char *strtmp = NULL;

                _LOGT("obj[port:%s]: changed a port: %s%s%s, external-ids=%s",
                      key,
                      ovs_port->name,
                      NM_PRINT_FMT_QUOTED2(ovs_port->connection_uuid,
                                           ", ",
                                           ovs_port->connection_uuid,
                                           ""),
                      (strtmp = _external_ids_to_string(ovs_port->external_ids)));
            }
        } else {
            gs_free char *strtmp = NULL;

            ovs_port  = g_slice_new(OpenvswitchPort);
            *ovs_port = (OpenvswitchPort){
                .port_uuid       = g_strdup(key),
                .name            = g_strdup(name),
                .connection_uuid = g_strdup(connection_uuid),
                .interfaces      = g_steal_pointer(&interfaces),
                .external_ids    = g_steal_pointer(&external_ids_arr),
            };
            g_hash_table_add(priv->ports, ovs_port);
            _LOGT("obj[port:%s]: added a port: %s%s%s, external-ids=%s",
                  key,
                  ovs_port->name,
                  NM_PRINT_FMT_QUOTED2(ovs_port->connection_uuid,
                                       ", ",
                                       ovs_port->connection_uuid,
                                       ""),
                  (strtmp = _external_ids_to_string(ovs_port->external_ids)));
            _signal_emit_device_added(self, ovs_port->name, NM_DEVICE_TYPE_OVS_PORT, NULL);
        }
    }

    json_object_foreach (bridge, key, value) {
        gs_unref_ptrarray GPtrArray *ports = NULL;
        OpenvswitchBridge *          ovs_bridge;
        gs_unref_array GArray *external_ids_arr = NULL;
        const char *           connection_uuid  = NULL;
        int                    r;

        r = json_unpack(value,
                        "{s:{s:s, s:o, s:o}}",
                        "new",
                        "name",
                        &name,
                        "external_ids",
                        &external_ids,
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

        _external_ids_extract(external_ids, &external_ids_arr, &connection_uuid);
        ports = _uuids_to_array(items);

        if (ovs_bridge) {
            gboolean changed = FALSE;

            nm_assert(nm_streq0(ovs_bridge->name, name));

            changed = nm_utils_strdup_reset(&ovs_bridge->name, name);
            changed = nm_utils_strdup_reset(&ovs_bridge->connection_uuid, connection_uuid);
            if (nm_strv_ptrarray_cmp(ovs_bridge->ports, ports) != 0) {
                NM_SWAP(&ovs_bridge->ports, &ports);
                changed = TRUE;
            }
            if (!_external_ids_equal(ovs_bridge->external_ids, external_ids_arr)) {
                NM_SWAP(&ovs_bridge->external_ids, &external_ids_arr);
                changed = TRUE;
            }
            if (changed) {
                gs_free char *strtmp = NULL;

                _LOGT("obj[bridge:%s]: changed a bridge: %s%s%s, external-ids=%s",
                      key,
                      ovs_bridge->name,
                      NM_PRINT_FMT_QUOTED2(ovs_bridge->connection_uuid,
                                           ", ",
                                           ovs_bridge->connection_uuid,
                                           ""),
                      (strtmp = _external_ids_to_string(ovs_bridge->external_ids)));
            }
        } else {
            gs_free char *strtmp = NULL;

            ovs_bridge  = g_slice_new(OpenvswitchBridge);
            *ovs_bridge = (OpenvswitchBridge){
                .bridge_uuid     = g_strdup(key),
                .name            = g_strdup(name),
                .connection_uuid = g_strdup(connection_uuid),
                .ports           = g_steal_pointer(&ports),
                .external_ids    = g_steal_pointer(&external_ids_arr),
            };
            g_hash_table_add(priv->bridges, ovs_bridge);
            _LOGT("obj[bridge:%s]: added a bridge: %s%s%s, external-ids=%s",
                  key,
                  ovs_bridge->name,
                  NM_PRINT_FMT_QUOTED2(ovs_bridge->connection_uuid,
                                       ", ",
                                       ovs_bridge->connection_uuid,
                                       ""),
                  (strtmp = _external_ids_to_string(ovs_bridge->external_ids)));
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
    NMOvsdbPrivate *    priv        = NM_OVSDB_GET_PRIVATE(self);
    nm_auto_decref_json json_t *msg = NULL;
    char *                      reply;
    gboolean                    output_was_empty;

    output_was_empty = priv->output->len == 0;

    msg   = json_pack("{s:I, s:O}", "id", id, "result", data);
    reply = json_dumps(msg, 0);
    g_string_append(priv->output, reply);
    free(reply);

    if (output_was_empty)
        ovsdb_write(self);
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
    json_t *    json_id = NULL;
    json_int_t  id      = (json_int_t) -1;
    const char *method  = NULL;
    json_t *    params  = NULL;
    json_t *    result  = NULL;
    json_t *    error   = NULL;

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
        OvsdbMethodCall *call;
        gs_free_error GError *local      = NULL;
        gs_free char *        msg_as_str = NULL;

        /* This is a response to a method call. */
        if (c_list_is_empty(&priv->calls_lst_head)) {
            _LOGE("there are no queued calls expecting response %" G_GUINT64_FORMAT, (guint64) id);
            ovsdb_disconnect(self, FALSE, FALSE);
            return;
        }
        call = c_list_first_entry(&priv->calls_lst_head, OvsdbMethodCall, calls_lst);
        if (call->call_id != id) {
            _LOGE("expected a response to call %" G_GUINT64_FORMAT ", not %" G_GUINT64_FORMAT,
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
        if (!priv->conn)
            return;

        /* Now we're free to serialize and send the next command, if any. */
        ovsdb_next_command(self);

        return;
    }

    /* This is a message we are not interested in. */
    _LOGW("got an unknown message, ignoring");
}

/*****************************************************************************/

/* Lower level marshalling and demarshalling of the JSON-RPC traffic on the
 * ovsdb socket. */

static size_t
_json_callback(void *buffer, size_t buflen, void *user_data)
{
    NMOvsdb *       self = NM_OVSDB(user_data);
    NMOvsdbPrivate *priv = NM_OVSDB_GET_PRIVATE(self);

    if (priv->bufp == priv->input->len) {
        /* No more bytes buffered for decoding. */
        return 0;
    }

    /* Pass one more byte to the JSON decoder. */
    *(char *) buffer = priv->input->str[priv->bufp];
    priv->bufp++;

    return (size_t) 1;
}

/**
 * ovsdb_read_cb:
 *
 * Read out the data available from the ovsdb socket and try to deserialize
 * the JSON. If we see a complete object, pass it upwards to ovsdb_got_msg().
 */
static void
ovsdb_read_cb(GObject *source_object, GAsyncResult *res, gpointer user_data)
{
    NMOvsdb *       self   = NM_OVSDB(user_data);
    NMOvsdbPrivate *priv   = NM_OVSDB_GET_PRIVATE(self);
    GInputStream *  stream = G_INPUT_STREAM(source_object);
    GError *        error  = NULL;
    gssize          size;
    json_t *        msg;
    json_error_t    json_error = {
        0,
    };

    size = g_input_stream_read_finish(stream, res, &error);
    if (size == -1) {
        /* ovsdb-server was possibly restarted */
        _LOGW("short read from ovsdb: %s", error->message);
        priv->num_failures++;
        g_clear_error(&error);
        ovsdb_disconnect(self, priv->num_failures <= OVSDB_MAX_FAILURES, FALSE);
        return;
    }

    g_string_append_len(priv->input, priv->buf, size);
    do {
        priv->bufp = 0;
        /* The callback always eats up only up to a single byte. This makes
         * it possible for us to identify complete JSON objects in spite of
         * us not knowing the length in advance. */
        msg = json_load_callback(_json_callback, self, JSON_DISABLE_EOF_CHECK, &json_error);
        if (msg) {
            ovsdb_got_msg(self, msg);
            g_string_erase(priv->input, 0, priv->bufp);
        }
        json_decref(msg);
    } while (msg);

    if (!priv->conn)
        return;

    if (size)
        ovsdb_read(self);
}

static void
ovsdb_read(NMOvsdb *self)
{
    NMOvsdbPrivate *priv = NM_OVSDB_GET_PRIVATE(self);

    g_input_stream_read_async(g_io_stream_get_input_stream(G_IO_STREAM(priv->conn)),
                              priv->buf,
                              sizeof(priv->buf),
                              G_PRIORITY_DEFAULT,
                              NULL,
                              ovsdb_read_cb,
                              self);
}

static void
ovsdb_write_cb(GObject *source_object, GAsyncResult *res, gpointer user_data)
{
    GOutputStream * stream = G_OUTPUT_STREAM(source_object);
    NMOvsdb *       self   = NM_OVSDB(user_data);
    NMOvsdbPrivate *priv   = NM_OVSDB_GET_PRIVATE(self);
    GError *        error  = NULL;
    gssize          size;

    size = g_output_stream_write_finish(stream, res, &error);
    if (size == -1) {
        /* ovsdb-server was possibly restarted */
        _LOGW("short write to ovsdb: %s", error->message);
        priv->num_failures++;
        g_clear_error(&error);
        ovsdb_disconnect(self, priv->num_failures <= OVSDB_MAX_FAILURES, FALSE);
        return;
    }

    if (!priv->conn)
        return;

    g_string_erase(priv->output, 0, size);

    ovsdb_write(self);
}

static void
ovsdb_write(NMOvsdb *self)
{
    NMOvsdbPrivate *priv = NM_OVSDB_GET_PRIVATE(self);
    GOutputStream * stream;

    if (!priv->output->len)
        return;

    stream = g_io_stream_get_output_stream(G_IO_STREAM(priv->conn));
    if (g_output_stream_has_pending(stream))
        return;

    g_output_stream_write_async(stream,
                                priv->output->str,
                                priv->output->len,
                                G_PRIORITY_DEFAULT,
                                NULL,
                                ovsdb_write_cb,
                                self);
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
    NMOvsdbPrivate * priv = NM_OVSDB_GET_PRIVATE(self);
    OvsdbMethodCall *call;

    nm_assert(!retry || !is_disposing);

    if (!priv->client)
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

    priv->bufp = 0;
    g_string_truncate(priv->input, 0);
    g_string_truncate(priv->output, 0);
    g_clear_object(&priv->client);
    g_clear_object(&priv->conn);
    nm_clear_g_free(&priv->db_uuid);
    nm_clear_g_cancellable(&priv->cancellable);

    if (retry)
        ovsdb_try_connect(self);
}

static void
_check_ready(NMOvsdb *self)
{
    NMOvsdbPrivate *priv = NM_OVSDB_GET_PRIVATE(self);

    nm_assert(!priv->ready);

    if (priv->num_pending_deletions == 0) {
        priv->ready = TRUE;
        g_signal_emit(self, signals[READY], 0);
        nm_manager_unblock_failed_ovs_interfaces(nm_manager_get());
    }
}

static void
_del_initial_iface_cb(GError *error, gpointer user_data)
{
    NMOvsdb *       self;
    gs_free char *  ifname = NULL;
    NMOvsdbPrivate *priv;

    nm_utils_user_data_unpack(user_data, &self, &ifname);

    if (nm_utils_error_is_cancelled_or_disposing(error))
        return;

    priv = NM_OVSDB_GET_PRIVATE(self);
    nm_assert(priv->num_pending_deletions > 0);
    priv->num_pending_deletions--;

    _LOGD("delete initial interface '%s': %s %s%s%s, pending %u",
          ifname,
          error ? "error" : "success",
          error ? "(" : "",
          error ? error->message : "",
          error ? ")" : "",
          priv->num_pending_deletions);

    _check_ready(self);
}

static void
ovsdb_cleanup_initial_interfaces(NMOvsdb *self)
{
    NMOvsdbPrivate *            priv = NM_OVSDB_GET_PRIVATE(self);
    const OpenvswitchInterface *interface;
    NMUtilsUserData *           data;
    GHashTableIter              iter;

    if (priv->ready || priv->num_pending_deletions != 0)
        return;

    /* Delete OVS interfaces added by NM. Bridges and ports and
     * not considered because they are deleted automatically
     * when no interface is present. */
    g_hash_table_iter_init(&iter, self->_priv.interfaces);
    while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &interface)) {
        if (interface->connection_uuid) {
            priv->num_pending_deletions++;
            _LOGD("deleting initial interface '%s' (pending: %u)",
                  interface->name,
                  priv->num_pending_deletions);
            data = nm_utils_user_data_pack(self, g_strdup(interface->name));
            nm_ovsdb_del_interface(self, interface->name, _del_initial_iface_cb, data);
        }
    }

    _check_ready(self);
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
_client_connect_cb(GObject *source_object, GAsyncResult *res, gpointer user_data)
{
    GSocketClient *    client = G_SOCKET_CLIENT(source_object);
    NMOvsdb *          self   = NM_OVSDB(user_data);
    NMOvsdbPrivate *   priv;
    GError *           error = NULL;
    GSocketConnection *conn;

    conn = g_socket_client_connect_finish(client, res, &error);
    if (conn == NULL) {
        if (!g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
            _LOGI("%s", error->message);

        ovsdb_disconnect(self, FALSE, FALSE);
        g_clear_error(&error);
        return;
    }

    priv       = NM_OVSDB_GET_PRIVATE(self);
    priv->conn = conn;
    g_clear_object(&priv->cancellable);

    ovsdb_read(self);
    ovsdb_next_command(self);
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
    GSocketAddress *addr;

    if (priv->client)
        return;

    /* TODO: This should probably be made configurable via NetworkManager.conf */
    addr = g_unix_socket_address_new(RUNSTATEDIR "/openvswitch/db.sock");

    priv->client      = g_socket_client_new();
    priv->cancellable = g_cancellable_new();
    g_socket_client_connect_async(priv->client,
                                  G_SOCKET_CONNECTABLE(addr),
                                  priv->cancellable,
                                  _client_connect_cb,
                                  self);
    g_object_unref(addr);

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
    OvsdbCall * call = user_data;
    const char *err;
    const char *err_details;
    size_t      index;
    json_t *    value;

    if (error)
        goto out;

    json_array_foreach (result, index, value) {
        if (json_unpack(value, "{s:s, s:s}", "error", &err, "details", &err_details) == 0) {
            g_set_error(&error,
                        G_IO_ERROR,
                        G_IO_ERROR_FAILED,
                        "Error running the transaction: %s: %s",
                        err,
                        err_details);
            goto out;
        }
    }

out:
    call->callback(error, call->user_data);
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
nm_ovsdb_add_interface(NMOvsdb *       self,
                       NMConnection *  bridge,
                       NMConnection *  port,
                       NMConnection *  interface,
                       NMDevice *      bridge_device,
                       NMDevice *      interface_device,
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
nm_ovsdb_del_interface(NMOvsdb *       self,
                       const char *    ifname,
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
nm_ovsdb_set_interface_mtu(NMOvsdb *       self,
                           const char *    ifname,
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
nm_ovsdb_set_external_ids(NMOvsdb *                self,
                          NMDeviceType             device_type,
                          const char *             ifname,
                          const char *             connection_uuid,
                          NMSettingOvsExternalIDs *s_exid_old,
                          NMSettingOvsExternalIDs *s_exid_new)
{
    gs_unref_hashtable GHashTable *exid_old = NULL;
    gs_unref_hashtable GHashTable *exid_new = NULL;

    exid_old = s_exid_old
                   ? nm_utils_strdict_clone(_nm_setting_ovs_external_ids_get_data(s_exid_old))
                   : NULL;
    exid_new = s_exid_new
                   ? nm_utils_strdict_clone(_nm_setting_ovs_external_ids_get_data(s_exid_new))
                   : NULL;

    ovsdb_call_method(self,
                      NULL,
                      NULL,
                      FALSE,
                      OVSDB_SET_EXTERNAL_IDS,
                      OVSDB_METHOD_PAYLOAD_SET_EXTERNAL_IDS(device_type,
                                                            ifname,
                                                            connection_uuid,
                                                            exid_old,
                                                            exid_new));
}

/*****************************************************************************/

static void
nm_ovsdb_init(NMOvsdb *self)
{
    NMOvsdbPrivate *priv = NM_OVSDB_GET_PRIVATE(self);

    c_list_init(&priv->calls_lst_head);

    priv->input  = g_string_new(NULL);
    priv->output = g_string_new(NULL);
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
    NMOvsdb *       self = NM_OVSDB(object);
    NMOvsdbPrivate *priv = NM_OVSDB_GET_PRIVATE(self);

    ovsdb_disconnect(self, FALSE, TRUE);

    nm_assert(c_list_is_empty(&priv->calls_lst_head));

    if (priv->input) {
        g_string_free(priv->input, TRUE);
        priv->input = NULL;
    }
    if (priv->output) {
        g_string_free(priv->output, TRUE);
        priv->output = NULL;
    }

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
