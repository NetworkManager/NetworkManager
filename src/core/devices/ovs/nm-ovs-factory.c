/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-manager.h"
#include "nm-ovsdb.h"
#include "nm-device-ovs-interface.h"
#include "nm-device-ovs-port.h"
#include "nm-device-ovs-bridge.h"
#include "platform/nm-platform.h"
#include "nm-core-internal.h"
#include "settings/nm-settings.h"
#include "devices/nm-device-factory.h"
#include "devices/nm-device-private.h"

/*****************************************************************************/

typedef struct {
    NMDeviceFactory parent;
} NMOvsFactory;

typedef struct {
    NMDeviceFactoryClass parent;
} NMOvsFactoryClass;

#define NM_TYPE_OVS_FACTORY (nm_ovs_factory_get_type())
#define NM_OVS_FACTORY(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_OVS_FACTORY, NMOvsFactory))
#define NM_OVS_FACTORY_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_OVS_FACTORY, NMOvsFactoryClass))
#define NM_IS_OVS_FACTORY(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_OVS_FACTORY))
#define NM_IS_OVS_FACTORY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_OVS_FACTORY))
#define NM_OVS_FACTORY_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_OVS_FACTORY, NMOvsFactoryClass))

static GType nm_ovs_factory_get_type(void);
G_DEFINE_TYPE(NMOvsFactory, nm_ovs_factory, NM_TYPE_DEVICE_FACTORY)

/*****************************************************************************/

#define _NMLOG_DOMAIN LOGD_DEVICE
#define _NMLOG(level, ifname, con_uuid, ...)                                                  \
    G_STMT_START                                                                              \
    {                                                                                         \
        nm_log((level),                                                                       \
               _NMLOG_DOMAIN,                                                                 \
               (ifname),                                                                      \
               (con_uuid),                                                                    \
               "ovs: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__) _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
    }                                                                                         \
    G_STMT_END

/*****************************************************************************/

NM_DEVICE_FACTORY_DECLARE_TYPES(
    NM_DEVICE_FACTORY_DECLARE_LINK_TYPES(NM_LINK_TYPE_OPENVSWITCH)
        NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES(NM_SETTING_OVS_BRIDGE_SETTING_NAME,
                                                NM_SETTING_OVS_INTERFACE_SETTING_NAME,
                                                NM_SETTING_OVS_PORT_SETTING_NAME))

G_MODULE_EXPORT NMDeviceFactory *
                nm_device_factory_create(GError **error)
{
    nm_manager_set_capability(NM_MANAGER_GET, NM_CAPABILITY_OVS);
    return g_object_new(NM_TYPE_OVS_FACTORY, NULL);
}

static NMDevice *
new_device_from_type(const char *name, NMDeviceType device_type)
{
    GType       type;
    const char *type_desc;
    NMLinkType  link_type = NM_LINK_TYPE_NONE;

    if (nm_manager_get_device(NM_MANAGER_GET, name, device_type))
        return NULL;

    if (device_type == NM_DEVICE_TYPE_OVS_INTERFACE) {
        type      = NM_TYPE_DEVICE_OVS_INTERFACE;
        type_desc = "Open vSwitch Interface";
        link_type = NM_LINK_TYPE_OPENVSWITCH;
    } else if (device_type == NM_DEVICE_TYPE_OVS_PORT) {
        type      = NM_TYPE_DEVICE_OVS_PORT;
        type_desc = "Open vSwitch Port";
    } else if (device_type == NM_DEVICE_TYPE_OVS_BRIDGE) {
        type      = NM_TYPE_DEVICE_OVS_BRIDGE;
        type_desc = "Open vSwitch Bridge";
    } else {
        return NULL;
    }

    return g_object_new(type,
                        NM_DEVICE_IFACE,
                        name,
                        NM_DEVICE_DRIVER,
                        "openvswitch",
                        NM_DEVICE_DEVICE_TYPE,
                        device_type,
                        NM_DEVICE_TYPE_DESC,
                        type_desc,
                        NM_DEVICE_LINK_TYPE,
                        link_type,
                        NULL);
}

static void
ovsdb_device_added(NMOvsdb *        ovsdb,
                   const char *     name,
                   guint            device_type_i,
                   const char *     subtype,
                   NMDeviceFactory *self)
{
    const NMDeviceType device_type = device_type_i;
    NMDevice *         device;

    if (device_type == NM_DEVICE_TYPE_OVS_INTERFACE
        && !NM_IN_STRSET(subtype, "internal", "patch")) {
        /* system interfaces refer to kernel devices and
         * don't need to be created by this factory. Ignore
         * anything that is not an internal or patch
         * interface. */
        return;
    }

    device = new_device_from_type(name, device_type);
    if (!device)
        return;

    g_signal_emit_by_name(self, NM_DEVICE_FACTORY_DEVICE_ADDED, device);
    g_object_unref(device);
}

static void
ovsdb_device_removed(NMOvsdb *        ovsdb,
                     const char *     name,
                     guint            device_type_i,
                     const char *     subtype,
                     NMDeviceFactory *self)
{
    const NMDeviceType device_type = device_type_i;
    NMDevice *         device      = NULL;
    NMDeviceState      device_state;
    gboolean           is_system_interface = FALSE;

    if (device_type == NM_DEVICE_TYPE_OVS_INTERFACE
        && !NM_IN_STRSET(subtype, "internal", "patch", "system"))
        return;

    if (device_type == NM_DEVICE_TYPE_OVS_INTERFACE && nm_streq0(subtype, "system")) {
        NMDevice *             d;
        const CList *          list;
        NMSettingOvsInterface *s_ovs_int;

        /* The device associated to an OVS system interface can be of
         * any kind. Find an interface with the same name and which has
         * the OVS-interface setting. */
        is_system_interface = TRUE;
        nm_manager_for_each_device (NM_MANAGER_GET, d, list) {
            if (!nm_streq0(nm_device_get_iface(d), name))
                continue;
            s_ovs_int = nm_device_get_applied_setting(d, NM_TYPE_SETTING_OVS_INTERFACE);
            if (!s_ovs_int)
                continue;
            if (!nm_streq0(nm_setting_ovs_interface_get_interface_type(s_ovs_int), "system"))
                continue;
            /* Failing the system interface device is almost always the right
             * thing to do when the ovsdb entry is removed. However, to avoid
             * that a late device-removed signal tears down a different,
             * newly-activated connection, let's also check that we have a master.
             * Or in alternative, that the device is assumed/external: in such
             * case it's always fine to fail the device.
             */
            if (!nm_device_get_master(d) && !nm_device_sys_iface_state_is_external_or_assume(d))
                continue;

            device = d;
        }
    } else {
        device = nm_manager_get_device(NM_MANAGER_GET, name, device_type);
    }

    if (!device)
        return;

    device_state = nm_device_get_state(device);

    if (device_type == NM_DEVICE_TYPE_OVS_INTERFACE && nm_device_get_act_request(device)
        && device_state < NM_DEVICE_STATE_DEACTIVATING) {
        nm_device_state_changed(device,
                                NM_DEVICE_STATE_DEACTIVATING,
                                NM_DEVICE_STATE_REASON_REMOVED);
        return;
    }

    /* OVS system interfaces still exist even without the ovsdb entry */
    if (!is_system_interface && device_state == NM_DEVICE_STATE_UNMANAGED) {
        nm_device_unrealize(device, TRUE, NULL);
    }
}

static void
ovsdb_interface_failed(NMOvsdb *        ovsdb,
                       const char *     name,
                       const char *     connection_uuid,
                       const char *     error,
                       NMDeviceFactory *self)
{
    NMDevice *             device     = NULL;
    NMSettingsConnection * connection = NULL;
    NMConnection *         c;
    const char *           type;
    NMSettingOvsInterface *s_ovs_int;
    gboolean               is_patch = FALSE;
    gboolean               ignore;

    device = nm_manager_get_device(NM_MANAGER_GET, name, NM_DEVICE_TYPE_OVS_INTERFACE);
    if (device && connection_uuid) {
        connection =
            nm_settings_get_connection_by_uuid(nm_device_get_settings(device), connection_uuid);
    }

    /* The patch interface which gets created first is expected to
     * fail because the second patch doesn't exist yet. Ignore all
     * failures of patch interfaces. */
    if (connection && (c = nm_settings_connection_get_connection(connection))
        && (type = nm_connection_get_connection_type(c))
        && nm_streq0(type, NM_SETTING_OVS_INTERFACE_SETTING_NAME)
        && (s_ovs_int = nm_connection_get_setting_ovs_interface(c))
        && nm_streq0(nm_setting_ovs_interface_get_interface_type(s_ovs_int), "patch"))
        is_patch = TRUE;

    ignore = !device || is_patch;

    _NMLOG(ignore ? LOGL_DEBUG : LOGL_INFO,
           name,
           connection_uuid,
           "ovs interface \"%s\" (%s) failed%s: %s",
           name,
           connection_uuid,
           ignore ? " (ignored)" : "",
           error);

    if (ignore)
        return;

    if (connection) {
        nm_settings_connection_autoconnect_blocked_reason_set(
            connection,
            NM_SETTINGS_AUTO_CONNECT_BLOCKED_REASON_FAILED,
            TRUE);
    }

    nm_device_state_changed(device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_OVSDB_FAILED);
}

static void
start(NMDeviceFactory *self)
{
    NMOvsdb *ovsdb;

    ovsdb = nm_ovsdb_get();

    g_signal_connect_object(ovsdb,
                            NM_OVSDB_DEVICE_ADDED,
                            G_CALLBACK(ovsdb_device_added),
                            self,
                            (GConnectFlags) 0);
    g_signal_connect_object(ovsdb,
                            NM_OVSDB_DEVICE_REMOVED,
                            G_CALLBACK(ovsdb_device_removed),
                            self,
                            (GConnectFlags) 0);
    g_signal_connect_object(ovsdb,
                            NM_OVSDB_INTERFACE_FAILED,
                            G_CALLBACK(ovsdb_interface_failed),
                            self,
                            (GConnectFlags) 0);
}

static NMDevice *
create_device(NMDeviceFactory *     self,
              const char *          iface,
              const NMPlatformLink *plink,
              NMConnection *        connection,
              gboolean *            out_ignore)
{
    NMDeviceType device_type     = NM_DEVICE_TYPE_UNKNOWN;
    const char * connection_type = NULL;

    if (g_strcmp0(iface, "ovs-system") == 0) {
        *out_ignore = TRUE;
        return NULL;
    }

    if (connection)
        connection_type = nm_connection_get_connection_type(connection);

    if (plink)
        device_type = NM_DEVICE_TYPE_OVS_INTERFACE;
    else if (g_strcmp0(connection_type, NM_SETTING_OVS_INTERFACE_SETTING_NAME) == 0)
        device_type = NM_DEVICE_TYPE_OVS_INTERFACE;
    else if (g_strcmp0(connection_type, NM_SETTING_OVS_PORT_SETTING_NAME) == 0)
        device_type = NM_DEVICE_TYPE_OVS_PORT;
    else if (g_strcmp0(connection_type, NM_SETTING_OVS_BRIDGE_SETTING_NAME) == 0)
        device_type = NM_DEVICE_TYPE_OVS_BRIDGE;

    return new_device_from_type(iface, device_type);
}

static void
nm_ovs_factory_init(NMOvsFactory *self)
{}

static void
nm_ovs_factory_class_init(NMOvsFactoryClass *klass)
{
    NMDeviceFactoryClass *factory_class = NM_DEVICE_FACTORY_CLASS(klass);

    factory_class->get_supported_types = get_supported_types;
    factory_class->start               = start;
    factory_class->create_device       = create_device;
}
