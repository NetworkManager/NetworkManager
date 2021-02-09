/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "src/core/nm-default-daemon.h"

#include "nm-device-vrf.h"

#include "nm-core-internal.h"
#include "nm-device-factory.h"
#include "nm-device-private.h"
#include "nm-manager.h"
#include "nm-setting-vrf.h"
#include "platform/nm-platform.h"
#include "settings/nm-settings.h"

#define _NMLOG_DEVICE_TYPE NMDeviceVrf
#include "nm-device-logging.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE(NMDeviceVrf, PROP_TABLE, );

typedef struct {
    NMPlatformLnkVrf props;
} NMDeviceVrfPrivate;

struct _NMDeviceVrf {
    NMDevice           parent;
    NMDeviceVrfPrivate _priv;
};

struct _NMDeviceVrfClass {
    NMDeviceClass parent;
};

G_DEFINE_TYPE(NMDeviceVrf, nm_device_vrf, NM_TYPE_DEVICE)

#define NM_DEVICE_VRF_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NMDeviceVrf, NM_IS_DEVICE_VRF, NMDevice)

/*****************************************************************************/

static void
do_update_properties(NMDeviceVrf *self, const NMPlatformLnkVrf *props)
{
    NMDeviceVrfPrivate *priv   = NM_DEVICE_VRF_GET_PRIVATE(self);
    GObject *           object = G_OBJECT(self);
    NMPlatformLnkVrf    props_null;

    if (!props) {
        props_null = (NMPlatformLnkVrf){};
        props      = &props_null;
    }

    g_object_freeze_notify(object);

#define CHECK_PROPERTY_CHANGED(field, prop)      \
    G_STMT_START                                 \
    {                                            \
        if (priv->props.field != props->field) { \
            priv->props.field = props->field;    \
            _notify(self, prop);                 \
        }                                        \
    }                                            \
    G_STMT_END

    CHECK_PROPERTY_CHANGED(table, PROP_TABLE);

    g_object_thaw_notify(object);
}

static void
update_properties(NMDevice *device)
{
    NMDeviceVrf *           self = NM_DEVICE_VRF(device);
    const NMPlatformLnkVrf *props;

    props = nm_platform_link_get_lnk_vrf(nm_device_get_platform(device),
                                         nm_device_get_ifindex(device),
                                         NULL);
    if (!props) {
        _LOGW(LOGD_PLATFORM, "could not get vrf properties");
        return;
    }

    do_update_properties(self, props);
}

static NMDeviceCapabilities
get_generic_capabilities(NMDevice *dev)
{
    return NM_DEVICE_CAP_IS_SOFTWARE;
}

static void
link_changed(NMDevice *device, const NMPlatformLink *pllink)
{
    NM_DEVICE_CLASS(nm_device_vrf_parent_class)->link_changed(device, pllink);
    update_properties(device);
}

static void
unrealize_notify(NMDevice *device)
{
    NMDeviceVrf *self = NM_DEVICE_VRF(device);

    NM_DEVICE_CLASS(nm_device_vrf_parent_class)->unrealize_notify(device);

    do_update_properties(self, NULL);
}

static gboolean
create_and_realize(NMDevice *             device,
                   NMConnection *         connection,
                   NMDevice *             parent,
                   const NMPlatformLink **out_plink,
                   GError **              error)
{
    const char *     iface = nm_device_get_iface(device);
    NMPlatformLnkVrf props = {};
    NMSettingVrf *   s_vrf;
    int              r;

    s_vrf = _nm_connection_get_setting(connection, NM_TYPE_SETTING_VRF);
    nm_assert(s_vrf);

    props.table = nm_setting_vrf_get_table(s_vrf);

    r = nm_platform_link_vrf_add(nm_device_get_platform(device), iface, &props, out_plink);
    if (r < 0) {
        g_set_error(error,
                    NM_DEVICE_ERROR,
                    NM_DEVICE_ERROR_CREATION_FAILED,
                    "Failed to create VRF interface '%s' for '%s': %s",
                    iface,
                    nm_connection_get_id(connection),
                    nm_strerror(r));
        return FALSE;
    }

    return TRUE;
}

static gboolean
check_connection_compatible(NMDevice *device, NMConnection *connection, GError **error)
{
    NMDeviceVrfPrivate *priv = NM_DEVICE_VRF_GET_PRIVATE(device);
    NMSettingVrf *      s_vrf;

    if (!NM_DEVICE_CLASS(nm_device_vrf_parent_class)
             ->check_connection_compatible(device, connection, error))
        return FALSE;

    if (nm_device_is_real(device)) {
        s_vrf = _nm_connection_get_setting(connection, NM_TYPE_SETTING_VRF);

        if (priv->props.table != nm_setting_vrf_get_table(s_vrf)) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                       "vrf table mismatches");
            return FALSE;
        }
    }

    return TRUE;
}

static gboolean
complete_connection(NMDevice *           device,
                    NMConnection *       connection,
                    const char *         specific_object,
                    NMConnection *const *existing_connections,
                    GError **            error)
{
    NMSettingVrf *s_vrf;

    nm_utils_complete_generic(nm_device_get_platform(device),
                              connection,
                              NM_SETTING_VRF_SETTING_NAME,
                              existing_connections,
                              NULL,
                              _("VRF connection"),
                              NULL,
                              NULL,
                              TRUE);

    s_vrf = _nm_connection_get_setting(connection, NM_TYPE_SETTING_VRF);
    if (!s_vrf) {
        g_set_error_literal(error,
                            NM_DEVICE_ERROR,
                            NM_DEVICE_ERROR_INVALID_CONNECTION,
                            "A 'vrf' setting is required.");
        return FALSE;
    }

    return TRUE;
}

static void
update_connection(NMDevice *device, NMConnection *connection)
{
    NMDeviceVrfPrivate *priv  = NM_DEVICE_VRF_GET_PRIVATE(device);
    NMSettingVrf *      s_vrf = _nm_connection_get_setting(connection, NM_TYPE_SETTING_VRF);

    if (!s_vrf) {
        s_vrf = (NMSettingVrf *) nm_setting_vrf_new();
        nm_connection_add_setting(connection, (NMSetting *) s_vrf);
    }

    if (priv->props.table != nm_setting_vrf_get_table(s_vrf))
        g_object_set(G_OBJECT(s_vrf), NM_SETTING_VRF_TABLE, priv->props.table, NULL);
}

static gboolean
enslave_slave(NMDevice *device, NMDevice *slave, NMConnection *connection, gboolean configure)
{
    NMDeviceVrf *self        = NM_DEVICE_VRF(device);
    gboolean     success     = TRUE;
    const char * slave_iface = nm_device_get_ip_iface(slave);

    nm_device_master_check_slave_physical_port(device, slave, LOGD_DEVICE);

    if (configure) {
        nm_device_take_down(slave, TRUE);
        success = nm_platform_link_enslave(nm_device_get_platform(device),
                                           nm_device_get_ip_ifindex(device),
                                           nm_device_get_ip_ifindex(slave));
        nm_device_bring_up(slave, TRUE, NULL);

        if (!success)
            return FALSE;

        _LOGI(LOGD_DEVICE, "enslaved VRF slave %s", slave_iface);
    } else
        _LOGI(LOGD_BOND, "VRF slave %s was enslaved", slave_iface);

    return TRUE;
}

static void
release_slave(NMDevice *device, NMDevice *slave, gboolean configure)
{
    NMDeviceVrf *self = NM_DEVICE_VRF(device);
    gboolean     success;
    int          ifindex_slave;
    int          ifindex;

    if (configure) {
        ifindex = nm_device_get_ifindex(device);
        if (ifindex <= 0 || !nm_platform_link_get(nm_device_get_platform(device), ifindex))
            configure = FALSE;
    }

    ifindex_slave = nm_device_get_ip_ifindex(slave);

    if (ifindex_slave <= 0)
        _LOGD(LOGD_DEVICE, "VRF slave %s is already released", nm_device_get_ip_iface(slave));

    if (configure) {
        if (ifindex_slave > 0) {
            success = nm_platform_link_release(nm_device_get_platform(device),
                                               nm_device_get_ip_ifindex(device),
                                               ifindex_slave);

            if (success) {
                _LOGI(LOGD_DEVICE, "released VRF slave %s", nm_device_get_ip_iface(slave));
            } else {
                _LOGW(LOGD_DEVICE, "failed to release VRF slave %s", nm_device_get_ip_iface(slave));
            }
        }
    } else {
        if (ifindex_slave > 0) {
            _LOGI(LOGD_DEVICE, "VRF slave %s was released", nm_device_get_ip_iface(slave));
        }
    }
}

/*****************************************************************************/

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMDeviceVrfPrivate *priv = NM_DEVICE_VRF_GET_PRIVATE(object);

    switch (prop_id) {
    case PROP_TABLE:
        g_value_set_uint(value, priv->props.table);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

/*****************************************************************************/

static void
nm_device_vrf_init(NMDeviceVrf *self)
{}

static const NMDBusInterfaceInfoExtended interface_info_device_vrf = {
    .parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT(
        NM_DBUS_INTERFACE_DEVICE_VRF,
        .properties = NM_DEFINE_GDBUS_PROPERTY_INFOS(
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Table", "u", NM_DEVICE_VRF_TABLE), ), ),
};

static void
nm_device_vrf_class_init(NMDeviceVrfClass *klass)
{
    GObjectClass *     object_class      = G_OBJECT_CLASS(klass);
    NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS(klass);
    NMDeviceClass *    device_class      = NM_DEVICE_CLASS(klass);

    object_class->get_property = get_property;

    dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS(&interface_info_device_vrf);

    device_class->connection_type_supported        = NM_SETTING_VRF_SETTING_NAME;
    device_class->connection_type_check_compatible = NM_SETTING_VRF_SETTING_NAME;
    device_class->is_master                        = TRUE;
    device_class->link_types                       = NM_DEVICE_DEFINE_LINK_TYPES(NM_LINK_TYPE_VRF);

    device_class->enslave_slave               = enslave_slave;
    device_class->release_slave               = release_slave;
    device_class->link_changed                = link_changed;
    device_class->unrealize_notify            = unrealize_notify;
    device_class->create_and_realize          = create_and_realize;
    device_class->check_connection_compatible = check_connection_compatible;
    device_class->complete_connection         = complete_connection;
    device_class->get_generic_capabilities    = get_generic_capabilities;
    device_class->update_connection           = update_connection;

    obj_properties[PROP_TABLE] = g_param_spec_uint(NM_DEVICE_VRF_TABLE,
                                                   "",
                                                   "",
                                                   0,
                                                   G_MAXUINT32,
                                                   0,
                                                   G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}

/*****************************************************************************/

#define NM_TYPE_VRF_DEVICE_FACTORY (nm_vrf_device_factory_get_type())
#define NM_VRF_DEVICE_FACTORY(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_VRF_DEVICE_FACTORY, NMVrfDeviceFactory))

static NMDevice *
create_device(NMDeviceFactory *     factory,
              const char *          iface,
              const NMPlatformLink *plink,
              NMConnection *        connection,
              gboolean *            out_ignore)
{
    return g_object_new(NM_TYPE_DEVICE_VRF,
                        NM_DEVICE_IFACE,
                        iface,
                        NM_DEVICE_TYPE_DESC,
                        "Vrf",
                        NM_DEVICE_DEVICE_TYPE,
                        NM_DEVICE_TYPE_VRF,
                        NM_DEVICE_LINK_TYPE,
                        NM_LINK_TYPE_VRF,
                        NULL);
}

NM_DEVICE_FACTORY_DEFINE_INTERNAL(
    VRF,
    Vrf,
    vrf,
    NM_DEVICE_FACTORY_DECLARE_LINK_TYPES(NM_LINK_TYPE_VRF)
        NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES(NM_SETTING_VRF_SETTING_NAME),
    factory_class->create_device = create_device;);
