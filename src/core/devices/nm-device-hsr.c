/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2023 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-manager.h"
#include "nm-device-hsr.h"

#include <linux/if_ether.h>

#include "libnm-core-intern/nm-core-internal.h"
#include "nm-act-request.h"
#include "nm-device-private.h"
#include "nm-setting-hsr.h"
#include "libnm-platform/nm-platform.h"
#include "nm-device-factory.h"

#define _NMLOG_DEVICE_TYPE NMDeviceHsr
#include "nm-device-logging.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE(NMDeviceHsr,
                             PROP_PORT1,
                             PROP_PORT2,
                             PROP_SUPERVISION_ADDRESS,
                             PROP_MULTICAST_SPEC,
                             PROP_PRP, );

typedef struct {
    NMPlatformLnkHsr props;
} NMDeviceHsrPrivate;

struct _NMDeviceHsr {
    NMDevice           parent;
    NMDeviceHsrPrivate _priv;
};

struct _NMDeviceHsrClass {
    NMDeviceClass parent;
};

G_DEFINE_TYPE(NMDeviceHsr, nm_device_hsr, NM_TYPE_DEVICE)

#define NM_DEVICE_HSR_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NMDeviceHsr, NM_IS_DEVICE_HSR, NMDevice)

/*****************************************************************************/

static NMDeviceCapabilities
get_generic_capabilities(NMDevice *dev)
{
    return NM_DEVICE_CAP_CARRIER_DETECT | NM_DEVICE_CAP_IS_SOFTWARE;
}

static void
update_properties(NMDevice *device)
{
    NMDeviceHsr            *self;
    NMDeviceHsrPrivate     *priv;
    const NMPlatformLink   *plink;
    const NMPlatformLnkHsr *props;
    int                     ifindex;

    g_return_if_fail(NM_IS_DEVICE_HSR(device));
    self = NM_DEVICE_HSR(device);
    priv = NM_DEVICE_HSR_GET_PRIVATE(self);

    ifindex = nm_device_get_ifindex(device);
    g_return_if_fail(ifindex > 0);
    props = nm_platform_link_get_lnk_hsr(nm_device_get_platform(device), ifindex, &plink);

    if (!props) {
        _LOGW(LOGD_PLATFORM, "could not get HSR properties");
        return;
    }

    g_object_freeze_notify((GObject *) device);

#define CHECK_PROPERTY_CHANGED(field, prop)      \
    G_STMT_START                                 \
    {                                            \
        if (priv->props.field != props->field) { \
            priv->props.field = props->field;    \
            _notify(self, prop);                 \
        }                                        \
    }                                            \
    G_STMT_END

    CHECK_PROPERTY_CHANGED(port1, PROP_PORT1);
    CHECK_PROPERTY_CHANGED(port2, PROP_PORT2);
    CHECK_PROPERTY_CHANGED(multicast_spec, PROP_MULTICAST_SPEC);
    CHECK_PROPERTY_CHANGED(prp, PROP_PRP);

    if (!nm_ether_addr_equal(&priv->props.supervision_address, &props->supervision_address)) {
        priv->props.supervision_address = props->supervision_address;
        _notify(self, PROP_SUPERVISION_ADDRESS);
    }

    g_object_thaw_notify((GObject *) device);
}

static void
link_changed(NMDevice *device, const NMPlatformLink *pllink)
{
    NM_DEVICE_CLASS(nm_device_hsr_parent_class)->link_changed(device, pllink);
    update_properties(device);
}

static gboolean
create_and_realize(NMDevice              *device,
                   NMConnection          *connection,
                   NMDevice              *parent,
                   const NMPlatformLink **out_plink,
                   GError               **error)
{
    const char      *iface = nm_device_get_iface(device);
    NMSettingHsr    *s_hsr;
    NMPlatformLnkHsr lnk = {};
    int              r;

    s_hsr = _nm_connection_get_setting(connection, NM_TYPE_SETTING_HSR);
    nm_assert(s_hsr);

    if (nm_setting_hsr_get_port1(s_hsr) != NULL)
        lnk.port1 = nm_platform_link_get_ifindex(NM_PLATFORM_GET, nm_setting_hsr_get_port1(s_hsr));
    if (nm_setting_hsr_get_port2(s_hsr) != NULL)
        lnk.port2 = nm_platform_link_get_ifindex(NM_PLATFORM_GET, nm_setting_hsr_get_port2(s_hsr));
    lnk.multicast_spec = nm_setting_hsr_get_multicast_spec(s_hsr);
    lnk.prp            = nm_setting_hsr_get_prp(s_hsr);
    r = nm_platform_link_hsr_add(nm_device_get_platform(device), iface, &lnk, out_plink);
    if (r < 0) {
        g_set_error(error,
                    NM_DEVICE_ERROR,
                    NM_DEVICE_ERROR_CREATION_FAILED,
                    "Failed to create HSR interface '%s' for '%s': %s",
                    iface,
                    nm_connection_get_id(connection),
                    nm_strerror(r));
        return FALSE;
    }

    return TRUE;
}

/*****************************************************************************/

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMDeviceHsr        *self = NM_DEVICE_HSR(object);
    NMDeviceHsrPrivate *priv = NM_DEVICE_HSR_GET_PRIVATE(self);
    NMDevice           *port;

    switch (prop_id) {
    case PROP_PORT1:
        port = nm_manager_get_device_by_ifindex(NM_MANAGER_GET, priv->props.port1);
        nm_dbus_utils_g_value_set_object_path(value, port);
        break;
    case PROP_PORT2:
        port = nm_manager_get_device_by_ifindex(NM_MANAGER_GET, priv->props.port2);
        nm_dbus_utils_g_value_set_object_path(value, port);
        break;
    case PROP_SUPERVISION_ADDRESS:
        g_value_take_string(value, nm_ether_addr_to_string_dup(&priv->props.supervision_address));
        break;
    case PROP_MULTICAST_SPEC:
        g_value_set_uchar(value, priv->props.multicast_spec);
        break;
    case PROP_PRP:
        g_value_set_boolean(value, priv->props.prp);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

static void
nm_device_hsr_init(NMDeviceHsr *self)
{}

/*****************************************************************************/

static const NMDBusInterfaceInfoExtended interface_info_device_hsr = {
    .parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT(
        NM_DBUS_INTERFACE_DEVICE_HSR,
        .properties = NM_DEFINE_GDBUS_PROPERTY_INFOS(
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Port1", "o", NM_DEVICE_HSR_PORT1),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Port2", "o", NM_DEVICE_HSR_PORT2),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("SupervisionAddress",
                                                           "s",
                                                           NM_DEVICE_HSR_SUPERVISION_ADDRESS),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("MulticastSpec",
                                                           "y",
                                                           NM_DEVICE_HSR_MULTICAST_SPEC),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Prp", "b", NM_DEVICE_HSR_PRP), ), ),
};

static void
nm_device_hsr_class_init(NMDeviceHsrClass *klass)
{
    GObjectClass      *object_class      = G_OBJECT_CLASS(klass);
    NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS(klass);
    NMDeviceClass     *device_class      = NM_DEVICE_CLASS(klass);

    object_class->get_property = get_property;

    dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS(&interface_info_device_hsr);

    device_class->connection_type_supported        = NM_SETTING_HSR_SETTING_NAME;
    device_class->connection_type_check_compatible = NM_SETTING_HSR_SETTING_NAME;
    device_class->link_types                       = NM_DEVICE_DEFINE_LINK_TYPES(NM_LINK_TYPE_HSR);

    device_class->link_changed             = link_changed;
    device_class->create_and_realize       = create_and_realize;
    device_class->get_generic_capabilities = get_generic_capabilities;

    obj_properties[PROP_PORT1] = g_param_spec_string(NM_DEVICE_HSR_PORT1,
                                                     "",
                                                     "",
                                                     NULL,
                                                     G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_PORT2] = g_param_spec_string(NM_DEVICE_HSR_PORT2,
                                                     "",
                                                     "",
                                                     NULL,
                                                     G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_SUPERVISION_ADDRESS] =
        g_param_spec_string(NM_DEVICE_HSR_SUPERVISION_ADDRESS,
                            "",
                            "",
                            NULL,
                            G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_MULTICAST_SPEC] =
        g_param_spec_uchar(NM_DEVICE_HSR_MULTICAST_SPEC,
                           "",
                           "",
                           0,
                           G_MAXUINT8,
                           0,
                           G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_PRP] = g_param_spec_boolean(NM_DEVICE_HSR_PRP,
                                                    "",
                                                    "",
                                                    FALSE,
                                                    G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}

/*****************************************************************************/

#define NM_TYPE_HSR_DEVICE_FACTORY (nm_hsr_device_factory_get_type())
#define NM_HSR_DEVICE_FACTORY(obj) \
    (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_HSR_DEVICE_FACTORY, NMHsrDeviceFactory))

static NMDevice *
create_device(NMDeviceFactory      *factory,
              const char           *iface,
              const NMPlatformLink *plink,
              NMConnection         *connection,
              gboolean             *out_ignore)
{
    return g_object_new(NM_TYPE_DEVICE_HSR,
                        NM_DEVICE_IFACE,
                        iface,
                        NM_DEVICE_TYPE_DESC,
                        "hsr",
                        NM_DEVICE_DEVICE_TYPE,
                        NM_DEVICE_TYPE_HSR,
                        NM_DEVICE_LINK_TYPE,
                        NM_LINK_TYPE_HSR,
                        NULL);
}

NM_DEVICE_FACTORY_DEFINE_INTERNAL(
    HSR,
    Hsr,
    hsr,
    NM_DEVICE_FACTORY_DECLARE_LINK_TYPES(NM_LINK_TYPE_HSR)
        NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES(NM_SETTING_HSR_SETTING_NAME),
    factory_class->create_device = create_device;)
