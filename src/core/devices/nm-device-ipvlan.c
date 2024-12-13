/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2024 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-device-ipvlan.h"

#include <linux/if_link.h>

#include "libnm-core-intern/nm-core-internal.h"
#include "nm-device-private.h"
#include "settings/nm-settings.h"
#include "nm-act-request.h"
#include "nm-manager.h"
#include "libnm-core-aux-intern/nm-libnm-core-utils.h"
#include "libnm-platform/nm-platform.h"
#include "nm-device-factory.h"
#include "nm-setting-ipvlan.h"
#include "nm-setting-wired.h"
#include "nm-active-connection.h"
#include "nm-utils.h"

#define _NMLOG_DEVICE_TYPE NMDeviceIpvlan
#include "nm-device-logging.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE(NMDeviceIpvlan, PROP_MODE, PROP_PRIVATE, PROP_VEPA, );

typedef struct {
    NMPlatformLnkIpvlan props;
} NMDeviceIpvlanPrivate;

struct _NMDeviceIpvlan {
    NMDevice              parent;
    NMDeviceIpvlanPrivate _priv;
};

struct _NMDeviceIpvlanClass {
    NMDeviceClass parent;
};

G_DEFINE_TYPE(NMDeviceIpvlan, nm_device_ipvlan, NM_TYPE_DEVICE);

#define NM_DEVICE_IPVLAN_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NMDeviceIpvlan, NM_IS_DEVICE_IPVLAN, NMDevice)

/*****************************************************************************/

static int modes[][2] = {
    {NM_SETTING_IPVLAN_MODE_L2, IPVLAN_MODE_L2},
    {NM_SETTING_IPVLAN_MODE_L3, IPVLAN_MODE_L3},
    {NM_SETTING_IPVLAN_MODE_L3S, IPVLAN_MODE_L3S},
};

static int
setting_mode_to_platform(int mode)
{
    guint i;

    for (i = 0; i < G_N_ELEMENTS(modes); i++) {
        if (modes[i][0] == mode)
            return modes[i][1];
    }

    return -1;
}

static int
platform_mode_to_setting(int mode)
{
    guint i;

    for (i = 0; i < G_N_ELEMENTS(modes); i++) {
        if (modes[i][1] == mode)
            return modes[i][0];
    }

    return 0;
}

static const char *
platform_mode_to_string(guint mode)
{
    switch (mode) {
    case IPVLAN_MODE_L2:
        return "l2";
    case IPVLAN_MODE_L3:
        return "l3";
    case IPVLAN_MODE_L3S:
        return "l3s";
    default:
        return "unknown";
    }
}

/*****************************************************************************/

static void
update_properties(NMDevice *device)
{
    NMDeviceIpvlan            *self   = NM_DEVICE_IPVLAN(device);
    NMDeviceIpvlanPrivate     *priv   = NM_DEVICE_IPVLAN_GET_PRIVATE(self);
    GObject                   *object = G_OBJECT(device);
    const NMPlatformLnkIpvlan *props;
    const NMPlatformLink      *plink;

    props = nm_platform_link_get_lnk_ipvlan(nm_device_get_platform(device),
                                            nm_device_get_ifindex(device),
                                            &plink);

    if (!props) {
        _LOGW(LOGD_PLATFORM, "could not get IPVLAN properties");
        return;
    }

    g_object_freeze_notify(object);

    nm_device_parent_set_ifindex(device, plink->parent);

#define CHECK_PROPERTY_CHANGED(field, prop)      \
    G_STMT_START                                 \
    {                                            \
        if (priv->props.field != props->field) { \
            priv->props.field = props->field;    \
            _notify(self, prop);                 \
        }                                        \
    }                                            \
    G_STMT_END

    CHECK_PROPERTY_CHANGED(mode, PROP_MODE);
    CHECK_PROPERTY_CHANGED(private_flag, PROP_PRIVATE);
    CHECK_PROPERTY_CHANGED(vepa, PROP_VEPA);

    g_object_thaw_notify(object);
}

static void
link_changed(NMDevice *device, const NMPlatformLink *pllink)
{
    NM_DEVICE_CLASS(nm_device_ipvlan_parent_class)->link_changed(device, pllink);
    update_properties(device);
}

static gboolean
create_and_realize(NMDevice              *device,
                   NMConnection          *connection,
                   NMDevice              *parent,
                   const NMPlatformLink **out_plink,
                   GError               **error)
{
    const char         *iface = nm_device_get_iface(device);
    NMSettingIpvlan    *s_ipvlan;
    NMPlatformLnkIpvlan lnk = {};
    int                 parent_ifindex;
    int                 r;

    s_ipvlan = _nm_connection_get_setting(connection, NM_TYPE_SETTING_IPVLAN);
    nm_assert(s_ipvlan);

    if (!parent) {
        g_set_error(error,
                    NM_DEVICE_ERROR,
                    NM_DEVICE_ERROR_MISSING_DEPENDENCIES,
                    "IPVLAN device cannot be created without a parent interface");
        return FALSE;
    }

    parent_ifindex = nm_device_get_ifindex(parent);
    if (parent_ifindex <= 0) {
        g_set_error(error,
                    NM_DEVICE_ERROR,
                    NM_DEVICE_ERROR_MISSING_DEPENDENCIES,
                    "cannot retrieve ifindex of interface %s (%s)",
                    nm_device_get_iface(parent),
                    nm_device_get_type_desc(parent));
        return FALSE;
    }

    if (setting_mode_to_platform(nm_setting_ipvlan_get_mode(s_ipvlan)) < 0) {
        g_set_error(error,
                    NM_DEVICE_ERROR,
                    NM_DEVICE_ERROR_FAILED,
                    "unsupported IPVLAN mode %u in connection %s",
                    nm_setting_ipvlan_get_mode(s_ipvlan),
                    nm_connection_get_uuid(connection));
        return FALSE;
    }
    lnk.mode         = setting_mode_to_platform(nm_setting_ipvlan_get_mode(s_ipvlan));
    lnk.private_flag = nm_setting_ipvlan_get_private(s_ipvlan);
    lnk.vepa         = nm_setting_ipvlan_get_vepa(s_ipvlan);

    r = nm_platform_link_ipvlan_add(nm_device_get_platform(device),
                                    iface,
                                    parent_ifindex,
                                    &lnk,
                                    out_plink);

    if (r < 0) {
        g_set_error(error,
                    NM_DEVICE_ERROR,
                    NM_DEVICE_ERROR_CREATION_FAILED,
                    "Failed to create IPVLAN interface '%s' for '%s': %s",
                    iface,
                    nm_connection_get_id(connection),
                    nm_strerror(r));
        return FALSE;
    }

    return TRUE;
}

/*****************************************************************************/

static NMDeviceCapabilities
get_generic_capabilities(NMDevice *device)
{
    return NM_DEVICE_CAP_CARRIER_DETECT | NM_DEVICE_CAP_IS_SOFTWARE;
}

/*****************************************************************************/

static gboolean
is_available(NMDevice *device, NMDeviceCheckDevAvailableFlags flags)
{
    if (!nm_device_parent_get_device(device))
        return FALSE;
    return NM_DEVICE_CLASS(nm_device_ipvlan_parent_class)->is_available(device, flags);
}

/*****************************************************************************/

static gboolean
check_connection_compatible(NMDevice     *device,
                            NMConnection *connection,
                            gboolean      check_properties,
                            GError      **error)
{
    NMDeviceIpvlanPrivate *priv = NM_DEVICE_IPVLAN_GET_PRIVATE(device);
    NMSettingIpvlan       *s_ipvlan;
    const char            *parent = NULL;

    if (!NM_DEVICE_CLASS(nm_device_ipvlan_parent_class)
             ->check_connection_compatible(device, connection, check_properties, error))
        return FALSE;

    s_ipvlan = _nm_connection_get_setting(connection, NM_TYPE_SETTING_IPVLAN);

    if (check_properties && nm_device_is_real(device)) {
        if (setting_mode_to_platform(nm_setting_ipvlan_get_mode(s_ipvlan)) != priv->props.mode) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                       "IPVLAN mode setting differs");
            return FALSE;
        }

        if (nm_setting_ipvlan_get_private(s_ipvlan) != priv->props.private_flag) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                       "IPVLAN private flag setting differs");
            return FALSE;
        }
        if (nm_setting_ipvlan_get_vepa(s_ipvlan) != priv->props.vepa) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                       "IPVLAN VEPA flag setting differs");
            return FALSE;
        }

        /* Check parent interface; could be an interface name or a UUID */
        parent = nm_setting_ipvlan_get_parent(s_ipvlan);
        if (parent) {
            if (!nm_device_match_parent(device, parent)) {
                nm_utils_error_set_literal(error,
                                           NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                           "IPVLAN parent setting differs");
                return FALSE;
            }
        } else {
            /* Parent could be a MAC address in an NMSettingWired */
            if (!nm_device_match_parent_hwaddr(device, connection, TRUE)) {
                nm_utils_error_set_literal(error,
                                           NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                           "IPVLAN parent mac setting differs");
                return FALSE;
            }
        }
    }
    return TRUE;
}

static void
update_connection(NMDevice *device, NMConnection *connection)
{
    NMDeviceIpvlanPrivate *priv = NM_DEVICE_IPVLAN_GET_PRIVATE(device);
    NMSettingIpvlan *s_ipvlan   = _nm_connection_ensure_setting(connection, NM_TYPE_SETTING_IPVLAN);

    if (priv->props.mode != setting_mode_to_platform(nm_setting_ipvlan_get_mode(s_ipvlan)))
        g_object_set(s_ipvlan,
                     NM_SETTING_IPVLAN_MODE,
                     platform_mode_to_setting(priv->props.mode),
                     NULL);

    if (priv->props.private_flag != nm_setting_ipvlan_get_private(s_ipvlan))
        g_object_set(s_ipvlan, NM_SETTING_IPVLAN_PRIVATE, priv->props.private_flag, NULL);

    if (priv->props.vepa != nm_setting_ipvlan_get_vepa(s_ipvlan))
        g_object_set(s_ipvlan, NM_SETTING_IPVLAN_VEPA, priv->props.vepa, NULL);

    g_object_set(
        s_ipvlan,
        NM_SETTING_IPVLAN_PARENT,
        nm_device_parent_find_for_connection(device, nm_setting_ipvlan_get_parent(s_ipvlan)),
        NULL);
}

/*****************************************************************************/

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMDeviceIpvlanPrivate *priv = NM_DEVICE_IPVLAN_GET_PRIVATE(object);

    switch (prop_id) {
    case PROP_MODE:
        g_value_set_string(value, platform_mode_to_string(priv->props.mode));
        break;
    case PROP_PRIVATE:
        g_value_set_boolean(value, priv->props.private_flag);
        break;
    case PROP_VEPA:
        g_value_set_boolean(value, priv->props.vepa);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

/*****************************************************************************/

static void
nm_device_ipvlan_init(NMDeviceIpvlan *self)
{}

static const NMDBusInterfaceInfoExtended interface_info_device_ipvlan = {
    .parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT(
        NM_DBUS_INTERFACE_DEVICE_IPVLAN,
        .properties = NM_DEFINE_GDBUS_PROPERTY_INFOS(
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Parent", "o", NM_DEVICE_PARENT),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Mode", "s", NM_DEVICE_IPVLAN_MODE),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Private",
                                                           "b",
                                                           NM_DEVICE_IPVLAN_PRIVATE),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Vepa",
                                                           "b",
                                                           NM_DEVICE_IPVLAN_VEPA), ), ),
};

static void
nm_device_ipvlan_class_init(NMDeviceIpvlanClass *klass)
{
    GObjectClass      *object_class      = G_OBJECT_CLASS(klass);
    NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS(klass);
    NMDeviceClass     *device_class      = NM_DEVICE_CLASS(klass);

    object_class->get_property = get_property;

    dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS(&interface_info_device_ipvlan);

    device_class->connection_type_supported        = NM_SETTING_IPVLAN_SETTING_NAME;
    device_class->connection_type_check_compatible = NM_SETTING_IPVLAN_SETTING_NAME;
    device_class->link_types = NM_DEVICE_DEFINE_LINK_TYPES(NM_LINK_TYPE_IPVLAN);

    device_class->check_connection_compatible = check_connection_compatible;
    device_class->create_and_realize          = create_and_realize;
    device_class->get_generic_capabilities    = get_generic_capabilities;
    device_class->is_available                = is_available;
    device_class->link_changed                = link_changed;
    device_class->update_connection           = update_connection;

    obj_properties[PROP_MODE] = g_param_spec_string(NM_DEVICE_IPVLAN_MODE,
                                                    "",
                                                    "",
                                                    NULL,
                                                    G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_PRIVATE] = g_param_spec_boolean(NM_DEVICE_IPVLAN_PRIVATE,
                                                        "",
                                                        "",
                                                        TRUE,
                                                        G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_VEPA] = g_param_spec_boolean(NM_DEVICE_IPVLAN_VEPA,
                                                     "",
                                                     "",
                                                     TRUE,
                                                     G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}

/*****************************************************************************/

#define NM_TYPE_IPVLAN_DEVICE_FACTORY (nm_ipvlan_device_factory_get_type())
#define NM_IPVLAN_DEVICE_FACTORY(obj) \
    (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_IPVLAN_DEVICE_FACTORY, NMIpvlanDeviceFactory))

static NMDevice *
create_device(NMDeviceFactory      *factory,
              const char           *iface,
              const NMPlatformLink *plink,
              NMConnection         *connection,
              gboolean             *out_ignore)
{
    NMSettingIpvlan *s_ipvlan;

    if (connection) {
        s_ipvlan = _nm_connection_get_setting(connection, NM_TYPE_SETTING_IPVLAN);
        nm_assert(s_ipvlan);
    }

    return g_object_new(NM_TYPE_DEVICE_IPVLAN,
                        NM_DEVICE_IFACE,
                        iface,
                        NM_DEVICE_TYPE_DESC,
                        "Ipvlan",
                        NM_DEVICE_DEVICE_TYPE,
                        NM_DEVICE_TYPE_IPVLAN,
                        NM_DEVICE_LINK_TYPE,
                        NM_LINK_TYPE_IPVLAN,
                        NULL);
}

static const char *
get_connection_parent(NMDeviceFactory *factory, NMConnection *connection)
{
    NMSettingIpvlan *s_ipvlan;
    NMSettingWired  *s_wired;
    const char      *parent = NULL;

    g_return_val_if_fail(nm_connection_is_type(connection, NM_SETTING_IPVLAN_SETTING_NAME), NULL);

    s_ipvlan = _nm_connection_get_setting(connection, NM_TYPE_SETTING_IPVLAN);
    if (s_ipvlan) {
        parent = nm_setting_ipvlan_get_parent(s_ipvlan);
        if (parent)
            return parent;
    }

    /* Try the hardware address from the IPVLAN connection's hardware setting */
    s_wired = nm_connection_get_setting_wired(connection);
    if (s_wired)
        return nm_setting_wired_get_mac_address(s_wired);
    else
        return NULL;
}

NM_DEVICE_FACTORY_DEFINE_INTERNAL(
    IPVLAN,
    Ipvlan,
    ipvlan,
    NM_DEVICE_FACTORY_DECLARE_LINK_TYPES(NM_LINK_TYPE_IPVLAN)
        NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES(NM_SETTING_IPVLAN_SETTING_NAME),
    factory_class->create_device         = create_device;
    factory_class->get_connection_parent = get_connection_parent;);
