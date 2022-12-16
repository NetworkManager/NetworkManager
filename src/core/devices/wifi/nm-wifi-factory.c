/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2011 - 2014 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include <gmodule.h>

#include "devices/nm-device-factory.h"
#include "nm-setting-wireless.h"
#include "nm-setting-olpc-mesh.h"
#include "nm-device-wifi.h"
#include "nm-device-wifi-p2p.h"
#include "nm-device-olpc-mesh.h"
#include "nm-device-iwd.h"
#include "nm-device-iwd-p2p.h"
#include "nm-iwd-manager.h"
#include "settings/nm-settings-connection.h"
#include "libnm-platform/nm-platform.h"
#include "nm-config.h"

/*****************************************************************************/

#define NM_TYPE_WIFI_FACTORY (nm_wifi_factory_get_type())
#define NM_WIFI_FACTORY(obj) \
    (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_WIFI_FACTORY, NMWifiFactory))
#define NM_WIFI_FACTORY_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_WIFI_FACTORY, NMWifiFactoryClass))
#define NM_IS_WIFI_FACTORY(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_WIFI_FACTORY))
#define NM_IS_WIFI_FACTORY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_WIFI_FACTORY))
#define NM_WIFI_FACTORY_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_WIFI_FACTORY, NMWifiFactoryClass))

typedef struct {
    NMDeviceFactory parent;
} NMWifiFactory;

typedef struct {
    NMDeviceFactoryClass parent;
} NMWifiFactoryClass;

static GType nm_wifi_factory_get_type(void);

G_DEFINE_TYPE(NMWifiFactory, nm_wifi_factory, NM_TYPE_DEVICE_FACTORY)

/*****************************************************************************/

NM_DEVICE_FACTORY_DECLARE_TYPES(
    NM_DEVICE_FACTORY_DECLARE_LINK_TYPES(NM_LINK_TYPE_WIFI, NM_LINK_TYPE_OLPC_MESH)
        NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES(NM_SETTING_WIRELESS_SETTING_NAME,
                                                NM_SETTING_OLPC_MESH_SETTING_NAME))

G_MODULE_EXPORT NMDeviceFactory *
nm_device_factory_create(GError **error)
{
    return g_object_new(NM_TYPE_WIFI_FACTORY, NULL);
}

/*****************************************************************************/

static void
p2p_device_created(NMDeviceWifi *device, NMDeviceWifiP2P *p2p_device, NMDeviceFactory *self)
{
    nm_log_info(LOGD_PLATFORM | LOGD_WIFI,
                "Wi-Fi P2P device controlled by interface %s created",
                nm_device_get_iface(NM_DEVICE(device)));

    g_signal_emit_by_name(self, NM_DEVICE_FACTORY_DEVICE_ADDED, p2p_device);
}

#if WITH_IWD
static void
iwd_p2p_device_added(NMIwdManager    *iwd,
                     NMDeviceIwdP2P  *p2p_device,
                     const char      *phy_name,
                     NMDeviceFactory *self)
{
    nm_log_info(LOGD_PLATFORM | LOGD_WIFI, "Wi-Fi P2P device added on %s", phy_name);

    g_signal_emit_by_name(self, NM_DEVICE_FACTORY_DEVICE_ADDED, p2p_device);
}
#endif

static NMDevice *
create_device(NMDeviceFactory      *factory,
              const char           *iface,
              const NMPlatformLink *plink,
              NMConnection         *connection,
              gboolean             *out_ignore)
{
    gs_free char *backend_free = NULL;
    const char   *backend;
    _NM80211Mode  mode;

    g_return_val_if_fail(iface != NULL, NULL);
    g_return_val_if_fail(plink != NULL, NULL);
    g_return_val_if_fail(g_strcmp0(iface, plink->name) == 0, NULL);
    g_return_val_if_fail(NM_IN_SET(plink->type, NM_LINK_TYPE_WIFI, NM_LINK_TYPE_OLPC_MESH), NULL);

    if (plink->type != NM_LINK_TYPE_WIFI)
        return nm_device_olpc_mesh_new(iface);

    /* Ignore monitor-mode and other unhandled interface types.
     * FIXME: keep TYPE_MONITOR devices in UNAVAILABLE state and manage
     * them if/when they change to a handled type.
     */
    mode = nm_platform_wifi_get_mode(NM_PLATFORM_GET, plink->ifindex);
    if (!NM_IN_SET(mode,
                   _NM_802_11_MODE_INFRA,
                   _NM_802_11_MODE_ADHOC,
                   _NM_802_11_MODE_AP,
                   _NM_802_11_MODE_MESH)) {
        *out_ignore = TRUE;
        return NULL;
    }

    backend = nm_config_data_get_device_config_by_pllink(NM_CONFIG_GET_DATA,
                                                         NM_CONFIG_KEYFILE_KEY_DEVICE_WIFI_BACKEND,
                                                         plink,
                                                         "wifi",
                                                         NULL);
    backend = nm_strstrip_avoid_copy_a(300, backend, &backend_free);

    if (!backend)
        backend = "" NM_CONFIG_DEFAULT_WIFI_BACKEND;

    nm_log_dbg(LOGD_PLATFORM | LOGD_WIFI,
               "(%s) config: backend is %s%s%s%s",
               iface,
               NM_PRINT_FMT_QUOTE_STRING(backend),
               WITH_IWD ? " (iwd support enabled)" : "");
    if (!g_ascii_strcasecmp(backend, "wpa_supplicant")) {
        NMDevice                 *device;
        _NMDeviceWifiCapabilities capabilities;

        if (!nm_platform_wifi_get_capabilities(NM_PLATFORM_GET, plink->ifindex, &capabilities)) {
            nm_log_warn(LOGD_PLATFORM | LOGD_WIFI,
                        "(%s) failed to initialize Wi-Fi driver for ifindex %d",
                        iface,
                        plink->ifindex);
            return NULL;
        }

        device = nm_device_wifi_new(iface, capabilities);

        g_signal_connect_object(device,
                                NM_DEVICE_WIFI_P2P_DEVICE_CREATED,
                                G_CALLBACK(p2p_device_created),
                                factory,
                                0);

        return device;
    }
#if WITH_IWD
    else if (!g_ascii_strcasecmp(backend, "iwd")) {
        NMIwdManager *iwd = nm_iwd_manager_get();

        if (!g_signal_handler_find(iwd,
                                   G_SIGNAL_MATCH_FUNC | G_SIGNAL_MATCH_DATA,
                                   0,
                                   0,
                                   NULL,
                                   G_CALLBACK(iwd_p2p_device_added),
                                   factory))
            g_signal_connect(iwd,
                             NM_IWD_MANAGER_P2P_DEVICE_ADDED,
                             G_CALLBACK(iwd_p2p_device_added),
                             factory);

        return nm_device_iwd_new(iface);
    }
#endif

    nm_log_warn(LOGD_PLATFORM | LOGD_WIFI,
                "(%s) config: unknown or unsupported wifi-backend %s",
                iface,
                backend);
    return NULL;
}

/*****************************************************************************/

static void
nm_wifi_factory_init(NMWifiFactory *self)
{}

static void
nm_wifi_factory_class_init(NMWifiFactoryClass *klass)
{
    NMDeviceFactoryClass *factory_class = NM_DEVICE_FACTORY_CLASS(klass);

    factory_class->create_device       = create_device;
    factory_class->get_supported_types = get_supported_types;
}
