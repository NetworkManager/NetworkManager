/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2005 - 2013 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-dhcp-manager.h"

#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

#include "libnm-glib-aux/nm-dedup-multi.h"

#include "nm-config.h"
#include "NetworkManagerUtils.h"

/*****************************************************************************/

typedef struct {
    const NMDhcpClientFactory *client_factory;
} NMDhcpManagerPrivate;

struct _NMDhcpManager {
    GObject              parent;
    NMDhcpManagerPrivate _priv;
};

struct _NMDhcpManagerClass {
    GObjectClass parent;
};

G_DEFINE_TYPE(NMDhcpManager, nm_dhcp_manager, G_TYPE_OBJECT)

#define NM_DHCP_MANAGER_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMDhcpManager, NM_IS_DHCP_MANAGER)

/*****************************************************************************/

#undef _NMLOG_ENABLED
#define _NMLOG_ENABLED(level, addr_family) nm_logging_enabled((level), _LOGD_DHCP(addr_family))

#define _NMLOG(level, addr_family, ...)                                                           \
    G_STMT_START                                                                                  \
    {                                                                                             \
        const int         _addr_family = (addr_family);                                           \
        const NMLogLevel  _log_level   = (level);                                                 \
        const NMLogDomain _log_domain  = LOGD_DHCP_af(_addr_family);                              \
                                                                                                  \
        if (nm_logging_enabled(_log_level, _log_domain)) {                                        \
            _nm_log(_log_level,                                                                   \
                    _log_domain,                                                                  \
                    0,                                                                            \
                    NULL,                                                                         \
                    NULL,                                                                         \
                    "dhcp%s: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__),                                \
                    nm_utils_addr_family_to_str(_addr_family) _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
        }                                                                                         \
    }                                                                                             \
    G_STMT_END

/*****************************************************************************/

/* default to installed helper, but can be modified for testing */
const char *nm_dhcp_helper_path = LIBEXECDIR "/nm-dhcp-helper";

/*****************************************************************************/

static const NMDhcpClientFactory *
_client_factory_find_by_name(const char *name)
{
    int i;

    nm_assert(name);

    for (i = 0; i < (int) G_N_ELEMENTS(_nm_dhcp_manager_factories); i++) {
        const NMDhcpClientFactory *f = _nm_dhcp_manager_factories[i];

        if (f && nm_streq(f->name, name))
            return f;
    }
    return NULL;
}

static const NMDhcpClientFactory *
_client_factory_available(const NMDhcpClientFactory *client_factory)
{
    if (client_factory && (!client_factory->get_path || client_factory->get_path()))
        return client_factory;
    return NULL;
}

static GType
_client_factory_get_gtype(const NMDhcpClientFactory *client_factory, int addr_family)
{
    GType gtype;
    GType (*get_type_fcn)(void);

    nm_assert(client_factory);

    /* currently, the chosen DHCP plugin for IPv4 and IPv6 is configured in NetworkManager.conf
     * and cannot be reloaded. It would be nice to configure the plugin per address family
     * or to be able to reload it.
     *
     * Note that certain options in NetworkManager.conf depend on the chosen DHCP plugin.
     * See "dhcp-plugin:" in "Device List Format" (`man NetworkManager.conf`).
     * Supporting reloading the plugin would also require to re-evalate the decisions from
     * the "Device List Format". Likewise, having per-address family plugins would make the
     * "main.dhcp" setting and "dhcp-plugin:" match non-sensical because these configurations
     * currently are address family independent.
     *
     * So actually, we don't want that complexity. We want to phase out all plugins in favor
     * of the internal plugin.
     * However, certain existing plugins are well known to not support an address family.
     * In those cases, we should just silently fallback to the internal plugin.
     *
     * This could be a problem with forward compatibility if we ever intended to add IPv6 support
     * to those plugins. But we don't intend to do so. The internal plugin is the way forward and
     * not extending other plugins. */

    if (NM_IS_IPv4(addr_family))
        get_type_fcn = client_factory->get_type_4;
    else
        get_type_fcn = client_factory->get_type_6;

    if (!get_type_fcn) {
        /* If the factory does not support the address family, we always
         * fallback to the internal. */
        if (NM_IS_IPv4(addr_family))
            get_type_fcn = _nm_dhcp_client_factory_internal.get_type_4;
        else
            get_type_fcn = _nm_dhcp_client_factory_internal.get_type_6;
    }

    gtype = get_type_fcn();

    nm_assert(g_type_is_a(gtype, NM_TYPE_DHCP_CLIENT));
    nm_assert(({
        nm_auto_unref_gtypeclass NMDhcpClientClass *k = g_type_class_ref(gtype);

        (addr_family == AF_INET6 && k->ip6_start) || (addr_family == AF_INET && k->ip4_start);
    }));

    return gtype;
}

/*****************************************************************************/

NMDhcpClient *
nm_dhcp_manager_start_client(NMDhcpManager *self, NMDhcpClientConfig *config, GError **error)
{
    NMDhcpManagerPrivate         *priv;
    gs_unref_object NMDhcpClient *client = NULL;
    gsize                         hwaddr_len;
    GType                         gtype;

    g_return_val_if_fail(NM_IS_DHCP_MANAGER(self), NULL);
    g_return_val_if_fail(config, NULL);
    g_return_val_if_fail(config->iface, NULL);
    g_return_val_if_fail(config->l3cfg, NULL);
    g_return_val_if_fail(config->uuid != NULL, NULL);
    g_return_val_if_fail(!config->client_id || g_bytes_get_size(config->client_id) >= 2, NULL);
    g_return_val_if_fail(!config->vendor_class_identifier
                             || g_bytes_get_size(config->vendor_class_identifier) <= 255,
                         NULL);
    g_return_val_if_fail(!error || !*error, NULL);

    if (config->addr_family == AF_INET) {
        if (!config->hwaddr || !config->bcast_hwaddr) {
            nm_utils_error_set(error,
                               NM_UTILS_ERROR_UNKNOWN,
                               "missing %s address",
                               config->hwaddr ? "broadcast" : "MAC");
            return NULL;
        }

        hwaddr_len = g_bytes_get_size(config->hwaddr);
        if (hwaddr_len == 0 || hwaddr_len > _NM_UTILS_HWADDR_LEN_MAX) {
            nm_utils_error_set(error, NM_UTILS_ERROR_UNKNOWN, "invalid MAC address");
            g_return_val_if_reached(NULL);
        }
        nm_assert(g_bytes_get_size(config->hwaddr) == g_bytes_get_size(config->bcast_hwaddr));
    }

    priv = NM_DHCP_MANAGER_GET_PRIVATE(self);

    gtype = _client_factory_get_gtype(priv->client_factory, config->addr_family);

    _LOGT(config->addr_family,
          "creating IPv%c DHCP client of type %s",
          nm_utils_addr_family_to_char(config->addr_family),
          g_type_name(gtype));

    client = g_object_new(gtype, NM_DHCP_CLIENT_CONFIG, config, NULL);

    /* unfortunately, our implementations work differently per address-family regarding client-id/DUID.
     *
     * - for IPv4, the calling code may determine a client-id (from NM's connection profile).
     *   If present, it is taken. If not present, the DHCP plugin uses a plugin specific default.
     *     - for "internal" plugin, the default is just "mac".
     *     - for "dhclient", we try to get the configuration from dhclient's /etc/dhcp or fallback
     *       to whatever dhclient uses by default.
     *   We do it this way, because for dhclient the user may configure a default
     *   outside of NM, and we want to honor that. Worse, dhclient could be a wapper
     *   script where the wrapper script overwrites the client-id. We need to distinguish
     *   between: force a particular client-id and leave it unspecified to whatever dhclient
     *   wants.
     *
     * - for IPv6, the calling code always determines a client-id. It also specifies @enforce_duid,
     *   to determine whether the given client-id must be used.
     *     - for "internal" plugin @enforce_duid doesn't matter and the given client-id is
     *       always used.
     *     - for "dhclient", @enforce_duid FALSE means to first try to load the DUID from the
     *       lease file, and only otherwise fallback to the given client-id.
     *     - other plugins don't support DHCPv6.
     *   It's done this way, so that existing dhclient setups don't change behavior on upgrade.
     *
     * This difference is cumbersome and only exists because of "dhclient" which supports hacking the
     * default outside of NetworkManager API.
     */

    if (!nm_dhcp_client_start(client, error))
        return NULL;

    return g_steal_pointer(&client);
}

const char *
nm_dhcp_manager_get_config(NMDhcpManager *self)
{
    const NMDhcpClientFactory *factory;

    g_return_val_if_fail(NM_IS_DHCP_MANAGER(self), NULL);

    factory = NM_DHCP_MANAGER_GET_PRIVATE(self)->client_factory;
    return factory ? factory->name : NULL;
}

/*****************************************************************************/

NM_DEFINE_SINGLETON_GETTER(NMDhcpManager, nm_dhcp_manager_get, NM_TYPE_DHCP_MANAGER);

void
nmtst_dhcp_manager_unget(gpointer self)
{
    _nmtst_nm_dhcp_manager_get_reset(self);
}

static void
nm_dhcp_manager_init(NMDhcpManager *self)
{
    NMDhcpManagerPrivate      *priv        = NM_DHCP_MANAGER_GET_PRIVATE(self);
    NMConfig                  *config      = nm_config_get();
    gs_free char              *client_free = NULL;
    const char                *client;
    int                        i;
    const NMDhcpClientFactory *client_factory = NULL;

    for (i = 0; i < (int) G_N_ELEMENTS(_nm_dhcp_manager_factories); i++) {
        const NMDhcpClientFactory *f = _nm_dhcp_manager_factories[i];

        if (!f)
            continue;

        _LOGD(AF_UNSPEC,
              "init: enabled DHCP client '%s'%s%s",
              f->name,
              _client_factory_available(f) ? "" : " (not available)",
              f->undocumented ? " (undocumented internal plugin)" : "");
    }

    /* Client-specific setup */
    client_free =
        nm_config_data_get_value(nm_config_get_data_orig(config),
                                 NM_CONFIG_KEYFILE_GROUP_MAIN,
                                 NM_CONFIG_KEYFILE_KEY_MAIN_DHCP,
                                 NM_CONFIG_GET_VALUE_STRIP | NM_CONFIG_GET_VALUE_NO_EMPTY);
    client = client_free;
    if (client) {
        client_factory = _client_factory_available(_client_factory_find_by_name(client));
        if (!client_factory)
            _LOGW(AF_UNSPEC, "init: DHCP client '%s' not available", client);
    }
    if (!client_factory) {
        client_factory = _client_factory_find_by_name("" NM_CONFIG_DEFAULT_MAIN_DHCP);
        if (!client_factory)
            _LOGE(AF_UNSPEC,
                  "init: default DHCP client '%s' is not installed",
                  NM_CONFIG_DEFAULT_MAIN_DHCP);
        else {
            client_factory = _client_factory_available(client_factory);
            if (!client_factory)
                _LOGI(AF_UNSPEC,
                      "init: default DHCP client '%s' is not available",
                      NM_CONFIG_DEFAULT_MAIN_DHCP);
        }
    }
    if (!client_factory) {
        for (i = 0; i < (int) G_N_ELEMENTS(_nm_dhcp_manager_factories); i++) {
            client_factory = _client_factory_available(_nm_dhcp_manager_factories[i]);
            if (client_factory)
                break;
        }
    }

    g_return_if_fail(client_factory);

    _LOGI(AF_UNSPEC, "init: Using DHCP client '%s'", client_factory->name);

    /* NOTE: currently the DHCP plugin is chosen once at start. It's not
     * possible to reload that configuration. If that ever becomes possible,
     * beware that the "dhcp-plugin" device spec made decisions based on
     * the previous plugin and may need reevaluation. */
    priv->client_factory = client_factory;
}

static void
nm_dhcp_manager_class_init(NMDhcpManagerClass *manager_class)
{}
