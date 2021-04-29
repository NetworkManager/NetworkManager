/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2004 - 2005 Colin Walters <walters@redhat.com>
 * Copyright (C) 2004 - 2017 Red Hat, Inc.
 * Copyright (C) 2005 - 2008 Novell, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include <fcntl.h>
#include <resolv.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <linux/fs.h>

#if WITH_LIBPSL
    #include <libpsl.h>
#endif

#include "nm-utils.h"
#include "nm-core-internal.h"
#include "nm-dns-manager.h"
#include "nm-ip4-config.h"
#include "nm-ip6-config.h"
#include "NetworkManagerUtils.h"
#include "nm-config.h"
#include "nm-dbus-object.h"
#include "devices/nm-device.h"
#include "nm-manager.h"

#include "nm-dns-plugin.h"
#include "nm-dns-dnsmasq.h"
#include "nm-dns-systemd-resolved.h"
#include "nm-dns-unbound.h"

#define HASH_LEN NM_UTILS_CHECKSUM_LENGTH_SHA1

#ifndef RESOLVCONF_PATH
    #define RESOLVCONF_PATH "/sbin/resolvconf"
    #define HAS_RESOLVCONF  0
#else
    #define HAS_RESOLVCONF 1
#endif

#ifndef NETCONFIG_PATH
    #define NETCONFIG_PATH "/sbin/netconfig"
    #define HAS_NETCONFIG  0
#else
    #define HAS_NETCONFIG 1
#endif

/*****************************************************************************/

typedef enum { SR_SUCCESS, SR_NOTFOUND, SR_ERROR } SpawnResult;

typedef struct {
    GPtrArray * nameservers;
    GPtrArray * searches;
    GPtrArray * options;
    const char *nis_domain;
    GPtrArray * nis_servers;
    NMTernary   has_trust_ad;
} NMResolvConfData;

/*****************************************************************************/

enum {
    CONFIG_CHANGED,

    LAST_SIGNAL
};

NM_GOBJECT_PROPERTIES_DEFINE(NMDnsManager, PROP_MODE, PROP_RC_MANAGER, PROP_CONFIGURATION, );

static guint signals[LAST_SIGNAL] = {0};

typedef struct {
    GHashTable *configs_dict;
    CList       configs_lst_head;

    CList     ip_configs_lst_head;
    GVariant *config_variant;

    NMDnsConfigIPData *best_ip_config_4;
    NMDnsConfigIPData *best_ip_config_6;

    bool ip_configs_lst_need_sort : 1;

    bool configs_lst_need_sort : 1;

    bool dns_touched : 1;
    bool is_stopped : 1;

    char *hostname;
    guint updates_queue;

    guint8 hash[HASH_LEN];      /* SHA1 hash of current DNS config */
    guint8 prev_hash[HASH_LEN]; /* Hash when begin_updates() was called */

    NMDnsManagerResolvConfManager rc_manager;
    char *                        mode;
    NMDnsPlugin *                 sd_resolve_plugin;
    NMDnsPlugin *                 plugin;

    NMConfig *config;

    struct {
        guint64 ts;
        guint   num_restarts;
        guint   timer;
    } plugin_ratelimit;
} NMDnsManagerPrivate;

struct _NMDnsManager {
    NMDBusObject        parent;
    NMDnsManagerPrivate _priv;
};

struct _NMDnsManagerClass {
    NMDBusObjectClass parent;
};

G_DEFINE_TYPE(NMDnsManager, nm_dns_manager, NM_TYPE_DBUS_OBJECT)

#define NM_DNS_MANAGER_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMDnsManager, NM_IS_DNS_MANAGER)

NM_DEFINE_SINGLETON_GETTER(NMDnsManager, nm_dns_manager_get, NM_TYPE_DNS_MANAGER);

/*****************************************************************************/

#define _NMLOG_PREFIX_NAME "dns-mgr"
#define _NMLOG_DOMAIN      LOGD_DNS
#define _NMLOG(level, ...)                                           \
    G_STMT_START                                                     \
    {                                                                \
        const NMLogLevel __level = (level);                          \
                                                                     \
        if (nm_logging_enabled(__level, _NMLOG_DOMAIN)) {            \
            char                      __prefix[20];                  \
            const NMDnsManager *const __self = (self);               \
                                                                     \
            _nm_log(__level,                                         \
                    _NMLOG_DOMAIN,                                   \
                    0,                                               \
                    NULL,                                            \
                    NULL,                                            \
                    "%s%s: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__),     \
                    _NMLOG_PREFIX_NAME,                              \
                    ((!__self || __self == singleton_instance)       \
                         ? ""                                        \
                         : nm_sprintf_buf(__prefix, "[%p]", __self)) \
                        _NM_UTILS_MACRO_REST(__VA_ARGS__));          \
        }                                                            \
    }                                                                \
    G_STMT_END

/*****************************************************************************/

static void
_ip_config_dns_priority_changed(gpointer config, GParamSpec *pspec, NMDnsConfigIPData *ip_data);

/*****************************************************************************/

static gboolean
domain_is_valid(const char *domain, gboolean check_public_suffix)
{
    if (*domain == '\0')
        return FALSE;
#if WITH_LIBPSL
    if (check_public_suffix && psl_is_public_suffix(psl_builtin(), domain))
        return FALSE;
#endif
    return TRUE;
}

static gboolean
domain_is_routing(const char *domain)
{
    return domain[0] == '~';
}

/*****************************************************************************/

static NM_UTILS_LOOKUP_STR_DEFINE(
    _rc_manager_to_string,
    NMDnsManagerResolvConfManager,
    NM_UTILS_LOOKUP_DEFAULT_WARN(NULL),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DNS_MANAGER_RESOLV_CONF_MAN_AUTO, "auto"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DNS_MANAGER_RESOLV_CONF_MAN_UNKNOWN, "unknown"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DNS_MANAGER_RESOLV_CONF_MAN_UNMANAGED, "unmanaged"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DNS_MANAGER_RESOLV_CONF_MAN_IMMUTABLE, "immutable"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DNS_MANAGER_RESOLV_CONF_MAN_SYMLINK, "symlink"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DNS_MANAGER_RESOLV_CONF_MAN_FILE, "file"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DNS_MANAGER_RESOLV_CONF_MAN_RESOLVCONF, "resolvconf"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DNS_MANAGER_RESOLV_CONF_MAN_NETCONFIG, "netconfig"), );

static NM_UTILS_LOOKUP_STR_DEFINE(
    _config_type_to_string,
    NMDnsIPConfigType,
    NM_UTILS_LOOKUP_DEFAULT_WARN("<unknown>"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DNS_IP_CONFIG_TYPE_REMOVED, "removed"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DNS_IP_CONFIG_TYPE_DEFAULT, "default"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DNS_IP_CONFIG_TYPE_BEST_DEVICE, "best"),
    NM_UTILS_LOOKUP_STR_ITEM(NM_DNS_IP_CONFIG_TYPE_VPN, "vpn"), );

/*****************************************************************************/

static void
_ASSERT_dns_config_data(const NMDnsConfigData *data)
{
    nm_assert(data);
    nm_assert(NM_IS_DNS_MANAGER(data->self));
    nm_assert(data->ifindex > 0);
}

static void
_ASSERT_dns_config_ip_data(const NMDnsConfigIPData *ip_data)
{
    nm_assert(ip_data);
    _ASSERT_dns_config_data(ip_data->data);
    nm_assert(NM_IS_IP_CONFIG(ip_data->ip_config));
    nm_assert(c_list_contains(&ip_data->data->data_lst_head, &ip_data->data_lst));
    nm_assert(ip_data->data->ifindex == nm_ip_config_get_ifindex(ip_data->ip_config));
#if NM_MORE_ASSERTS > 5
    {
        gboolean has_default = FALSE;
        gsize    i;

        for (i = 0; ip_data->domains.search && ip_data->domains.search; i++) {
            const char *d = ip_data->domains.search[i];

            d = nm_utils_parse_dns_domain(d, NULL);
            nm_assert(d);
            if (d[0] == '\0')
                has_default = TRUE;
        }
        nm_assert(has_default == ip_data->domains.has_default_route_explicit);
        if (ip_data->domains.has_default_route_explicit)
            nm_assert(ip_data->domains.has_default_route_exclusive);
        if (ip_data->domains.has_default_route_exclusive)
            nm_assert(ip_data->domains.has_default_route);
    }
#endif
}

static NMDnsConfigIPData *
_dns_config_ip_data_new(NMDnsConfigData * data,
                        NMIPConfig *      ip_config,
                        NMDnsIPConfigType ip_config_type)
{
    NMDnsConfigIPData *ip_data;

    _ASSERT_dns_config_data(data);
    nm_assert(NM_IS_IP_CONFIG(ip_config));
    nm_assert(ip_config_type != NM_DNS_IP_CONFIG_TYPE_REMOVED);

    ip_data  = g_slice_new(NMDnsConfigIPData);
    *ip_data = (NMDnsConfigIPData){
        .data           = data,
        .ip_config      = g_object_ref(ip_config),
        .ip_config_type = ip_config_type,
    };
    c_list_link_tail(&data->data_lst_head, &ip_data->data_lst);
    c_list_link_tail(&NM_DNS_MANAGER_GET_PRIVATE(data->self)->ip_configs_lst_head,
                     &ip_data->ip_config_lst);

    g_signal_connect(ip_config,
                     NM_IS_IP4_CONFIG(ip_config) ? "notify::" NM_IP4_CONFIG_DNS_PRIORITY
                                                 : "notify::" NM_IP6_CONFIG_DNS_PRIORITY,
                     (GCallback) _ip_config_dns_priority_changed,
                     ip_data);

    _ASSERT_dns_config_ip_data(ip_data);
    return ip_data;
}

static void
_dns_config_ip_data_free(NMDnsConfigIPData *ip_data)
{
    _ASSERT_dns_config_ip_data(ip_data);

    c_list_unlink_stale(&ip_data->data_lst);
    c_list_unlink_stale(&ip_data->ip_config_lst);

    g_free(ip_data->domains.search);
    g_strfreev(ip_data->domains.reverse);

    g_signal_handlers_disconnect_by_func(ip_data->ip_config,
                                         _ip_config_dns_priority_changed,
                                         ip_data);

    g_object_unref(ip_data->ip_config);
    nm_g_slice_free(ip_data);
}

static NMDnsConfigIPData *
_dns_config_data_find_ip_config(NMDnsConfigData *data, NMIPConfig *ip_config)
{
    NMDnsConfigIPData *ip_data;

    _ASSERT_dns_config_data(data);

    c_list_for_each_entry (ip_data, &data->data_lst_head, data_lst) {
        _ASSERT_dns_config_ip_data(ip_data);

        if (ip_data->ip_config == ip_config)
            return ip_data;
    }
    return NULL;
}

static void
_dns_config_data_free(NMDnsConfigData *data)
{
    _ASSERT_dns_config_data(data);

    nm_assert(c_list_is_empty(&data->data_lst_head));
    c_list_unlink_stale(&data->configs_lst);
    nm_g_slice_free(data);
}

static int
_mgr_get_ip_configs_lst_cmp(const CList *a_lst, const CList *b_lst, const void *user_data)
{
    const NMDnsConfigIPData *a = c_list_entry(a_lst, NMDnsConfigIPData, ip_config_lst);
    const NMDnsConfigIPData *b = c_list_entry(b_lst, NMDnsConfigIPData, ip_config_lst);

    /* Configurations with lower priority value first */
    NM_CMP_DIRECT(nm_ip_config_get_dns_priority(a->ip_config),
                  nm_ip_config_get_dns_priority(b->ip_config));

    /* Sort according to type (descendingly) */
    NM_CMP_FIELD(b, a, ip_config_type);

    return 0;
}

static CList *
_mgr_get_ip_configs_lst_head(NMDnsManager *self)
{
    NMDnsManagerPrivate *priv = NM_DNS_MANAGER_GET_PRIVATE(self);

    if (G_UNLIKELY(priv->ip_configs_lst_need_sort)) {
        priv->ip_configs_lst_need_sort = FALSE;
        c_list_sort(&priv->ip_configs_lst_head, _mgr_get_ip_configs_lst_cmp, NULL);
    }

    return &priv->ip_configs_lst_head;
}

static int
_mgr_get_configs_lst_cmp(const CList *a_lst, const CList *b_lst, const void *user_data)
{
    const NMDnsConfigData *a = c_list_entry(a_lst, NMDnsConfigData, configs_lst);
    const NMDnsConfigData *b = c_list_entry(b_lst, NMDnsConfigData, configs_lst);

    NM_CMP_FIELD(b, a, ifindex);
    return nm_assert_unreachable_val(0);
}

_nm_unused static CList *
_mgr_get_configs_lst_head(NMDnsManager *self)
{
    NMDnsManagerPrivate *priv = NM_DNS_MANAGER_GET_PRIVATE(self);

    if (G_UNLIKELY(priv->configs_lst_need_sort)) {
        priv->configs_lst_need_sort = FALSE;
        c_list_sort(&priv->configs_lst_head, _mgr_get_configs_lst_cmp, NULL);
    }

    return &priv->configs_lst_head;
}

/*****************************************************************************/

gboolean
nm_dns_manager_has_systemd_resolved(NMDnsManager *self)
{
    NMDnsManagerPrivate * priv;
    NMDnsSystemdResolved *plugin = NULL;

    g_return_val_if_fail(NM_IS_DNS_MANAGER(self), FALSE);

    priv = NM_DNS_MANAGER_GET_PRIVATE(self);

    if (priv->sd_resolve_plugin) {
        nm_assert(!NM_IS_DNS_SYSTEMD_RESOLVED(priv->plugin));
        plugin = NM_DNS_SYSTEMD_RESOLVED(priv->sd_resolve_plugin);
    } else if (NM_IS_DNS_SYSTEMD_RESOLVED(priv->plugin))
        plugin = NM_DNS_SYSTEMD_RESOLVED(priv->plugin);

    return plugin && nm_dns_systemd_resolved_is_running(plugin);
}

/*****************************************************************************/

static void
add_string_item(GPtrArray *array, const char *str, gboolean dup)
{
    int i;

    g_return_if_fail(array != NULL);
    g_return_if_fail(str != NULL);

    /* Check for dupes before adding */
    for (i = 0; i < array->len; i++) {
        const char *candidate = g_ptr_array_index(array, i);

        if (candidate && !strcmp(candidate, str))
            return;
    }

    /* No dupes, add the new item */
    g_ptr_array_add(array, dup ? g_strdup(str) : (gpointer) str);
}

static void
add_dns_option_item(GPtrArray *array, const char *str)
{
    if (_nm_utils_dns_option_find_idx(array, str) < 0)
        g_ptr_array_add(array, g_strdup(str));
}

static void
add_dns_domains(GPtrArray *       array,
                const NMIPConfig *ip_config,
                gboolean          include_routing,
                gboolean          dup)
{
    guint       num_domains, num_searches, i;
    const char *str;

    num_domains  = nm_ip_config_get_num_domains(ip_config);
    num_searches = nm_ip_config_get_num_searches(ip_config);

    for (i = 0; i < num_searches; i++) {
        str = nm_ip_config_get_search(ip_config, i);
        if (!include_routing && domain_is_routing(str))
            continue;
        if (!domain_is_valid(nm_utils_parse_dns_domain(str, NULL), FALSE))
            continue;
        add_string_item(array, str, dup);
    }
    if (num_domains > 1 || !num_searches) {
        for (i = 0; i < num_domains; i++) {
            str = nm_ip_config_get_domain(ip_config, i);
            if (!include_routing && domain_is_routing(str))
                continue;
            if (!domain_is_valid(nm_utils_parse_dns_domain(str, NULL), FALSE))
                continue;
            add_string_item(array, str, dup);
        }
    }
}

static void
merge_one_ip_config(NMResolvConfData *rc, int ifindex, const NMIPConfig *ip_config)
{
    int      addr_family;
    char     buf[NM_UTILS_INET_ADDRSTRLEN + 50];
    gboolean has_trust_ad;
    guint    num_nameservers;
    guint    num;
    guint    i;

    addr_family = nm_ip_config_get_addr_family(ip_config);

    nm_assert_addr_family(addr_family);
    nm_assert(ifindex > 0);
    nm_assert(ifindex == nm_ip_config_get_ifindex(ip_config));

    num_nameservers = nm_ip_config_get_num_nameservers(ip_config);
    for (i = 0; i < num_nameservers; i++) {
        const NMIPAddr *addr;

        addr = nm_ip_config_get_nameserver(ip_config, i);
        if (addr_family == AF_INET)
            nm_utils_inet_ntop(addr_family, addr, buf);
        else if (IN6_IS_ADDR_V4MAPPED(addr))
            _nm_utils_inet4_ntop(addr->addr6.s6_addr32[3], buf);
        else {
            _nm_utils_inet6_ntop(&addr->addr6, buf);
            if (IN6_IS_ADDR_LINKLOCAL(addr)) {
                const char *ifname;

                ifname = nm_platform_link_get_name(NM_PLATFORM_GET, ifindex);
                if (ifname) {
                    g_strlcat(buf, "%", sizeof(buf));
                    g_strlcat(buf, ifname, sizeof(buf));
                }
            }
        }

        add_string_item(rc->nameservers, buf, TRUE);
    }

    add_dns_domains(rc->searches, ip_config, FALSE, TRUE);

    has_trust_ad = FALSE;
    num          = nm_ip_config_get_num_dns_options(ip_config);
    for (i = 0; i < num; i++) {
        const char *option = nm_ip_config_get_dns_option(ip_config, i);

        if (nm_streq(option, NM_SETTING_DNS_OPTION_TRUST_AD)) {
            has_trust_ad = TRUE;
            continue;
        }
        add_dns_option_item(rc->options, nm_ip_config_get_dns_option(ip_config, i));
    }
    if (num_nameservers == 0) {
        /* If the @ip_config contributes no DNS servers, ignore whether trust-ad is set or unset
         * for this @ip_config. */
    } else if (has_trust_ad) {
        /* We only set has_trust_ad to TRUE, if all IP configs agree (or don't contribute).
         * Once set to FALSE, it doesn't get reset. */
        if (rc->has_trust_ad == NM_TERNARY_DEFAULT)
            rc->has_trust_ad = NM_TERNARY_TRUE;
    } else
        rc->has_trust_ad = NM_TERNARY_FALSE;

    if (addr_family == AF_INET) {
        const NMIP4Config *ip4_config = (const NMIP4Config *) ip_config;

        /* NIS stuff */
        num = nm_ip4_config_get_num_nis_servers(ip4_config);
        for (i = 0; i < num; i++) {
            add_string_item(rc->nis_servers,
                            _nm_utils_inet4_ntop(nm_ip4_config_get_nis_server(ip4_config, i), buf),
                            TRUE);
        }

        if (nm_ip4_config_get_nis_domain(ip4_config)) {
            /* FIXME: handle multiple domains */
            if (!rc->nis_domain)
                rc->nis_domain = nm_ip4_config_get_nis_domain(ip4_config);
        }
    }
}

static GPid
run_netconfig(NMDnsManager *self, GError **error, int *stdin_fd)
{
    char *        argv[5];
    gs_free char *tmp = NULL;
    GPid          pid = -1;

    argv[0] = NETCONFIG_PATH;
    argv[1] = "modify";
    argv[2] = "--service";
    argv[3] = "NetworkManager";
    argv[4] = NULL;

    _LOGD("spawning '%s'", (tmp = g_strjoinv(" ", argv)));

    if (!g_spawn_async_with_pipes(NULL,
                                  argv,
                                  NULL,
                                  G_SPAWN_DO_NOT_REAP_CHILD,
                                  NULL,
                                  NULL,
                                  &pid,
                                  stdin_fd,
                                  NULL,
                                  NULL,
                                  error))
        return -1;

    return pid;
}

static void
netconfig_construct_str(NMDnsManager *self, GString *str, const char *key, const char *value)
{
    if (value) {
        _LOGD("writing to netconfig: %s='%s'", key, value);
        g_string_append_printf(str, "%s='%s'\n", key, value);
    }
}

static void
netconfig_construct_strv(NMDnsManager *     self,
                         GString *          str,
                         const char *       key,
                         const char *const *values)
{
    if (values) {
        gs_free char *value = NULL;

        value = g_strjoinv(" ", (char **) values);
        netconfig_construct_str(self, str, key, value);
    }
}

static SpawnResult
dispatch_netconfig(NMDnsManager *     self,
                   const char *const *searches,
                   const char *const *nameservers,
                   const char *       nis_domain,
                   const char *const *nis_servers,
                   GError **          error)
{
    GPid                 pid;
    int                  fd;
    int                  errsv;
    int                  status;
    gssize               l;
    nm_auto_free_gstring GString *str = NULL;

    pid = run_netconfig(self, error, &fd);
    if (pid <= 0)
        return SR_NOTFOUND;

    str = g_string_new("");

    /* NM is writing already-merged DNS information to netconfig, so it
     * does not apply to a specific network interface.
     */
    netconfig_construct_str(self, str, "INTERFACE", "NetworkManager");
    netconfig_construct_strv(self, str, "DNSSEARCH", searches);
    netconfig_construct_strv(self, str, "DNSSERVERS", nameservers);
    netconfig_construct_str(self, str, "NISDOMAIN", nis_domain);
    netconfig_construct_strv(self, str, "NISSERVERS", nis_servers);

again:
    l = write(fd, str->str, str->len);
    if (l == -1) {
        if (errno == EINTR)
            goto again;
    }

    nm_close(fd);

    /* FIXME: don't write to netconfig synchronously. */

    /* Wait until the process exits */
    if (!nm_utils_kill_child_sync(pid, 0, LOGD_DNS, "netconfig", &status, 1000, 0)) {
        errsv = errno;
        g_set_error(error,
                    NM_MANAGER_ERROR,
                    NM_MANAGER_ERROR_FAILED,
                    "Error waiting for netconfig to exit: %s",
                    nm_strerror_native(errsv));
        return SR_ERROR;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != EXIT_SUCCESS) {
        g_set_error(error,
                    NM_MANAGER_ERROR,
                    NM_MANAGER_ERROR_FAILED,
                    "Error calling netconfig: %s %d",
                    WIFEXITED(status) ? "exited with status"
                                      : (WIFSIGNALED(status) ? "exited with signal"
                                                             : "exited with unknown reason"),
                    WIFEXITED(status) ? WEXITSTATUS(status)
                                      : (WIFSIGNALED(status) ? WTERMSIG(status) : status));
        return SR_ERROR;
    }
    return SR_SUCCESS;
}

static char *
create_resolv_conf(const char *const *searches,
                   const char *const *nameservers,
                   const char *const *options)
{
    GString *str;
    gsize    i;

    str = g_string_new_len(NULL, 245);

    g_string_append(str, "# Generated by NetworkManager\n");

    if (searches && searches[0]) {
        gsize search_base_idx;

        g_string_append(str, "search");
        search_base_idx = str->len;

        for (i = 0; searches[i]; i++) {
            const char *s = searches[i];
            gsize       l = strlen(s);

            if (l == 0 || NM_STRCHAR_ANY(s, ch, NM_IN_SET(ch, ' ', '\t', '\n'))) {
                /* there should be no such characters in the search entry. Also,
                 * because glibc parser would treat them as line/word separator.
                 *
                 * Skip the value silently. */
                continue;
            }

            if (search_base_idx > 0) {
                if (str->len - search_base_idx + 1 + l > 254) {
                    /* this entry crosses the 256 character boundary. Older glibc versions
                     * would truncate the entry at this point.
                     *
                     * Fill the line with spaces to cross the 256 char boundary and continue
                     * afterwards. This way, the truncation happens between two search entries. */
                    while (str->len - search_base_idx < 257)
                        g_string_append_c(str, ' ');
                    search_base_idx = 0;
                }
            }

            g_string_append_c(str, ' ');
            g_string_append_len(str, s, l);
        }
        g_string_append_c(str, '\n');
    }

    if (nameservers && nameservers[0]) {
        for (i = 0; nameservers[i]; i++) {
            if (i == 3) {
                g_string_append(
                    str,
                    "# NOTE: the libc resolver may not support more than 3 nameservers.\n");
                g_string_append(str, "# The nameservers listed below may not be recognized.\n");
            }
            g_string_append(str, "nameserver ");
            g_string_append(str, nameservers[i]);
            g_string_append_c(str, '\n');
        }
    }

    if (options && options[0]) {
        g_string_append(str, "options");
        for (i = 0; options[i]; i++) {
            g_string_append_c(str, ' ');
            g_string_append(str, options[i]);
        }
        g_string_append_c(str, '\n');
    }

    return g_string_free(str, FALSE);
}

char *
nmtst_dns_create_resolv_conf(const char *const *searches,
                             const char *const *nameservers,
                             const char *const *options)
{
    return create_resolv_conf(searches, nameservers, options);
}

static gboolean
write_resolv_conf_contents(FILE *f, const char *content, GError **error)
{
    int errsv;

    if (fprintf(f, "%s", content) < 0) {
        errsv = errno;
        g_set_error(error,
                    NM_MANAGER_ERROR,
                    NM_MANAGER_ERROR_FAILED,
                    "Could not write " _PATH_RESCONF ": %s",
                    nm_strerror_native(errsv));
        errno = errsv;
        return FALSE;
    }

    return TRUE;
}

static gboolean
write_resolv_conf(FILE *             f,
                  const char *const *searches,
                  const char *const *nameservers,
                  const char *const *options,
                  GError **          error)
{
    gs_free char *content = NULL;

    content = create_resolv_conf(searches, nameservers, options);
    return write_resolv_conf_contents(f, content, error);
}

static SpawnResult
dispatch_resolvconf(NMDnsManager *self,
                    char **       searches,
                    char **       nameservers,
                    char **       options,
                    GError **     error)
{
    gs_free char *cmd = NULL;
    FILE *        f;
    gboolean      success = FALSE;
    int           errsv;
    int           err;
    char *        argv[] = {RESOLVCONF_PATH, "-d", "NetworkManager", NULL};
    int           status;

    if (!g_file_test(RESOLVCONF_PATH, G_FILE_TEST_IS_EXECUTABLE)) {
        g_set_error_literal(error,
                            NM_MANAGER_ERROR,
                            NM_MANAGER_ERROR_FAILED,
                            RESOLVCONF_PATH " is not executable");
        return SR_NOTFOUND;
    }

    if (!searches && !nameservers) {
        _LOGI("Removing DNS information from %s", RESOLVCONF_PATH);

        if (!g_spawn_sync("/", argv, NULL, 0, NULL, NULL, NULL, NULL, &status, error))
            return SR_ERROR;

        if (status != 0) {
            g_set_error(error,
                        NM_MANAGER_ERROR,
                        NM_MANAGER_ERROR_FAILED,
                        "%s returned error code",
                        RESOLVCONF_PATH);
            return SR_ERROR;
        }

        return SR_SUCCESS;
    }

    _LOGI("Writing DNS information to %s", RESOLVCONF_PATH);

    /* FIXME: don't write to resolvconf synchronously. */

    cmd = g_strconcat(RESOLVCONF_PATH, " -a ", "NetworkManager", NULL);
    if ((f = popen(cmd, "w")) == NULL) {
        errsv = errno;
        g_set_error(error,
                    NM_MANAGER_ERROR,
                    NM_MANAGER_ERROR_FAILED,
                    "Could not write to %s: %s",
                    RESOLVCONF_PATH,
                    nm_strerror_native(errsv));
        return SR_ERROR;
    }

    success = write_resolv_conf(f,
                                NM_CAST_STRV_CC(searches),
                                NM_CAST_STRV_CC(nameservers),
                                NM_CAST_STRV_CC(options),
                                error);
    err     = pclose(f);
    if (err < 0) {
        errsv = errno;
        g_clear_error(error);
        g_set_error(error,
                    G_IO_ERROR,
                    g_io_error_from_errno(errsv),
                    "Failed to close pipe to resolvconf: %d",
                    errsv);
        return SR_ERROR;
    } else if (err > 0) {
        _LOGW("resolvconf failed with status %d", err);
        g_clear_error(error);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "resolvconf failed with status %d", err);
        return SR_ERROR;
    }

    return success ? SR_SUCCESS : SR_ERROR;
}

static const char *
_read_link_cached(const char *path, gboolean *is_cached, char **cached)
{
    nm_assert(is_cached);
    nm_assert(cached);

    if (*is_cached)
        return *cached;

    nm_assert(!*cached);
    *is_cached = TRUE;
    return (*cached = g_file_read_link(path, NULL));
}

#define MY_RESOLV_CONF     NMRUNDIR "/resolv.conf"
#define MY_RESOLV_CONF_TMP MY_RESOLV_CONF ".tmp"
#define RESOLV_CONF_TMP    "/etc/.resolv.conf.NetworkManager"

#define NO_STUB_RESOLV_CONF NMRUNDIR "/no-stub-resolv.conf"

static void
update_resolv_conf_no_stub(NMDnsManager *     self,
                           const char *const *searches,
                           const char *const *nameservers,
                           const char *const *options)
{
    gs_free char *content = NULL;
    GError *      local   = NULL;

    content = create_resolv_conf(searches, nameservers, options);

    if (!g_file_set_contents(NO_STUB_RESOLV_CONF, content, -1, &local)) {
        _LOGD("update-resolv-no-stub: failure to write file: %s", local->message);
        g_error_free(local);
        return;
    }

    _LOGT("update-resolv-no-stub: '%s' successfully written", NO_STUB_RESOLV_CONF);
}

static SpawnResult
update_resolv_conf(NMDnsManager *                self,
                   const char *const *           searches,
                   const char *const *           nameservers,
                   const char *const *           options,
                   GError **                     error,
                   NMDnsManagerResolvConfManager rc_manager)
{
    FILE *        f;
    gboolean      success;
    gs_free char *content           = NULL;
    SpawnResult   write_file_result = SR_SUCCESS;
    int           errsv;
    gboolean      resconf_link_cached = FALSE;
    gs_free char *resconf_link        = NULL;

    content = create_resolv_conf(searches, nameservers, options);

    if (rc_manager == NM_DNS_MANAGER_RESOLV_CONF_MAN_FILE
        || (rc_manager == NM_DNS_MANAGER_RESOLV_CONF_MAN_SYMLINK
            && !_read_link_cached(_PATH_RESCONF, &resconf_link_cached, &resconf_link))) {
        gs_free char *     rc_path_syml = NULL;
        nm_auto_free char *rc_path_real = NULL;
        const char *       rc_path      = _PATH_RESCONF;
        GError *           local        = NULL;

        if (rc_manager == NM_DNS_MANAGER_RESOLV_CONF_MAN_FILE) {
            rc_path_real = realpath(_PATH_RESCONF, NULL);
            if (rc_path_real)
                rc_path = rc_path_real;
            else {
                /* realpath did not resolve a path-name. That either means,
                 * _PATH_RESCONF:
                 *   - does not exist
                 *   - is a plain file
                 *   - is a dangling symlink
                 *
                 * Handle the case, where it is a dangling symlink... */
                rc_path_syml = nm_utils_read_link_absolute(_PATH_RESCONF, NULL);
                if (rc_path_syml)
                    rc_path = rc_path_syml;
            }
        }

        /* we first write to /etc/resolv.conf directly. If that fails,
         * we still continue to write to runstatedir but remember the
         * error. */
        if (!g_file_set_contents(rc_path, content, -1, &local)) {
            _LOGT("update-resolv-conf: write to %s failed (rc-manager=%s, %s)",
                  rc_path,
                  _rc_manager_to_string(rc_manager),
                  local->message);
            g_propagate_error(error, local);
            /* clear @error, so that we don't try reset it. This is the error
             * we want to propagate to the caller. */
            error             = NULL;
            write_file_result = SR_ERROR;
        } else {
            _LOGT("update-resolv-conf: write to %s succeeded (rc-manager=%s)",
                  rc_path,
                  _rc_manager_to_string(rc_manager));
        }
    }

    if ((f = fopen(MY_RESOLV_CONF_TMP, "we")) == NULL) {
        errsv = errno;
        g_set_error(error,
                    NM_MANAGER_ERROR,
                    NM_MANAGER_ERROR_FAILED,
                    "Could not open %s: %s",
                    MY_RESOLV_CONF_TMP,
                    nm_strerror_native(errsv));
        _LOGT("update-resolv-conf: open temporary file %s failed (%s)",
              MY_RESOLV_CONF_TMP,
              nm_strerror_native(errsv));
        return SR_ERROR;
    }

    success = write_resolv_conf_contents(f, content, error);
    if (!success) {
        errsv = errno;
        _LOGT("update-resolv-conf: write temporary file %s failed (%s)",
              MY_RESOLV_CONF_TMP,
              nm_strerror_native(errsv));
    }

    if (fclose(f) < 0) {
        if (success) {
            errsv = errno;
            /* only set an error here if write_resolv_conf() was successful,
             * since its error is more important.
             */
            g_set_error(error,
                        NM_MANAGER_ERROR,
                        NM_MANAGER_ERROR_FAILED,
                        "Could not close %s: %s",
                        MY_RESOLV_CONF_TMP,
                        nm_strerror_native(errsv));
            _LOGT("update-resolv-conf: close temporary file %s failed (%s)",
                  MY_RESOLV_CONF_TMP,
                  nm_strerror_native(errsv));
        }
        return SR_ERROR;
    } else if (!success)
        return SR_ERROR;

    if (rename(MY_RESOLV_CONF_TMP, MY_RESOLV_CONF) < 0) {
        errsv = errno;
        g_set_error(error,
                    NM_MANAGER_ERROR,
                    NM_MANAGER_ERROR_FAILED,
                    "Could not replace %s: %s",
                    MY_RESOLV_CONF,
                    nm_strerror_native(errsv));
        _LOGT("update-resolv-conf: failed to rename temporary file %s to %s (%s)",
              MY_RESOLV_CONF_TMP,
              MY_RESOLV_CONF,
              nm_strerror_native(errsv));
        return SR_ERROR;
    }

    if (rc_manager == NM_DNS_MANAGER_RESOLV_CONF_MAN_FILE) {
        _LOGT("update-resolv-conf: write internal file %s succeeded (rc-manager=%s)",
              MY_RESOLV_CONF,
              _rc_manager_to_string(rc_manager));
        return write_file_result;
    }

    if (rc_manager != NM_DNS_MANAGER_RESOLV_CONF_MAN_SYMLINK
        || !_read_link_cached(_PATH_RESCONF, &resconf_link_cached, &resconf_link)) {
        _LOGT("update-resolv-conf: write internal file %s succeeded", MY_RESOLV_CONF);
        return write_file_result;
    }

    if (!nm_streq0(_read_link_cached(_PATH_RESCONF, &resconf_link_cached, &resconf_link),
                   MY_RESOLV_CONF)) {
        _LOGT("update-resolv-conf: write internal file %s succeeded (don't touch symlink %s "
              "linking to %s)",
              MY_RESOLV_CONF,
              _PATH_RESCONF,
              _read_link_cached(_PATH_RESCONF, &resconf_link_cached, &resconf_link));
        return write_file_result;
    }

    /* By this point, /etc/resolv.conf exists and is a symlink to our internal
     * resolv.conf. We update the symlink so that applications get an inotify
     * notification.
     */
    if (unlink(RESOLV_CONF_TMP) != 0 && ((errsv = errno) != ENOENT)) {
        g_set_error(error,
                    NM_MANAGER_ERROR,
                    NM_MANAGER_ERROR_FAILED,
                    "Could not unlink %s: %s",
                    RESOLV_CONF_TMP,
                    nm_strerror_native(errsv));
        _LOGT("update-resolv-conf: write internal file %s succeeded "
              "but cannot delete temporary file %s: %s",
              MY_RESOLV_CONF,
              RESOLV_CONF_TMP,
              nm_strerror_native(errsv));
        return SR_ERROR;
    }

    if (symlink(MY_RESOLV_CONF, RESOLV_CONF_TMP) == -1) {
        errsv = errno;
        g_set_error(error,
                    NM_MANAGER_ERROR,
                    NM_MANAGER_ERROR_FAILED,
                    "Could not create symlink %s pointing to %s: %s",
                    RESOLV_CONF_TMP,
                    MY_RESOLV_CONF,
                    nm_strerror_native(errsv));
        _LOGT("update-resolv-conf: write internal file %s succeeded "
              "but failed to symlink %s: %s",
              MY_RESOLV_CONF,
              RESOLV_CONF_TMP,
              nm_strerror_native(errsv));
        return SR_ERROR;
    }

    if (rename(RESOLV_CONF_TMP, _PATH_RESCONF) == -1) {
        errsv = errno;
        g_set_error(error,
                    NM_MANAGER_ERROR,
                    NM_MANAGER_ERROR_FAILED,
                    "Could not rename %s to %s: %s",
                    RESOLV_CONF_TMP,
                    _PATH_RESCONF,
                    nm_strerror_native(errsv));
        _LOGT("update-resolv-conf: write internal file %s succeeded "
              "but failed to rename temporary symlink %s to %s: %s",
              MY_RESOLV_CONF,
              RESOLV_CONF_TMP,
              _PATH_RESCONF,
              nm_strerror_native(errsv));
        return SR_ERROR;
    }

    _LOGT("update-resolv-conf: write internal file %s succeeded and update symlink %s",
          MY_RESOLV_CONF,
          _PATH_RESCONF);
    return write_file_result;
}

static void
compute_hash(NMDnsManager *self, const NMGlobalDnsConfig *global, guint8 buffer[HASH_LEN])
{
    nm_auto_free_checksum GChecksum *sum = NULL;
    NMDnsConfigIPData *              ip_data;

    sum = g_checksum_new(G_CHECKSUM_SHA1);
    nm_assert(HASH_LEN == g_checksum_type_get_length(G_CHECKSUM_SHA1));

    if (global)
        nm_global_dns_config_update_checksum(global, sum);
    else {
        const CList *head;

        /* FIXME(ip-config-checksum): this relies on the fact that an IP
         * configuration without DNS parameters gives a zero checksum. */
        head = _mgr_get_ip_configs_lst_head(self);
        c_list_for_each_entry (ip_data, head, ip_config_lst)
            nm_ip_config_hash(ip_data->ip_config, sum, TRUE);
    }

    nm_utils_checksum_get_digest_len(sum, buffer, HASH_LEN);
}

static gboolean
merge_global_dns_config(NMResolvConfData *rc, NMGlobalDnsConfig *global_conf)
{
    NMGlobalDnsDomain *default_domain;
    const char *const *searches;
    const char *const *options;
    const char *const *servers;
    guint              i;

    if (!global_conf)
        return FALSE;

    searches = nm_global_dns_config_get_searches(global_conf);
    if (searches) {
        for (i = 0; searches[i]; i++) {
            if (domain_is_routing(searches[i]))
                continue;
            if (!domain_is_valid(searches[i], FALSE))
                continue;
            add_string_item(rc->searches, searches[i], TRUE);
        }
    }

    options = nm_global_dns_config_get_options(global_conf);
    if (options) {
        for (i = 0; options[i]; i++)
            add_string_item(rc->options, options[i], TRUE);
    }

    default_domain = nm_global_dns_config_lookup_domain(global_conf, "*");
    nm_assert(default_domain);

    servers = nm_global_dns_domain_get_servers(default_domain);
    if (servers) {
        for (i = 0; servers[i]; i++)
            add_string_item(rc->nameservers, servers[i], TRUE);
    }

    return TRUE;
}

static const char *
get_nameserver_list(const NMIPConfig *config, GString **str)
{
    guint num, i;
    char  buf[NM_UTILS_INET_ADDRSTRLEN];
    int   addr_family;

    if (*str)
        g_string_truncate(*str, 0);
    else
        *str = g_string_sized_new(64);

    addr_family = nm_ip_config_get_addr_family(config);
    num         = nm_ip_config_get_num_nameservers(config);
    for (i = 0; i < num; i++) {
        nm_utils_inet_ntop(addr_family, nm_ip_config_get_nameserver(config, i), buf);
        if (i > 0)
            g_string_append_c(*str, ' ');
        g_string_append(*str, buf);
    }

    return (*str)->str;
}

static char **
_ptrarray_to_strv(GPtrArray *parray)
{
    if (parray->len > 0)
        g_ptr_array_add(parray, NULL);
    return (char **) g_ptr_array_free(parray, parray->len == 0);
}

static void
_collect_resolv_conf_data(NMDnsManager *     self,
                          NMGlobalDnsConfig *global_config,
                          char ***           out_searches,
                          char ***           out_options,
                          char ***           out_nameservers,
                          char ***           out_nis_servers,
                          const char **      out_nis_domain)
{
    NMDnsManagerPrivate *priv;
    NMResolvConfData     rc = {
        .nameservers  = g_ptr_array_new(),
        .searches     = g_ptr_array_new(),
        .options      = g_ptr_array_new(),
        .nis_domain   = NULL,
        .nis_servers  = g_ptr_array_new(),
        .has_trust_ad = NM_TERNARY_DEFAULT,
    };

    priv = NM_DNS_MANAGER_GET_PRIVATE(self);

    if (global_config)
        merge_global_dns_config(&rc, global_config);
    else {
        nm_auto_free_gstring GString *tmp_gstring = NULL;
        int                           prio, first_prio = 0;
        const NMDnsConfigIPData *     ip_data;
        const CList *                 head;
        gboolean                      is_first = TRUE;

        head = _mgr_get_ip_configs_lst_head(self);
        c_list_for_each_entry (ip_data, head, ip_config_lst) {
            gboolean skip = FALSE;

            _ASSERT_dns_config_ip_data(ip_data);

            prio = nm_ip_config_get_dns_priority(ip_data->ip_config);

            if (is_first) {
                is_first   = FALSE;
                first_prio = prio;
            } else if (first_prio < 0 && first_prio != prio)
                skip = TRUE;

            if (nm_ip_config_get_num_nameservers(ip_data->ip_config)) {
                _LOGT(
                    "config: %8d %-7s v%c %-5d %s: %s",
                    prio,
                    _config_type_to_string(ip_data->ip_config_type),
                    nm_utils_addr_family_to_char(nm_ip_config_get_addr_family(ip_data->ip_config)),
                    ip_data->data->ifindex,
                    skip ? "<SKIP>" : "",
                    get_nameserver_list(ip_data->ip_config, &tmp_gstring));
            }

            if (!skip)
                merge_one_ip_config(&rc, ip_data->data->ifindex, ip_data->ip_config);
        }
    }

    /* If the hostname is a FQDN ("dcbw.example.com"), then add the domain part of it
     * ("example.com") to the searches list, to ensure that we can still resolve its
     * non-FQ form ("dcbw") too. (Also, if there are no other search domains specified,
     * this makes a good default.) However, if the hostname is the top level of a domain
     * (eg, "example.com"), then use the hostname itself as the search (since the user is
     * unlikely to want "com" as a search domain).
     */
    if (priv->hostname) {
        const char *hostdomain = strchr(priv->hostname, '.');

        if (hostdomain && !nm_utils_ipaddr_is_valid(AF_UNSPEC, priv->hostname)) {
            hostdomain++;
            if (domain_is_valid(hostdomain, TRUE))
                add_string_item(rc.searches, hostdomain, TRUE);
            else if (domain_is_valid(priv->hostname, TRUE))
                add_string_item(rc.searches, priv->hostname, TRUE);
        }
    }

    if (rc.has_trust_ad == NM_TERNARY_TRUE)
        g_ptr_array_add(rc.options, g_strdup(NM_SETTING_DNS_OPTION_TRUST_AD));

    *out_searches    = _ptrarray_to_strv(rc.searches);
    *out_options     = _ptrarray_to_strv(rc.options);
    *out_nameservers = _ptrarray_to_strv(rc.nameservers);
    *out_nis_servers = _ptrarray_to_strv(rc.nis_servers);
    *out_nis_domain  = rc.nis_domain;
}

/*****************************************************************************/

static char **
get_ip_rdns_domains(NMIPConfig *ip_config)
{
    int                        addr_family = nm_ip_config_get_addr_family(ip_config);
    char **                    strv;
    GPtrArray *                domains;
    NMDedupMultiIter           ipconf_iter;
    const NMPlatformIPAddress *address;
    const NMPlatformIPRoute *  route;

    nm_assert_addr_family(addr_family);

    domains = g_ptr_array_sized_new(5);

    nm_ip_config_iter_ip_address_for_each (&ipconf_iter, ip_config, &address) {
        nm_utils_get_reverse_dns_domains_ip(addr_family,
                                            address->address_ptr,
                                            address->plen,
                                            domains);
    }

    nm_ip_config_iter_ip_route_for_each (&ipconf_iter, ip_config, &route) {
        if (!NM_PLATFORM_IP_ROUTE_IS_DEFAULT(route)) {
            nm_utils_get_reverse_dns_domains_ip(addr_family,
                                                route->network_ptr,
                                                route->plen,
                                                domains);
        }
    }

    /* Terminating NULL so we can use g_strfreev() to free it */
    g_ptr_array_add(domains, NULL);

    /* Free the array and return NULL if the only element was the ending NULL */
    strv = (char **) g_ptr_array_free(domains, (domains->len == 1));

    return _nm_utils_strv_cleanup(strv, FALSE, FALSE, TRUE);
}

static gboolean
_domain_track_get_priority(GHashTable *ht, const char *domain, int *out_priority)
{
    gpointer ptr;

    if (!ht || !g_hash_table_lookup_extended(ht, domain, NULL, &ptr)) {
        *out_priority = 0;
        return FALSE;
    }
    *out_priority = GPOINTER_TO_INT(ptr);
    return TRUE;
}

/* Check if the domain is shadowed by a parent domain with more negative priority */
static gboolean
_domain_track_is_shadowed(GHashTable * ht,
                          const char * domain,
                          int          priority,
                          const char **out_parent,
                          int *        out_parent_priority)
{
    char *parent;
    int   parent_priority;

    if (!ht)
        return FALSE;

    nm_assert(!g_hash_table_contains(ht, domain));

    if (_domain_track_get_priority(ht, "", &parent_priority)) {
        nm_assert(parent_priority <= priority);
        if (parent_priority < 0 && parent_priority < priority) {
            *out_parent          = "";
            *out_parent_priority = parent_priority;
            return TRUE;
        }
    }

    parent = strchr(domain, '.');
    while (parent && parent[1]) {
        parent++;
        if (_domain_track_get_priority(ht, parent, &parent_priority)) {
            nm_assert(parent_priority <= priority);
            if (parent_priority < 0 && parent_priority < priority) {
                *out_parent          = parent;
                *out_parent_priority = parent_priority;
                return TRUE;
            }
        }
        parent = strchr(parent, '.');
    }

    return FALSE;
}

static void
_mgr_configs_data_construct(NMDnsManager *self)
{
    NMDnsConfigIPData *ip_data;
    gs_unref_hashtable GHashTable *ht               = NULL;
    gs_unref_hashtable GHashTable *wildcard_entries = NULL;
    CList *                        head;
    int                            prev_priority = G_MININT;

    head = _mgr_get_ip_configs_lst_head(self);

#if NM_MORE_ASSERTS
    /* we call _mgr_configs_data_clear() at the end of update. We
     * don't expect any domain settings here. */
    c_list_for_each_entry (ip_data, head, ip_config_lst) {
        nm_assert(!ip_data->domains.search);
        nm_assert(!ip_data->domains.reverse);
        nm_assert(!ip_data->domains.has_default_route_explicit);
        nm_assert(!ip_data->domains.has_default_route_exclusive);
        nm_assert(!ip_data->domains.has_default_route);
    }
#endif

    c_list_for_each_entry (ip_data, head, ip_config_lst) {
        NMIPConfig *ip_config    = ip_data->ip_config;
        gboolean    add_wildcard = FALSE;

        if (!nm_ip_config_get_num_nameservers(ip_config))
            continue;
        if (nm_ip_config_best_default_route_get(ip_config))
            add_wildcard = TRUE;
        else {
            /* If a VPN has never-default=no but doesn't get a default
             * route (this can happen for example when the server
             * pushes routes with openconnect), and there are no
             * search or routing domains, then the name servers pushed
             * by the server would be unused. It is preferable in this
             * case to use the VPN DNS server for all queries. */
            if (ip_data->ip_config_type == NM_DNS_IP_CONFIG_TYPE_VPN
                && !nm_ip_config_get_never_default(ip_data->ip_config)
                && nm_ip_config_get_num_searches(ip_data->ip_config) == 0
                && nm_ip_config_get_num_domains(ip_data->ip_config) == 0)
                add_wildcard = TRUE;
        }

        if (add_wildcard) {
            if (!wildcard_entries)
                wildcard_entries = g_hash_table_new(nm_direct_hash, NULL);
            g_hash_table_add(wildcard_entries, ip_data);
        }
    }

    c_list_for_each_entry (ip_data, head, ip_config_lst) {
        NMIPConfig * ip_config = ip_data->ip_config;
        int          priority;
        const char **domains;
        guint        n_searches;
        guint        n_domains;
        guint        num_dom1;
        guint        num_dom2;
        guint        n_domains_allocated;
        guint        i;
        gboolean     has_default_route_maybe    = FALSE;
        gboolean     has_default_route_explicit = FALSE;
        gboolean     has_default_route_auto     = FALSE;

        if (!nm_ip_config_get_num_nameservers(ip_config))
            continue;

        n_searches = nm_ip_config_get_num_searches(ip_config);
        n_domains  = nm_ip_config_get_num_domains(ip_config);

        priority = nm_ip_config_get_dns_priority(ip_config);

        nm_assert(priority != 0);
        nm_assert(prev_priority <= priority);
        prev_priority = priority;

        /* Add wildcard lookup domain to connections with the default route.
         * If there is no default route, add the wildcard domain to all non-VPN
         * connections */
        if (wildcard_entries) {
            /* FIXME: this heuristic of which device has a default route does
             * not work with policy routing (as used by default with WireGuard).
             * We should have a more stable mechanism where an NMIPConfig indicates
             * whether it is suitable for certain operations (like having an automatically
             * added "~" domain). */
            if (g_hash_table_contains(wildcard_entries, ip_data))
                has_default_route_maybe = TRUE;
        } else {
            if (ip_data->ip_config_type != NM_DNS_IP_CONFIG_TYPE_VPN)
                has_default_route_maybe = TRUE;
        }

        n_domains_allocated = (n_searches > 0 ? n_searches : n_domains) + 1u;
        domains             = g_new(const char *, n_domains_allocated);

        num_dom1 = 0;

        /* searches are preferred over domains */
        if (n_searches > 0) {
            for (i = 0; i < n_searches; i++)
                domains[num_dom1++] = nm_ip_config_get_search(ip_config, i);
        } else {
            for (i = 0; i < n_domains; i++)
                domains[num_dom1++] = nm_ip_config_get_domain(ip_config, i);
        }

        nm_assert(num_dom1 < n_domains_allocated);

        num_dom2 = 0;
        for (i = 0; TRUE; i++) {
            const char *domain_full;
            const char *domain_clean;
            const char *parent;
            int         old_priority;
            int         parent_priority;
            gboolean    check_default_route;

            if (i < num_dom1) {
                check_default_route = FALSE;
                domain_full         = domains[i];
                domain_clean        = nm_utils_parse_dns_domain(domains[i], NULL);
            } else if (i == num_dom1) {
                if (!has_default_route_maybe)
                    continue;
                if (has_default_route_explicit)
                    continue;
                check_default_route = TRUE;
                domain_full         = "~";
                domain_clean        = "";
            } else
                break;

            /* Remove domains with lower priority */
            if (_domain_track_get_priority(ht, domain_clean, &old_priority)) {
                nm_assert(old_priority <= priority);
                if (old_priority < priority) {
                    _LOGT("plugin: drop domain %s%s%s (i=%d, p=%d) because it already exists "
                          "with p=%d",
                          NM_PRINT_FMT_QUOTED(!check_default_route,
                                              "'",
                                              domain_full,
                                              "'",
                                              "<auto-default>"),
                          ip_data->data->ifindex,
                          priority,
                          old_priority);
                    continue;
                }
            } else if (_domain_track_is_shadowed(ht,
                                                 domain_clean,
                                                 priority,
                                                 &parent,
                                                 &parent_priority)) {
                _LOGT("plugin: drop domain %s%s%s (i=%d, p=%d) shadowed by '%s' (p=%d)",
                      NM_PRINT_FMT_QUOTED(!check_default_route,
                                          "'",
                                          domain_full,
                                          "'",
                                          "<auto-default>"),
                      ip_data->data->ifindex,
                      priority,
                      parent,
                      parent_priority);
                continue;
            }

            _LOGT(
                "plugin: add domain %s%s%s (i=%d, p=%d)",
                NM_PRINT_FMT_QUOTED(!check_default_route, "'", domain_full, "'", "<auto-default>"),
                ip_data->data->ifindex,
                priority);

            if (!ht)
                ht = g_hash_table_new(nm_str_hash, g_str_equal);
            g_hash_table_insert(ht, (gpointer) domain_clean, GINT_TO_POINTER(priority));

            if (check_default_route)
                has_default_route_auto = TRUE;
            else {
                nm_assert(num_dom2 <= num_dom1);
                nm_assert(num_dom2 < n_domains_allocated);
                domains[num_dom2++] = domain_full;
                if (domain_clean[0] == '\0')
                    has_default_route_explicit = TRUE;
            }
        }
        nm_assert(num_dom2 < n_domains_allocated);
        domains[num_dom2] = NULL;

        nm_assert(!ip_data->domains.search);
        nm_assert(!ip_data->domains.reverse);
        ip_data->domains.search                     = domains;
        ip_data->domains.reverse                    = get_ip_rdns_domains(ip_config);
        ip_data->domains.has_default_route_explicit = has_default_route_explicit;
        ip_data->domains.has_default_route_exclusive =
            has_default_route_explicit || (priority < 0 && has_default_route_auto);
        ip_data->domains.has_default_route =
            ip_data->domains.has_default_route_exclusive || has_default_route_auto;

        {
            gs_free char *str1 = NULL;
            gs_free char *str2 = NULL;

            _LOGT("plugin: settings: ifindex=%d, priority=%d, default-route=%d%s, search=%s, "
                  "reverse=%s",
                  ip_data->data->ifindex,
                  priority,
                  ip_data->domains.has_default_route,
                  ip_data->domains.has_default_route_explicit
                      ? " (explicit)"
                      : (ip_data->domains.has_default_route_exclusive ? " (exclusive)" : ""),
                  (str1 = g_strjoinv(",", (char **) ip_data->domains.search)),
                  (ip_data->domains.reverse ? (str2 = g_strjoinv(",", ip_data->domains.reverse))
                                            : ""));
        }
    }
}

static void
_mgr_configs_data_clear(NMDnsManager *self)
{
    NMDnsConfigIPData *ip_data;
    CList *            head;

    head = _mgr_get_ip_configs_lst_head(self);
    c_list_for_each_entry (ip_data, head, ip_config_lst) {
        nm_clear_g_free(&ip_data->domains.search);
        nm_clear_pointer(&ip_data->domains.reverse, g_strfreev);
        ip_data->domains.has_default_route_explicit  = FALSE;
        ip_data->domains.has_default_route_exclusive = FALSE;
        ip_data->domains.has_default_route           = FALSE;
    }
}

/*****************************************************************************/

static gboolean
update_dns(NMDnsManager *self, gboolean no_caching, gboolean force_emit, GError **error)
{
    NMDnsManagerPrivate *priv                = NM_DNS_MANAGER_GET_PRIVATE(self);
    const char *         nis_domain          = NULL;
    gs_strfreev char **  searches            = NULL;
    gs_strfreev char **  options             = NULL;
    gs_strfreev char **  nameservers         = NULL;
    gs_strfreev char **  nis_servers         = NULL;
    gboolean             caching             = FALSE;
    gboolean             do_update           = TRUE;
    gboolean             resolv_conf_updated = FALSE;
    SpawnResult          result              = SR_SUCCESS;
    NMConfigData *       data;
    NMGlobalDnsConfig *  global_config;
    gs_free_error GError *local_error   = NULL;
    GError **const        p_local_error = error ? &local_error : NULL;

    nm_assert(!error || !*error);

    if (priv->is_stopped) {
        _LOGD("update-dns: not updating resolv.conf (is stopped)");
        return TRUE;
    }

    nm_clear_g_source(&priv->plugin_ratelimit.timer);

    if (NM_IN_SET(priv->rc_manager,
                  NM_DNS_MANAGER_RESOLV_CONF_MAN_UNMANAGED,
                  NM_DNS_MANAGER_RESOLV_CONF_MAN_IMMUTABLE)) {
        do_update = FALSE;
        _LOGD("update-dns: not updating resolv.conf");
    } else {
        priv->dns_touched = TRUE;
        _LOGD("update-dns: updating resolv.conf");
    }

    data          = nm_config_get_data(priv->config);
    global_config = nm_config_data_get_global_dns_config(data);

    /* Update hash with config we're applying */
    compute_hash(self, global_config, priv->hash);

    _collect_resolv_conf_data(self,
                              global_config,
                              &searches,
                              &options,
                              &nameservers,
                              &nis_servers,
                              &nis_domain);

    if (priv->plugin || priv->sd_resolve_plugin)
        _mgr_configs_data_construct(self);

    if (priv->sd_resolve_plugin) {
        nm_dns_plugin_update(priv->sd_resolve_plugin,
                             global_config,
                             _mgr_get_ip_configs_lst_head(self),
                             priv->hostname,
                             NULL);
    }

    /* Let any plugins do their thing first */
    if (priv->plugin) {
        NMDnsPlugin * plugin               = priv->plugin;
        const char *  plugin_name          = nm_dns_plugin_get_name(plugin);
        gs_free_error GError *plugin_error = NULL;

        if (nm_dns_plugin_is_caching(plugin)) {
            if (no_caching) {
                _LOGD("update-dns: plugin %s ignored (caching disabled)", plugin_name);
                goto plugin_skip;
            }
            caching = TRUE;
        }

        _LOGD("update-dns: updating plugin %s", plugin_name);
        if (!nm_dns_plugin_update(plugin,
                                  global_config,
                                  _mgr_get_ip_configs_lst_head(self),
                                  priv->hostname,
                                  &plugin_error)) {
            _LOGW("update-dns: plugin %s update failed: %s", plugin_name, plugin_error->message);

            /* If the plugin failed to update, we shouldn't write out a local
             * caching DNS configuration to resolv.conf.
             */
            caching = FALSE;
        }

plugin_skip:;
    }

    /* Clear the generated search list as it points to
     * strings owned by IP configurations and we can't
     * guarantee they stay alive. */
    _mgr_configs_data_clear(self);

    update_resolv_conf_no_stub(self,
                               NM_CAST_STRV_CC(searches),
                               NM_CAST_STRV_CC(nameservers),
                               NM_CAST_STRV_CC(options));

    /* If caching was successful, we only send 127.0.0.1 to /etc/resolv.conf
     * to ensure that the glibc resolver doesn't try to round-robin nameservers,
     * but only uses the local caching nameserver.
     */
    if (caching) {
        const char *lladdr = "127.0.0.1";
        gboolean    need_edns0;
        gboolean    need_trust;

        if (NM_IS_DNS_SYSTEMD_RESOLVED(priv->plugin)) {
            /* systemd-resolved uses a different link-local address */
            lladdr = "127.0.0.53";
        }

        g_strfreev(nameservers);
        nameservers    = g_new0(char *, 2);
        nameservers[0] = g_strdup(lladdr);

        need_edns0 = nm_utils_strv_find_first(options, -1, NM_SETTING_DNS_OPTION_EDNS0) < 0;
        need_trust = nm_utils_strv_find_first(options, -1, NM_SETTING_DNS_OPTION_TRUST_AD) < 0;

        if (need_edns0 || need_trust) {
            gsize len;

            len     = NM_PTRARRAY_LEN(options);
            options = g_realloc(options, sizeof(char *) * (len + 3u));
            if (need_edns0)
                options[len++] = g_strdup(NM_SETTING_DNS_OPTION_EDNS0);
            if (need_trust)
                options[len++] = g_strdup(NM_SETTING_DNS_OPTION_TRUST_AD);
            options[len] = NULL;
        }
    }

    if (do_update) {
        switch (priv->rc_manager) {
        case NM_DNS_MANAGER_RESOLV_CONF_MAN_SYMLINK:
        case NM_DNS_MANAGER_RESOLV_CONF_MAN_FILE:
            result              = update_resolv_conf(self,
                                        NM_CAST_STRV_CC(searches),
                                        NM_CAST_STRV_CC(nameservers),
                                        NM_CAST_STRV_CC(options),
                                        p_local_error,
                                        priv->rc_manager);
            resolv_conf_updated = TRUE;
            /* If we have ended with no nameservers avoid updating again resolv.conf
             * on stop, as some external changes may be applied to it in the meanwhile */
            if (!nameservers && !options)
                priv->dns_touched = FALSE;
            break;
        case NM_DNS_MANAGER_RESOLV_CONF_MAN_RESOLVCONF:
            result = dispatch_resolvconf(self, searches, nameservers, options, p_local_error);
            break;
        case NM_DNS_MANAGER_RESOLV_CONF_MAN_NETCONFIG:
            result = dispatch_netconfig(self,
                                        (const char *const *) searches,
                                        (const char *const *) nameservers,
                                        nis_domain,
                                        (const char *const *) nis_servers,
                                        p_local_error);
            break;
        default:
            nm_assert_not_reached();
        }

        if (result == SR_NOTFOUND) {
            _LOGD("update-dns: program not available, writing to resolv.conf");
            g_clear_error(&local_error);
            result              = update_resolv_conf(self,
                                        NM_CAST_STRV_CC(searches),
                                        NM_CAST_STRV_CC(nameservers),
                                        NM_CAST_STRV_CC(options),
                                        p_local_error,
                                        NM_DNS_MANAGER_RESOLV_CONF_MAN_SYMLINK);
            resolv_conf_updated = TRUE;
        }
    }

    /* Unless we've already done it, update private resolv.conf in NMRUNDIR
     * ignoring any errors */
    if (!resolv_conf_updated) {
        update_resolv_conf(self,
                           NM_CAST_STRV_CC(searches),
                           NM_CAST_STRV_CC(nameservers),
                           NM_CAST_STRV_CC(options),
                           NULL,
                           NM_DNS_MANAGER_RESOLV_CONF_MAN_UNMANAGED);
    }

    /* signal that DNS resolution configs were changed */
    if ((do_update || caching || force_emit) && result == SR_SUCCESS)
        g_signal_emit(self, signals[CONFIG_CHANGED], 0);

    nm_clear_pointer(&priv->config_variant, g_variant_unref);
    _notify(self, PROP_CONFIGURATION);

    if (result != SR_SUCCESS) {
        if (error)
            g_propagate_error(error, g_steal_pointer(&local_error));
        return FALSE;
    }

    nm_assert(!local_error);
    return TRUE;
}

/*****************************************************************************/

static void
_ip_config_dns_priority_changed(gpointer config, GParamSpec *pspec, NMDnsConfigIPData *ip_data)
{
    _ASSERT_dns_config_ip_data(ip_data);

    NM_DNS_MANAGER_GET_PRIVATE(ip_data->data->self)->ip_configs_lst_need_sort = TRUE;
}

gboolean
nm_dns_manager_set_ip_config(NMDnsManager *    self,
                             NMIPConfig *      ip_config,
                             NMDnsIPConfigType ip_config_type)
{
    NMDnsManagerPrivate *priv;
    NMDnsConfigIPData *  ip_data;
    NMDnsConfigData *    data;
    int                  ifindex;
    NMDnsConfigIPData ** p_best;

    g_return_val_if_fail(NM_IS_DNS_MANAGER(self), FALSE);
    g_return_val_if_fail(NM_IS_IP_CONFIG(ip_config), FALSE);

    ifindex = nm_ip_config_get_ifindex(ip_config);
    g_return_val_if_fail(ifindex > 0, FALSE);

    priv = NM_DNS_MANAGER_GET_PRIVATE(self);

    data = g_hash_table_lookup(priv->configs_dict, &ifindex);
    if (!data)
        ip_data = NULL;
    else
        ip_data = _dns_config_data_find_ip_config(data, ip_config);

    if (ip_config_type == NM_DNS_IP_CONFIG_TYPE_REMOVED) {
        if (!ip_data)
            return FALSE;
        if (priv->best_ip_config_4 == ip_data)
            priv->best_ip_config_4 = NULL;
        if (priv->best_ip_config_6 == ip_data)
            priv->best_ip_config_6 = NULL;
        /* deleting a config doesn't invalidate the configs' sort order. */
        _dns_config_ip_data_free(ip_data);
        if (c_list_is_empty(&data->data_lst_head))
            g_hash_table_remove(priv->configs_dict, &ifindex);
        goto changed;
    }

    if (ip_data && ip_data->ip_config_type == ip_config_type) {
        /* nothing to do. */
        return FALSE;
    }

    if (!data) {
        data  = g_slice_new(NMDnsConfigData);
        *data = (NMDnsConfigData){
            .ifindex       = ifindex,
            .self          = self,
            .data_lst_head = C_LIST_INIT(data->data_lst_head),
        };
        _ASSERT_dns_config_data(data);
        g_hash_table_add(priv->configs_dict, data);
        c_list_link_tail(&priv->configs_lst_head, &data->configs_lst);
        priv->configs_lst_need_sort = TRUE;
    }

    if (!ip_data)
        ip_data = _dns_config_ip_data_new(data, ip_config, ip_config_type);
    else
        ip_data->ip_config_type = ip_config_type;

    priv->ip_configs_lst_need_sort = TRUE;

    p_best = NM_IS_IP4_CONFIG(ip_config) ? &priv->best_ip_config_4 : &priv->best_ip_config_6;

    if (ip_config_type == NM_DNS_IP_CONFIG_TYPE_BEST_DEVICE) {
        /* Only one best-device per IP version is allowed */
        if (*p_best != ip_data) {
            if (*p_best)
                (*p_best)->ip_config_type = NM_DNS_IP_CONFIG_TYPE_DEFAULT;
            *p_best = ip_data;
        }
    } else {
        if (*p_best == ip_data)
            *p_best = NULL;
    }

changed:
    if (!priv->updates_queue) {
        gs_free_error GError *error = NULL;

        if (!update_dns(self, FALSE, FALSE, &error))
            _LOGW("could not commit DNS changes: %s", error->message);
    }

    return TRUE;
}

void
nm_dns_manager_set_initial_hostname(NMDnsManager *self, const char *hostname)
{
    NMDnsManagerPrivate *priv = NM_DNS_MANAGER_GET_PRIVATE(self);

    g_free(priv->hostname);
    priv->hostname = g_strdup(hostname);
}

void
nm_dns_manager_set_hostname(NMDnsManager *self, const char *hostname, gboolean skip_update)
{
    NMDnsManagerPrivate *priv     = NM_DNS_MANAGER_GET_PRIVATE(self);
    const char *         filtered = NULL;

    /* Certain hostnames we don't want to include in resolv.conf 'searches' */
    if (hostname && nm_utils_is_specific_hostname(hostname) && !strstr(hostname, ".in-addr.arpa")
        && strchr(hostname, '.')) {
        filtered = hostname;
    }

    if ((!priv->hostname && !filtered)
        || (priv->hostname && filtered && !strcmp(priv->hostname, filtered)))
        return;

    g_free(priv->hostname);
    priv->hostname = g_strdup(filtered);

    if (skip_update)
        return;

    if (!priv->updates_queue) {
        gs_free_error GError *error = NULL;

        if (!update_dns(self, FALSE, FALSE, &error))
            _LOGW("could not commit DNS changes: %s", error->message);
    }
}

void
nm_dns_manager_begin_updates(NMDnsManager *self, const char *func)
{
    NMDnsManagerPrivate *priv;

    g_return_if_fail(self != NULL);
    priv = NM_DNS_MANAGER_GET_PRIVATE(self);

    /* Save current hash when starting a new batch */
    if (priv->updates_queue == 0)
        memcpy(priv->prev_hash, priv->hash, sizeof(priv->hash));

    priv->updates_queue++;

    _LOGD("(%s): queueing DNS updates (%d)", func, priv->updates_queue);
}

void
nm_dns_manager_end_updates(NMDnsManager *self, const char *func)
{
    NMDnsManagerPrivate *priv;
    gs_free_error GError *error = NULL;
    gboolean              changed;
    guint8 new[HASH_LEN];

    g_return_if_fail(self != NULL);

    priv = NM_DNS_MANAGER_GET_PRIVATE(self);
    g_return_if_fail(priv->updates_queue > 0);

    compute_hash(self, nm_config_data_get_global_dns_config(nm_config_get_data(priv->config)), new);
    changed = (memcmp(new, priv->prev_hash, sizeof(new)) != 0) ? TRUE : FALSE;
    _LOGD("(%s): DNS configuration %s", func, changed ? "changed" : "did not change");

    priv->updates_queue--;
    if ((priv->updates_queue > 0) || (changed == FALSE)) {
        _LOGD("(%s): no DNS changes to commit (%d)", func, priv->updates_queue);
        return;
    }

    /* Commit all the outstanding changes */
    _LOGD("(%s): committing DNS changes (%d)", func, priv->updates_queue);
    if (!update_dns(self, FALSE, FALSE, &error))
        _LOGW("could not commit DNS changes: %s", error->message);

    memset(priv->prev_hash, 0, sizeof(priv->prev_hash));
}

void
nm_dns_manager_stop(NMDnsManager *self)
{
    NMDnsManagerPrivate *priv;

    priv = NM_DNS_MANAGER_GET_PRIVATE(self);

    if (priv->is_stopped)
        g_return_if_reached();

    _LOGT("stopping...");

    /* If we're quitting, leave a valid resolv.conf in place, not one
     * pointing to 127.0.0.1 if dnsmasq was active.  But if we haven't
     * done any DNS updates yet, there's no reason to touch resolv.conf
     * on shutdown.
     */
    if (priv->dns_touched && priv->plugin && NM_IS_DNS_DNSMASQ(priv->plugin)) {
        gs_free_error GError *error = NULL;

        if (!update_dns(self, TRUE, FALSE, &error))
            _LOGW("could not commit DNS changes on shutdown: %s", error->message);

        priv->dns_touched = FALSE;
    }

    priv->is_stopped = TRUE;
}

/*****************************************************************************/

static gboolean
_clear_plugin(NMDnsManager *self)
{
    NMDnsManagerPrivate *priv = NM_DNS_MANAGER_GET_PRIVATE(self);

    priv->plugin_ratelimit.ts = 0;
    nm_clear_g_source(&priv->plugin_ratelimit.timer);

    if (priv->plugin) {
        nm_dns_plugin_stop(priv->plugin);
        g_clear_object(&priv->plugin);
        return TRUE;
    }
    return FALSE;
}

static NMDnsManagerResolvConfManager
_check_resconf_immutable(NMDnsManagerResolvConfManager rc_manager)
{
    struct stat st;
    int         fd, flags;
    bool        immutable = FALSE;

    switch (rc_manager) {
    case NM_DNS_MANAGER_RESOLV_CONF_MAN_UNKNOWN:
    case NM_DNS_MANAGER_RESOLV_CONF_MAN_IMMUTABLE:
        nm_assert_not_reached();
        /* fall-through */
    case NM_DNS_MANAGER_RESOLV_CONF_MAN_UNMANAGED:
        return NM_DNS_MANAGER_RESOLV_CONF_MAN_UNMANAGED;
    default:

        if (lstat(_PATH_RESCONF, &st) != 0)
            return rc_manager;

        if (S_ISLNK(st.st_mode)) {
            /* only regular files and directories can have extended file attributes. */
            switch (rc_manager) {
            case NM_DNS_MANAGER_RESOLV_CONF_MAN_SYMLINK:
                /* we don't care whether the link-target is immutable.
                 * If the symlink points to another file, rc-manager=symlink anyway backs off.
                 * Otherwise, we would only check whether our internal resolv.conf is immutable. */
                return NM_DNS_MANAGER_RESOLV_CONF_MAN_SYMLINK;
            case NM_DNS_MANAGER_RESOLV_CONF_MAN_UNKNOWN:
            case NM_DNS_MANAGER_RESOLV_CONF_MAN_UNMANAGED:
            case NM_DNS_MANAGER_RESOLV_CONF_MAN_IMMUTABLE:
                nm_assert_not_reached();
                /* fall-through */
            case NM_DNS_MANAGER_RESOLV_CONF_MAN_FILE:
            case NM_DNS_MANAGER_RESOLV_CONF_MAN_RESOLVCONF:
            case NM_DNS_MANAGER_RESOLV_CONF_MAN_NETCONFIG:
            case NM_DNS_MANAGER_RESOLV_CONF_MAN_AUTO:
                break;
            }
        }

        fd = open(_PATH_RESCONF, O_RDONLY | O_CLOEXEC);
        if (fd != -1) {
            if (ioctl(fd, FS_IOC_GETFLAGS, &flags) != -1)
                immutable = NM_FLAGS_HAS(flags, FS_IMMUTABLE_FL);
            nm_close(fd);
        }
        return immutable ? NM_DNS_MANAGER_RESOLV_CONF_MAN_IMMUTABLE : rc_manager;
    }
}

static gboolean
_resolvconf_resolved_managed(void)
{
    static const char *const RESOLVED_PATHS[] = {
        "../run/systemd/resolve/stub-resolv.conf",
        "../run/systemd/resolve/resolv.conf",
        "../lib/systemd/resolv.conf",
        "../usr/lib/systemd/resolv.conf",
        "/run/systemd/resolve/stub-resolv.conf",
        "/run/systemd/resolve/resolv.conf",
        "/lib/systemd/resolv.conf",
        "/usr/lib/systemd/resolv.conf",
    };
    struct stat st, st_test;
    guint       i;

    if (lstat(_PATH_RESCONF, &st) != 0)
        return FALSE;

    if (S_ISLNK(st.st_mode)) {
        gs_free char *     full_path = NULL;
        nm_auto_free char *real_path = NULL;

        /* see if resolv.conf is a symlink with a target that is
         * exactly like one of the candidates.
         *
         * This check will work for symlinks, even if the target
         * does not exist and realpath() cannot resolve anything.
         *
         * We want to handle that, because systemd-resolved might not
         * have started yet. */
        full_path = g_file_read_link(_PATH_RESCONF, NULL);
        if (nm_utils_strv_find_first((char **) RESOLVED_PATHS,
                                     G_N_ELEMENTS(RESOLVED_PATHS),
                                     full_path)
            >= 0)
            return TRUE;

        /* see if resolv.conf is a symlink that resolves exactly one
         * of the candidate paths.
         *
         * This check will work for symlinks that can be resolved
         * to a realpath, but the actual file might not exist.
         *
         * We want to handle that, because systemd-resolved might not
         * have started yet. */
        real_path = realpath(_PATH_RESCONF, NULL);
        if (nm_utils_strv_find_first((char **) RESOLVED_PATHS,
                                     G_N_ELEMENTS(RESOLVED_PATHS),
                                     real_path)
            >= 0)
            return TRUE;

        /* fall-through and resolve the symlink, to check the file
         * it points to (below).
         *
         * This check is the most reliable, but it only works if
         * systemd-resolved already started and created the file. */
        if (stat(_PATH_RESCONF, &st) != 0)
            return FALSE;
    }

    /* see if resolv.conf resolves to one of the candidate
     * paths (or whether it is hard-linked). */
    for (i = 0; i < G_N_ELEMENTS(RESOLVED_PATHS); i++) {
        const char *p = RESOLVED_PATHS[i];

        if (p[0] == '/' && stat(p, &st_test) == 0 && st.st_dev == st_test.st_dev
            && st.st_ino == st_test.st_ino)
            return TRUE;
    }

    return FALSE;
}

static void
init_resolv_conf_mode(NMDnsManager *self, gboolean force_reload_plugin)
{
    NMDnsManagerPrivate *         priv = NM_DNS_MANAGER_GET_PRIVATE(self);
    NMDnsManagerResolvConfManager rc_manager;
    const char *                  mode;
    gboolean                      systemd_resolved;
    gboolean                      param_changed            = FALSE;
    gboolean                      plugin_changed           = FALSE;
    gboolean                      systemd_resolved_changed = FALSE;
    gboolean                      rc_manager_was_auto      = FALSE;

    mode             = nm_config_data_get_dns_mode(nm_config_get_data(priv->config));
    systemd_resolved = nm_config_data_get_systemd_resolved(nm_config_get_data(priv->config));

    if (nm_streq0(mode, "none"))
        rc_manager = NM_DNS_MANAGER_RESOLV_CONF_MAN_UNMANAGED;
    else {
        const char *man;

        rc_manager = NM_DNS_MANAGER_RESOLV_CONF_MAN_UNKNOWN;
        man        = nm_config_data_get_rc_manager(nm_config_get_data(priv->config));

again:
        if (!man) {
            /* nop */
        } else if (nm_streq(man, "auto"))
            rc_manager = NM_DNS_MANAGER_RESOLV_CONF_MAN_AUTO;
        else if (NM_IN_STRSET(man, "symlink", "none"))
            rc_manager = NM_DNS_MANAGER_RESOLV_CONF_MAN_SYMLINK;
        else if (nm_streq(man, "file"))
            rc_manager = NM_DNS_MANAGER_RESOLV_CONF_MAN_FILE;
        else if (nm_streq(man, "resolvconf"))
            rc_manager = NM_DNS_MANAGER_RESOLV_CONF_MAN_RESOLVCONF;
        else if (nm_streq(man, "netconfig"))
            rc_manager = NM_DNS_MANAGER_RESOLV_CONF_MAN_NETCONFIG;
        else if (nm_streq(man, "unmanaged"))
            rc_manager = NM_DNS_MANAGER_RESOLV_CONF_MAN_UNMANAGED;

        if (rc_manager == NM_DNS_MANAGER_RESOLV_CONF_MAN_UNKNOWN) {
            if (man) {
                _LOGW("init: unknown resolv.conf manager \"%s\", fallback to \"%s\"",
                      man,
                      "" NM_CONFIG_DEFAULT_MAIN_RC_MANAGER);
            }
            man        = "" NM_CONFIG_DEFAULT_MAIN_RC_MANAGER;
            rc_manager = NM_DNS_MANAGER_RESOLV_CONF_MAN_AUTO;
            goto again;
        }
    }

    rc_manager = _check_resconf_immutable(rc_manager);

    if ((!mode && _resolvconf_resolved_managed()) || nm_streq0(mode, "systemd-resolved")) {
        if (force_reload_plugin || !NM_IS_DNS_SYSTEMD_RESOLVED(priv->plugin)) {
            _clear_plugin(self);
            priv->plugin   = nm_dns_systemd_resolved_new();
            plugin_changed = TRUE;
        }
        mode             = "systemd-resolved";
        systemd_resolved = FALSE;
    } else if (nm_streq0(mode, "dnsmasq")) {
        if (force_reload_plugin || !NM_IS_DNS_DNSMASQ(priv->plugin)) {
            _clear_plugin(self);
            priv->plugin   = nm_dns_dnsmasq_new();
            plugin_changed = TRUE;
        }
    } else if (nm_streq0(mode, "unbound")) {
        if (force_reload_plugin || !NM_IS_DNS_UNBOUND(priv->plugin)) {
            _clear_plugin(self);
            priv->plugin   = nm_dns_unbound_new();
            plugin_changed = TRUE;
        }
    } else {
        if (!NM_IN_STRSET(mode, "none", "default")) {
            if (mode)
                _LOGW("init: unknown dns mode '%s'", mode);
            mode = "default";
        }
        if (_clear_plugin(self))
            plugin_changed = TRUE;
    }

    if (rc_manager == NM_DNS_MANAGER_RESOLV_CONF_MAN_AUTO) {
        rc_manager_was_auto = TRUE;
        if (nm_streq(mode, "systemd-resolved"))
            rc_manager = NM_DNS_MANAGER_RESOLV_CONF_MAN_UNMANAGED;
        else if (HAS_RESOLVCONF && g_file_test(RESOLVCONF_PATH, G_FILE_TEST_IS_EXECUTABLE)) {
            /* We detect /sbin/resolvconf only at this stage. That means, if you install
             * or uninstall openresolv afterwards, you need to reload the DNS settings
             * (with SIGHUP or `systemctl reload NetworkManager.service`).
             *
             * We only accept resolvconf if NetworkManager was built with --with-resolvconf.
             * For example, on Fedora the systemd package provides a compat resolvconf
             * implementation for systemd-resolved. But using that never makes sense, because
             * there we either use full systemd-resolved mode or not. In no case does it
             * make sense to call that resolvconf implementation. */
            rc_manager = NM_DNS_MANAGER_RESOLV_CONF_MAN_RESOLVCONF;
        } else if (HAS_NETCONFIG && g_file_test(NETCONFIG_PATH, G_FILE_TEST_IS_EXECUTABLE)) {
            /* Like for resolvconf, we detect only once. We only autoenable this
             * option, if NetworkManager was built with netconfig explicitly enabled. */
            rc_manager = NM_DNS_MANAGER_RESOLV_CONF_MAN_NETCONFIG;
        } else
            rc_manager = NM_DNS_MANAGER_RESOLV_CONF_MAN_SYMLINK;
    }

    /* The systemd-resolved plugin is special. We typically always want to keep
     * systemd-resolved up to date even if the configured plugin is different. */
    if (systemd_resolved) {
        if (!priv->sd_resolve_plugin) {
            priv->sd_resolve_plugin  = nm_dns_systemd_resolved_new();
            systemd_resolved_changed = TRUE;
        }
    } else if (nm_clear_g_object(&priv->sd_resolve_plugin))
        systemd_resolved_changed = TRUE;

    g_object_freeze_notify(G_OBJECT(self));

    if (!nm_streq0(priv->mode, mode)) {
        g_free(priv->mode);
        priv->mode    = g_strdup(mode);
        param_changed = TRUE;
        _notify(self, PROP_MODE);
    }

    if (priv->rc_manager != rc_manager) {
        priv->rc_manager = rc_manager;
        param_changed    = TRUE;
        _notify(self, PROP_RC_MANAGER);
    }

    if (param_changed || plugin_changed || systemd_resolved_changed) {
        _LOGI("init: dns=%s%s rc-manager=%s%s%s%s%s",
              mode,
              (systemd_resolved ? ",systemd-resolved" : ""),
              _rc_manager_to_string(rc_manager),
              rc_manager_was_auto ? " (auto)" : "",
              NM_PRINT_FMT_QUOTED(priv->plugin,
                                  ", plugin=",
                                  nm_dns_plugin_get_name(priv->plugin),
                                  "",
                                  ""));
    }

    g_object_thaw_notify(G_OBJECT(self));
}

static void
config_changed_cb(NMConfig *          config,
                  NMConfigData *      config_data,
                  NMConfigChangeFlags changes,
                  NMConfigData *      old_data,
                  NMDnsManager *      self)
{
    if (NM_FLAGS_ANY(changes,
                     NM_CONFIG_CHANGE_DNS_MODE | NM_CONFIG_CHANGE_RC_MANAGER
                         | NM_CONFIG_CHANGE_CAUSE_SIGHUP | NM_CONFIG_CHANGE_CAUSE_DNS_FULL)) {
        /* reload the resolv-conf mode also on SIGHUP (when DNS_MODE didn't change).
         * The reason is, that the configuration also depends on whether resolv.conf
         * is immutable, thus, without the configuration changing, we always want to
         * re-configure the mode. */
        init_resolv_conf_mode(
            self,
            NM_FLAGS_ANY(changes, NM_CONFIG_CHANGE_CAUSE_SIGHUP | NM_CONFIG_CHANGE_CAUSE_DNS_FULL));
    }

    if (NM_FLAGS_ANY(changes,
                     NM_CONFIG_CHANGE_CAUSE_SIGHUP | NM_CONFIG_CHANGE_CAUSE_SIGUSR1
                         | NM_CONFIG_CHANGE_CAUSE_DNS_RC | NM_CONFIG_CHANGE_CAUSE_DNS_FULL
                         | NM_CONFIG_CHANGE_DNS_MODE | NM_CONFIG_CHANGE_RC_MANAGER
                         | NM_CONFIG_CHANGE_GLOBAL_DNS_CONFIG)) {
        gs_free_error GError *error = NULL;

        if (!update_dns(self, FALSE, TRUE, &error))
            _LOGW("could not commit DNS changes: %s", error->message);
    }
}

static GVariant *
_get_global_config_variant(NMGlobalDnsConfig *global)
{
    NMGlobalDnsDomain *domain;
    GVariantBuilder    builder;
    guint              i, num;

    g_variant_builder_init(&builder, G_VARIANT_TYPE("aa{sv}"));
    num = nm_global_dns_config_get_num_domains(global);
    for (i = 0; i < num; i++) {
        GVariantBuilder    conf_builder;
        GVariantBuilder    item_builder;
        const char *       domain_name;
        const char *const *servers;

        g_variant_builder_init(&conf_builder, G_VARIANT_TYPE("a{sv}"));

        domain      = nm_global_dns_config_get_domain(global, i);
        domain_name = nm_global_dns_domain_get_name(domain);

        if (domain_name && !nm_streq0(domain_name, "*")) {
            g_variant_builder_init(&item_builder, G_VARIANT_TYPE("as"));
            g_variant_builder_add(&item_builder, "s", domain_name);
            g_variant_builder_add(&conf_builder,
                                  "{sv}",
                                  "domains",
                                  g_variant_builder_end(&item_builder));
        }

        g_variant_builder_init(&item_builder, G_VARIANT_TYPE("as"));
        for (servers = nm_global_dns_domain_get_servers(domain); *servers; servers++) {
            g_variant_builder_add(&item_builder, "s", *servers);
        }
        g_variant_builder_add(&conf_builder,
                              "{sv}",
                              "nameservers",
                              g_variant_builder_end(&item_builder));

        g_variant_builder_add(&conf_builder,
                              "{sv}",
                              "priority",
                              g_variant_new_int32(NM_DNS_PRIORITY_DEFAULT_NORMAL));

        g_variant_builder_add(&builder, "a{sv}", &conf_builder);
    }

    return g_variant_ref_sink(g_variant_builder_end(&builder));
}

static GVariant *
_get_config_variant(NMDnsManager *self)
{
    NMDnsManagerPrivate *priv = NM_DNS_MANAGER_GET_PRIVATE(self);
    NMGlobalDnsConfig *  global_config;
    gs_free char *       str = NULL;
    GVariantBuilder      builder;
    NMDnsConfigIPData *  ip_data;
    const CList *        head;
    gs_unref_ptrarray GPtrArray *array_domains = NULL;

    if (priv->config_variant)
        return priv->config_variant;

    global_config = nm_config_data_get_global_dns_config(nm_config_get_data(priv->config));
    if (global_config) {
        priv->config_variant = _get_global_config_variant(global_config);
        _LOGT("current configuration: %s", (str = g_variant_print(priv->config_variant, TRUE)));
        return priv->config_variant;
    }

    g_variant_builder_init(&builder, G_VARIANT_TYPE("aa{sv}"));

    head = _mgr_get_ip_configs_lst_head(self);
    c_list_for_each_entry (ip_data, head, ip_config_lst) {
        const NMIPConfig *ip_config = ip_data->ip_config;
        GVariantBuilder   entry_builder;
        GVariantBuilder   strv_builder;
        guint             i, num;
        const int         addr_family = nm_ip_config_get_addr_family(ip_config);
        char              buf[NM_UTILS_INET_ADDRSTRLEN];
        const NMIPAddr *  addr;
        const char *      ifname;

        num = nm_ip_config_get_num_nameservers(ip_config);
        if (!num)
            continue;

        g_variant_builder_init(&entry_builder, G_VARIANT_TYPE("a{sv}"));

        g_variant_builder_init(&strv_builder, G_VARIANT_TYPE("as"));
        for (i = 0; i < num; i++) {
            addr = nm_ip_config_get_nameserver(ip_config, i);
            g_variant_builder_add(&strv_builder, "s", nm_utils_inet_ntop(addr_family, addr, buf));
        }
        g_variant_builder_add(&entry_builder,
                              "{sv}",
                              "nameservers",
                              g_variant_builder_end(&strv_builder));

        num = nm_ip_config_get_num_domains(ip_config);
        num += nm_ip_config_get_num_searches(ip_config);
        if (num > 0) {
            if (!array_domains)
                array_domains = g_ptr_array_sized_new(num);
            else
                g_ptr_array_set_size(array_domains, 0);

            add_dns_domains(array_domains, ip_config, TRUE, FALSE);
            if (array_domains->len) {
                g_variant_builder_init(&strv_builder, G_VARIANT_TYPE("as"));
                for (i = 0; i < array_domains->len; i++) {
                    g_variant_builder_add(&strv_builder, "s", array_domains->pdata[i]);
                }
                g_variant_builder_add(&entry_builder,
                                      "{sv}",
                                      "domains",
                                      g_variant_builder_end(&strv_builder));
            }
        }

        ifname = nm_platform_link_get_name(NM_PLATFORM_GET, ip_data->data->ifindex);
        if (ifname) {
            g_variant_builder_add(&entry_builder,
                                  "{sv}",
                                  "interface",
                                  g_variant_new_string(ifname));
        }

        g_variant_builder_add(&entry_builder,
                              "{sv}",
                              "priority",
                              g_variant_new_int32(nm_ip_config_get_dns_priority(ip_config)));

        g_variant_builder_add(
            &entry_builder,
            "{sv}",
            "vpn",
            g_variant_new_boolean(ip_data->ip_config_type == NM_DNS_IP_CONFIG_TYPE_VPN));

        g_variant_builder_add(&builder, "a{sv}", &entry_builder);
    }

    priv->config_variant = g_variant_ref_sink(g_variant_builder_end(&builder));
    _LOGT("current configuration: %s", (str = g_variant_print(priv->config_variant, TRUE)));

    return priv->config_variant;
}

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMDnsManager *       self = NM_DNS_MANAGER(object);
    NMDnsManagerPrivate *priv = NM_DNS_MANAGER_GET_PRIVATE(self);

    switch (prop_id) {
    case PROP_MODE:
        g_value_set_string(value, priv->mode);
        break;
    case PROP_RC_MANAGER:
        g_value_set_string(value, _rc_manager_to_string(priv->rc_manager));
        break;
    case PROP_CONFIGURATION:
        g_value_set_variant(value, _get_config_variant(self));
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

static void
nm_dns_manager_init(NMDnsManager *self)
{
    NMDnsManagerPrivate *priv = NM_DNS_MANAGER_GET_PRIVATE(self);

    _LOGT("creating...");

    c_list_init(&priv->configs_lst_head);
    c_list_init(&priv->ip_configs_lst_head);

    priv->config = g_object_ref(nm_config_get());

    G_STATIC_ASSERT_EXPR(G_STRUCT_OFFSET(NMDnsConfigData, ifindex) == 0);
    priv->configs_dict = g_hash_table_new_full(nm_pint_hash,
                                               nm_pint_equals,
                                               (GDestroyNotify) _dns_config_data_free,
                                               NULL);

    /* Set the initial hash */
    compute_hash(self, NULL, NM_DNS_MANAGER_GET_PRIVATE(self)->hash);

    g_signal_connect(G_OBJECT(priv->config),
                     NM_CONFIG_SIGNAL_CONFIG_CHANGED,
                     G_CALLBACK(config_changed_cb),
                     self);
    init_resolv_conf_mode(self, TRUE);
}

static void
dispose(GObject *object)
{
    NMDnsManager *       self = NM_DNS_MANAGER(object);
    NMDnsManagerPrivate *priv = NM_DNS_MANAGER_GET_PRIVATE(self);
    NMDnsConfigIPData *  ip_data, *ip_data_safe;

    _LOGT("disposing");

    if (!priv->is_stopped)
        nm_dns_manager_stop(self);

    if (priv->config)
        g_signal_handlers_disconnect_by_func(priv->config, config_changed_cb, self);

    g_clear_object(&priv->sd_resolve_plugin);
    _clear_plugin(self);

    priv->best_ip_config_4 = NULL;
    priv->best_ip_config_6 = NULL;

    c_list_for_each_entry_safe (ip_data, ip_data_safe, &priv->ip_configs_lst_head, ip_config_lst)
        _dns_config_ip_data_free(ip_data);

    nm_clear_pointer(&priv->configs_dict, g_hash_table_destroy);
    nm_assert(c_list_is_empty(&priv->configs_lst_head));

    nm_clear_g_source(&priv->plugin_ratelimit.timer);

    g_clear_object(&priv->config);

    G_OBJECT_CLASS(nm_dns_manager_parent_class)->dispose(object);

    nm_clear_pointer(&priv->config_variant, g_variant_unref);
}

static void
finalize(GObject *object)
{
    NMDnsManager *       self = NM_DNS_MANAGER(object);
    NMDnsManagerPrivate *priv = NM_DNS_MANAGER_GET_PRIVATE(self);

    g_free(priv->hostname);
    g_free(priv->mode);

    G_OBJECT_CLASS(nm_dns_manager_parent_class)->finalize(object);
}

static const NMDBusInterfaceInfoExtended interface_info_dns_manager = {
    .parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT(
        NM_DBUS_INTERFACE_DNS_MANAGER,
        .properties = NM_DEFINE_GDBUS_PROPERTY_INFOS(
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L("Mode", "s", NM_DNS_MANAGER_MODE),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L("RcManager",
                                                             "s",
                                                             NM_DNS_MANAGER_RC_MANAGER),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L("Configuration",
                                                             "aa{sv}",
                                                             NM_DNS_MANAGER_CONFIGURATION), ), ),
};

static void
nm_dns_manager_class_init(NMDnsManagerClass *klass)
{
    GObjectClass *     object_class      = G_OBJECT_CLASS(klass);
    NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS(klass);

    object_class->dispose      = dispose;
    object_class->finalize     = finalize;
    object_class->get_property = get_property;

    dbus_object_class->export_path     = NM_DBUS_EXPORT_PATH_STATIC(NM_DBUS_PATH "/DnsManager");
    dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS(&interface_info_dns_manager);
    dbus_object_class->export_on_construction = TRUE;

    obj_properties[PROP_MODE] = g_param_spec_string(NM_DNS_MANAGER_MODE,
                                                    "",
                                                    "",
                                                    NULL,
                                                    G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_RC_MANAGER] =
        g_param_spec_string(NM_DNS_MANAGER_RC_MANAGER,
                            "",
                            "",
                            NULL,
                            G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_CONFIGURATION] =
        g_param_spec_variant(NM_DNS_MANAGER_CONFIGURATION,
                             "",
                             "",
                             G_VARIANT_TYPE("aa{sv}"),
                             NULL,
                             G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    signals[CONFIG_CHANGED] = g_signal_new(NM_DNS_MANAGER_CONFIG_CHANGED,
                                           G_OBJECT_CLASS_TYPE(object_class),
                                           G_SIGNAL_RUN_FIRST,
                                           0,
                                           NULL,
                                           NULL,
                                           g_cclosure_marshal_VOID__VOID,
                                           G_TYPE_NONE,
                                           0);
}
