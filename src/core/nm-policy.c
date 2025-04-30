/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2004 - 2013 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-policy.h"

#include <unistd.h>
#include <netdb.h>

#include "libnm-core-intern/nm-core-internal.h"
#include "libnm-platform/nm-platform.h"
#include "libnm-platform/nmp-object.h"

#include "NetworkManagerUtils.h"
#include "devices/nm-device.h"
#include "devices/nm-device-factory.h"
#include "dns/nm-dns-manager.h"
#include "nm-act-request.h"
#include "nm-auth-utils.h"
#include "nm-config.h"
#include "nm-dhcp-config.h"
#include "nm-dispatcher.h"
#include "nm-firewalld-manager.h"
#include "nm-hostname-manager.h"
#include "nm-keep-alive.h"
#include "nm-l3-config-data.h"
#include "nm-manager.h"
#include "nm-netns.h"
#include "nm-setting-connection.h"
#include "nm-setting-ip4-config.h"
#include "nm-utils.h"
#include "settings/nm-agent-manager.h"
#include "settings/nm-settings-connection.h"
#include "settings/nm-settings.h"
#include "vpn/nm-vpn-manager.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE(NMPolicy,
                             PROP_MANAGER,
                             PROP_SETTINGS,
                             PROP_DEFAULT_IP4_AC,
                             PROP_DEFAULT_IP6_AC,
                             PROP_ACTIVATING_IP4_AC,
                             PROP_ACTIVATING_IP6_AC, );

#define HOSTNAME_RETRY_INTERVAL_MIN        30U
#define HOSTNAME_RETRY_INTERVAL_MAX        (60U * 60 * 12) /* 12 hours */
#define HOSTNAME_RETRY_INTERVAL_MULTIPLIER 8U

typedef struct {
    NMManager          *manager;
    NMNetns            *netns;
    NMFirewalldManager *firewalld_manager;
    CList               policy_auto_activate_lst_head;

    NMAgentManager *agent_mgr;

    GHashTable *devices;
    GHashTable *pending_active_connections;

    GSList *pending_secondaries;

    NMSettings *settings;

    GSource *device_recheck_auto_activate_all_idle_source;

    GSource *reset_connections_retries_idle_source;

    NMHostnameManager *hostname_manager;

    NMActiveConnection *default_ac4, *activating_ac4;
    NMActiveConnection *default_ac6, *activating_ac6;

    NMDnsManager *dns_manager;
    gulong        config_changed_id;

    NMPolicyHostnameMode hostname_mode;
    char                *orig_hostname;     /* hostname at NM start time */
    char                *cur_hostname;      /* hostname we want to assign */
    char                *cur_hostname_full; /* similar to @last_hostname, but before shortening */
    char                *last_hostname;     /* last hostname NM set (to detect if someone else
                                             * changed it in the meanwhile) */
    struct {
        GSource *source;
        guint    interval_sec;
        gboolean do_restart; /* when something changes, set this to TRUE so that the next retry
                              * will restart from the lowest timeout. */
    } hostname_retry;

    bool changing_hostname : 1; /* hostname set operation in progress */
    bool dhcp_hostname : 1;     /* current hostname was set from dhcp */
    bool updating_dns : 1;

    GArray *ip6_prefix_delegations; /* pool of ip6 prefixes delegated to all devices */

} NMPolicyPrivate;

struct _NMPolicy {
    GObject         parent;
    NMPolicyPrivate _priv;
};

struct _NMPolicyClass {
    GObjectClass parent;
};

G_DEFINE_TYPE(NMPolicy, nm_policy, G_TYPE_OBJECT)

#define NM_POLICY_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMPolicy, NM_IS_POLICY)

static NMPolicy *
_PRIV_TO_SELF(NMPolicyPrivate *priv)
{
    NMPolicy *self;

    nm_assert(priv);

    self = NM_CAST_ALIGN(NMPolicy, (((char *) priv) - G_STRUCT_OFFSET(NMPolicy, _priv)));

    nm_assert(NM_IS_POLICY(self));

    return self;
}

/*****************************************************************************/

#define _NMLOG_PREFIX_NAME "policy"
#undef _NMLOG_ENABLED
#define _NMLOG_ENABLED(level, domain) (nm_logging_enabled((level), (domain)))
#define _NMLOG(level, domain, ...)                                         \
    G_STMT_START                                                           \
    {                                                                      \
        nm_log((level),                                                    \
               (domain),                                                   \
               NULL,                                                       \
               NULL,                                                       \
               "%s" _NM_UTILS_MACRO_FIRST(__VA_ARGS__),                    \
               _NMLOG_PREFIX_NAME ": " _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
    }                                                                      \
    G_STMT_END

/*****************************************************************************/

static void update_system_hostname(NMPolicy *self, const char *msg, gboolean reset_retry_interval);
static void nm_policy_device_recheck_auto_activate_all_schedule(NMPolicy *self);
static NMDevice *get_default_device(NMPolicy *self, int addr_family);
static gboolean  hostname_retry_cb(gpointer user_data);

/*****************************************************************************/

typedef struct {
    NMPlatformIP6Address prefix;
    NMDevice            *device;                   /* The requesting ("uplink") device */
    GHashTable          *map_subnet_id_to_ifindex; /* (guint64 *) subnet_id -> int ifindex */
    GHashTable          *map_ifindex_to_subnet; /* int ifindex -> (NMPlatformIP6Address *) prefix */
} IP6PrefixDelegation;

static void
clear_ip6_subnet(int ifindex, NMPlatformIP6Address *subnet)
{
    NMDevice *device = nm_manager_get_device_by_ifindex(NM_MANAGER_GET, ifindex);

    if (device) {
        /* We can not remove a subnet we already started announcing.
         * Just un-prefer it. */
        subnet->preferred = 0;
        nm_device_use_ip6_subnet(device, subnet);
    }
    g_slice_free(NMPlatformIP6Address, subnet);
}

static void
clear_ip6_subnet_entry(gpointer key, gpointer value, gpointer user_data)
{
    clear_ip6_subnet(GPOINTER_TO_INT(key), value);
}

static void
clear_ip6_prefix_delegation(gpointer data)
{
    IP6PrefixDelegation *delegation = data;
    char                 sbuf[NM_INET_ADDRSTRLEN];

    _LOGD(LOGD_IP6,
          "ipv6-pd: undelegating prefix %s/%d",
          nm_inet6_ntop(&delegation->prefix.address, sbuf),
          delegation->prefix.plen);

    g_hash_table_foreach(delegation->map_ifindex_to_subnet, clear_ip6_subnet_entry, NULL);
    g_hash_table_destroy(delegation->map_ifindex_to_subnet);
    g_hash_table_destroy(delegation->map_subnet_id_to_ifindex);
}

static void
expire_ip6_delegations(NMPolicy *self)
{
    NMPolicyPrivate     *priv       = NM_POLICY_GET_PRIVATE(self);
    guint32              now        = nm_utils_get_monotonic_timestamp_sec();
    IP6PrefixDelegation *delegation = NULL;
    guint                i;

    for (i = 0; i < priv->ip6_prefix_delegations->len; i++) {
        delegation = &nm_g_array_index(priv->ip6_prefix_delegations, IP6PrefixDelegation, i);
        if (delegation->prefix.timestamp + delegation->prefix.lifetime < now)
            g_array_remove_index_fast(priv->ip6_prefix_delegations, i);
    }
}

/*
 * Try to obtain a new subnet for a particular active connection from given
 * delegated prefix, possibly reusing the existing subnet.
 * Return value of FALSE indicates no more subnets are available from
 * this prefix (and other prefix should be used -- and requested if necessary).
 */
static gboolean
ip6_subnet_from_delegation(IP6PrefixDelegation *delegation, NMDevice *device)
{
    NMPlatformIP6Address      *subnet;
    int                        ifindex = nm_device_get_ifindex(device);
    char                       sbuf[NM_INET_ADDRSTRLEN];
    NMSettingPrefixDelegation *s_pd;
    gint64                     wanted_subnet_id = -1;
    guint64                    num_subnets;
    guint64                    old_subnet_id;

    nm_assert(delegation->prefix.plen > 0 && delegation->prefix.plen <= 64);

    s_pd = nm_device_get_applied_setting(device, NM_TYPE_SETTING_PREFIX_DELEGATION);
    if (s_pd) {
        wanted_subnet_id = nm_setting_prefix_delegation_get_subnet_id(s_pd);
    }

    /* Try to use the cached subnet assigned to the interface */
    subnet = g_hash_table_lookup(delegation->map_ifindex_to_subnet, GINT_TO_POINTER(ifindex));
    if (subnet) {
        old_subnet_id = nm_ip6_addr_get_subnet_id(&subnet->address, delegation->prefix.plen);
        if (wanted_subnet_id != -1 && wanted_subnet_id != old_subnet_id) {
            /* The device had a subnet assigned before, but now wants a
             * different subnet-id. Release the old subnet and continue below
             * to get a new one. */
            clear_ip6_subnet(ifindex, subnet);
            subnet = NULL;
            g_hash_table_remove(delegation->map_ifindex_to_subnet, GINT_TO_POINTER(ifindex));
            g_hash_table_remove(delegation->map_subnet_id_to_ifindex, &old_subnet_id);
        } else {
            goto subnet_found;
        }
    }

    /* Check for out-of-prefixes condition */
    num_subnets = 1 << (64 - delegation->prefix.plen);
    if (nm_g_hash_table_size(delegation->map_subnet_id_to_ifindex) >= num_subnets) {
        _LOGD(LOGD_IP6,
              "ipv6-pd: no more prefixes in %s/%u",
              nm_inet6_ntop(&delegation->prefix.address, sbuf),
              delegation->prefix.plen);
        return FALSE;
    }

    /* Try to honor the "prefix-delegation.subnet-id" property */
    if (wanted_subnet_id >= 0) {
        gpointer  value;
        NMDevice *other_device;

        if (g_hash_table_lookup_extended(delegation->map_subnet_id_to_ifindex,
                                         &wanted_subnet_id,
                                         NULL,
                                         &value)) {
            other_device = nm_manager_get_device_by_ifindex(NM_MANAGER_GET, GPOINTER_TO_INT(value));
            _LOGW(LOGD_IP6,
                  "ipv6-pd: subnet-id 0x%" G_GINT64_MODIFIER
                  "x wanted by device %s is already in use by "
                  "device %s (ifindex %d)",
                  (guint64) wanted_subnet_id,
                  nm_device_get_iface(device),
                  other_device ? nm_device_get_ip_iface(other_device) : NULL,
                  GPOINTER_TO_INT(value));
            wanted_subnet_id = -1;
        }
    }

    /* If we don't have a subnet-id yet, find the first one available */
    if (wanted_subnet_id < 0) {
        guint64 i;

        for (i = 0; i < num_subnets; i++) {
            if (!g_hash_table_lookup_extended(delegation->map_subnet_id_to_ifindex,
                                              &i,
                                              NULL,
                                              NULL)) {
                wanted_subnet_id = (gint64) i;
                break;
            }
        }

        if (wanted_subnet_id < 0) {
            /* We already verified that there are available subnets, this should not happen */
            return nm_assert_unreachable_val(FALSE);
        }
    }

    /* Allocate a new subnet */
    subnet = g_slice_new0(NMPlatformIP6Address);
    g_hash_table_insert(delegation->map_ifindex_to_subnet, GINT_TO_POINTER(ifindex), subnet);
    g_hash_table_insert(delegation->map_subnet_id_to_ifindex,
                        nm_memdup(&wanted_subnet_id, sizeof(guint64)),
                        GINT_TO_POINTER(ifindex));

    subnet->plen = 64;
    subnet->address.s6_addr32[0] =
        delegation->prefix.address.s6_addr32[0] | htonl(wanted_subnet_id >> 32);
    subnet->address.s6_addr32[1] =
        delegation->prefix.address.s6_addr32[1] | htonl(wanted_subnet_id);

subnet_found:
    subnet->timestamp = delegation->prefix.timestamp;
    subnet->lifetime  = delegation->prefix.lifetime;
    subnet->preferred = delegation->prefix.preferred;

    _LOGD(LOGD_IP6,
          "ipv6-pd: %s/64 (subnet-id 0x%" G_GINT64_MODIFIER "x) allocated from a /%d prefix on %s",
          nm_inet6_ntop(&subnet->address, sbuf),
          (guint64) wanted_subnet_id,
          delegation->prefix.plen,
          nm_device_get_iface(device));

    nm_device_use_ip6_subnet(device, subnet);

    return TRUE;
}

/*
 * Try to obtain a subnet from each prefix delegated to given requesting
 * ("uplink") device and assign it to the downlink device.
 * Requests a new prefix if no subnet could be found.
 */
static void
ip6_subnet_from_device(NMPolicy *self, NMDevice *from_device, NMDevice *device)
{
    NMPolicyPrivate     *priv          = NM_POLICY_GET_PRIVATE(self);
    IP6PrefixDelegation *delegation    = NULL;
    gboolean             got_subnet    = FALSE;
    guint                have_prefixes = 0;
    guint                i;

    expire_ip6_delegations(self);

    for (i = 0; i < priv->ip6_prefix_delegations->len; i++) {
        delegation = &nm_g_array_index(priv->ip6_prefix_delegations, IP6PrefixDelegation, i);

        if (delegation->device != from_device)
            continue;

        if (ip6_subnet_from_delegation(delegation, device))
            got_subnet = TRUE;
        have_prefixes++;
    }

    if (!got_subnet) {
        _LOGI(LOGD_IP6,
              "ipv6-pd: none of %u prefixes of %s can be shared on %s",
              have_prefixes,
              nm_device_get_iface(from_device),
              nm_device_get_iface(device));
        nm_device_request_ip6_prefixes(from_device, have_prefixes + 1);
    }
}

static void
ip6_remove_device_prefix_delegations(NMPolicy *self, NMDevice *device)
{
    NMPolicyPrivate     *priv       = NM_POLICY_GET_PRIVATE(self);
    IP6PrefixDelegation *delegation = NULL;
    guint                i;

    for (i = 0; i < priv->ip6_prefix_delegations->len; i++) {
        delegation = &nm_g_array_index(priv->ip6_prefix_delegations, IP6PrefixDelegation, i);
        if (delegation->device == device)
            g_array_remove_index_fast(priv->ip6_prefix_delegations, i);
    }
}

static void
device_ip6_prefix_delegated(NMDevice                   *device,
                            const NMPlatformIP6Address *prefix,
                            gpointer                    user_data)
{
    NMPolicyPrivate     *priv       = user_data;
    NMPolicy            *self       = _PRIV_TO_SELF(priv);
    IP6PrefixDelegation *delegation = NULL;
    guint                i;
    const CList         *tmp_list;
    NMActiveConnection  *ac;
    char                 sbuf[NM_INET_ADDRSTRLEN];

    _LOGI(LOGD_IP6,
          "ipv6-pd: received a prefix %s/%d from %s",
          nm_inet6_ntop(&prefix->address, sbuf),
          prefix->plen,
          nm_device_get_iface(device));

    expire_ip6_delegations(self);

    for (i = 0; i < priv->ip6_prefix_delegations->len; i++) {
        /* Look for an already known prefix to update. */
        delegation = &nm_g_array_index(priv->ip6_prefix_delegations, IP6PrefixDelegation, i);
        if (IN6_ARE_ADDR_EQUAL(&delegation->prefix.address, &prefix->address))
            break;
    }

    if (i == priv->ip6_prefix_delegations->len) {
        /* Allocate a delegation for new prefix. */
        delegation = nm_g_array_append_new(priv->ip6_prefix_delegations, IP6PrefixDelegation);
        delegation->map_subnet_id_to_ifindex =
            g_hash_table_new_full(nm_puint64_hash, nm_puint64_equal, g_free, NULL);
        delegation->map_ifindex_to_subnet = g_hash_table_new(nm_direct_hash, NULL);
    }

    delegation->device = device;
    delegation->prefix = *prefix;

    /* The newly activated connections are added to the end of the list,
     * so traversing it from the end makes it likely for newly
     * activated connections that have no subnet assigned to be served
     * first. That is a simple yet fair policy, which is good. */
    nm_manager_for_each_active_connection_prev (priv->manager, ac, tmp_list) {
        NMDevice *to_device;

        to_device = nm_active_connection_get_device(ac);
        if (nm_device_needs_ip6_subnet(to_device))
            ip6_subnet_from_delegation(delegation, to_device);
    }
}

static void
device_ip6_subnet_needed(NMDevice *device, gpointer user_data)
{
    NMPolicyPrivate *priv = user_data;
    NMPolicy        *self = _PRIV_TO_SELF(priv);

    _LOGD(LOGD_IP6, "ipv6-pd: %s needs a subnet", nm_device_get_iface(device));

    if (!priv->default_ac6) {
        /* We request the prefixes when the default IPv6 device is set. */
        _LOGI(LOGD_IP6,
              "ipv6-pd: no device to obtain a subnet to share on %s from",
              nm_device_get_iface(device));
        return;
    }
    ip6_subnet_from_device(self, get_default_device(self, AF_INET6), device);
    nm_device_copy_ip6_dns_config(device, get_default_device(self, AF_INET6));
}

/*****************************************************************************/

static NMDevice *
get_default_device(NMPolicy *self, int addr_family)
{
    NMPolicyPrivate    *priv = NM_POLICY_GET_PRIVATE(self);
    NMActiveConnection *ac;

    nm_assert_addr_family(addr_family);

    ac = (addr_family == AF_INET) ? priv->default_ac4 : priv->default_ac6;

    return ac ? nm_active_connection_get_device(ac) : NULL;
}

static NMActiveConnection *
get_best_active_connection(NMPolicy *self, int addr_family, gboolean fully_activated)
{
    NMPolicyPrivate    *priv = NM_POLICY_GET_PRIVATE(self);
    const CList        *tmp_lst;
    NMDevice           *device;
    guint32             best_metric             = G_MAXUINT32;
    gboolean            best_is_fully_activated = FALSE;
    NMActiveConnection *best_ac, *prev_ac;

    nm_assert(NM_IN_SET(addr_family, AF_INET, AF_INET6));

    /* we prefer the current AC in case of identical metric.
     * Hence, try that one first. */
    prev_ac = addr_family == AF_INET ? (fully_activated ? priv->default_ac4 : priv->activating_ac4)
                                     : (fully_activated ? priv->default_ac6 : priv->activating_ac6);
    best_ac = NULL;

    nm_manager_for_each_device (priv->manager, device, tmp_lst) {
        NMDeviceState       state;
        const NMPObject    *r;
        NMActiveConnection *ac;
        NMConnection       *connection;
        guint32             metric;
        gboolean            is_fully_activated;

        state = nm_device_get_state(device);
        if (state <= NM_DEVICE_STATE_DISCONNECTED || state >= NM_DEVICE_STATE_DEACTIVATING)
            continue;

        if (nm_device_managed_type_is_external(device))
            continue;

        r = nm_device_get_best_default_route(device, addr_family);
        if (r) {
            /* NOTE: the best route might have rt_source NM_IP_CONFIG_SOURCE_VPN,
             * which means it was injected by a VPN, not added by device.
             *
             * In this case, is it really the best device? Why do we even need the best
             * device?? */
            metric             = NMP_OBJECT_CAST_IP_ROUTE(r)->metric;
            is_fully_activated = TRUE;
        } else if (!fully_activated && (connection = nm_device_get_applied_connection(device))
                   && nm_utils_connection_has_default_route(connection, addr_family, NULL)) {
            metric             = nm_device_get_route_metric(device, addr_family);
            is_fully_activated = FALSE;
        } else
            continue;

        ac = (NMActiveConnection *) nm_device_get_act_request(device);
        nm_assert(ac);

        if (!best_ac || (!best_is_fully_activated && is_fully_activated)
            || (metric < best_metric || (metric == best_metric && ac == prev_ac))) {
            best_ac                 = ac;
            best_metric             = metric;
            best_is_fully_activated = is_fully_activated;
        }
    }

    if (!fully_activated && best_ac && best_is_fully_activated) {
        /* There's a best activating AC only if the best device
         * among all activating and already-activated devices is a
         * still-activating one. */
        return NULL;
    }

    return best_ac;
}

static gboolean
any_devices_active(NMPolicy *self)
{
    NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE(self);
    const CList     *tmp_lst;
    NMDevice        *device;

    nm_manager_for_each_device (priv->manager, device, tmp_lst) {
        NMDeviceState state;

        state = nm_device_get_state(device);
        if (state <= NM_DEVICE_STATE_DISCONNECTED || state >= NM_DEVICE_STATE_DEACTIVATING)
            continue;
        if (nm_device_managed_type_is_external(device))
            continue;
        return TRUE;
    }
    return FALSE;
}

#define FALLBACK_HOSTNAME4 "localhost.localdomain"

static void
settings_set_hostname_cb(const char *hostname, gboolean result, gpointer user_data)
{
    NMPolicy        *self = NM_POLICY(user_data);
    NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE(self);
    int              ret  = 0;
    int              errsv;

    if (!result) {
        _LOGT(LOGD_DNS, "set-hostname: hostname set via dbus failed, fallback to \"sethostname\"");
        ret = sethostname(hostname, strlen(hostname));
        if (ret != 0) {
            errsv = errno;
            _LOGW(LOGD_DNS,
                  "set-hostname: couldn't set the system hostname to '%s': (%d) %s",
                  hostname,
                  errsv,
                  nm_strerror_native(errsv));
            if (errsv == EPERM)
                _LOGW(
                    LOGD_DNS,
                    "set-hostname: you should use hostnamed when systemd hardening is in effect!");
        }
    }

    priv->changing_hostname = FALSE;
    if (!ret)
        nm_dispatcher_call_hostname(NULL, NULL, NULL);
    g_object_unref(self);
}

#define HOST_NAME_BUFSIZE (HOST_NAME_MAX + 2)

static char *
_get_hostname(NMPolicy *self)
{
    NMPolicyPrivate *priv     = NM_POLICY_GET_PRIVATE(self);
    char            *hostname = NULL;
    int              errsv;

    /* If there is an in-progress hostname change, return
     * the last hostname set as would be set soon...
     */
    if (priv->changing_hostname) {
        _LOGT(LOGD_DNS, "get-hostname: \"%s\" (last on set)", priv->last_hostname);
        return g_strdup(priv->last_hostname);
    }

    /* try to get the hostname via dbus... */
    if (nm_hostname_manager_get_transient_hostname(priv->hostname_manager, &hostname)) {
        _LOGT(LOGD_DNS, "get-hostname: \"%s\" (from dbus)", hostname);
        return hostname;
    }

    /* ...or retrieve it by yourself */
    hostname = g_malloc(HOST_NAME_BUFSIZE);
    if (gethostname(hostname, HOST_NAME_BUFSIZE - 1) != 0) {
        errsv = errno;
        _LOGT(LOGD_DNS,
              "get-hostname: couldn't get the system hostname: (%d) %s",
              errsv,
              nm_strerror_native(errsv));
        g_free(hostname);
        return NULL;
    }

    /* the name may be truncated... */
    hostname[HOST_NAME_BUFSIZE - 1] = '\0';
    if (strlen(hostname) >= HOST_NAME_BUFSIZE - 1) {
        _LOGT(LOGD_DNS, "get-hostname: system hostname too long: \"%s\"", hostname);
        g_free(hostname);
        return NULL;
    }

    _LOGT(LOGD_DNS, "get-hostname: \"%s\"", hostname);
    return hostname;
}

static void
hostname_retry_schedule(NMPolicy *self)
{
    NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE(self);

    if (priv->hostname_retry.source && !priv->hostname_retry.do_restart)
        return;

    nm_clear_g_source_inst(&priv->hostname_retry.source);

    if (priv->hostname_retry.do_restart)
        priv->hostname_retry.interval_sec = 0;

    priv->hostname_retry.interval_sec *= HOSTNAME_RETRY_INTERVAL_MULTIPLIER;
    priv->hostname_retry.interval_sec = NM_CLAMP(priv->hostname_retry.interval_sec,
                                                 HOSTNAME_RETRY_INTERVAL_MIN,
                                                 HOSTNAME_RETRY_INTERVAL_MAX);

    _LOGT(LOGD_DNS,
          "hostname-retry: schedule in %u seconds%s",
          priv->hostname_retry.interval_sec,
          priv->hostname_retry.do_restart ? " (restarted)" : "");
    priv->hostname_retry.source =
        nm_g_timeout_add_seconds_source(priv->hostname_retry.interval_sec, hostname_retry_cb, self);

    priv->hostname_retry.do_restart = FALSE;
}

static gboolean
hostname_retry_cb(gpointer user_data)
{
    NMPolicy        *self = NM_POLICY(user_data);
    NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE(self);
    const CList     *tmp_lst;
    NMDevice        *device;

    _LOGT(LOGD_DNS, "hostname-retry: timeout");

    nm_clear_g_source_inst(&priv->hostname_retry.source);

    /* Clear any cached DNS results before retrying */
    nm_manager_for_each_device (priv->manager, device, tmp_lst) {
        nm_device_clear_dns_lookup_data(device, "hostname retry timeout");
    }
    update_system_hostname(self, "hostname retry timeout", FALSE);

    return G_SOURCE_CONTINUE;
}

static void
_set_hostname(NMPolicy *self, const char *new_hostname, const char *msg, gboolean do_retry)
{
    NMPolicyPrivate *priv         = NM_POLICY_GET_PRIVATE(self);
    gs_free char    *old_hostname = NULL;
    gboolean         cur_hostname_full_changed;
    const char      *name;

    /* The incoming hostname *can* be NULL, which will get translated to
     * 'localhost.localdomain' or such in the hostname policy code, but we
     * keep cur_hostname = NULL in the case because we need to know that
     * there was no valid hostname to start with.
     */

    if (nm_strdup_reset(&priv->cur_hostname_full, new_hostname)) {
        gs_free char *shortened = NULL;

        cur_hostname_full_changed = TRUE;

        if (priv->cur_hostname_full
            && !nm_utils_shorten_hostname(priv->cur_hostname_full, &shortened)) {
            _LOGW(LOGD_DNS,
                  "set-hostname: hostname '%s' %s is invalid",
                  priv->cur_hostname_full,
                  msg);
            return;
        }

        if (shortened) {
            _LOGI(LOGD_DNS,
                  "set-hostname: shortened hostname %s from '%s' to '%s'",
                  msg,
                  priv->cur_hostname_full,
                  shortened);
            nm_strdup_reset_take(&priv->cur_hostname, g_steal_pointer(&shortened));
        } else
            nm_strdup_reset(&priv->cur_hostname, priv->cur_hostname_full);
    } else
        cur_hostname_full_changed = FALSE;

    /* Update the DNS only if the hostname is actually
     * going to change.
     */
    if (cur_hostname_full_changed) {
        /* Notify the DNS manager of the hostname change so that the domain part, if
         * present, can be added to the search list. Set the @updating_dns flag
         * so that dns_config_changed() doesn't try again to restart DNS lookup.
         */
        priv->updating_dns = TRUE;
        nm_dns_manager_set_hostname(priv->dns_manager,
                                    priv->cur_hostname_full,
                                    !any_devices_active(self));
        priv->updating_dns = FALSE;
    }

    if (!do_retry) {
        _LOGT(LOGD_DNS, "hostname-retry: clear");
        nm_clear_g_source_inst(&priv->hostname_retry.source);
        priv->hostname_retry.interval_sec = 0;
        priv->hostname_retry.do_restart   = FALSE;
    } else if (!priv->hostname_retry.source) {
        hostname_retry_schedule(self);
    }

    /* Finally, set kernel hostname */
    nm_assert(!priv->cur_hostname || priv->cur_hostname[0]);
    name = priv->cur_hostname ?: FALLBACK_HOSTNAME4;

    /* Don't set the hostname if it isn't actually changing */
    if ((old_hostname = _get_hostname(self)) && (nm_streq(name, old_hostname))) {
        _LOGT(LOGD_DNS, "set-hostname: hostname already set to '%s' (%s)", name, msg);
        return;
    }

    /* Keep track of the last set hostname */
    nm_strdup_reset(&priv->last_hostname, name);
    priv->changing_hostname = TRUE;

    _LOGI(LOGD_DNS, "set-hostname: set hostname to '%s' (%s)", name, msg);

    /* Ask NMSettings to update the transient hostname using its
     * systemd-hostnamed proxy.
     *
     * FIXME(shutdown): an async request must be cancellable, so we are guaranteed
     *   to tear down in a reasonable time.*/
    nm_hostname_manager_set_transient_hostname(priv->hostname_manager,
                                               name,
                                               settings_set_hostname_cb,
                                               g_object_ref(self));
}

typedef struct {
    NMDevice *device;
    int       priority;
    bool      from_dhcp : 1;
    bool      from_dns : 1;
    bool      IS_IPv4 : 1;
    bool      is_default : 1;
} DeviceHostnameInfo;

static int
device_hostname_info_compare(gconstpointer a, gconstpointer b)
{
    const DeviceHostnameInfo *info1 = a;
    const DeviceHostnameInfo *info2 = b;

    NM_CMP_FIELD(info1, info2, priority);
    NM_CMP_FIELD_UNSAFE(info2, info1, is_default);
    NM_CMP_FIELD_UNSAFE(info2, info1, IS_IPv4);

    return 0;
}

NM_CON_DEFAULT_NOP("hostname.from-dhcp");
NM_CON_DEFAULT_NOP("hostname.from-dns-lookup");
NM_CON_DEFAULT_NOP("hostname.only-from-default");

static gboolean
device_get_hostname_property_boolean(NMDevice *device, const char *name)
{
    NMSettingHostname *s_hostname;
    char               buf[128];
    int                value;
    NMTernary          default_value;

    nm_assert(NM_IN_STRSET(name,
                           NM_SETTING_HOSTNAME_FROM_DHCP,
                           NM_SETTING_HOSTNAME_FROM_DNS_LOOKUP,
                           NM_SETTING_HOSTNAME_ONLY_FROM_DEFAULT));

    s_hostname = nm_device_get_applied_setting(device, NM_TYPE_SETTING_HOSTNAME);

    if (s_hostname) {
        g_object_get(s_hostname, name, &value, NULL);
        if (NM_IN_SET(value, NM_TERNARY_FALSE, NM_TERNARY_TRUE))
            return value;
    }

    if (nm_streq(name, NM_SETTING_HOSTNAME_ONLY_FROM_DEFAULT))
        default_value = NM_TERNARY_FALSE;
    else
        default_value = NM_TERNARY_TRUE;

    return nm_config_data_get_connection_default_int64(NM_CONFIG_GET_DATA,
                                                       nm_sprintf_buf(buf, "hostname.%s", name),
                                                       device,
                                                       NM_TERNARY_FALSE,
                                                       NM_TERNARY_TRUE,
                                                       default_value);
}

static int
device_get_hostname_priority(NMDevice *device)
{
    NMSettingHostname *s_hostname;
    int                priority;

    s_hostname = nm_device_get_applied_setting(device, NM_TYPE_SETTING_HOSTNAME);
    if (s_hostname) {
        priority = nm_setting_hostname_get_priority(s_hostname);
        if (priority != 0)
            return priority;
    }

    return nm_config_data_get_connection_default_int64(NM_CONFIG_GET_DATA,
                                                       NM_CON_DEFAULT("hostname.priority"),
                                                       device,
                                                       G_MININT,
                                                       G_MAXINT,
                                                       100);
}

static GArray *
build_device_hostname_infos(NMPolicy *self)
{
    NMPolicyPrivate    *priv = NM_POLICY_GET_PRIVATE(self);
    const CList        *tmp_clist;
    NMActiveConnection *ac;
    GArray             *array = NULL;

    nm_manager_for_each_active_connection (priv->manager, ac, tmp_clist) {
        DeviceHostnameInfo *info;
        NMDevice           *device;
        gboolean            only_from_default;
        gboolean            is_default;
        int                 IS_IPv4;

        device = nm_active_connection_get_device(ac);
        if (!device)
            continue;

        if (nm_device_managed_type_is_external(device))
            continue;

        only_from_default =
            device_get_hostname_property_boolean(device, NM_SETTING_HOSTNAME_ONLY_FROM_DEFAULT);

        for (IS_IPv4 = 1; IS_IPv4 >= 0; IS_IPv4--) {
            is_default = (ac == (IS_IPv4 ? priv->default_ac4 : priv->default_ac6));
            if (only_from_default && !is_default)
                continue;

            if (!array)
                array = g_array_sized_new(FALSE, FALSE, sizeof(DeviceHostnameInfo), 4);

            info  = nm_g_array_append_new(array, DeviceHostnameInfo);
            *info = (DeviceHostnameInfo) {
                .device   = device,
                .priority = device_get_hostname_priority(device),
                .from_dhcp =
                    device_get_hostname_property_boolean(device, NM_SETTING_HOSTNAME_FROM_DHCP),
                .from_dns =
                    device_get_hostname_property_boolean(device,
                                                         NM_SETTING_HOSTNAME_FROM_DNS_LOOKUP),
                .IS_IPv4    = IS_IPv4,
                .is_default = is_default,
            };
        }
    }

    if (array && array->len > 1) {
        const DeviceHostnameInfo *info0;
        guint                     i;

        g_array_sort(array, device_hostname_info_compare);

        info0 = &nm_g_array_first(array, DeviceHostnameInfo);
        if (info0->priority < 0) {
            for (i = 1; i < array->len; i++) {
                const DeviceHostnameInfo *info = &nm_g_array_index(array, DeviceHostnameInfo, i);

                if (info->priority > info0->priority) {
                    g_array_set_size(array, i);
                    break;
                }
            }
        }
    }

    return array;
}

static void
device_dns_lookup_done(NMDevice *device, gpointer user_data)
{
    NMPolicy *self = user_data;

    g_signal_handlers_disconnect_by_func(device, device_dns_lookup_done, self);

    update_system_hostname(self, "lookup finished", FALSE);
}

static void
device_carrier_changed(NMDevice *device, GParamSpec *pspec, gpointer user_data)
{
    NMPolicyPrivate *priv = user_data;
    NMPolicy        *self = _PRIV_TO_SELF(priv);
    gs_free char    *msg  = NULL;

    if (nm_device_has_carrier(device)) {
        g_signal_handlers_disconnect_by_func(device, device_carrier_changed, priv);
        msg = g_strdup_printf("device '%s' got carrier", nm_device_get_iface(device));
        update_system_hostname(self, msg, TRUE);
    }
}

/*
 * This function evaluates different sources (static configuration, DHCP, DNS, ...)
 * to set the system hostname.
 *
 * When the function needs to perform a blocking action like a DNS resolution, it
 * subscribes to a signal for the completion event, registering a callback that
 * invokes this function again. In the new invocation, any previous DNS result is
 * cached and doesn't need a new resolution.
 *
 * In case no hostname is found when after sources have been evaluated, it schedules
 * a timer to retry later with an interval that is increased at each attempt. When
 * this function is called after something changed (for example, carrier went up, a
 * new address was added), @reset_retry_interval should be set to TRUE so that the
 * next retry will use the smallest interval. In this way, it can quickly adapt to
 * temporary misconfigurations at boot or when the network environment changes.
 */
static void
update_system_hostname(NMPolicy *self, const char *msg, gboolean reset_retry_interval)
{
    NMPolicyPrivate       *priv = NM_POLICY_GET_PRIVATE(self);
    const char            *configured_hostname;
    gs_free char          *temp_hostname = NULL;
    const char            *dhcp_hostname, *p;
    gboolean               external_hostname = FALSE;
    NMDhcpConfig          *dhcp_config;
    gs_unref_array GArray *infos = NULL;
    DeviceHostnameInfo    *info;
    guint                  i;
    int                    addr_family;

    g_return_if_fail(self != NULL);

    if (reset_retry_interval)
        priv->hostname_retry.do_restart = TRUE;

    if (priv->hostname_mode == NM_POLICY_HOSTNAME_MODE_NONE) {
        _LOGT(LOGD_DNS, "set-hostname: hostname is unmanaged");
        return;
    }

    _LOGT(LOGD_DNS, "set-hostname: updating hostname (%s)", msg);

    /* Check if the hostname was set externally to NM, so that in that case
     * we can avoid to fallback to the one we got when we started.
     * Consider "not specific" hostnames as equal. */
    if ((temp_hostname = _get_hostname(self)) && !nm_streq0(temp_hostname, priv->last_hostname)
        && (nm_utils_is_specific_hostname(temp_hostname)
            || nm_utils_is_specific_hostname(priv->last_hostname))) {
        external_hostname = TRUE;
        _LOGD(LOGD_DNS,
              "set-hostname: current hostname was changed outside NetworkManager: '%s'",
              temp_hostname);
        priv->dhcp_hostname = FALSE;

        if (!nm_utils_is_specific_hostname(temp_hostname))
            nm_clear_g_free(&temp_hostname);
        if (!nm_streq0(temp_hostname, priv->orig_hostname)) {
            /* Update original (fallback) hostname */
            g_free(priv->orig_hostname);
            priv->orig_hostname = g_steal_pointer(&temp_hostname);
            _LOGT(LOGD_DNS,
                  "hostname-original: update to %s%s%s",
                  NM_PRINT_FMT_QUOTE_STRING(priv->orig_hostname));
        }
    }

    /* Hostname precedence order:
     *
     * 1) a configured hostname (from settings)
     * 2) automatic hostname from DHCP of eligible interfaces
     * 3) reverse-DNS lookup of the first address on eligible interfaces
     * 4) the last hostname set outside NM
     */

    /* Try a persistent hostname first */
    configured_hostname = nm_hostname_manager_get_static_hostname(priv->hostname_manager);
    if (configured_hostname && nm_utils_is_not_empty_hostname(configured_hostname)) {
        _set_hostname(self, configured_hostname, "from system configuration", FALSE);
        priv->dhcp_hostname = FALSE;
        return;
    }

    infos = build_device_hostname_infos(self);

    if (infos && _LOGT_ENABLED(LOGD_DNS)) {
        _LOGT(LOGD_DNS, "device hostname info:");
        for (i = 0; i < infos->len; i++) {
            info = &nm_g_array_index(infos, DeviceHostnameInfo, i);
            _LOGT(LOGD_DNS,
                  "  - prio:%5d ipv%c%s %s %s dev:%s",
                  info->priority,
                  info->IS_IPv4 ? '4' : '6',
                  info->is_default ? " (def)" : "      ",
                  info->from_dhcp ? "dhcp " : "     ",
                  info->from_dns ? "dns " : "    ",
                  nm_device_get_iface(info->device));
        }
    }

    for (i = 0; infos && i < infos->len; i++) {
        info        = &nm_g_array_index(infos, DeviceHostnameInfo, i);
        addr_family = info->IS_IPv4 ? AF_INET : AF_INET6;
        g_signal_handlers_disconnect_by_func(info->device, device_dns_lookup_done, self);
        g_signal_handlers_disconnect_by_func(info->device, device_carrier_changed, priv);

        if (info->from_dhcp) {
            dhcp_config = nm_device_get_dhcp_config(info->device, addr_family);
            if (dhcp_config) {
                dhcp_hostname =
                    nm_dhcp_config_get_option(dhcp_config,
                                              info->IS_IPv4 ? "host_name" : "fqdn_fqdn");
                if (dhcp_hostname && dhcp_hostname[0]) {
                    p = nm_str_skip_leading_spaces(dhcp_hostname);
                    if (p[0]) {
                        _set_hostname(self,
                                      p,
                                      info->IS_IPv4 ? "from DHCPv4" : "from DHCPv6",
                                      FALSE);
                        priv->dhcp_hostname = TRUE;
                        return;
                    }
                    _LOGW(LOGD_DNS,
                          "set-hostname: DHCPv%c-provided hostname '%s' looks invalid; "
                          "ignoring it",
                          nm_utils_addr_family_to_char(addr_family),
                          dhcp_hostname);
                }
            }
        }

        if (priv->hostname_mode != NM_POLICY_HOSTNAME_MODE_DHCP) {
            if (info->from_dns) {
                const char *result = NULL;
                gboolean    wait   = FALSE;

                if (nm_device_has_carrier(info->device)) {
                    result =
                        nm_device_get_hostname_from_dns_lookup(info->device, addr_family, &wait);
                } else {
                    g_signal_connect(info->device,
                                     "notify::" NM_DEVICE_CARRIER,
                                     G_CALLBACK(device_carrier_changed),
                                     priv);
                }
                if (result) {
                    _set_hostname(self, result, "from address lookup", FALSE);
                    return;
                }
                if (wait) {
                    g_signal_connect(info->device,
                                     NM_DEVICE_DNS_LOOKUP_DONE,
                                     G_CALLBACK(device_dns_lookup_done),
                                     self);
                    return;
                }
            }
        }
    }

    /* If an hostname was set outside NetworkManager keep it */
    if (external_hostname) {
        hostname_retry_schedule(self);
        return;
    }

    if (priv->hostname_mode == NM_POLICY_HOSTNAME_MODE_DHCP) {
        /* In dhcp hostname-mode, the hostname is updated only if it comes from
         * a DHCP host-name option: if last set was from a host-name option and
         * we are here than that connection is gone (with its host-name option),
         * so reset the hostname to the previous value
         */
        if (priv->dhcp_hostname) {
            _set_hostname(self, priv->orig_hostname, "reset dhcp hostname", TRUE);
            priv->dhcp_hostname = FALSE;
        }
        return;
    }

    priv->dhcp_hostname = FALSE;

    /* If no automatically-configured hostname, try using the last hostname
     * set externally to NM
     */
    if (priv->orig_hostname) {
        _set_hostname(self, priv->orig_hostname, "from system startup", TRUE);
        return;
    }

    _set_hostname(self, NULL, "no hostname found", TRUE);
}

static void
update_default_ac(NMPolicy *self, int addr_family, NMActiveConnection *best)
{
    NMPolicyPrivate    *priv = NM_POLICY_GET_PRIVATE(self);
    const CList        *tmp_list;
    NMActiveConnection *ac;

    /* Clear the 'default[6]' flag on all active connections that aren't the new
     * default active connection.  We'll set the new default after; this ensures
     * we don't ever have two marked 'default[6]' simultaneously.
     */
    nm_manager_for_each_active_connection (priv->manager, ac, tmp_list) {
        if (ac != best)
            nm_active_connection_set_default(ac, addr_family, FALSE);
    }

    /* Mark new default active connection */
    if (best)
        nm_active_connection_set_default(best, addr_family, TRUE);
}

static const NML3ConfigData *
get_best_ip_config(NMPolicy            *self,
                   int                  addr_family,
                   const char         **out_ip_iface,
                   NMActiveConnection **out_ac,
                   NMDevice           **out_device,
                   NMVpnConnection    **out_vpn)
{
    NMPolicyPrivate      *priv      = NM_POLICY_GET_PRIVATE(self);
    const NML3ConfigData *l3cd_best = NULL;
    const CList          *tmp_list;
    NMActiveConnection   *ac;
    guint64               best_metric = G_MAXUINT64;
    NMVpnConnection      *best_vpn    = NULL;

    nm_assert(NM_IN_SET(addr_family, AF_INET, AF_INET6));

    nm_manager_for_each_active_connection (priv->manager, ac, tmp_list) {
        const NML3ConfigData *l3cd;
        NMVpnConnection      *candidate;
        NMVpnConnectionState  vpn_state;
        const NMPObject      *obj;
        guint32               metric;

        if (!NM_IS_VPN_CONNECTION(ac))
            continue;

        candidate = NM_VPN_CONNECTION(ac);

        vpn_state = nm_vpn_connection_get_vpn_state(candidate);
        if (vpn_state != NM_VPN_CONNECTION_STATE_ACTIVATED)
            continue;

        l3cd = nm_vpn_connection_get_l3cd(candidate);
        if (!l3cd)
            continue;

        obj = nm_l3_config_data_get_best_default_route(l3cd, addr_family);
        if (!obj)
            continue;

        metric = NMP_OBJECT_CAST_IPX_ROUTE(obj)->rx.metric;
        if (metric <= best_metric) {
            best_metric = metric;
            l3cd_best   = l3cd;
            best_vpn    = candidate;
        }
    }

    if (best_metric != G_MAXUINT64) {
        NM_SET_OUT(out_device, NULL);
        NM_SET_OUT(out_vpn, best_vpn);
        NM_SET_OUT(out_ac, NM_ACTIVE_CONNECTION(best_vpn));
        NM_SET_OUT(out_ip_iface, nm_vpn_connection_get_ip_iface(best_vpn, TRUE));
        return l3cd_best;
    }

    ac = get_best_active_connection(self, addr_family, TRUE);
    if (ac) {
        NMDevice *device = nm_active_connection_get_device(ac);

        nm_assert(NM_IS_DEVICE(device));

        NM_SET_OUT(out_device, device);
        NM_SET_OUT(out_vpn, NULL);
        NM_SET_OUT(out_ac, ac);
        NM_SET_OUT(out_ip_iface, nm_device_get_ip_iface(device));
        return nm_device_get_l3cd(device, TRUE);
    }

    NM_SET_OUT(out_device, NULL);
    NM_SET_OUT(out_vpn, NULL);
    NM_SET_OUT(out_ac, NULL);
    NM_SET_OUT(out_ip_iface, NULL);
    return NULL;
}

static void
update_ip4_routing(NMPolicy *self, gboolean force_update)
{
    NMPolicyPrivate    *priv     = NM_POLICY_GET_PRIVATE(self);
    NMDevice           *best     = NULL;
    NMVpnConnection    *vpn      = NULL;
    NMActiveConnection *best_ac  = NULL;
    const char         *ip_iface = NULL;

    /* Note that we might have an IPv4 VPN tunneled over an IPv6-only device,
     * so we can get (vpn != NULL && best == NULL).
     */
    if (!get_best_ip_config(self, AF_INET, &ip_iface, &best_ac, &best, &vpn)) {
        if (nm_clear_g_object(&priv->default_ac4)) {
            _LOGt(LOGD_DNS, "set-default-ac-4: %p", NULL);
            _notify(self, PROP_DEFAULT_IP4_AC);
        }
        return;
    }
    g_assert((best || vpn) && best_ac);

    if (!force_update && best_ac && best_ac == priv->default_ac4)
        return;

    if (best) {
        const CList        *tmp_list;
        NMActiveConnection *ac;

        nm_manager_for_each_active_connection (priv->manager, ac, tmp_list) {
            if (NM_IS_VPN_CONNECTION(ac) && !nm_active_connection_get_device(ac))
                nm_active_connection_set_device(ac, best);
        }
    }

    update_default_ac(self, AF_INET, best_ac);

    if (!nm_g_object_ref_set(&priv->default_ac4, best_ac))
        return;
    _LOGt(LOGD_DNS, "set-default-ac-4: %p", priv->default_ac4);

    _LOGI(LOGD_CORE,
          "set '%s' (%s) as default for IPv4 routing and DNS",
          nm_connection_get_id(nm_active_connection_get_applied_connection(best_ac)),
          ip_iface);
    _notify(self, PROP_DEFAULT_IP4_AC);
}

static void
update_ip6_prefix_delegation(NMPolicy *self)
{
    NMPolicyPrivate    *priv = NM_POLICY_GET_PRIVATE(self);
    NMDevice           *device;
    NMActiveConnection *ac;
    const CList        *tmp_list;

    /* There's new default IPv6 connection, try to get a prefix for everyone. */
    nm_manager_for_each_active_connection (priv->manager, ac, tmp_list) {
        device = nm_active_connection_get_device(ac);
        if (device && nm_device_needs_ip6_subnet(device))
            ip6_subnet_from_device(self, get_default_device(self, AF_INET6), device);
    }
}

static void
update_ip6_routing(NMPolicy *self, gboolean force_update)
{
    NMPolicyPrivate    *priv     = NM_POLICY_GET_PRIVATE(self);
    NMDevice           *best     = NULL;
    NMVpnConnection    *vpn      = NULL;
    NMActiveConnection *best_ac  = NULL;
    const char         *ip_iface = NULL;

    /* Note that we might have an IPv6 VPN tunneled over an IPv4-only device,
     * so we can get (vpn != NULL && best == NULL).
     */
    if (!get_best_ip_config(self, AF_INET6, &ip_iface, &best_ac, &best, &vpn)) {
        if (nm_clear_g_object(&priv->default_ac6)) {
            _LOGt(LOGD_DNS, "set-default-ac-6: %p", NULL);
            _notify(self, PROP_DEFAULT_IP6_AC);
        }
        return;
    }
    g_assert((best || vpn) && best_ac);

    if (!force_update && best_ac && best_ac == priv->default_ac6)
        return;

    if (best) {
        const CList        *tmp_list;
        NMActiveConnection *ac;

        nm_manager_for_each_active_connection (priv->manager, ac, tmp_list) {
            if (NM_IS_VPN_CONNECTION(ac) && !nm_active_connection_get_device(ac))
                nm_active_connection_set_device(ac, best);
        }
    }

    update_default_ac(self, AF_INET6, best_ac);

    if (!nm_g_object_ref_set(&priv->default_ac6, best_ac))
        return;
    _LOGt(LOGD_DNS, "set-default-ac-6: %p", priv->default_ac6);

    update_ip6_prefix_delegation(self);

    _LOGI(LOGD_CORE,
          "set '%s' (%s) as default for IPv6 routing and DNS",
          nm_connection_get_id(nm_active_connection_get_applied_connection(best_ac)),
          ip_iface);
    _notify(self, PROP_DEFAULT_IP6_AC);
}

static void
update_ip_dns(NMPolicy *self, int addr_family, NMDevice *changed_device)
{
    NMPolicyPrivate      *priv = NM_POLICY_GET_PRIVATE(self);
    const NML3ConfigData *l3cd;
    const char           *ip_iface = NULL;
    NMVpnConnection      *vpn      = NULL;
    NMDevice             *device   = NULL;

    nm_assert_addr_family(addr_family);

    l3cd = get_best_ip_config(self, addr_family, &ip_iface, NULL, &device, &vpn);
    if (l3cd) {
        NMDnsIPConfigType ip_config_type;

        nm_assert(!device || NM_IS_DEVICE(device));
        nm_assert(!vpn || NM_IS_VPN_CONNECTION(vpn));
        nm_assert((!!device) != (!!vpn));

        /* Tell the DNS manager this config is preferred by re-adding it with
         * a different IP config type.
         */
        if (device && nm_device_managed_type_is_external(device))
            ip_config_type = NM_DNS_IP_CONFIG_TYPE_REMOVED;
        else if (vpn || (device && nm_device_is_vpn(device)))
            ip_config_type = NM_DNS_IP_CONFIG_TYPE_VPN;
        else
            ip_config_type = NM_DNS_IP_CONFIG_TYPE_BEST_DEVICE;

        nm_dns_manager_set_ip_config(NM_POLICY_GET_PRIVATE(self)->dns_manager,
                                     addr_family,
                                     ((gconstpointer) device) ?: ((gconstpointer) vpn),
                                     l3cd,
                                     ip_config_type,
                                     TRUE);
    }

    if (addr_family == AF_INET6) {
        NMActiveConnection *ac;
        const CList        *tmp_list;

        /* Tell devices needing a subnet about the new DNS configuration */
        nm_manager_for_each_active_connection (priv->manager, ac, tmp_list) {
            device = nm_active_connection_get_device(ac);
            if (device && device != changed_device && nm_device_needs_ip6_subnet(device))
                nm_device_copy_ip6_dns_config(device, get_default_device(self, AF_INET6));
        }
    }
}

static void
update_routing_and_dns(NMPolicy *self, gboolean force_update, NMDevice *changed_device)
{
    NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE(self);

    nm_dns_manager_begin_updates(priv->dns_manager, __func__);

    update_ip_dns(self, AF_INET, changed_device);
    update_ip_dns(self, AF_INET6, changed_device);

    update_ip4_routing(self, force_update);
    update_ip6_routing(self, force_update);

    /* Update the system hostname */
    update_system_hostname(self, "routing and dns", FALSE);

    nm_dns_manager_end_updates(priv->dns_manager, __func__);
}

static void
check_activating_active_connections(NMPolicy *self)
{
    NMPolicyPrivate    *priv = NM_POLICY_GET_PRIVATE(self);
    NMActiveConnection *best4, *best6 = NULL;

    best4 = get_best_active_connection(self, AF_INET, FALSE);
    best6 = get_best_active_connection(self, AF_INET6, FALSE);

    g_object_freeze_notify(G_OBJECT(self));

    if (nm_g_object_ref_set(&priv->activating_ac4, best4)) {
        _LOGt(LOGD_DNS, "set-activating-ac-4: %p", priv->activating_ac4);
        _notify(self, PROP_ACTIVATING_IP4_AC);
    }
    if (nm_g_object_ref_set(&priv->activating_ac6, best6)) {
        _LOGt(LOGD_DNS, "set-activating-ac-6: %p", priv->activating_ac6);
        _notify(self, PROP_ACTIVATING_IP6_AC);
    }

    g_object_thaw_notify(G_OBJECT(self));
}

static void
pending_ac_gone(gpointer data, GObject *where_the_object_was)
{
    NMPolicy        *self = NM_POLICY(data);
    NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE(self);

    /* Active connections should reach the DEACTIVATED state
     * before disappearing. */
    nm_assert_not_reached();

    if (g_hash_table_remove(priv->pending_active_connections, where_the_object_was))
        g_object_unref(self);
}

static void
pending_ac_state_changed(NMActiveConnection *ac, guint state, guint reason, NMPolicy *self)
{
    NMPolicyPrivate      *priv = NM_POLICY_GET_PRIVATE(self);
    NMSettingsConnection *con;

    if (state >= NM_ACTIVE_CONNECTION_STATE_DEACTIVATING) {
        /* The AC is being deactivated before the device had a chance
         * to move to PREPARE. Schedule a new auto-activation on the
         * device, but block the current connection to avoid an activation
         * loop.
         */
        if (reason != NM_ACTIVE_CONNECTION_STATE_REASON_DEVICE_DISCONNECTED
            && reason != NM_ACTIVE_CONNECTION_STATE_REASON_CONNECTION_REMOVED) {
            con = nm_active_connection_get_settings_connection(ac);
            nm_manager_devcon_autoconnect_blocked_reason_set(
                priv->manager,
                nm_active_connection_get_device(ac),
                con,
                NM_SETTINGS_AUTOCONNECT_BLOCKED_REASON_FAILED,
                TRUE);
            nm_policy_device_recheck_auto_activate_schedule(self,
                                                            nm_active_connection_get_device(ac));
        }

        /* Cleanup */
        g_signal_handlers_disconnect_by_func(ac, pending_ac_state_changed, self);
        if (!g_hash_table_remove(priv->pending_active_connections, ac))
            nm_assert_not_reached();
        g_object_weak_unref(G_OBJECT(ac), pending_ac_gone, self);
        g_object_unref(self);
    }
}

static void
_auto_activate_device(NMPolicy *self, NMDevice *device)
{
    NMPolicyPrivate               *priv;
    NMSettingsConnection          *best_connection;
    gs_free char                  *specific_object = NULL;
    gs_free NMSettingsConnection **connections     = NULL;
    guint                          i, len;
    gs_free_error GError          *error   = NULL;
    gs_unref_object NMAuthSubject *subject = NULL;
    NMActiveConnection            *ac;

    nm_assert(NM_IS_POLICY(self));
    nm_assert(NM_IS_DEVICE(device));

    priv = NM_POLICY_GET_PRIVATE(self);

    // FIXME: if a device is already activating (or activated) with a connection
    // but another connection now overrides the current one for that device,
    // deactivate the device and activate the new connection instead of just
    // bailing if the device is already active
    if (nm_device_get_act_request(device)) {
        if (nm_device_managed_type_is_external(device)
            && nm_device_get_allow_autoconnect_on_external(device)) {
            /* this is an external activation, and we allow autoconnecting on
             * top of that.
             *
             * pass. */
        } else
            return;
    }

    if (!nm_device_autoconnect_allowed(device))
        return;

    connections = nm_manager_get_activatable_connections(priv->manager, TRUE, TRUE, &len);
    if (!connections[0])
        return;

    /* Find the first connection that should be auto-activated */
    best_connection = NULL;
    for (i = 0; i < len; i++) {
        NMSettingsConnection *candidate = connections[i];
        NMConnection         *cand_conn;
        NMSettingConnection  *s_con;
        const char           *permission;

        if (nm_manager_devcon_autoconnect_is_blocked(priv->manager, device, candidate))
            continue;

        cand_conn = nm_settings_connection_get_connection(candidate);

        s_con = nm_connection_get_setting_connection(cand_conn);
        if (!nm_setting_connection_get_autoconnect(s_con))
            continue;

        permission = nm_utils_get_shared_wifi_permission(cand_conn);
        if (permission && !nm_settings_connection_check_permission(candidate, permission))
            continue;

        if (nm_device_can_auto_connect(device, candidate, &specific_object)) {
            best_connection = candidate;
            break;
        }
    }

    if (!best_connection)
        return;

    _LOGI(LOGD_DEVICE,
          "auto-activating connection '%s' (%s)",
          nm_settings_connection_get_id(best_connection),
          nm_settings_connection_get_uuid(best_connection));

    subject = nm_auth_subject_new_internal();
    ac      = nm_manager_activate_connection(
        priv->manager,
        best_connection,
        NULL,
        specific_object,
        device,
        subject,
        NM_ACTIVATION_TYPE_MANAGED,
        NM_ACTIVATION_REASON_AUTOCONNECT,
        NM_ACTIVATION_STATE_FLAG_LIFETIME_BOUND_TO_PROFILE_VISIBILITY,
        &error);
    if (!ac) {
        _LOGI(LOGD_DEVICE,
              "connection '%s' auto-activation failed: %s",
              nm_settings_connection_get_id(best_connection),
              error->message);
        nm_manager_devcon_autoconnect_blocked_reason_set(
            priv->manager,
            device,
            best_connection,
            NM_SETTINGS_AUTOCONNECT_BLOCKED_REASON_FAILED,
            TRUE);
        nm_policy_device_recheck_auto_activate_schedule(self, device);
        return;
    }

    /* Subscribe to AC state-changed signal to detect when the
     * activation fails in early stages without changing device
     * state.
     */
    if (g_hash_table_add(priv->pending_active_connections, ac)) {
        g_signal_connect(ac,
                         NM_ACTIVE_CONNECTION_STATE_CHANGED,
                         G_CALLBACK(pending_ac_state_changed),
                         g_object_ref(self));
        g_object_weak_ref(G_OBJECT(ac), (GWeakNotify) pending_ac_gone, self);
    }
}

static void
_auto_activate_device_clear(NMPolicy *self, NMDevice *device, gboolean do_activate)
{
    nm_assert(NM_IS_DEVICE(device));
    nm_assert(NM_IS_POLICY(self));
    nm_assert(c_list_is_linked(&device->policy_auto_activate_lst));
    nm_assert(c_list_contains(&NM_POLICY_GET_PRIVATE(self)->policy_auto_activate_lst_head,
                              &device->policy_auto_activate_lst));

    c_list_unlink(&device->policy_auto_activate_lst);
    nm_clear_g_source_inst(&device->policy_auto_activate_idle_source);

    if (do_activate)
        _auto_activate_device(self, device);

    nm_device_remove_pending_action(device, NM_PENDING_ACTION_AUTOACTIVATE, TRUE);
}

static gboolean
_auto_activate_idle_cb(gpointer user_data)
{
    NMDevice *device = user_data;

    nm_assert(NM_IS_DEVICE(device));

    _auto_activate_device_clear(nm_manager_get_policy(nm_device_get_manager(device)), device, TRUE);
    return G_SOURCE_CONTINUE;
}

/*****************************************************************************/

typedef struct {
    NMDevice *device;
    GSList   *secondaries;
} PendingSecondaryData;

static PendingSecondaryData *
pending_secondary_data_new(NMDevice *device, GSList *secondaries)
{
    PendingSecondaryData *data;

    data              = g_slice_new(PendingSecondaryData);
    data->device      = g_object_ref(device);
    data->secondaries = secondaries;
    return data;
}

static void
pending_secondary_data_free(PendingSecondaryData *data)
{
    g_object_unref(data->device);
    g_slist_free_full(data->secondaries, g_object_unref);
    g_slice_free(PendingSecondaryData, data);
}

static void
process_secondaries(NMPolicy *self, NMActiveConnection *active, gboolean connected)
{
    NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE(self);
    GSList          *iter, *iter2, *next, *next2;

    /* Loop through devices waiting for secondary connections to activate */
    for (iter = priv->pending_secondaries; iter; iter = next) {
        PendingSecondaryData *secondary_data = (PendingSecondaryData *) iter->data;
        NMDevice             *item_device    = secondary_data->device;

        next = g_slist_next(iter);

        /* Look for 'active' in each device's secondary connections list */
        for (iter2 = secondary_data->secondaries; iter2; iter2 = next2) {
            NMActiveConnection *secondary_active = NM_ACTIVE_CONNECTION(iter2->data);

            next2 = g_slist_next(iter2);

            if (active != secondary_active)
                continue;

            if (connected) {
                _LOGD(LOGD_DEVICE,
                      "secondary connection '%s' succeeded; active path '%s'",
                      nm_active_connection_get_settings_connection_id(active),
                      nm_dbus_object_get_path(NM_DBUS_OBJECT(active)));

                /* Secondary connection activated */
                secondary_data->secondaries =
                    g_slist_remove(secondary_data->secondaries, secondary_active);
                g_object_unref(secondary_active);
                if (!secondary_data->secondaries) {
                    /* No secondary UUID remained -> remove the secondary data item */
                    priv->pending_secondaries =
                        g_slist_remove(priv->pending_secondaries, secondary_data);
                    pending_secondary_data_free(secondary_data);
                    if (nm_device_get_state(item_device) == NM_DEVICE_STATE_SECONDARIES)
                        nm_device_state_changed(item_device,
                                                NM_DEVICE_STATE_ACTIVATED,
                                                NM_DEVICE_STATE_REASON_NONE);
                    break;
                }
            } else {
                _LOGD(LOGD_DEVICE,
                      "secondary connection '%s' failed; active path '%s'",
                      nm_active_connection_get_settings_connection_id(active),
                      nm_dbus_object_get_path(NM_DBUS_OBJECT(active)));

                /* Secondary connection failed -> do not watch other connections */
                priv->pending_secondaries =
                    g_slist_remove(priv->pending_secondaries, secondary_data);
                pending_secondary_data_free(secondary_data);
                if (nm_device_get_state(item_device) == NM_DEVICE_STATE_SECONDARIES
                    || nm_device_get_state(item_device) == NM_DEVICE_STATE_ACTIVATED)
                    nm_device_state_changed(item_device,
                                            NM_DEVICE_STATE_FAILED,
                                            NM_DEVICE_STATE_REASON_SECONDARY_CONNECTION_FAILED);
                break;
            }
        }
    }
}

static void
_static_hostname_changed_cb(NMHostnameManager *hostname_manager,
                            GParamSpec        *pspec,
                            gpointer           user_data)
{
    NMPolicyPrivate *priv = user_data;
    NMPolicy        *self = _PRIV_TO_SELF(priv);

    update_system_hostname(self, "hostname changed", FALSE);
}

void
nm_policy_unblock_failed_ovs_interfaces(NMPolicy *self)
{
    NMPolicyPrivate             *priv        = NM_POLICY_GET_PRIVATE(self);
    NMSettingsConnection *const *connections = NULL;
    guint                        i;

    _LOGT(LOGD_DEVICE, "unblocking failed OVS interfaces");

    connections = nm_settings_get_connections(priv->settings, NULL);
    for (i = 0; connections[i]; i++) {
        NMSettingsConnection *sett_conn  = connections[i];
        NMConnection         *connection = nm_settings_connection_get_connection(sett_conn);

        if (nm_connection_get_setting_ovs_interface(connection)) {
            nm_manager_devcon_autoconnect_retries_reset(priv->manager, NULL, sett_conn);
            nm_manager_devcon_autoconnect_blocked_reason_set(
                priv->manager,
                NULL,
                sett_conn,
                NM_SETTINGS_AUTOCONNECT_BLOCKED_REASON_FAILED,
                FALSE);
        }
    }
}

static gboolean
reset_autoconnect_all(
    NMPolicy *self,
    NMDevice *device, /* if present, only reset connections compatible with @device */
    gboolean  only_no_secrets)
{
    NMPolicyPrivate             *priv        = NM_POLICY_GET_PRIVATE(self);
    NMSettingsConnection *const *connections = NULL;
    guint                        i;
    gboolean                     changed = FALSE;

    _LOGD(LOGD_DEVICE,
          "re-enabling autoconnect for all connections%s%s%s",
          device ? " on " : "",
          device ? nm_device_get_iface(device) : "",
          only_no_secrets ? " (only clear no-secrets flag)" : "");

    connections = nm_settings_get_connections(priv->settings, NULL);
    for (i = 0; connections[i]; i++) {
        NMSettingsConnection *sett_conn = connections[i];

        if (device
            && !nm_device_check_connection_compatible(
                device,
                nm_settings_connection_get_connection(sett_conn),
                TRUE,
                NULL))
            continue;

        if (nm_manager_devcon_autoconnect_reset_reconnect_all(priv->manager,
                                                              device,
                                                              sett_conn,
                                                              only_no_secrets))
            changed = TRUE;
    }
    return changed;
}

static void
sleeping_changed(NMManager *manager, GParamSpec *pspec, gpointer user_data)
{
    NMPolicyPrivate *priv     = user_data;
    NMPolicy        *self     = _PRIV_TO_SELF(priv);
    gboolean         sleeping = FALSE, enabled = FALSE;

    g_object_get(G_OBJECT(manager), NM_MANAGER_SLEEPING, &sleeping, NULL);
    g_object_get(G_OBJECT(manager), NM_MANAGER_NETWORKING_ENABLED, &enabled, NULL);

    /* Reset retries on all connections so they'll checked on wakeup */
    if (sleeping || !enabled)
        reset_autoconnect_all(self, NULL, FALSE);
}

void
nm_policy_device_recheck_auto_activate_schedule(NMPolicy *self, NMDevice *device)
{
    NMPolicyPrivate    *priv;
    NMActiveConnection *ac;
    const CList        *tmp_list;

    g_return_if_fail(NM_IS_POLICY(self));
    g_return_if_fail(NM_IS_DEVICE(device));
    nm_assert(g_signal_handler_find(device,
                                    G_SIGNAL_MATCH_DATA,
                                    0,
                                    0,
                                    NULL,
                                    NULL,
                                    NM_POLICY_GET_PRIVATE(self))
              != 0);

    if (!c_list_is_empty(&device->policy_auto_activate_lst)) {
        /* already queued. Return. */
        return;
    }

    priv = NM_POLICY_GET_PRIVATE(self);

    if (nm_manager_get_state(priv->manager) == NM_STATE_ASLEEP)
        return;

    if (!nm_device_autoconnect_allowed(device))
        return;

    nm_manager_for_each_active_connection (priv->manager, ac, tmp_list) {
        if (nm_active_connection_get_device(ac) == device) {
            if (nm_device_managed_type_is_external(device)
                && nm_device_get_allow_autoconnect_on_external(device)) {
                /* pass */
            } else
                return;
        }
    }

    nm_device_add_pending_action(device, NM_PENDING_ACTION_AUTOACTIVATE, TRUE);

    c_list_link_tail(&priv->policy_auto_activate_lst_head, &device->policy_auto_activate_lst);
    device->policy_auto_activate_idle_source = nm_g_idle_add_source(_auto_activate_idle_cb, device);
}

static gboolean
reset_connections_retries(gpointer user_data)
{
    NMPolicy                    *self        = (NMPolicy *) user_data;
    NMPolicyPrivate             *priv        = NM_POLICY_GET_PRIVATE(self);
    NMSettingsConnection *const *connections = NULL;
    guint                        i;
    gint32                       con_stamp, min_stamp, now;
    gboolean                     changed = FALSE;

    nm_clear_g_source_inst(&priv->reset_connections_retries_idle_source);

    min_stamp   = 0;
    now         = nm_utils_get_monotonic_timestamp_sec();
    connections = nm_settings_get_connections(priv->settings, NULL);
    for (i = 0; connections[i]; i++) {
        NMSettingsConnection *connection = connections[i];

        con_stamp =
            nm_manager_devcon_autoconnect_retries_blocked_until(priv->manager, NULL, connection);
        if (con_stamp == 0)
            continue;

        if (con_stamp <= now) {
            nm_manager_devcon_autoconnect_retries_reset(priv->manager, NULL, connection);
            changed = TRUE;
        } else if (min_stamp == 0 || min_stamp > con_stamp)
            min_stamp = con_stamp;
    }

    /* Schedule the handler again if there are some stamps left */
    if (min_stamp != 0) {
        priv->reset_connections_retries_idle_source =
            nm_g_timeout_add_seconds_source(min_stamp - now, reset_connections_retries, self);
    }

    /* If anything changed, try to activate the newly re-enabled connections */
    if (changed)
        nm_policy_device_recheck_auto_activate_all_schedule(self);

    return G_SOURCE_CONTINUE;
}

static void
_connection_autoconnect_retries_set(NMPolicy             *self,
                                    NMDevice             *device,
                                    NMSettingsConnection *connection,
                                    guint32               tries)
{
    NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE(self);

    nm_assert(NM_IS_SETTINGS_CONNECTION(connection));

    nm_manager_devcon_autoconnect_retries_set(priv->manager, device, connection, tries);

    if (tries == 0) {
        /* Schedule a handler to reset retries count */
        if (!priv->reset_connections_retries_idle_source) {
            gint32 retry_time;

            retry_time = nm_manager_devcon_autoconnect_retries_blocked_until(priv->manager,
                                                                             device,
                                                                             connection);
            nm_assert(retry_time != 0);

            priv->reset_connections_retries_idle_source = nm_g_timeout_add_seconds_source(
                NM_MAX(0, retry_time - nm_utils_get_monotonic_timestamp_sec()),
                reset_connections_retries,
                self);
        }
    }
}

static void
unblock_autoconnect_for_children(NMPolicy   *self,
                                 const char *parent_device,
                                 const char *parent_uuid_settings,
                                 const char *parent_uuid_applied,
                                 const char *parent_mac_addr)
{
    NMPolicyPrivate             *priv = NM_POLICY_GET_PRIVATE(self);
    NMSettingsConnection *const *connections;
    gboolean                     changed;
    guint                        i;

    _LOGT(LOGD_CORE,
          "block-autoconnect: unblocking child profiles for parent ifname=%s%s%s, uuid=%s%s%s"
          "%s%s%s",
          NM_PRINT_FMT_QUOTE_STRING(parent_device),
          NM_PRINT_FMT_QUOTE_STRING(parent_uuid_settings),
          NM_PRINT_FMT_QUOTED(parent_uuid_applied,
                              ", applied-uuid=\"",
                              parent_uuid_applied,
                              "\"",
                              ""));

    changed     = FALSE;
    connections = nm_settings_get_connections(priv->settings, NULL);
    for (i = 0; connections[i]; i++) {
        NMSettingsConnection *sett_conn = connections[i];
        NMConnection         *connection;
        NMDeviceFactory      *factory;
        const char           *parent_name = NULL;

        connection = nm_settings_connection_get_connection(sett_conn);
        factory    = nm_device_factory_manager_find_factory_for_connection(connection);
        if (factory)
            parent_name = nm_device_factory_get_connection_parent(factory, connection);

        if (!parent_name)
            continue;

        if (!NM_IN_STRSET(parent_name,
                          parent_device,
                          parent_uuid_applied,
                          parent_uuid_settings,
                          parent_mac_addr))
            continue;

        if (nm_manager_devcon_autoconnect_retries_reset(priv->manager, NULL, sett_conn))
            changed = TRUE;

        /* unblock the devices associated with that connection */
        if (nm_manager_devcon_autoconnect_blocked_reason_set(
                priv->manager,
                NULL,
                sett_conn,
                NM_SETTINGS_AUTOCONNECT_BLOCKED_REASON_FAILED,
                FALSE)) {
            if (!nm_settings_connection_autoconnect_is_blocked(sett_conn))
                changed = TRUE;
        }
    }

    if (changed)
        nm_policy_device_recheck_auto_activate_all_schedule(self);
}

static void
unblock_autoconnect_for_ports(NMPolicy   *self,
                              const char *controller_device,
                              const char *controller_uuid_settings,
                              const char *controller_uuid_applied)
{
    NMPolicyPrivate             *priv = NM_POLICY_GET_PRIVATE(self);
    NMSettingsConnection *const *connections;
    gboolean                     changed = FALSE;
    guint                        i;

    _LOGT(LOGD_CORE,
          "block-autoconnect: unblocking port profiles for controller ifname=%s%s%s, uuid=%s%s%s"
          "%s%s%s",
          NM_PRINT_FMT_QUOTE_STRING(controller_device),
          NM_PRINT_FMT_QUOTE_STRING(controller_uuid_settings),
          NM_PRINT_FMT_QUOTED(controller_uuid_applied,
                              ", applied-uuid=\"",
                              controller_uuid_applied,
                              "\"",
                              ""));

    connections = nm_settings_get_connections(priv->settings, NULL);
    for (i = 0; connections[i]; i++) {
        NMSettingsConnection *sett_conn = connections[i];
        NMSettingConnection  *s_port_con;
        const char           *port_controller;

        s_port_con = nm_settings_connection_get_setting(sett_conn, NM_META_SETTING_TYPE_CONNECTION);
        port_controller = nm_setting_connection_get_controller(s_port_con);
        if (!port_controller)
            continue;

        if (!NM_IN_STRSET(port_controller,
                          controller_device,
                          controller_uuid_applied,
                          controller_uuid_settings))
            continue;

        if (nm_manager_devcon_autoconnect_retries_reset(priv->manager, NULL, sett_conn))
            changed = TRUE;

        /* unblock the devices associated with that connection */
        if (nm_manager_devcon_autoconnect_blocked_reason_set(
                priv->manager,
                NULL,
                sett_conn,
                NM_SETTINGS_AUTOCONNECT_BLOCKED_REASON_FAILED,
                FALSE)) {
            if (!nm_settings_connection_autoconnect_is_blocked(sett_conn))
                changed = TRUE;
        }
    }

    if (changed)
        nm_policy_device_recheck_auto_activate_all_schedule(self);
}

static void
unblock_autoconnect_for_ports_for_sett_conn(NMPolicy *self, NMSettingsConnection *sett_conn)
{
    const char          *controller_device;
    const char          *controller_uuid_settings;
    NMSettingConnection *s_con;

    nm_assert(NM_IS_POLICY(self));
    nm_assert(NM_IS_SETTINGS_CONNECTION(sett_conn));

    s_con = nm_settings_connection_get_setting(sett_conn, NM_META_SETTING_TYPE_CONNECTION);

    nm_assert(NM_IS_SETTING_CONNECTION(s_con));

    controller_uuid_settings = nm_setting_connection_get_uuid(s_con);
    controller_device        = nm_setting_connection_get_interface_name(s_con);

    unblock_autoconnect_for_ports(self, controller_device, controller_uuid_settings, NULL);
}

static void
activate_port_or_children_connections(NMPolicy *self,
                                      NMDevice *device,
                                      gboolean  activate_children_connections_only)
{
    const char   *controller_device;
    const char   *controller_uuid_settings = NULL;
    const char   *controller_uuid_applied  = NULL;
    const char   *parent_mac_addr          = NULL;
    NMActRequest *req;

    controller_device = nm_device_get_iface(device);
    nm_assert(controller_device);

    parent_mac_addr = nm_device_get_permanent_hw_address(device);

    req = nm_device_get_act_request(device);
    if (req) {
        NMConnection         *connection;
        NMSettingsConnection *sett_conn;

        sett_conn = nm_active_connection_get_settings_connection(NM_ACTIVE_CONNECTION(req));
        if (sett_conn)
            controller_uuid_settings = nm_settings_connection_get_uuid(sett_conn);

        connection = nm_active_connection_get_applied_connection(NM_ACTIVE_CONNECTION(req));
        if (connection)
            controller_uuid_applied = nm_connection_get_uuid(connection);

        if (nm_streq0(controller_uuid_settings, controller_uuid_applied))
            controller_uuid_applied = NULL;
    }

    if (!activate_children_connections_only) {
        unblock_autoconnect_for_ports(self,
                                      controller_device,
                                      controller_uuid_settings,
                                      controller_uuid_applied);
    }
    unblock_autoconnect_for_children(self,
                                     controller_device,
                                     controller_uuid_settings,
                                     controller_uuid_applied,
                                     parent_mac_addr);
}

static gboolean
activate_secondary_connections(NMPolicy *self, NMConnection *connection, NMDevice *device)
{
    NMPolicyPrivate       *priv = NM_POLICY_GET_PRIVATE(self);
    NMSettingConnection   *s_con;
    NMActiveConnection    *ac;
    PendingSecondaryData  *secondary_data;
    GSList                *secondary_ac_list = NULL;
    GError                *error             = NULL;
    guint32                i;
    gboolean               success = TRUE;
    NMActivationStateFlags initial_state_flags;

    s_con = nm_connection_get_setting_connection(connection);
    nm_assert(NM_IS_SETTING_CONNECTION(s_con));

    /* we propagate the activation's state flags. */
    initial_state_flags = nm_device_get_activation_state_flags(device)
                          & NM_ACTIVATION_STATE_FLAG_LIFETIME_BOUND_TO_PROFILE_VISIBILITY;

    for (i = 0; i < nm_setting_connection_get_num_secondaries(s_con); i++) {
        NMSettingsConnection *sett_conn;
        const char           *sec_uuid = nm_setting_connection_get_secondary(s_con, i);
        NMActRequest         *req;

        sett_conn = nm_settings_get_connection_by_uuid(priv->settings, sec_uuid);
        if (!sett_conn) {
            _LOGW(LOGD_DEVICE,
                  "secondary connection '%s' auto-activation failed: The connection doesn't exist.",
                  sec_uuid);
            success = FALSE;
            break;
        }

        if (!nm_connection_is_type(nm_settings_connection_get_connection(sett_conn),
                                   NM_SETTING_VPN_SETTING_NAME)) {
            _LOGW(LOGD_DEVICE,
                  "secondary connection '%s (%s)' auto-activation failed: The connection is not a "
                  "VPN.",
                  nm_settings_connection_get_id(sett_conn),
                  sec_uuid);
            success = FALSE;
            break;
        }

        req = nm_device_get_act_request(device);

        _LOGD(LOGD_DEVICE,
              "activating secondary connection '%s (%s)' for base connection '%s (%s)'",
              nm_settings_connection_get_id(sett_conn),
              sec_uuid,
              nm_connection_get_id(connection),
              nm_connection_get_uuid(connection));
        ac = nm_manager_activate_connection(
            priv->manager,
            sett_conn,
            NULL,
            nm_dbus_object_get_path(NM_DBUS_OBJECT(req)),
            device,
            nm_active_connection_get_subject(NM_ACTIVE_CONNECTION(req)),
            NM_ACTIVATION_TYPE_MANAGED,
            nm_active_connection_get_activation_reason(NM_ACTIVE_CONNECTION(req)),
            initial_state_flags,
            &error);
        if (ac)
            secondary_ac_list = g_slist_append(secondary_ac_list, g_object_ref(ac));
        else {
            _LOGW(LOGD_DEVICE,
                  "secondary connection '%s (%s)' auto-activation failed: (%d) %s",
                  nm_settings_connection_get_id(sett_conn),
                  sec_uuid,
                  error->code,
                  error->message);
            g_clear_error(&error);
            success = FALSE;
            break;
        }
    }

    if (success && secondary_ac_list != NULL) {
        secondary_data            = pending_secondary_data_new(device, secondary_ac_list);
        priv->pending_secondaries = g_slist_append(priv->pending_secondaries, secondary_data);
    } else
        g_slist_free_full(secondary_ac_list, g_object_unref);

    return success;
}

static void
device_state_changed(NMDevice           *device,
                     NMDeviceState       new_state,
                     NMDeviceState       old_state,
                     NMDeviceStateReason reason,
                     gpointer            user_data)
{
    NMPolicyPrivate      *priv = user_data;
    NMPolicy             *self = _PRIV_TO_SELF(priv);
    NMActiveConnection   *ac;
    NMSettingsConnection *sett_conn = nm_device_get_settings_connection(device);
    NMSettingConnection  *s_con     = NULL;

    switch (nm_device_state_reason_check(reason)) {
    case NM_DEVICE_STATE_REASON_GSM_SIM_PIN_REQUIRED:
    case NM_DEVICE_STATE_REASON_GSM_SIM_PUK_REQUIRED:
    case NM_DEVICE_STATE_REASON_SIM_PIN_INCORRECT:
    case NM_DEVICE_STATE_REASON_GSM_APN_FAILED:
        /* Block autoconnection at settings level if there is any settings-specific
         * error reported by the modem (e.g. wrong SIM-PIN or wrong APN). Do not block
         * autoconnection at settings level for errors in the device domain (e.g.
         * a missing SIM or wrong modem initialization).
         */
        if (sett_conn) {
            nm_manager_devcon_autoconnect_blocked_reason_set(
                priv->manager,
                device,
                sett_conn,
                NM_SETTINGS_AUTOCONNECT_BLOCKED_REASON_FAILED,
                TRUE);
        }
        break;
    default:
        break;
    }

    switch (new_state) {
    case NM_DEVICE_STATE_FAILED:
        g_signal_handlers_disconnect_by_func(device, device_dns_lookup_done, self);

        /* Mark the connection invalid if it failed during activation so that
         * it doesn't get automatically chosen over and over and over again.
         */
        if (sett_conn && old_state >= NM_DEVICE_STATE_PREPARE
            && old_state <= NM_DEVICE_STATE_ACTIVATED) {
            gboolean blocked = FALSE;
            guint64  con_v;

            switch (nm_device_state_reason_check(reason)) {
            case NM_DEVICE_STATE_REASON_NO_SECRETS:
                /* we want to block the connection from auto-connect if it failed due to no-secrets.
                 * However, if a secret-agent registered, since the connection made the last
                 * secret-request, we do not block it. The new secret-agent might not yet
                 * been consulted, and it may be able to provide the secrets.
                 *
                 * We detect this by using a version-id of the agent-manager, which increments
                 * whenever new agents register. Note that the agent-manager's version-id is
                 * never zero and strictly increasing.
                 *
                 * A connection's version-id of zero means that the connection never tried to request secrets.
                 * That can happen when nm_settings_connection_get_secrets() fails early without actually
                 * consulting any agents.
                 */
                con_v = nm_settings_connection_get_last_secret_agent_version_id(sett_conn);
                if (con_v == 0 || con_v == nm_agent_manager_get_agent_version_id(priv->agent_mgr)) {
                    _LOGD(LOGD_DEVICE,
                          "block-autoconnect: connection[" NM_HASH_OBFUSCATE_PTR_FMT
                          "] (%s) now blocked from "
                          "autoconnect due to no secrets",
                          NM_HASH_OBFUSCATE_PTR(sett_conn),
                          nm_settings_connection_get_id(sett_conn));
                    nm_settings_connection_autoconnect_blocked_reason_set(
                        sett_conn,
                        NM_SETTINGS_AUTOCONNECT_BLOCKED_REASON_NO_SECRETS,
                        TRUE);
                    blocked = TRUE;
                }
                break;
            case NM_DEVICE_STATE_REASON_DEPENDENCY_FAILED:
                /* A connection that fails due to dependency-failed is not able to
                 * reconnect until the connection it depends on activates again;
                 * when this happens, the controller or parent clears the blocked
                 * reason for all its dependent devices in activate_port_or_children_connections()
                 * and tries to reconnect them. For this to work, the port should
                 * be marked as blocked when it fails with dependency-failed.
                 */
                _LOGD(LOGD_DEVICE,
                      "block-autoconnect: connection[" NM_HASH_OBFUSCATE_PTR_FMT
                      "] (%s) now blocked "
                      "from autoconnect due to failed dependency",
                      NM_HASH_OBFUSCATE_PTR(sett_conn),
                      nm_settings_connection_get_id(sett_conn));
                nm_manager_devcon_autoconnect_blocked_reason_set(
                    priv->manager,
                    device,
                    sett_conn,
                    NM_SETTINGS_AUTOCONNECT_BLOCKED_REASON_FAILED,
                    TRUE);
                blocked = TRUE;
                break;
            default:
                break;
            }

            if (!blocked) {
                guint32 tries;

                tries = nm_manager_devcon_autoconnect_retries_get(priv->manager, device, sett_conn);
                if (tries == 0) {
                    /* blocked */
                } else if (tries != NM_AUTOCONNECT_RETRIES_FOREVER) {
                    _LOGD(LOGD_DEVICE,
                          "autoconnect: connection[" NM_HASH_OBFUSCATE_PTR_FMT "] (%s): failed to "
                          "autoconnect; %u tries left",
                          NM_HASH_OBFUSCATE_PTR(sett_conn),
                          nm_settings_connection_get_id(sett_conn),
                          tries - 1u);
                    _connection_autoconnect_retries_set(self, device, sett_conn, tries - 1u);
                } else {
                    _LOGD(LOGD_DEVICE,
                          "autoconnect: connection[" NM_HASH_OBFUSCATE_PTR_FMT "] (%s) failed to "
                          "autoconnect; infinite tries left",
                          NM_HASH_OBFUSCATE_PTR(sett_conn),
                          nm_settings_connection_get_id(sett_conn));
                }
            }
        }
        break;
    case NM_DEVICE_STATE_ACTIVATED:
        if (nm_device_get_device_type(device) == NM_DEVICE_TYPE_OVS_INTERFACE) {
            /* When parent is ovs-interface, the kernel link is only created in stage3, we have to
            * delay unblocking the children and schedule them for activation until parent is activated */
            activate_port_or_children_connections(self, device, TRUE);
        }
        if (sett_conn) {
            /* Reset auto retries back to default since connection was successful */
            nm_manager_devcon_autoconnect_retries_reset(priv->manager, device, sett_conn);
        }

        /* Since there is no guarantee that device_l3cd_changed() is called
         * again when the device becomes ACTIVATED, we need also to update
         * routing and DNS here. */
        nm_dns_manager_begin_updates(priv->dns_manager, __func__);
        if (!nm_device_managed_type_is_external(device)) {
            nm_dns_manager_set_ip_config(priv->dns_manager,
                                         AF_UNSPEC,
                                         device,
                                         nm_device_get_l3cd(device, TRUE),
                                         nm_device_is_vpn(device) ? NM_DNS_IP_CONFIG_TYPE_VPN
                                                                  : NM_DNS_IP_CONFIG_TYPE_DEFAULT,
                                         TRUE);
        }
        update_ip_dns(self, AF_INET, device);
        update_ip_dns(self, AF_INET6, device);
        update_ip4_routing(self, TRUE);
        update_ip6_routing(self, TRUE);
        update_system_hostname(self, "routing and dns", TRUE);
        nm_dns_manager_end_updates(priv->dns_manager, __func__);

        break;
    case NM_DEVICE_STATE_UNMANAGED:
    case NM_DEVICE_STATE_UNAVAILABLE:
        if (old_state > NM_DEVICE_STATE_DISCONNECTED)
            update_routing_and_dns(self, FALSE, device);
        break;
    case NM_DEVICE_STATE_DEACTIVATING:
        if (sett_conn) {
            NMSettingsAutoconnectBlockedReason blocked_reason =
                NM_SETTINGS_AUTOCONNECT_BLOCKED_REASON_NONE;

            switch (nm_device_state_reason_check(reason)) {
            case NM_DEVICE_STATE_REASON_USER_REQUESTED:
                blocked_reason = NM_SETTINGS_AUTOCONNECT_BLOCKED_REASON_USER_REQUEST;
                break;
            case NM_DEVICE_STATE_REASON_DEPENDENCY_FAILED:
                blocked_reason = NM_SETTINGS_AUTOCONNECT_BLOCKED_REASON_FAILED;
                break;
            default:
                break;
            }
            if (blocked_reason != NM_SETTINGS_AUTOCONNECT_BLOCKED_REASON_NONE) {
                _LOGD(LOGD_DEVICE,
                      "block-autoconnect: blocking autoconnect of connection '%s': %s",
                      nm_settings_connection_get_id(sett_conn),
                      NM_UTILS_LOOKUP_STR_A(nm_device_state_reason_to_string,
                                            nm_device_state_reason_check(reason)));
                if (blocked_reason == NM_SETTINGS_AUTOCONNECT_BLOCKED_REASON_FAILED)
                    nm_manager_devcon_autoconnect_blocked_reason_set(priv->manager,
                                                                     device,
                                                                     sett_conn,
                                                                     blocked_reason,
                                                                     TRUE);
                else
                    nm_settings_connection_autoconnect_blocked_reason_set(sett_conn,
                                                                          blocked_reason,
                                                                          TRUE);
            }
        }
        ip6_remove_device_prefix_delegations(self, device);
        break;
    case NM_DEVICE_STATE_DISCONNECTED:
        g_signal_handlers_disconnect_by_func(device, device_dns_lookup_done, self);

        /* Reset retry counts for a device's connections when carrier on; if cable
         * was unplugged and plugged in again, we should try to reconnect.
         */
        if (nm_device_state_reason_check(reason) == NM_DEVICE_STATE_REASON_CARRIER
            && old_state == NM_DEVICE_STATE_UNAVAILABLE)
            reset_autoconnect_all(self, device, FALSE);

        if (old_state > NM_DEVICE_STATE_DISCONNECTED)
            update_routing_and_dns(self, FALSE, device);

        /* Device is now available for auto-activation */
        nm_policy_device_recheck_auto_activate_schedule(self, device);
        break;

    case NM_DEVICE_STATE_PREPARE:
        /* Reset auto-connect retries of all ports or children and schedule them for
         * activation. */
        activate_port_or_children_connections(self, device, FALSE);

        /* Now that the device state is progressing, we don't care
         * anymore for the AC state. */
        ac = (NMActiveConnection *) nm_device_get_act_request(device);
        if (ac && g_hash_table_remove(priv->pending_active_connections, ac)) {
            g_signal_handlers_disconnect_by_func(ac, pending_ac_state_changed, self);
            g_object_weak_unref(G_OBJECT(ac), pending_ac_gone, self);
            g_object_unref(self);
        }
        break;
    case NM_DEVICE_STATE_IP_CONFIG:
        /* We must have secrets if we got here. */
        if (sett_conn)
            nm_manager_devcon_autoconnect_blocked_reason_set(
                priv->manager,
                device,
                sett_conn,
                NM_SETTINGS_AUTOCONNECT_BLOCKED_REASON_FAILED,
                FALSE);
        break;
    case NM_DEVICE_STATE_SECONDARIES:
        if (sett_conn)
            s_con = nm_connection_get_setting_connection(
                nm_settings_connection_get_connection(sett_conn));
        if (s_con && nm_setting_connection_get_num_secondaries(s_con) > 0) {
            /* Make routes and DNS up-to-date before activating dependent connections */
            update_routing_and_dns(self, FALSE, device);

            /* Activate secondary (VPN) connections */
            if (!activate_secondary_connections(self,
                                                nm_settings_connection_get_connection(sett_conn),
                                                device)) {
                nm_device_queue_state(device,
                                      NM_DEVICE_STATE_FAILED,
                                      NM_DEVICE_STATE_REASON_SECONDARY_CONNECTION_FAILED);
            }
        } else
            nm_device_queue_state(device, NM_DEVICE_STATE_ACTIVATED, NM_DEVICE_STATE_REASON_NONE);
        break;

    default:
        break;
    }

    check_activating_active_connections(self);
}

static void
device_l3cd_changed(NMDevice             *device,
                    const NML3ConfigData *l3cd_old,
                    const NML3ConfigData *l3cd_new,
                    gpointer              user_data)
{
    NMPolicyPrivate *priv = user_data;
    NMPolicy        *self = _PRIV_TO_SELF(priv);
    NMDeviceState    state;

    nm_assert(!l3cd_new || NM_IS_L3_CONFIG_DATA(l3cd_new));
    nm_assert(!l3cd_old || NM_IS_L3_CONFIG_DATA(l3cd_old));

    nm_dns_manager_begin_updates(priv->dns_manager, __func__);

    /* FIXME(l3cfg): Note that this function is not always called when the
     * device becomes ACTIVATED. Previously, we would also update the DNS
     * manager's IP config in device_state_change(ACTIVATED). There we would
     * also special-case pseudo-VPNs like wireguard. I don't see the code where
     * this is handled now.
     */
    state = nm_device_get_state(device);
    if (l3cd_new && state >= NM_DEVICE_STATE_IP_CONFIG && state < NM_DEVICE_STATE_DEACTIVATING) {
        /* Since the device L3CD_CHANGED signal is emitted *after* the commit of
         * configuration, addresses and routes are already set in kernel when we
         * write the configuration to resolv.conf or send it to the DNS plugin.
         * This prevents "leaks" of DNS queries via the wrong routes.*/
        nm_dns_manager_set_ip_config(priv->dns_manager,
                                     AF_UNSPEC,
                                     device,
                                     l3cd_new,
                                     nm_device_is_vpn(device) ? NM_DNS_IP_CONFIG_TYPE_VPN
                                                              : NM_DNS_IP_CONFIG_TYPE_DEFAULT,
                                     TRUE);
        update_ip_dns(self, AF_INET, device);
        update_ip_dns(self, AF_INET6, device);
        update_ip4_routing(self, TRUE);
        update_ip6_routing(self, TRUE);
        /* FIXME: since we already monitor platform addresses changes,
         * this is probably no longer necessary? */
        update_system_hostname(self, "ip conf", FALSE);
    } else {
        nm_dns_manager_set_ip_config(priv->dns_manager,
                                     AF_UNSPEC,
                                     device,
                                     l3cd_old,
                                     NM_DNS_IP_CONFIG_TYPE_REMOVED,
                                     TRUE);
    }

    nm_dns_manager_end_updates(priv->dns_manager, __func__);
}

static void
device_platform_address_changed(NMDevice *device, gpointer user_data)
{
    NMPolicyPrivate *priv = user_data;
    NMPolicy        *self = _PRIV_TO_SELF(priv);
    NMDeviceState    state;

    state = nm_device_get_state(device);
    if (state > NM_DEVICE_STATE_DISCONNECTED && state < NM_DEVICE_STATE_DEACTIVATING) {
        update_system_hostname(self, "address changed", TRUE);
    }
}

/*****************************************************************************/

static void
device_autoconnect_changed(NMDevice *device, GParamSpec *pspec, gpointer user_data)
{
    NMPolicyPrivate *priv = user_data;
    NMPolicy        *self = _PRIV_TO_SELF(priv);

    nm_policy_device_recheck_auto_activate_schedule(self, device);
}

static void
devices_list_unregister(NMPolicy *self, NMDevice *device)
{
    NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE(self);

    g_signal_handlers_disconnect_by_data((GObject *) device, priv);
}

static void
devices_list_register(NMPolicy *self, NMDevice *device)
{
    NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE(self);

    /* Connect state-changed with _after, so that the handler is invoked after other handlers. */
    g_signal_connect_after(device, NM_DEVICE_STATE_CHANGED, G_CALLBACK(device_state_changed), priv);
    g_signal_connect(device, NM_DEVICE_L3CD_CHANGED, G_CALLBACK(device_l3cd_changed), priv);
    g_signal_connect(device,
                     NM_DEVICE_PLATFORM_ADDRESS_CHANGED,
                     G_CALLBACK(device_platform_address_changed),
                     priv);
    g_signal_connect(device,
                     NM_DEVICE_IP6_PREFIX_DELEGATED,
                     G_CALLBACK(device_ip6_prefix_delegated),
                     priv);
    g_signal_connect(device,
                     NM_DEVICE_IP6_SUBNET_NEEDED,
                     G_CALLBACK(device_ip6_subnet_needed),
                     priv);
    g_signal_connect(device,
                     "notify::" NM_DEVICE_AUTOCONNECT,
                     G_CALLBACK(device_autoconnect_changed),
                     priv);
}

static void
device_added(NMManager *manager, NMDevice *device, gpointer user_data)
{
    NMPolicyPrivate *priv = user_data;
    NMPolicy        *self = _PRIV_TO_SELF(priv);

    g_return_if_fail(NM_IS_POLICY(self));

    priv = NM_POLICY_GET_PRIVATE(self);

    if (!g_hash_table_add(priv->devices, device))
        g_return_if_reached();

    devices_list_register(self, device);
}

static void
device_removed(NMManager *manager, NMDevice *device, gpointer user_data)
{
    NMPolicyPrivate *priv = user_data;
    NMPolicy        *self = _PRIV_TO_SELF(priv);

    /* TODO: is this needed? The delegations are cleaned up
     * on transition to deactivated too. */
    ip6_remove_device_prefix_delegations(self, device);

    if (c_list_is_linked(&device->policy_auto_activate_lst))
        _auto_activate_device_clear(self, device, FALSE);

    if (g_hash_table_remove(priv->devices, device))
        devices_list_unregister(self, device);

    /* Don't update routing and DNS here as we've already handled that
     * for devices that need it when the device's state changed to UNMANAGED.
     */
}

/*****************************************************************************/

static void
vpn_connection_update_dns(NMPolicy *self, NMVpnConnection *vpn, gboolean remove)
{
    NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE(self);
    int              IS_IPv4;

    nm_dns_manager_begin_updates(priv->dns_manager, __func__);

    for (IS_IPv4 = 1; IS_IPv4 >= 0; IS_IPv4--) {
        int                   addr_family = IS_IPv4 ? AF_INET : AF_INET6;
        const NML3ConfigData *l3cd;

        l3cd = nm_vpn_connection_get_l3cd(vpn);
        nm_dns_manager_set_ip_config(priv->dns_manager,
                                     addr_family,
                                     vpn,
                                     l3cd,
                                     remove ? NM_DNS_IP_CONFIG_TYPE_REMOVED
                                            : NM_DNS_IP_CONFIG_TYPE_VPN,
                                     TRUE);
    }

    update_routing_and_dns(self, TRUE, NULL);

    nm_dns_manager_end_updates(priv->dns_manager, __func__);
}

static void
vpn_connection_state_changed(NMVpnConnection              *vpn,
                             NMVpnConnectionState          new_state,
                             NMVpnConnectionState          old_state,
                             NMActiveConnectionStateReason reason,
                             NMPolicy                     *self)
{
    /* FIXME(l3cfg): we need to track changes to nm_vpn_connection_get_l3cd(). */
    if (new_state == NM_VPN_CONNECTION_STATE_ACTIVATED)
        vpn_connection_update_dns(self, vpn, FALSE);
    else if (new_state >= NM_VPN_CONNECTION_STATE_FAILED) {
        /* Only clean up IP/DNS if the connection ever got past IP_CONFIG */
        if (old_state >= NM_VPN_CONNECTION_STATE_IP_CONFIG_GET
            && old_state <= NM_VPN_CONNECTION_STATE_ACTIVATED)
            vpn_connection_update_dns(self, vpn, TRUE);
    }
}

static void
vpn_connection_retry_after_failure(NMVpnConnection *vpn, NMPolicy *self)
{
    NMPolicyPrivate      *priv       = NM_POLICY_GET_PRIVATE(self);
    NMActiveConnection   *ac         = NM_ACTIVE_CONNECTION(vpn);
    NMSettingsConnection *connection = nm_active_connection_get_settings_connection(ac);
    GError               *error      = NULL;

    /* Attempt to reconnect VPN connections that failed after being connected */
    if (!nm_manager_activate_connection(
            priv->manager,
            connection,
            NULL,
            NULL,
            NULL,
            nm_active_connection_get_subject(ac),
            NM_ACTIVATION_TYPE_MANAGED,
            nm_active_connection_get_activation_reason(ac),
            (nm_active_connection_get_state_flags(ac)
             & NM_ACTIVATION_STATE_FLAG_LIFETIME_BOUND_TO_PROFILE_VISIBILITY),
            &error)) {
        _LOGW(LOGD_DEVICE,
              "VPN '%s' reconnect failed: %s",
              nm_settings_connection_get_id(connection),
              error->message ?: "unknown");
        g_clear_error(&error);
    }
}

static void
active_connection_state_changed(NMActiveConnection *active, GParamSpec *pspec, NMPolicy *self)
{
    NMActiveConnectionState state = nm_active_connection_get_state(active);

    if (state == NM_ACTIVE_CONNECTION_STATE_ACTIVATED)
        process_secondaries(self, active, TRUE);
    else if (state == NM_ACTIVE_CONNECTION_STATE_DEACTIVATED)
        process_secondaries(self, active, FALSE);
}

static void
active_connection_keep_alive_changed(NMKeepAlive *keep_alive, GParamSpec *pspec, NMPolicy *self)
{
    NMPolicyPrivate    *priv;
    NMActiveConnection *ac;
    GError             *error = NULL;

    nm_assert(NM_IS_POLICY(self));
    nm_assert(NM_IS_KEEP_ALIVE(keep_alive));
    nm_assert(NM_IS_ACTIVE_CONNECTION(nm_keep_alive_get_owner(keep_alive)));

    if (nm_keep_alive_is_alive(keep_alive))
        return;

    ac = nm_keep_alive_get_owner(keep_alive);

    if (nm_active_connection_get_state(ac) > NM_ACTIVE_CONNECTION_STATE_ACTIVATED)
        return;

    priv = NM_POLICY_GET_PRIVATE(self);

    if (!nm_manager_deactivate_connection(priv->manager,
                                          ac,
                                          NM_DEVICE_STATE_REASON_CONNECTION_REMOVED,
                                          &error)) {
        _LOGW(LOGD_DEVICE,
              "connection '%s' is no longer kept alive, but error deactivating it: %s",
              nm_active_connection_get_settings_connection_id(ac),
              error->message);
        g_clear_error(&error);
    }
}

static void
active_connection_added(NMManager *manager, NMActiveConnection *active, gpointer user_data)
{
    NMPolicyPrivate *priv = user_data;
    NMPolicy        *self = _PRIV_TO_SELF(priv);
    NMKeepAlive     *keep_alive;

    if (NM_IS_VPN_CONNECTION(active)) {
        g_signal_connect(active,
                         NM_VPN_CONNECTION_INTERNAL_STATE_CHANGED,
                         G_CALLBACK(vpn_connection_state_changed),
                         self);
        g_signal_connect(active,
                         NM_VPN_CONNECTION_INTERNAL_RETRY_AFTER_FAILURE,
                         G_CALLBACK(vpn_connection_retry_after_failure),
                         self);
    }

    keep_alive = nm_active_connection_get_keep_alive(active);

    nm_keep_alive_arm(keep_alive);

    g_signal_connect(active,
                     "notify::" NM_ACTIVE_CONNECTION_STATE,
                     G_CALLBACK(active_connection_state_changed),
                     self);
    g_signal_connect(keep_alive,
                     "notify::" NM_KEEP_ALIVE_ALIVE,
                     G_CALLBACK(active_connection_keep_alive_changed),
                     self);
    active_connection_keep_alive_changed(keep_alive, NULL, self);
}

static void
active_connection_removed(NMManager *manager, NMActiveConnection *active, gpointer user_data)
{
    NMPolicyPrivate *priv = user_data;
    NMPolicy        *self = _PRIV_TO_SELF(priv);

    g_signal_handlers_disconnect_by_func(active, vpn_connection_state_changed, self);
    g_signal_handlers_disconnect_by_func(active, vpn_connection_retry_after_failure, self);
    g_signal_handlers_disconnect_by_func(active, active_connection_state_changed, self);
    g_signal_handlers_disconnect_by_func(nm_active_connection_get_keep_alive(active),
                                         active_connection_keep_alive_changed,
                                         self);
}

/*****************************************************************************/

static gboolean
_device_recheck_auto_activate_all_cb(gpointer user_data)
{
    NMPolicy        *self = user_data;
    NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE(self);
    const CList     *tmp_lst;
    NMDevice        *device;

    nm_clear_g_source_inst(&priv->device_recheck_auto_activate_all_idle_source);

    nm_manager_for_each_device (priv->manager, device, tmp_lst)
        nm_policy_device_recheck_auto_activate_schedule(self, device);

    return G_SOURCE_CONTINUE;
}

static void
nm_policy_device_recheck_auto_activate_all_schedule(NMPolicy *self)
{
    NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE(self);

    /* always restart the idle handler. That way, we settle
     * all other events before restarting to activate them. */
    nm_clear_g_source_inst(&priv->device_recheck_auto_activate_all_idle_source);

    priv->device_recheck_auto_activate_all_idle_source =
        nm_g_idle_add_source(_device_recheck_auto_activate_all_cb, self);
}

/*****************************************************************************/

static void
connection_added(NMSettings *settings, NMSettingsConnection *connection, gpointer user_data)
{
    NMPolicyPrivate *priv = user_data;
    NMPolicy        *self = _PRIV_TO_SELF(priv);

    unblock_autoconnect_for_ports_for_sett_conn(self, connection);

    nm_policy_device_recheck_auto_activate_all_schedule(self);
}

static void
firewall_state_changed(NMFirewalldManager *manager, int signal_type_i, gpointer user_data)
{
    const NMFirewalldManagerStateChangedType signal_type = signal_type_i;
    NMPolicy                                *self        = user_data;
    NMPolicyPrivate                         *priv        = NM_POLICY_GET_PRIVATE(self);
    const CList                             *tmp_lst;
    NMDevice                                *device;

    if (signal_type == NM_FIREWALLD_MANAGER_STATE_CHANGED_TYPE_INITIALIZED) {
        /* the firewall manager was initializing, but all requests
         * so fare were queued and are already sent. No need to
         * re-update the firewall zone of the devices. */
        return;
    }

    if (!nm_firewalld_manager_get_running(manager))
        return;

    /* add interface of each device to correct zone */
    nm_manager_for_each_device (priv->manager, device, tmp_lst)
        nm_device_update_firewall_zone(device);
}

static void
dns_config_changed(NMDnsManager *dns_manager, gpointer user_data)
{
    NMPolicy        *self = (NMPolicy *) user_data;
    NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE(self);
    NMDevice        *device;
    const CList     *tmp_lst;

    /* We are currently updating the hostname in the DNS manager.
     * This doesn't warrant a new DNS lookup.*/
    if (priv->updating_dns)
        return;

    if (!nm_dns_manager_is_unmanaged(dns_manager)) {
        nm_manager_for_each_device (priv->manager, device, tmp_lst) {
            nm_device_clear_dns_lookup_data(device, "DNS configuration changed");
        }

        update_system_hostname(self, "DNS configuration changed", FALSE);
    }

    nm_dispatcher_call_dns_change();
}

static void
connection_updated(NMSettings           *settings,
                   NMSettingsConnection *connection,
                   guint                 update_reason_u,
                   gpointer              user_data)
{
    NMPolicyPrivate                 *priv          = user_data;
    NMPolicy                        *self          = _PRIV_TO_SELF(priv);
    NMSettingsConnectionUpdateReason update_reason = update_reason_u;

    unblock_autoconnect_for_ports_for_sett_conn(self, connection);

    if (NM_FLAGS_HAS(update_reason, NM_SETTINGS_CONNECTION_UPDATE_REASON_REAPPLY_PARTIAL)) {
        const CList *tmp_lst;
        NMDevice    *device;

        /* find device with given connection */
        nm_manager_for_each_device (priv->manager, device, tmp_lst) {
            if (nm_device_get_settings_connection(device) == connection)
                nm_device_reapply_settings_immediately(device);
        }
    }

    nm_policy_device_recheck_auto_activate_all_schedule(self);
}

static void
connection_removed(NMSettings *settings, NMSettingsConnection *connection, gpointer user_data)
{
    NMPolicyPrivate *priv = user_data;

    nm_manager_deactivate_ac(priv->manager, connection);
}

static void
connection_flags_changed(NMSettings *settings, NMSettingsConnection *connection, gpointer user_data)
{
    NMPolicyPrivate *priv = user_data;
    NMPolicy        *self = _PRIV_TO_SELF(priv);

    if (NM_FLAGS_HAS(nm_settings_connection_get_flags(connection),
                     NM_SETTINGS_CONNECTION_INT_FLAGS_VISIBLE)) {
        if (!nm_settings_connection_autoconnect_is_blocked(connection))
            nm_policy_device_recheck_auto_activate_all_schedule(self);
    }
}

static void
secret_agent_registered(NMSettings *settings, NMSecretAgent *agent, gpointer user_data)
{
    NMPolicy *self = NM_POLICY(user_data);

    /* The registered secret agent may provide some missing secrets. Thus we
     * reset retries count here and schedule activation, so that the
     * connections failed due to missing secrets may re-try auto-connection.
     */
    if (reset_autoconnect_all(self, NULL, TRUE))
        nm_policy_device_recheck_auto_activate_all_schedule(self);
}

NMActiveConnection *
nm_policy_get_default_ip4_ac(NMPolicy *self)
{
    return NM_POLICY_GET_PRIVATE(self)->default_ac4;
}

NMActiveConnection *
nm_policy_get_default_ip6_ac(NMPolicy *self)
{
    return NM_POLICY_GET_PRIVATE(self)->default_ac6;
}

NMActiveConnection *
nm_policy_get_activating_ip4_ac(NMPolicy *self)
{
    return NM_POLICY_GET_PRIVATE(self)->activating_ac4;
}

NMActiveConnection *
nm_policy_get_activating_ip6_ac(NMPolicy *self)
{
    return NM_POLICY_GET_PRIVATE(self)->activating_ac6;
}

/*****************************************************************************/

static NM_UTILS_LOOKUP_STR_DEFINE(_hostname_mode_to_string,
                                  NMPolicyHostnameMode,
                                  NM_UTILS_LOOKUP_DEFAULT_NM_ASSERT("unknown"),
                                  NM_UTILS_LOOKUP_STR_ITEM(NM_POLICY_HOSTNAME_MODE_NONE, "none"),
                                  NM_UTILS_LOOKUP_STR_ITEM(NM_POLICY_HOSTNAME_MODE_DHCP, "dhcp"),
                                  NM_UTILS_LOOKUP_STR_ITEM(NM_POLICY_HOSTNAME_MODE_FULL, "full"), );

/*****************************************************************************/

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMPolicy        *self = NM_POLICY(object);
    NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE(self);

    switch (prop_id) {
    case PROP_DEFAULT_IP4_AC:
        g_value_set_object(value, priv->default_ac4);
        break;
    case PROP_DEFAULT_IP6_AC:
        g_value_set_object(value, priv->default_ac6);
        break;
    case PROP_ACTIVATING_IP4_AC:
        g_value_set_object(value, priv->activating_ac4);
        break;
    case PROP_ACTIVATING_IP6_AC:
        g_value_set_object(value, priv->activating_ac6);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

static void
set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
    NMPolicy        *self = NM_POLICY(object);
    NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE(self);

    switch (prop_id) {
    case PROP_MANAGER:
        /* construct-only */
        priv->manager = g_value_get_object(value);
        g_return_if_fail(NM_IS_MANAGER(priv->manager));
        break;
    case PROP_SETTINGS:
        /* construct-only */
        priv->settings = g_value_dup_object(value);
        g_return_if_fail(NM_IS_SETTINGS(priv->settings));
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

/*****************************************************************************/

static void
nm_policy_init(NMPolicy *self)
{
    NMPolicyPrivate *priv          = NM_POLICY_GET_PRIVATE(self);
    gs_free char    *hostname_mode = NULL;

    c_list_init(&priv->policy_auto_activate_lst_head);

    priv->netns = g_object_ref(nm_netns_get());

    priv->hostname_manager = g_object_ref(nm_hostname_manager_get());

    hostname_mode =
        nm_config_data_get_value(NM_CONFIG_GET_DATA_ORIG,
                                 NM_CONFIG_KEYFILE_GROUP_MAIN,
                                 NM_CONFIG_KEYFILE_KEY_MAIN_HOSTNAME_MODE,
                                 NM_CONFIG_GET_VALUE_STRIP | NM_CONFIG_GET_VALUE_NO_EMPTY);
    if (nm_streq0(hostname_mode, "none"))
        priv->hostname_mode = NM_POLICY_HOSTNAME_MODE_NONE;
    else if (nm_streq0(hostname_mode, "dhcp"))
        priv->hostname_mode = NM_POLICY_HOSTNAME_MODE_DHCP;
    else /* default - full mode */
        priv->hostname_mode = NM_POLICY_HOSTNAME_MODE_FULL;

    priv->devices                    = g_hash_table_new(nm_direct_hash, NULL);
    priv->pending_active_connections = g_hash_table_new(nm_direct_hash, NULL);
    priv->ip6_prefix_delegations     = g_array_new(FALSE, FALSE, sizeof(IP6PrefixDelegation));
    g_array_set_clear_func(priv->ip6_prefix_delegations, clear_ip6_prefix_delegation);
}

static void
constructed(GObject *object)
{
    NMPolicy        *self     = NM_POLICY(object);
    NMPolicyPrivate *priv     = NM_POLICY_GET_PRIVATE(self);
    char            *hostname = NULL;

    /* Grab hostname on startup and use that if nothing provides one */
    if ((hostname = _get_hostname(self))) {
        /* init last_hostname */
        priv->last_hostname = hostname;

        /* only cache it if it's a valid hostname */
        if (nm_utils_is_specific_hostname(hostname))
            priv->orig_hostname = g_strdup(hostname);
    }
    _LOGT(LOGD_DNS,
          "hostname-original: set to %s%s%s",
          NM_PRINT_FMT_QUOTE_STRING(priv->orig_hostname));

    priv->agent_mgr = g_object_ref(nm_agent_manager_get());

    priv->firewalld_manager = g_object_ref(nm_firewalld_manager_get());
    g_signal_connect(priv->firewalld_manager,
                     NM_FIREWALLD_MANAGER_STATE_CHANGED,
                     G_CALLBACK(firewall_state_changed),
                     self);

    priv->dns_manager = g_object_ref(nm_dns_manager_get());
    nm_dns_manager_set_hostname(priv->dns_manager, priv->orig_hostname, TRUE);
    priv->config_changed_id = g_signal_connect(priv->dns_manager,
                                               NM_DNS_MANAGER_CONFIG_CHANGED,
                                               G_CALLBACK(dns_config_changed),
                                               self);

    g_signal_connect(priv->hostname_manager,
                     "notify::" NM_HOSTNAME_MANAGER_STATIC_HOSTNAME,
                     G_CALLBACK(_static_hostname_changed_cb),
                     priv);

    g_signal_connect(priv->manager,
                     "notify::" NM_MANAGER_SLEEPING,
                     G_CALLBACK(sleeping_changed),
                     priv);
    g_signal_connect(priv->manager,
                     "notify::" NM_MANAGER_NETWORKING_ENABLED,
                     G_CALLBACK(sleeping_changed),
                     priv);
    g_signal_connect(priv->manager,
                     NM_MANAGER_INTERNAL_DEVICE_ADDED,
                     G_CALLBACK(device_added),
                     priv);
    g_signal_connect(priv->manager,
                     NM_MANAGER_INTERNAL_DEVICE_REMOVED,
                     G_CALLBACK(device_removed),
                     priv);
    g_signal_connect(priv->manager,
                     NM_MANAGER_ACTIVE_CONNECTION_ADDED,
                     G_CALLBACK(active_connection_added),
                     priv);
    g_signal_connect(priv->manager,
                     NM_MANAGER_ACTIVE_CONNECTION_REMOVED,
                     G_CALLBACK(active_connection_removed),
                     priv);

    g_signal_connect(priv->settings,
                     NM_SETTINGS_SIGNAL_CONNECTION_ADDED,
                     G_CALLBACK(connection_added),
                     priv);
    g_signal_connect(priv->settings,
                     NM_SETTINGS_SIGNAL_CONNECTION_UPDATED,
                     G_CALLBACK(connection_updated),
                     priv);
    g_signal_connect(priv->settings,
                     NM_SETTINGS_SIGNAL_CONNECTION_REMOVED,
                     G_CALLBACK(connection_removed),
                     priv);
    g_signal_connect(priv->settings,
                     NM_SETTINGS_SIGNAL_CONNECTION_FLAGS_CHANGED,
                     G_CALLBACK(connection_flags_changed),
                     priv);

    g_signal_connect(priv->agent_mgr,
                     NM_AGENT_MANAGER_AGENT_REGISTERED,
                     G_CALLBACK(secret_agent_registered),
                     self);

    G_OBJECT_CLASS(nm_policy_parent_class)->constructed(object);

    _LOGD(LOGD_DNS, "hostname-mode: %s", _hostname_mode_to_string(priv->hostname_mode));
    update_system_hostname(self, "initial hostname", FALSE);
}

NMPolicy *
nm_policy_new(NMManager *manager, NMSettings *settings)
{
    g_return_val_if_fail(NM_IS_MANAGER(manager), NULL);
    g_return_val_if_fail(NM_IS_SETTINGS(settings), NULL);

    return g_object_new(NM_TYPE_POLICY,
                        NM_POLICY_MANAGER,
                        manager,
                        NM_POLICY_SETTINGS,
                        settings,
                        NULL);
}

static void
dispose(GObject *object)
{
    NMPolicy        *self = NM_POLICY(object);
    NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE(self);

    nm_assert(c_list_is_empty(&priv->policy_auto_activate_lst_head));
    nm_assert(g_hash_table_size(priv->devices) == 0);

    nm_clear_g_object(&priv->default_ac4);
    nm_clear_g_object(&priv->default_ac6);
    nm_clear_g_object(&priv->activating_ac4);
    nm_clear_g_object(&priv->activating_ac6);
    nm_clear_pointer(&priv->pending_active_connections, g_hash_table_unref);

    g_slist_free_full(priv->pending_secondaries, (GDestroyNotify) pending_secondary_data_free);
    priv->pending_secondaries = NULL;

    if (priv->firewalld_manager) {
        g_signal_handlers_disconnect_by_func(priv->firewalld_manager, firewall_state_changed, self);
        g_clear_object(&priv->firewalld_manager);
    }

    if (priv->agent_mgr) {
        g_signal_handlers_disconnect_by_func(priv->agent_mgr, secret_agent_registered, self);
        g_clear_object(&priv->agent_mgr);
    }

    if (priv->dns_manager) {
        nm_clear_g_signal_handler(priv->dns_manager, &priv->config_changed_id);
        g_clear_object(&priv->dns_manager);
    }

    /* The manager should have disposed of ActiveConnections already, which
     * will have called active_connection_removed() and thus we don't need
     * to clean anything up.  Assert that this is TRUE.
     */
    nm_assert(c_list_is_empty(nm_manager_get_active_connections(priv->manager)));

    nm_clear_g_source_inst(&priv->reset_connections_retries_idle_source);
    nm_clear_g_source_inst(&priv->device_recheck_auto_activate_all_idle_source);
    nm_clear_g_source_inst(&priv->hostname_retry.source);

    nm_clear_g_free(&priv->orig_hostname);
    nm_clear_g_free(&priv->cur_hostname);
    nm_clear_g_free(&priv->cur_hostname_full);
    nm_clear_g_free(&priv->last_hostname);

    if (priv->hostname_manager) {
        g_signal_handlers_disconnect_by_data(priv->hostname_manager, priv);
        g_clear_object(&priv->hostname_manager);
    }

    if (priv->settings) {
        g_signal_handlers_disconnect_by_data(priv->settings, priv);
        g_clear_object(&priv->settings);

        /* we don't clear priv->manager as we don't own a reference to it,
         * that is, NMManager must outlive NMPolicy anyway.
         *
         * Hence, we unsubscribe the signals here together with the signals
         * for settings. */
        g_signal_handlers_disconnect_by_data(priv->manager, priv);
    }

    if (priv->ip6_prefix_delegations) {
        g_array_free(priv->ip6_prefix_delegations, TRUE);
        priv->ip6_prefix_delegations = NULL;
    }

    nm_assert(NM_IS_MANAGER(priv->manager));

    G_OBJECT_CLASS(nm_policy_parent_class)->dispose(object);
}

static void
finalize(GObject *object)
{
    NMPolicy        *self = NM_POLICY(object);
    NMPolicyPrivate *priv = NM_POLICY_GET_PRIVATE(self);

    g_hash_table_unref(priv->devices);

    G_OBJECT_CLASS(nm_policy_parent_class)->finalize(object);

    g_object_unref(priv->netns);
}

static void
nm_policy_class_init(NMPolicyClass *policy_class)
{
    GObjectClass *object_class = G_OBJECT_CLASS(policy_class);

    object_class->get_property = get_property;
    object_class->set_property = set_property;
    object_class->constructed  = constructed;
    object_class->dispose      = dispose;
    object_class->finalize     = finalize;

    obj_properties[PROP_MANAGER] =
        g_param_spec_object(NM_POLICY_MANAGER,
                            "",
                            "",
                            NM_TYPE_MANAGER,
                            G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_SETTINGS] =
        g_param_spec_object(NM_POLICY_SETTINGS,
                            "",
                            "",
                            NM_TYPE_SETTINGS,
                            G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_DEFAULT_IP4_AC] =
        g_param_spec_object(NM_POLICY_DEFAULT_IP4_AC,
                            "",
                            "",
                            NM_TYPE_ACTIVE_CONNECTION,
                            G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_DEFAULT_IP6_AC] =
        g_param_spec_object(NM_POLICY_DEFAULT_IP6_AC,
                            "",
                            "",
                            NM_TYPE_DEVICE,
                            G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_ACTIVATING_IP4_AC] =
        g_param_spec_object(NM_POLICY_ACTIVATING_IP4_AC,
                            "",
                            "",
                            NM_TYPE_DEVICE,
                            G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_ACTIVATING_IP6_AC] =
        g_param_spec_object(NM_POLICY_ACTIVATING_IP6_AC,
                            "",
                            "",
                            NM_TYPE_DEVICE,
                            G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}
