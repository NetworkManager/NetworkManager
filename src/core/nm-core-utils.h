/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2004 - 2016 Red Hat, Inc.
 * Copyright (C) 2005 - 2008 Novell, Inc.
 */

#ifndef __NM_CORE_UTILS_H__
#define __NM_CORE_UTILS_H__

#include <stdio.h>
#include <arpa/inet.h>
#include <sys/types.h>

#include "nm-connection.h"

#include "libnm-glib-aux/nm-time-utils.h"

/*****************************************************************************/

#define NM_DEFINE_SINGLETON_INSTANCE(TYPE) static TYPE *singleton_instance

#define NM_DEFINE_SINGLETON_REGISTER(TYPE)                                                      \
    NM_DEFINE_SINGLETON_INSTANCE(TYPE);                                                         \
    static void _singleton_instance_weak_ref_cb(gpointer data, GObject *where_the_object_was)   \
    {                                                                                           \
        nm_log_dbg(LOGD_CORE,                                                                   \
                   "disposing %s singleton (" NM_HASH_OBFUSCATE_PTR_FMT ")",                    \
                   G_STRINGIFY(TYPE),                                                           \
                   NM_HASH_OBFUSCATE_PTR(singleton_instance));                                  \
        singleton_instance = NULL;                                                              \
    }                                                                                           \
    static inline void nm_singleton_instance_register(void)                                     \
    {                                                                                           \
        g_object_weak_ref(G_OBJECT(singleton_instance), _singleton_instance_weak_ref_cb, NULL); \
        _nm_singleton_instance_register_destruction(G_OBJECT(singleton_instance));              \
    }                                                                                           \
    _NM_DUMMY_STRUCT_FOR_TRAILING_SEMICOLON

void _nm_singleton_instance_register_destruction(GObject *instance);

/* By default, the getter will assert that the singleton will be created only once. You can
 * change this by redefining NM_DEFINE_SINGLETON_ALLOW_MULTIPLE. */
#ifndef NM_DEFINE_SINGLETON_ALLOW_MULTIPLE
#define NM_DEFINE_SINGLETON_ALLOW_MULTIPLE FALSE
#endif

#define NM_DEFINE_SINGLETON_GETTER(TYPE, GETTER, GTYPE, ...)                                \
    NM_DEFINE_SINGLETON_INSTANCE(TYPE);                                                     \
    NM_DEFINE_SINGLETON_REGISTER(TYPE);                                                     \
    static char _already_created_##GETTER = FALSE;                                          \
    TYPE       *GETTER(void)                                                                \
    {                                                                                       \
        if (G_UNLIKELY(!singleton_instance)) {                                              \
            g_assert(!(_already_created_##GETTER) || (NM_DEFINE_SINGLETON_ALLOW_MULTIPLE)); \
            (_already_created_##GETTER) = TRUE;                                             \
            singleton_instance          = g_object_new(GTYPE, ##__VA_ARGS__, NULL);         \
            g_assert(singleton_instance);                                                   \
            nm_singleton_instance_register();                                               \
            nm_log_dbg(LOGD_CORE,                                                           \
                       "create %s singleton (" NM_HASH_OBFUSCATE_PTR_FMT ")",               \
                       G_STRINGIFY(TYPE),                                                   \
                       NM_HASH_OBFUSCATE_PTR(singleton_instance));                          \
        }                                                                                   \
        return singleton_instance;                                                          \
    }                                                                                       \
    _nm_unused static void _nmtst_##GETTER##_reset(TYPE *instance)                          \
    {                                                                                       \
        /* usually, the singleton can only be created once (and further instantiations
     * are guarded by an assert). For testing, we need to reset the singleton to
     * allow multiple instantiations. */      \
        g_assert(G_IS_OBJECT(instance));                                                    \
        g_assert(instance == singleton_instance);                                           \
        g_assert(_already_created_##GETTER);                                                \
        g_object_unref(instance);                                                           \
                                                                                            \
        /* require that the last unref also destroyed the singleton. If this fails,
     * somebody still keeps a reference. Fix your test! */         \
        g_assert(!singleton_instance);                                                      \
        _already_created_##GETTER = FALSE;                                                  \
    }

/* attach @instance to the data or @owner. @owner owns a reference
 * to @instance thus the lifetime of @instance is at least as long
 * as that of @owner. Use this when @owner depends on @instance. */
#define NM_UTILS_KEEP_ALIVE(owner, instance, unique_token)              \
    G_STMT_START                                                        \
    {                                                                   \
        g_object_set_data_full(G_OBJECT(owner),                         \
                               ".nm-utils-keep-alive-" unique_token "", \
                               g_object_ref(instance),                  \
                               g_object_unref);                         \
    }                                                                   \
    G_STMT_END

/*****************************************************************************/

gboolean nm_ether_addr_is_valid(const NMEtherAddr *addr);
gboolean nm_ether_addr_is_valid_str(const char *str);

static inline void
nm_hash_update_in6addr(NMHashState *h, const struct in6_addr *addr)
{
    nm_assert(addr);

    nm_hash_update(h, addr, sizeof(*addr));
}

static inline void
nm_hash_update_in6addr_prefix(NMHashState *h, const struct in6_addr *addr, guint8 plen)
{
    struct in6_addr a;

    nm_assert(addr);

    nm_ip6_addr_clear_host_address(&a, addr, plen);
    /* we don't hash plen itself. The caller may want to do that.*/
    nm_hash_update_in6addr(h, &a);
}

/**
 * nm_utils_ip6_route_metric_normalize:
 * @metric: the route metric
 *
 * For IPv6 route, when adding a route via netlink, kernel treats the value 0 as IP6_RT_PRIO_USER (1024).
 * So, user space cannot add routes with such a metric, and 0 gets "normalized"
 * to NM_PLATFORM_ROUTE_METRIC_DEFAULT_IP6.
 *
 * Note that kernel itself can add IPv6 routes with metric zero. Also, you can delete
 * them, but mostly because with `ip -6 route delete ... metric 0` the 0 acts as a wildcard
 * and kills the first matching route.
 *
 * Returns: @metric, if @metric is not zero, otherwise 1024.
 */
static inline guint32
nm_utils_ip6_route_metric_normalize(guint32 metric)
{
    return metric ?: 1024 /*NM_PLATFORM_ROUTE_METRIC_DEFAULT_IP6*/;
}

static inline guint32
nm_utils_ip_route_metric_normalize(int addr_family, guint32 metric)
{
    return NM_IS_IPv4(addr_family) ? metric : nm_utils_ip6_route_metric_normalize(metric);
}

static inline guint32
nm_utils_ip_route_metric_penalize(guint32 metric, guint32 penalty)
{
    if (metric < G_MAXUINT32 - penalty)
        return metric + penalty;
    return G_MAXUINT32;
}

void nm_utils_kill_process_sync(pid_t       pid,
                                guint64     start_time,
                                int         sig,
                                NMLogDomain log_domain,
                                const char *log_name,
                                guint32     wait_before_kill_msec,
                                guint32     sleep_duration_msec,
                                guint32     max_wait_msec);

typedef void (*NMUtilsKillChildAsyncCb)(pid_t    pid,
                                        gboolean success,
                                        int      child_status,
                                        void    *user_data);
void     nm_utils_kill_child_async(pid_t                   pid,
                                   int                     sig,
                                   NMLogDomain             log_domain,
                                   const char             *log_name,
                                   guint32                 wait_before_kill_msec,
                                   NMUtilsKillChildAsyncCb callback,
                                   void                   *user_data);
gboolean nm_utils_kill_child_sync(pid_t       pid,
                                  int         sig,
                                  NMLogDomain log_domain,
                                  const char *log_name,
                                  int        *child_status,
                                  guint32     wait_before_kill_msec,
                                  guint32     sleep_duration_msec);

const char *nm_utils_find_helper(const char *progname, const char *try_first, GError **error);

char *nm_utils_read_link_absolute(const char *link_file, GError **error);

#define NM_MATCH_SPEC_MAC_TAG              "mac:"
#define NM_MATCH_SPEC_S390_SUBCHANNELS_TAG "s390-subchannels:"
#define NM_MATCH_SPEC_INTERFACE_NAME_TAG   "interface-name:"

typedef enum {
    NM_MATCH_SPEC_NO_MATCH  = 0,
    NM_MATCH_SPEC_MATCH     = 1,
    NM_MATCH_SPEC_NEG_MATCH = 2,
} NMMatchSpecMatchType;

NMMatchSpecMatchType nm_match_spec_device(const GSList *specs,
                                          const char   *interface_name,
                                          const char   *device_type,
                                          const char   *driver,
                                          const char   *driver_version,
                                          const char   *hwaddr,
                                          const char   *s390_subchannels,
                                          const char   *dhcp_plugin);
NMMatchSpecMatchType nm_match_spec_config(const GSList *specs, guint nm_version, const char *env);
GSList              *nm_match_spec_split(const char *value);
char                *nm_match_spec_join(GSList *specs);

gboolean nm_wildcard_match_check(const char *str, const char *const *patterns, guint num_patterns);

gboolean nm_utils_kernel_cmdline_match_check(const char *const *proc_cmdline,
                                             const char *const *patterns,
                                             guint              num_patterns,
                                             GError           **error);

int nm_utils_connection_match_spec_list(NMConnection *connection,
                                        const GSList *specs,
                                        int           no_match_value);

/*****************************************************************************/

gboolean nm_utils_connection_has_default_route(NMConnection *connection,
                                               int           addr_family,
                                               gboolean     *out_is_never_default);

int nm_utils_cmp_connection_by_autoconnect_priority(NMConnection *a, NMConnection *b);

void nm_utils_log_connection_diff(NMConnection *connection,
                                  NMConnection *diff_base,
                                  guint32       level,
                                  guint64       domain,
                                  const char   *name,
                                  const char   *prefix,
                                  const char   *dbus_path);

gboolean nm_utils_is_specific_hostname(const char *name);
gboolean nm_utils_shorten_hostname(const char *hostname, char **shortened);

struct _NMUuid;

const char           *nm_utils_machine_id_str(void);
const struct _NMUuid *nm_utils_machine_id_bin(void);
gboolean              nm_utils_machine_id_is_fake(void);

const char           *nm_utils_boot_id_str(void);
const struct _NMUuid *nm_utils_boot_id_bin(void);
const char           *nm_utils_proc_cmdline(void);
const char *const    *nm_utils_proc_cmdline_split(void);

gboolean nm_utils_host_id_get(const guint8 **out_host_id, gsize *out_host_id_len);
gint64   nm_utils_host_id_get_timestamp_nsec(void);

void nmtst_utils_host_id_push(const guint8 *host_id,
                              gssize        host_id_len,
                              gboolean      is_good,
                              const gint64 *timestamp_ns);

void nmtst_utils_host_id_pop(void);

static inline void
_nmtst_auto_utils_host_id_context_pop(const char *const *unused)
{
    nmtst_utils_host_id_pop();
}

#define _NMTST_UTILS_HOST_ID_CONTEXT(uniq, host_id)                                        \
    _nm_unused nm_auto(_nmtst_auto_utils_host_id_context_pop) const char *const NM_UNIQ_T( \
        _host_id_context_,                                                                 \
        uniq) = ({                                                                         \
        const gint64 _timestamp_ns = 1631000672;                                           \
                                                                                           \
        nmtst_utils_host_id_push((const guint8 *) "" host_id "",                           \
                                 NM_STRLEN(host_id),                                       \
                                 TRUE,                                                     \
                                 &_timestamp_ns);                                          \
        "" host_id "";                                                                     \
    })

#define NMTST_UTILS_HOST_ID_CONTEXT(host_id) _NMTST_UTILS_HOST_ID_CONTEXT(NM_UNIQ, host_id)

/*****************************************************************************/

int nm_utils_arp_type_detect_from_hwaddrlen(gsize hwaddr_len);

gboolean nm_utils_arp_type_validate_hwaddr(int arp_type, const guint8 *hwaddr, gsize hwaddr_len);

gboolean
nm_utils_arp_type_get_hwaddr_relevant_part(int arp_type, const guint8 **hwaddr, gsize *hwaddr_len);

/*****************************************************************************/

typedef enum {
    /* The stable type. Note that this value is encoded in the
     * generated addresses, thus the numbers MUST not change.
     *
     * Also note, if we ever allocate ID 255, we must take care
     * that nm_utils_ipv6_addr_set_stable_privacy() extends the
     * uint8 encoding of this value. */
    NM_UTILS_STABLE_TYPE_UUID      = 0,
    NM_UTILS_STABLE_TYPE_STABLE_ID = 1,
    NM_UTILS_STABLE_TYPE_GENERATED = 2,
    NM_UTILS_STABLE_TYPE_RANDOM    = 3,
} NMUtilsStableType;

#define NM_UTILS_STABLE_TYPE_NONE ((NMUtilsStableType) -1)

NMUtilsStableType nm_utils_stable_id_parse(const char *stable_id,
                                           const char *deviceid,
                                           const char *hwaddr,
                                           const char *bootid,
                                           const char *uuid,
                                           char      **out_generated);

char *nm_utils_stable_id_random(void);
char *nm_utils_stable_id_generated_complete(const char *msg);

#define NM_STABLE_PRIVACY_RFC7217_IDGEN_RETRIES 3

void nm_utils_ipv6_addr_set_stable_privacy_with_host_id(NMUtilsStableType stable_type,
                                                        struct in6_addr  *addr,
                                                        const char       *ifname,
                                                        const char       *network_id,
                                                        guint32           dad_counter,
                                                        const guint8     *host_id,
                                                        gsize             host_id_len);

void nm_utils_ipv6_addr_set_stable_privacy(NMUtilsStableType stable_type,
                                           struct in6_addr  *addr,
                                           const char       *ifname,
                                           const char       *network_id,
                                           guint32           dad_counter);

gboolean nm_utils_ipv6_addr_set_stable_privacy_may_fail(NMUtilsStableType stable_type,
                                                        struct in6_addr  *addr,
                                                        const char       *ifname,
                                                        const char       *network_id,
                                                        guint32           dad_counter,
                                                        GError          **error);

char *nm_utils_hw_addr_gen_random_eth(const char *current_mac_address,
                                      const char *generate_mac_address_mask);
char *nm_utils_hw_addr_gen_stable_eth_impl(NMUtilsStableType stable_type,
                                           const char       *stable_id,
                                           const guint8     *host_id,
                                           gsize             host_id_len,
                                           const char       *ifname,
                                           const char       *current_mac_address,
                                           const char       *generate_mac_address_mask);
char *nm_utils_hw_addr_gen_stable_eth(NMUtilsStableType stable_type,
                                      const char       *stable_id,
                                      const char       *ifname,
                                      const char       *current_mac_address,
                                      const char       *generate_mac_address_mask);

/*****************************************************************************/

GBytes *nm_utils_dhcp_client_id_mac(int arp_type, const guint8 *hwaddr, gsize hwaddr_len);

guint32 nm_utils_create_dhcp_iaid(gboolean      legacy_unstable_byteorder,
                                  const guint8 *interface_id,
                                  gsize         interface_id_len);

GBytes *nm_utils_dhcp_client_id_duid(guint32 iaid, const guint8 *duid, gsize duid_len);

GBytes *nm_utils_dhcp_client_id_systemd_node_specific_full(guint32       iaid,
                                                           const guint8 *machine_id,
                                                           gsize         machine_id_len);

GBytes *nm_utils_dhcp_client_id_systemd_node_specific(guint32 iaid);

/*****************************************************************************/

/* RFC 3315 defines the epoch for the DUID-LLT time field on Jan 1st 2000. */
#define NM_UTILS_EPOCH_DATETIME_200001010000 946684800

struct _NMUuid;

GBytes *
nm_utils_generate_duid_llt(int arp_type, const guint8 *hwaddr, gsize hwaddr_len, gint64 time);

GBytes *nm_utils_generate_duid_ll(int arp_type, const guint8 *hwaddr, gsize hwaddr_len);

GBytes *nm_utils_generate_duid_uuid(const struct _NMUuid *uuid);

GBytes *nm_utils_generate_duid_from_machine_id(void);

/*****************************************************************************/

void nm_utils_array_remove_at_indexes(GArray *array, const guint *indexes_to_delete, gsize len);

void nm_utils_setpgid(gpointer unused);

typedef enum {
    NM_UTILS_TEST_NONE = 0,

    /* Internal flag, marking that either nm_utils_get_testing() or _nm_utils_set_testing() was called. */
    _NM_UTILS_TEST_INITIALIZED = (1LL << 0),

    /* Indicate that test mode is enabled in general. Explicitly calling _nm_utils_set_testing() will always set this flag. */
    _NM_UTILS_TEST_GENERAL = (1LL << 1),

    /* Don't check the owner of keyfiles during testing. */
    NM_UTILS_TEST_NO_KEYFILE_OWNER_CHECK = (1LL << 2),

    _NM_UTILS_TEST_LAST,
    NM_UTILS_TEST_ALL = (((_NM_UTILS_TEST_LAST - 1) << 1) - 1) & ~(_NM_UTILS_TEST_INITIALIZED),
} NMUtilsTestFlags;

gboolean         nm_utils_get_testing_initialized(void);
NMUtilsTestFlags nm_utils_get_testing(void);
void             _nm_utils_set_testing(NMUtilsTestFlags flags);

void nm_utils_g_value_set_strv(GValue *value, GPtrArray *strings);

/*****************************************************************************/

const char *nm_utils_dnsmasq_status_to_string(int status, char *dest, gsize size);

void nm_utils_get_reverse_dns_domains_ip_4(guint32 ip, guint8 plen, GPtrArray *domains);
void
nm_utils_get_reverse_dns_domains_ip_6(const struct in6_addr *ip, guint8 plen, GPtrArray *domains);

static inline void
nm_utils_get_reverse_dns_domains_ip(int           addr_family,
                                    gconstpointer addr,
                                    guint8        plen,
                                    GPtrArray    *domains)
{
    if (NM_IS_IPv4(addr_family))
        nm_utils_get_reverse_dns_domains_ip_4(*((const in_addr_t *) addr), plen, domains);
    else
        nm_utils_get_reverse_dns_domains_ip_6(addr, plen, domains);
}

struct stat;

gboolean nm_utils_validate_plugin(const char *path, struct stat *stat, GError **error);
char   **nm_utils_read_plugin_paths(const char *dirname, const char *prefix);
char    *nm_utils_format_con_diff_for_audit(GHashTable *diff);

/*****************************************************************************/

const char *nm_activation_type_to_string(NMActivationType activation_type);

/*****************************************************************************/

const char *nm_utils_parse_dns_domain(const char *domain, gboolean *is_routing);

/*****************************************************************************/

void nm_wifi_utils_parse_ies(const guint8 *bytes,
                             gsize         len,
                             guint32      *out_max_rate,
                             gboolean     *out_metered,
                             gboolean     *out_owe_transition_mode);

guint8 nm_wifi_utils_level_to_quality(int val);

/*****************************************************************************/

#define NM_VPN_ROUTE_METRIC_DEFAULT 50

#define NM_UTILS_ERROR_MSG_REQ_AUTH_FAILED "Unable to authenticate the request"
#define NM_UTILS_ERROR_MSG_REQ_UID_UKNOWN  "Unable to determine UID of the request"
#define NM_UTILS_ERROR_MSG_INSUFF_PRIV     "Insufficient privileges"

/*****************************************************************************/

void nm_utils_spawn_helper(const char *const  *args,
                           GCancellable       *cancellable,
                           GAsyncReadyCallback callback,
                           gpointer            cb_data);

char *nm_utils_spawn_helper_finish(GAsyncResult *result, GError **error);

/*****************************************************************************/

uid_t nm_utils_get_nm_uid(void);

gid_t nm_utils_get_nm_gid(void);

#endif /* __NM_CORE_UTILS_H__ */
