/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright 2004 - 2016 Red Hat, Inc.
 * Copyright 2005 - 2008 Novell, Inc.
 */

#ifndef __NM_CORE_UTILS_H__
#define __NM_CORE_UTILS_H__

#include <stdio.h>
#include <arpa/inet.h>

#include "nm-connection.h"

#include "nm-glib-aux/nm-time-utils.h"

/*****************************************************************************/

#define NM_PLATFORM_LIFETIME_PERMANENT G_MAXUINT32

#define NM_DEFINE_SINGLETON_INSTANCE(TYPE) \
static TYPE *singleton_instance

#define NM_DEFINE_SINGLETON_REGISTER(TYPE) \
NM_DEFINE_SINGLETON_INSTANCE (TYPE); \
static void \
_singleton_instance_weak_ref_cb (gpointer data, \
                                 GObject *where_the_object_was) \
{ \
	nm_log_dbg (LOGD_CORE, "disposing %s singleton ("NM_HASH_OBFUSCATE_PTR_FMT")", \
	            G_STRINGIFY (TYPE), \
	            NM_HASH_OBFUSCATE_PTR (singleton_instance)); \
	singleton_instance = NULL; \
} \
static inline void \
nm_singleton_instance_register (void) \
{ \
	g_object_weak_ref (G_OBJECT (singleton_instance), _singleton_instance_weak_ref_cb, NULL); \
	_nm_singleton_instance_register_destruction (G_OBJECT (singleton_instance)); \
}

void _nm_singleton_instance_register_destruction (GObject *instance);

/* By default, the getter will assert that the singleton will be created only once. You can
 * change this by redefining NM_DEFINE_SINGLETON_ALLOW_MULTIPLE. */
#ifndef NM_DEFINE_SINGLETON_ALLOW_MULTIPLE
#define NM_DEFINE_SINGLETON_ALLOW_MULTIPLE     FALSE
#endif

#define NM_DEFINE_SINGLETON_GETTER(TYPE, GETTER, GTYPE, ...) \
NM_DEFINE_SINGLETON_INSTANCE (TYPE); \
NM_DEFINE_SINGLETON_REGISTER (TYPE); \
static char _already_created_##GETTER = FALSE; \
TYPE * \
GETTER (void) \
{ \
	if (G_UNLIKELY (!singleton_instance)) { \
		g_assert (!(_already_created_##GETTER) || (NM_DEFINE_SINGLETON_ALLOW_MULTIPLE)); \
		(_already_created_##GETTER) = TRUE;\
		singleton_instance = (g_object_new (GTYPE, ##__VA_ARGS__, NULL)); \
		g_assert (singleton_instance); \
		nm_singleton_instance_register (); \
		nm_log_dbg (LOGD_CORE, "create %s singleton ("NM_HASH_OBFUSCATE_PTR_FMT")", \
		            G_STRINGIFY (TYPE), \
		            NM_HASH_OBFUSCATE_PTR (singleton_instance)); \
	} \
	return singleton_instance; \
} \
_nm_unused static void \
_nmtst_##GETTER##_reset (TYPE *instance) \
{ \
	/* usually, the singleton can only be created once (and further instantiations
	 * are guarded by an assert). For testing, we need to reset the singleton to
	 * allow multiple instantiations. */ \
	g_assert (G_IS_OBJECT (instance)); \
	g_assert (instance == singleton_instance); \
	g_assert (_already_created_##GETTER); \
	g_object_unref (instance); \
	\
	/* require that the last unref also destroyed the singleton. If this fails,
	 * somebody still keeps a reference. Fix your test! */ \
	g_assert (!singleton_instance); \
	_already_created_##GETTER = FALSE; \
}

/* attach @instance to the data or @owner. @owner owns a reference
 * to @instance thus the lifetime of @instance is at least as long
 * as that of @owner. Use this when @owner depends on @instance. */
#define NM_UTILS_KEEP_ALIVE(owner, instance, unique_token) \
    G_STMT_START { \
         g_object_set_data_full (G_OBJECT (owner), \
                                 ".nm-utils-keep-alive-" unique_token "", \
                                 g_object_ref (instance), \
                                 g_object_unref); \
    } G_STMT_END

/*****************************************************************************/

gboolean nm_ethernet_address_is_valid (gconstpointer addr, gssize len);

gconstpointer nm_utils_ipx_address_clear_host_address (int family, gpointer dst, gconstpointer src, guint8 plen);
in_addr_t nm_utils_ip4_address_clear_host_address (in_addr_t addr, guint8 plen);
const struct in6_addr *nm_utils_ip6_address_clear_host_address (struct in6_addr *dst, const struct in6_addr *src, guint8 plen);

static inline int
nm_utils_ip4_address_same_prefix_cmp (in_addr_t addr_a, in_addr_t addr_b, guint8 plen)
{
	NM_CMP_DIRECT (htonl (nm_utils_ip4_address_clear_host_address (addr_a, plen)),
	               htonl (nm_utils_ip4_address_clear_host_address (addr_b, plen)));
	return 0;
}

int nm_utils_ip6_address_same_prefix_cmp (const struct in6_addr *addr_a, const struct in6_addr *addr_b, guint8 plen);

static inline gboolean
nm_utils_ip4_address_same_prefix (in_addr_t addr_a, in_addr_t addr_b, guint8 plen)
{
	return nm_utils_ip4_address_same_prefix_cmp (addr_a, addr_b, plen) == 0;
}

static inline gboolean
nm_utils_ip6_address_same_prefix (const struct in6_addr *addr_a, const struct in6_addr *addr_b, guint8 plen)
{
	return nm_utils_ip6_address_same_prefix_cmp (addr_a, addr_b, plen) == 0;
}

#define NM_CMP_DIRECT_IN4ADDR_SAME_PREFIX(a, b, plen) \
    NM_CMP_RETURN (nm_utils_ip4_address_same_prefix_cmp ((a), (b), (plen)))

#define NM_CMP_DIRECT_IN6ADDR_SAME_PREFIX(a, b, plen) \
    NM_CMP_RETURN (nm_utils_ip6_address_same_prefix_cmp ((a), (b), (plen)))

static inline void
nm_hash_update_in6addr (NMHashState *h, const struct in6_addr *addr)
{
	nm_assert (addr);

	nm_hash_update (h, addr, sizeof (*addr));
}

static inline void
nm_hash_update_in6addr_prefix (NMHashState *h, const struct in6_addr *addr, guint8 plen)
{
	struct in6_addr a;

	nm_assert (addr);

	nm_utils_ip6_address_clear_host_address (&a, addr, plen);
	/* we don't hash plen itself. The caller may want to do that.*/
	nm_hash_update_in6addr (h, &a);
}

double nm_utils_exp10 (gint16 e);

/**
 * nm_utils_ip6_route_metric_normalize:
 * @metric: the route metric
 *
 * For IPv6 route, kernel treats the value 0 as IP6_RT_PRIO_USER (1024).
 * Thus, when comparing metric (values), we want to treat zero as NM_PLATFORM_ROUTE_METRIC_DEFAULT_IP6.
 *
 * Returns: @metric, if @metric is not zero, otherwise 1024.
 */
static inline guint32
nm_utils_ip6_route_metric_normalize (guint32 metric)
{
	return metric ?: 1024 /*NM_PLATFORM_ROUTE_METRIC_DEFAULT_IP6*/;
}

static inline guint32
nm_utils_ip_route_metric_normalize (int addr_family, guint32 metric)
{
	return addr_family == AF_INET6 ? nm_utils_ip6_route_metric_normalize (metric) : metric;
}

static inline guint32
nm_utils_ip_route_metric_penalize (int addr_family, guint32 metric, guint32 penalty)
{
	metric = nm_utils_ip_route_metric_normalize (addr_family, metric);
	if (metric < G_MAXUINT32 - penalty)
		return metric + penalty;
	return G_MAXUINT32;
}

int nm_utils_modprobe (GError **error, gboolean suppress_error_loggin, const char *arg1, ...) G_GNUC_NULL_TERMINATED;

void nm_utils_kill_process_sync (pid_t pid, guint64 start_time, int sig, guint64 log_domain,
                                 const char *log_name, guint32 wait_before_kill_msec,
                                 guint32 sleep_duration_msec, guint32 max_wait_msec);

typedef void (*NMUtilsKillChildAsyncCb) (pid_t pid, gboolean success, int child_status, void *user_data);
void nm_utils_kill_child_async (pid_t pid, int sig, guint64 log_domain, const char *log_name,
                                guint32 wait_before_kill_msec,
                                NMUtilsKillChildAsyncCb callback, void *user_data);
gboolean nm_utils_kill_child_sync (pid_t pid, int sig, guint64 log_domain, const char *log_name,
                                   int *child_status, guint32 wait_before_kill_msec,
                                   guint32 sleep_duration_msec);

const char *nm_utils_find_helper (const char *progname,
                                  const char *try_first,
                                  GError **error);

char *nm_utils_read_link_absolute (const char *link_file, GError **error);

#define NM_MATCH_SPEC_MAC_TAG                    "mac:"
#define NM_MATCH_SPEC_S390_SUBCHANNELS_TAG       "s390-subchannels:"
#define NM_MATCH_SPEC_INTERFACE_NAME_TAG         "interface-name:"

typedef enum {
	NM_MATCH_SPEC_NO_MATCH  = 0,
	NM_MATCH_SPEC_MATCH     = 1,
	NM_MATCH_SPEC_NEG_MATCH = 2,
} NMMatchSpecMatchType;

NMMatchSpecMatchType nm_match_spec_device (const GSList *specs,
                                           const char *interface_name,
                                           const char *device_type,
                                           const char *driver,
                                           const char *driver_version,
                                           const char *hwaddr,
                                           const char *s390_subchannels,
                                           const char *dhcp_plugin);
NMMatchSpecMatchType nm_match_spec_config (const GSList *specs,
                                           guint nm_version,
                                           const char *env);
GSList *nm_match_spec_split (const char *value);
char *nm_match_spec_join (GSList *specs);

gboolean nm_wildcard_match_check (const char *str,
                                  const char *const *patterns,
                                  guint num_patterns);

/*****************************************************************************/

gboolean nm_utils_connection_has_default_route (NMConnection *connection,
                                                int addr_family,
                                                gboolean *out_is_never_default);

char *nm_utils_new_vlan_name (const char *parent_iface, guint32 vlan_id);
const char *nm_utils_new_infiniband_name (char *name, const char *parent_name, int p_key);

int nm_utils_cmp_connection_by_autoconnect_priority (NMConnection *a, NMConnection *b);

void nm_utils_log_connection_diff (NMConnection *connection,
                                   NMConnection *diff_base,
                                   guint32 level, guint64 domain,
                                   const char *name,
                                   const char *prefix,
                                   const char *dbus_path);

gboolean    nm_utils_is_valid_path_component (const char *name);
const char *NM_ASSERT_VALID_PATH_COMPONENT (const char *name);

#define NM_UTILS_SYSCTL_IP_CONF_PATH_BUFSIZE 100

const char *nm_utils_sysctl_ip_conf_path (int addr_family, char *buf, const char *ifname, const char *property);

gboolean nm_utils_sysctl_ip_conf_is_path (int addr_family, const char *path, const char *ifname, const char *property);

gboolean nm_utils_is_specific_hostname (const char *name);

struct _NMUuid;

const char *nm_utils_machine_id_str (void);
const struct _NMUuid *nm_utils_machine_id_bin (void);
gboolean nm_utils_machine_id_is_fake (void);

const char *nm_utils_boot_id_str (void);
const struct _NMUuid *nm_utils_boot_id_bin (void);

gboolean nm_utils_host_id_get (const guint8 **out_host_id,
                               gsize *out_host_id_len);
gint64 nm_utils_host_id_get_timestamp_ns (void);

/*****************************************************************************/

int nm_utils_arp_type_detect_from_hwaddrlen (gsize hwaddr_len);

gboolean nm_utils_arp_type_validate_hwaddr (int arp_type,
                                            const guint8 *hwaddr,
                                            gsize hwaddr_len);

gboolean nm_utils_arp_type_get_hwaddr_relevant_part (int arp_type,
                                                     const guint8 **hwaddr,
                                                     gsize *hwaddr_len);

/*****************************************************************************/

/* IPv6 Interface Identifier helpers */

/**
 * NMUtilsIPv6IfaceId:
 * @id: convenience member for validity checking; never use directly
 * @id_u8: the 64-bit Interface Identifier
 *
 * Holds a 64-bit IPv6 Interface Identifier.  The IID is a sequence of bytes
 * and should not normally be treated as a %guint64, but this is done for
 * convenience of validity checking and initialization.
 */
struct _NMUtilsIPv6IfaceId {
	union {
		guint64 id;
		guint8  id_u8[8];
	};
};

#define NM_UTILS_IPV6_IFACE_ID_INIT { { .id = 0 } }

void nm_utils_ipv6_addr_set_interface_identifier (struct in6_addr *addr,
                                                 const NMUtilsIPv6IfaceId iid);

void nm_utils_ipv6_interface_identifier_get_from_addr (NMUtilsIPv6IfaceId *iid,
                                                      const struct in6_addr *addr);

gboolean nm_utils_ipv6_interface_identifier_get_from_token (NMUtilsIPv6IfaceId *iid,
                                                           const char *token);

const char *nm_utils_inet6_interface_identifier_to_token (NMUtilsIPv6IfaceId iid,
                                                         char *buf);

gboolean nm_utils_get_ipv6_interface_identifier (NMLinkType link_type,
                                                 const guint8 *hwaddr,
                                                 guint len,
                                                 guint dev_id,
                                                 NMUtilsIPv6IfaceId *out_iid);

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

NMUtilsStableType nm_utils_stable_id_parse (const char *stable_id,
                                            const char *deviceid,
                                            const char *hwaddr,
                                            const char *bootid,
                                            const char *uuid,
                                            char **out_generated);

char *nm_utils_stable_id_random (void);
char *nm_utils_stable_id_generated_complete (const char *msg);

gboolean nm_utils_ipv6_addr_set_stable_privacy_impl (NMUtilsStableType stable_type,
                                                     struct in6_addr *addr,
                                                     const char *ifname,
                                                     const char *network_id,
                                                     guint32 dad_counter,
                                                     guint8 *host_id,
                                                     gsize host_id_len,
                                                     GError **error);

gboolean nm_utils_ipv6_addr_set_stable_privacy (NMUtilsStableType id_type,
                                                struct in6_addr *addr,
                                                const char *ifname,
                                                const char *network_id,
                                                guint32 dad_counter,
                                                GError **error);

char *nm_utils_hw_addr_gen_random_eth (const char *current_mac_address,
                                       const char *generate_mac_address_mask);
char *nm_utils_hw_addr_gen_stable_eth_impl (NMUtilsStableType stable_type,
                                            const char *stable_id,
                                            const guint8 *host_id,
                                            gsize host_id_len,
                                            const char *ifname,
                                            const char *current_mac_address,
                                            const char *generate_mac_address_mask);
char *nm_utils_hw_addr_gen_stable_eth (NMUtilsStableType stable_type,
                                       const char *stable_id,
                                       const char *ifname,
                                       const char *current_mac_address,
                                       const char *generate_mac_address_mask);

/*****************************************************************************/

GBytes *nm_utils_dhcp_client_id_mac (int arp_type,
                                     const guint8 *hwaddr,
                                     gsize hwaddr_len);

guint32 nm_utils_create_dhcp_iaid (gboolean legacy_unstable_byteorder,
                                   const guint8 *interface_id,
                                   gsize interface_id_len);

GBytes *nm_utils_dhcp_client_id_systemd_node_specific_full (gboolean legacy_unstable_byteorder,
                                                            const guint8 *interface_id,
                                                            gsize interface_id_len,
                                                            const guint8 *machine_id,
                                                            gsize machine_id_len);

GBytes *nm_utils_dhcp_client_id_systemd_node_specific (gboolean legacy_unstable_byteorder,
                                                       const char *ifname);

/*****************************************************************************/

void nm_utils_array_remove_at_indexes (GArray *array, const guint *indexes_to_delete, gsize len);

void nm_utils_setpgid (gpointer unused);

typedef enum {
	NM_UTILS_TEST_NONE                              = 0,

	/* Internal flag, marking that either nm_utils_get_testing() or _nm_utils_set_testing() was called. */
	_NM_UTILS_TEST_INITIALIZED                      = (1LL << 0),

	/* Indicate that test mode is enabled in general. Explicitly calling _nm_utils_set_testing() will always set this flag. */
	_NM_UTILS_TEST_GENERAL                          = (1LL << 1),

	/* Don't check the owner of keyfiles during testing. */
	NM_UTILS_TEST_NO_KEYFILE_OWNER_CHECK            = (1LL << 2),

	_NM_UTILS_TEST_LAST,
	NM_UTILS_TEST_ALL                               = (((_NM_UTILS_TEST_LAST - 1) << 1) - 1) & ~(_NM_UTILS_TEST_INITIALIZED),
} NMUtilsTestFlags;

gboolean nm_utils_get_testing_initialized (void);
NMUtilsTestFlags nm_utils_get_testing (void);
void _nm_utils_set_testing (NMUtilsTestFlags flags);

void nm_utils_g_value_set_strv (GValue *value, GPtrArray *strings);

guint nm_utils_parse_debug_string (const char *string,
                                   const GDebugKey *keys,
                                   guint nkeys);

void nm_utils_ifname_cpy (char *dst, const char *name);

guint32 nm_utils_lifetime_rebase_relative_time_on_now (guint32 timestamp,
                                                       guint32 duration,
                                                       gint32 now);

guint32 nm_utils_lifetime_get (guint32 timestamp,
                               guint32 lifetime,
                               guint32 preferred,
                               gint32 now,
                               guint32 *out_preferred);

gboolean nm_utils_ip4_address_is_link_local (in_addr_t addr);

const char *nm_utils_dnsmasq_status_to_string (int status, char *dest, gsize size);

void nm_utils_get_reverse_dns_domains_ip4 (guint32 ip, guint8 plen, GPtrArray *domains);
void nm_utils_get_reverse_dns_domains_ip6 (const struct in6_addr *ip, guint8 plen, GPtrArray *domains);

struct stat;

gboolean nm_utils_validate_plugin (const char *path, struct stat *stat, GError **error);
char **nm_utils_read_plugin_paths (const char *dirname, const char *prefix);
char *nm_utils_format_con_diff_for_audit (GHashTable *diff);

GVariant *nm_utils_strdict_to_variant (GHashTable *options);

/*****************************************************************************/

/* this enum is compatible with ICMPV6_ROUTER_PREF_* (from <linux/icmpv6.h>,
 * the values for netlink attribute RTA_PREF) and "enum ndp_route_preference"
 * from <ndp.h>. */
typedef enum {
	NM_ICMPV6_ROUTER_PREF_MEDIUM      = 0x0, /* ICMPV6_ROUTER_PREF_MEDIUM */
	NM_ICMPV6_ROUTER_PREF_LOW         = 0x3, /* ICMPV6_ROUTER_PREF_LOW */
	NM_ICMPV6_ROUTER_PREF_HIGH        = 0x1, /* ICMPV6_ROUTER_PREF_HIGH */
	NM_ICMPV6_ROUTER_PREF_INVALID     = 0x2, /* ICMPV6_ROUTER_PREF_INVALID */
} NMIcmpv6RouterPref;

const char *nm_icmpv6_router_pref_to_string (NMIcmpv6RouterPref pref, char *buf, gsize len);

/*****************************************************************************/

const char *nm_activation_type_to_string (NMActivationType activation_type);

/*****************************************************************************/

const char *nm_utils_parse_dns_domain (const char *domain, gboolean *is_routing);

/*****************************************************************************/

#define NM_VPN_ROUTE_METRIC_DEFAULT     50

#endif /* __NM_CORE_UTILS_H__ */
