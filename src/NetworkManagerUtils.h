/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2004 - 2016 Red Hat, Inc.
 * Copyright (C) 2005 - 2008 Novell, Inc.
 */

#ifndef __NETWORKMANAGER_UTILS_H__
#define __NETWORKMANAGER_UTILS_H__

#include "nm-core-utils.h"
#include "nm-glib-aux/nm-dedup-multi.h"
#include "nm-setting-ip-config.h"
#include "nm-setting-ip6-config.h"
#include "platform/nm-platform.h"

/*****************************************************************************/

const char *nm_utils_get_ip_config_method(NMConnection *connection, int addr_family);

const char *nm_utils_get_shared_wifi_permission(NMConnection *connection);

void nm_utils_complete_generic(NMPlatform *         platform,
                               NMConnection *       connection,
                               const char *         ctype,
                               NMConnection *const *existing_connections,
                               const char *         preferred_id,
                               const char *         fallback_id_prefix,
                               const char *         ifname_prefix,
                               const char *         ifname,
                               gboolean             default_enable_ipv6);

typedef gboolean(NMUtilsMatchFilterFunc)(NMConnection *connection, gpointer user_data);

NMConnection *nm_utils_match_connection(NMConnection *const *  connections,
                                        NMConnection *         original,
                                        gboolean               indicated,
                                        gboolean               device_has_carrier,
                                        gint64                 default_v4_metric,
                                        gint64                 default_v6_metric,
                                        NMUtilsMatchFilterFunc match_filter_func,
                                        gpointer               match_filter_data);

int nm_match_spec_device_by_pllink(const NMPlatformLink *pllink,
                                   const char *          match_device_type,
                                   const char *          match_dhcp_plugin,
                                   const GSList *        specs,
                                   int                   no_match_value);

/*****************************************************************************/

NMPlatformRoutingRule *nm_ip_routing_rule_to_platform(const NMIPRoutingRule *rule,
                                                      NMPlatformRoutingRule *out_pl);

/*****************************************************************************/

/* during shutdown, there are two relevant timeouts. One is
 * NM_SHUTDOWN_TIMEOUT_MS which is plenty of time, that we give for all
 * actions to complete. Of course, during shutdown components should hurry
 * to cleanup.
 *
 * When we initiate shutdown, we should start killing child processes
 * with SIGTERM. If they don't complete within NM_SHUTDOWN_TIMEOUT_MS, we send
 * SIGKILL.
 *
 * After NM_SHUTDOWN_TIMEOUT_MS, NetworkManager will however not yet terminate right
 * away. It iterates the mainloop for another NM_SHUTDOWN_TIMEOUT_MS_WATCHDOG. This
 * should give time to reap the child process (after SIGKILL).
 *
 * So, the maximum time we should wait before sending SIGKILL should be at most
 * NM_SHUTDOWN_TIMEOUT_MS.
 */
#define NM_SHUTDOWN_TIMEOUT_MS          1500
#define NM_SHUTDOWN_TIMEOUT_MS_WATCHDOG 500

typedef enum {
    /* There is no watched_obj argument, and the shutdown is delayed until the user
     * explicitly calls unregister on the returned handle. */
    NM_SHUTDOWN_WAIT_TYPE_HANDLE,

    /* The watched_obj argument is a GObject, and shutdown is delayed until the object
     * gets destroyed (or unregistered). */
    NM_SHUTDOWN_WAIT_TYPE_OBJECT,

    /* The watched_obj argument is a GCancellable, and shutdown is delayed until the object
     * gets destroyed (or unregistered). Note that after NM_SHUTDOWN_TIMEOUT_MS, the
     * cancellable will be cancelled to notify listeners about the shutdown. */
    NM_SHUTDOWN_WAIT_TYPE_CANCELLABLE,
} NMShutdownWaitType;

typedef struct _NMShutdownWaitObjHandle NMShutdownWaitObjHandle;

NMShutdownWaitObjHandle *nm_shutdown_wait_obj_register_full(gpointer           watched_obj,
                                                            NMShutdownWaitType wait_type,
                                                            char *             msg_reason,
                                                            gboolean           free_msg_reason);

static inline NMShutdownWaitObjHandle *
nm_shutdown_wait_obj_register_object_full(gpointer watched_obj,
                                          char *   msg_reason,
                                          gboolean free_msg_reason)
{
    return nm_shutdown_wait_obj_register_full(watched_obj,
                                              NM_SHUTDOWN_WAIT_TYPE_OBJECT,
                                              msg_reason,
                                              free_msg_reason);
}

#define nm_shutdown_wait_obj_register_object(watched_obj, msg_reason) \
    nm_shutdown_wait_obj_register_object_full((watched_obj), ("" msg_reason ""), FALSE)

static inline NMShutdownWaitObjHandle *
nm_shutdown_wait_obj_register_handle_full(char *msg_reason, gboolean free_msg_reason)
{
    return nm_shutdown_wait_obj_register_full(NULL,
                                              NM_SHUTDOWN_WAIT_TYPE_HANDLE,
                                              msg_reason,
                                              free_msg_reason);
}

#define nm_shutdown_wait_obj_register_handle(msg_reason) \
    nm_shutdown_wait_obj_register_handle_full(("" msg_reason ""), FALSE)

static inline NMShutdownWaitObjHandle *
nm_shutdown_wait_obj_register_cancellable_full(GCancellable *watched_obj,
                                               char *        msg_reason,
                                               gboolean      free_msg_reason)
{
    return nm_shutdown_wait_obj_register_full(watched_obj,
                                              NM_SHUTDOWN_WAIT_TYPE_CANCELLABLE,
                                              msg_reason,
                                              free_msg_reason);
}

#define nm_shutdown_wait_obj_register_cancellable(watched_obj, msg_reason) \
    nm_shutdown_wait_obj_register_cancellable_full((watched_obj), ("" msg_reason ""), FALSE)

void nm_shutdown_wait_obj_unregister(NMShutdownWaitObjHandle *handle);

/*****************************************************************************/

const char *nm_utils_file_is_in_path(const char *abs_filename, const char *abs_path);

/*****************************************************************************/

GPtrArray *
nm_utils_qdiscs_from_tc_setting(NMPlatform *platform, NMSettingTCConfig *s_tc, int ip_ifindex);
GPtrArray *
nm_utils_tfilters_from_tc_setting(NMPlatform *platform, NMSettingTCConfig *s_tc, int ip_ifindex);

void nm_utils_ip_route_attribute_to_platform(int                addr_family,
                                             NMIPRoute *        s_route,
                                             NMPlatformIPRoute *r,
                                             guint32            route_table);

void nm_utils_ip_addresses_to_dbus(int                          addr_family,
                                   const NMDedupMultiHeadEntry *head_entry,
                                   const NMPObject *            best_default_route,
                                   NMSettingIP6ConfigPrivacy    ipv6_privacy,
                                   GVariant **                  out_address_data,
                                   GVariant **                  out_addresses);

void nm_utils_ip_routes_to_dbus(int                          addr_family,
                                const NMDedupMultiHeadEntry *head_entry,
                                GVariant **                  out_route_data,
                                GVariant **                  out_routes);

/*****************************************************************************/

/* For now, all we track about a DHCP lease is the GHashTable with
 * the options.
 *
 * We don't add a separate type for that, but we also don't want to use
 * GHashTable directly (because most importantly leases should be immutable
 * and passing a GHashTable pointer around neither makes it clear that
 * this is a lease nor that it's immutable.
 *
 * Instead, add a simple opaque pointer and accessors that cast to a GHashTable.
 *
 * It has no overhead at run time, but gives some rudimentary type safety. */

typedef struct _NMDhcpLease NMDhcpLease;

static inline NMDhcpLease *
nm_dhcp_lease_new_from_options(GHashTable *options_take)
{
    /* a NMDhcpLease is really just a GHashTable. But it's also supposed to be *immutable*.
     *
     * Hence, the API here takes over ownership of the reference to @options_take, that
     * is to emphasize that we acquire ownership of the hash, and it should not be modified
     * anymore. */
    return (NMDhcpLease *) options_take;
}

static inline GHashTable *
nm_dhcp_lease_get_options(NMDhcpLease *lease)
{
    return (GHashTable *) lease;
}

static inline void
nm_dhcp_lease_ref(NMDhcpLease *lease)
{
    if (lease)
        g_hash_table_ref((GHashTable *) lease);
}

static inline void
nm_dhcp_lease_unref(NMDhcpLease *lease)
{
    if (lease)
        g_hash_table_unref((GHashTable *) lease);
}

static inline const char *
nm_dhcp_lease_lookup_option(NMDhcpLease *lease, const char *option)
{
    nm_assert(option);

    return nm_g_hash_table_lookup((GHashTable *) lease, option);
}

NM_AUTO_DEFINE_FCN(NMDhcpLease *, _nm_auto_unref_dhcplease, nm_dhcp_lease_unref);
#define nm_auto_unref_dhcplease nm_auto(_nm_auto_unref_dhcplease)

/*****************************************************************************/

typedef struct _NMUtilsShareRules NMUtilsShareRules;

NMUtilsShareRules *nm_utils_share_rules_new(void);

void nm_utils_share_rules_free(NMUtilsShareRules *self);

void
nm_utils_share_rules_add_rule_take(NMUtilsShareRules *self, const char *table, char *rule_take);

static inline void
nm_utils_share_rules_add_rule(NMUtilsShareRules *self, const char *table, const char *rule)
{
    nm_utils_share_rules_add_rule_take(self, table, g_strdup(rule));
}

#define nm_utils_share_rules_add_rule_v(self, table, ...) \
    nm_utils_share_rules_add_rule_take((self), (table), g_strdup_printf(__VA_ARGS__))

void nm_utils_share_rules_add_all_rules(NMUtilsShareRules *self,
                                        const char *       ip_iface,
                                        in_addr_t          addr,
                                        guint              plen);

void nm_utils_share_rules_apply(NMUtilsShareRules *self, gboolean shared);

/*****************************************************************************/

#endif /* __NETWORKMANAGER_UTILS_H__ */
