// SPDX-License-Identifier: GPL-2.0+
/* NetworkManager -- Network link manager
 *
 * Copyright 2004 - 2016 Red Hat, Inc.
 * Copyright 2005 - 2008 Novell, Inc.
 */

#ifndef __NETWORKMANAGER_UTILS_H__
#define __NETWORKMANAGER_UTILS_H__

#include "nm-core-utils.h"

#include "nm-setting-ip-config.h"
#include "platform/nm-platform.h"

/*****************************************************************************/

const char *nm_utils_get_ip_config_method (NMConnection *connection,
                                           int addr_family);

const char *nm_utils_get_shared_wifi_permission (NMConnection *connection);

void nm_utils_complete_generic (NMPlatform *platform,
                                NMConnection *connection,
                                const char *ctype,
                                NMConnection *const*existing_connections,
                                const char *preferred_id,
                                const char *fallback_id_prefix,
                                const char *ifname_prefix,
                                const char *ifname,
                                gboolean default_enable_ipv6);

typedef gboolean (NMUtilsMatchFilterFunc) (NMConnection *connection, gpointer user_data);

NMConnection *nm_utils_match_connection (NMConnection *const*connections,
                                         NMConnection *original,
                                         gboolean indicated,
                                         gboolean device_has_carrier,
                                         gint64 default_v4_metric,
                                         gint64 default_v6_metric,
                                         NMUtilsMatchFilterFunc match_filter_func,
                                         gpointer match_filter_data);

int nm_match_spec_device_by_pllink (const NMPlatformLink *pllink,
                                    const char *match_device_type,
                                    const char *match_dhcp_plugin,
                                    const GSList *specs,
                                    int no_match_value);


/*****************************************************************************/

NMPlatformRoutingRule *nm_ip_routing_rule_to_platform (const NMIPRoutingRule *rule,
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
#define NM_SHUTDOWN_TIMEOUT_MS            1500
#define NM_SHUTDOWN_TIMEOUT_MS_WATCHDOG    500

typedef enum {
	/* The watched_obj argument is a GObject, and shutdown is delayed until the object
	 * gets destroyed (or unregistered). */
	NM_SHUTDOWN_WAIT_TYPE_OBJECT,

	/* The watched_obj argument is a GCancellable, and shutdown is delayed until the object
	 * gets destroyed (or unregistered). Note that after NM_SHUTDOWN_TIMEOUT_MS, the
	 * cancellable will be cancelled to notify listeners about the shutdown. */
	NM_SHUTDOWN_WAIT_TYPE_CANCELLABLE,
} NMShutdownWaitType;

typedef struct _NMShutdownWaitObjHandle NMShutdownWaitObjHandle;

NMShutdownWaitObjHandle *nm_shutdown_wait_obj_register_full (gpointer watched_obj,
                                                             NMShutdownWaitType wait_type,
                                                             char *msg_reason,
                                                             gboolean free_msg_reason);

static inline NMShutdownWaitObjHandle *
nm_shutdown_wait_obj_register_object_full (gpointer watched_obj,
                                           char *msg_reason,
                                           gboolean free_msg_reason)
{
	return nm_shutdown_wait_obj_register_full (watched_obj, NM_SHUTDOWN_WAIT_TYPE_OBJECT, msg_reason, free_msg_reason);
}

#define nm_shutdown_wait_obj_register_object(watched_obj, msg_reason) nm_shutdown_wait_obj_register_object_full((watched_obj), (""msg_reason""), FALSE)

static inline NMShutdownWaitObjHandle *
nm_shutdown_wait_obj_register_cancellable_full (GCancellable *watched_obj,
                                                char *msg_reason,
                                                gboolean free_msg_reason)
{
	return nm_shutdown_wait_obj_register_full (watched_obj, NM_SHUTDOWN_WAIT_TYPE_CANCELLABLE, msg_reason, free_msg_reason);
}

#define nm_shutdown_wait_obj_register_cancellable(watched_obj, msg_reason) nm_shutdown_wait_obj_register_cancellable_full((watched_obj), (""msg_reason""), FALSE)

void nm_shutdown_wait_obj_unregister (NMShutdownWaitObjHandle *handle);

/*****************************************************************************/

const char *
nm_utils_file_is_in_path (const char *abs_filename,
                          const char *abs_path);

/*****************************************************************************/

#endif /* __NETWORKMANAGER_UTILS_H__ */
