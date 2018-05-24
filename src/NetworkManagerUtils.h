/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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

#ifndef __NETWORKMANAGER_UTILS_H__
#define __NETWORKMANAGER_UTILS_H__

#include "nm-core-utils.h"

/*****************************************************************************/

const char *nm_utils_get_shared_wifi_permission (NMConnection *connection);

void nm_utils_complete_generic (NMPlatform *platform,
                                NMConnection *connection,
                                const char *ctype,
                                NMConnection *const*existing_connections,
                                const char *preferred_id,
                                const char *fallback_id_prefix,
                                const char *ifname_prefix,
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
                                    const GSList *specs,
                                    int no_match_value);


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
 * away. It iterates the mainloop for another NM_SHUTDOWN_TIMEOUT_MS_EXTRA. This
 * should give time to reap the child process (after SIGKILL).
 *
 * So, the maxiumum time we should wait before sending SIGKILL should be at most
 * NM_SHUTDOWN_TIMEOUT_MS.
 */
#define NM_SHUTDOWN_TIMEOUT_MS            1500
#define NM_SHUTDOWN_TIMEOUT_MS_WATCHDOG    500

typedef struct _NMShutdownWaitObjHandle NMShutdownWaitObjHandle;

NMShutdownWaitObjHandle *_nm_shutdown_wait_obj_register (GObject *watched_obj,
                                                        const char *msg_reason);

#define nm_shutdown_wait_obj_register(watched_obj, msg_reason) _nm_shutdown_wait_obj_register((watched_obj), (""msg_reason""))

void nm_shutdown_wait_obj_unregister (NMShutdownWaitObjHandle *handle);

/*****************************************************************************/

#endif /* __NETWORKMANAGER_UTILS_H__ */
