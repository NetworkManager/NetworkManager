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
 * Copyright (C) 2015 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-arping-manager.h"

#include <netinet/in.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "nm-platform.h"
#include "nm-utils.h"
#include "NetworkManagerUtils.h"

/*****************************************************************************/

typedef enum {
	STATE_INIT,
	STATE_PROBING,
	STATE_PROBE_DONE,
	STATE_ANNOUNCING,
} State;

typedef struct {
	in_addr_t address;
	GPid pid;
	guint watch;
	gboolean duplicate;
	NMArpingManager *manager;
} AddressInfo;

/*****************************************************************************/

enum {
	PROBE_TERMINATED,
	LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = { 0 };

typedef struct {
	int            ifindex;
	State          state;
	GHashTable    *addresses;
	guint          completed;
	guint          timer;
	guint          round2_id;
} NMArpingManagerPrivate;

struct _NMArpingManager {
	GObject parent;
	NMArpingManagerPrivate _priv;
};

struct _NMArpingManagerClass {
	GObjectClass parent;
};

G_DEFINE_TYPE (NMArpingManager, nm_arping_manager, G_TYPE_OBJECT)

#define NM_ARPING_MANAGER_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMArpingManager, NM_IS_ARPING_MANAGER)

/*****************************************************************************/

#define _NMLOG_DOMAIN         LOGD_IP4
#define _NMLOG_PREFIX_NAME    "arping"
#define _NMLOG(level, ...) \
    G_STMT_START { \
        char _sbuf[64]; \
        \
        nm_log ((level), _NMLOG_DOMAIN, \
                "%s%s: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
                _NMLOG_PREFIX_NAME, \
                self ? nm_sprintf_buf (_sbuf, "[%p,%d]", \
                                       self, \
                                       NM_ARPING_MANAGER_GET_PRIVATE (self)->ifindex) : "" \
                _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
    } G_STMT_END

/*****************************************************************************/

/**
 * nm_arping_manager_add_address:
 * @self: a #NMArpingManager
 * @address: an IP address
 *
 * Add @address to the list of IP addresses to probe.

 * Returns: %TRUE on success, %FALSE if the address was already in the list
 */
gboolean
nm_arping_manager_add_address (NMArpingManager *self, in_addr_t address)
{
	NMArpingManagerPrivate *priv;
	AddressInfo *info;

	g_return_val_if_fail (NM_IS_ARPING_MANAGER (self), FALSE);
	priv = NM_ARPING_MANAGER_GET_PRIVATE (self);
	g_return_val_if_fail (priv->state == STATE_INIT, FALSE);

	if (g_hash_table_lookup (priv->addresses, GUINT_TO_POINTER (address))) {
		_LOGD ("address already exists");
		return FALSE;
	}

	info = g_slice_new0 (AddressInfo);
	info->address = address;
	info->manager = self;

	g_hash_table_insert (priv->addresses, GUINT_TO_POINTER (address), info);

	return TRUE;
}

static void
arping_watch_cb (GPid pid, gint status, gpointer user_data)
{
	AddressInfo *info = user_data;
	NMArpingManager *self = info->manager;
	NMArpingManagerPrivate *priv = NM_ARPING_MANAGER_GET_PRIVATE (self);
	const char *addr;

	info->pid = 0;
	info->watch = 0;
	addr = nm_utils_inet4_ntop (info->address, NULL);

	if (WIFEXITED (status)) {
		if (WEXITSTATUS (status) != 0) {
			_LOGD ("%s already used in the %s network",
			       addr, nm_platform_link_get_name (NM_PLATFORM_GET, priv->ifindex));
			info->duplicate = TRUE;
		} else
			_LOGD ("DAD succeeded for %s", addr);
	} else {
		_LOGD ("stopped unexpectedly with status %d for %s", status, addr);
	}

	if (++priv->completed == g_hash_table_size (priv->addresses)) {
		priv->state = STATE_PROBE_DONE;
		nm_clear_g_source (&priv->timer);
		g_signal_emit (self, signals[PROBE_TERMINATED], 0);
	}
}

static gboolean
arping_timeout_cb (gpointer user_data)
{
	NMArpingManager *self = user_data;
	NMArpingManagerPrivate *priv = NM_ARPING_MANAGER_GET_PRIVATE (self);
	GHashTableIter iter;
	AddressInfo *info;

	priv->timer = 0;

	g_hash_table_iter_init (&iter, priv->addresses);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &info)) {
		nm_clear_g_source (&info->watch);
		if (info->pid) {
			_LOGD ("DAD timed out for %s",
			       nm_utils_inet4_ntop (info->address, NULL));
			nm_utils_kill_child_async (info->pid, SIGTERM, LOGD_IP4,
			                           "arping", 1000, NULL, NULL);
			info->pid = 0;
		}
	}

	priv->state = STATE_PROBE_DONE;
	g_signal_emit (self, signals[PROBE_TERMINATED], 0);

	return G_SOURCE_REMOVE;
}

/**
 * nm_arping_manager_start_probe:
 * @self: a #NMArpingManager
 * @timeout: maximum probe duration in milliseconds
 * @error: location to store error, or %NULL
 *
 * Start probing IP addresses for duplicates; when the probe terminates a
 * PROBE_TERMINATED signal is emitted.
 *
 * Returns: %TRUE on success, %FALSE on failure
 */
gboolean
nm_arping_manager_start_probe (NMArpingManager *self, guint timeout, GError **error)
{
	const char *argv[] = { NULL, "-D", "-q", "-I", NULL, "-c", NULL, "-w", NULL, NULL, NULL };
	NMArpingManagerPrivate *priv;
	GHashTableIter iter;
	AddressInfo *info;
	gs_free char *timeout_str = NULL;

	g_return_val_if_fail (NM_IS_ARPING_MANAGER (self), FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);
	g_return_val_if_fail (timeout, FALSE);

	priv = NM_ARPING_MANAGER_GET_PRIVATE (self);
	g_return_val_if_fail (priv->state == STATE_INIT, FALSE);

	argv[4] = nm_platform_link_get_name (NM_PLATFORM_GET, priv->ifindex);
	if (!argv[4]) {
		/* The device was probably just removed. */
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
		             "can't find a name for ifindex %d", priv->ifindex);
		return FALSE;
	}

	priv->completed = 0;

	argv[0] = nm_utils_find_helper ("arping", NULL, NULL);
	if (!argv[0]) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
		                     "arping could not be found");
		return FALSE;
	}

	timeout_str = g_strdup_printf ("%u", timeout / 1000 + 2);
	argv[6] = timeout_str;
	argv[8] = timeout_str;

	g_hash_table_iter_init (&iter, priv->addresses);

	while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &info)) {
		gs_free char *tmp_str = NULL;
		gboolean success;

		argv[9] = nm_utils_inet4_ntop (info->address, NULL);
		_LOGD ("run %s", (tmp_str = g_strjoinv (" ", (char **) argv)));

		success = g_spawn_async (NULL, (char **) argv, NULL,
		                         G_SPAWN_STDOUT_TO_DEV_NULL |
		                         G_SPAWN_STDERR_TO_DEV_NULL |
		                         G_SPAWN_DO_NOT_REAP_CHILD,
		                         NULL, NULL, &info->pid, NULL);

		info->watch = g_child_watch_add (info->pid, arping_watch_cb, info);
	}

	priv->timer = g_timeout_add (timeout, arping_timeout_cb, self);
	priv->state = STATE_PROBING;

	return TRUE;
}

/**
 * nm_arping_manager_reset:
 * @self: a #NMArpingManager
 *
 * Stop any operation in progress and reset @self to the initial state.
 */
void
nm_arping_manager_reset (NMArpingManager *self)
{
	NMArpingManagerPrivate *priv;

	g_return_if_fail (NM_IS_ARPING_MANAGER (self));
	priv = NM_ARPING_MANAGER_GET_PRIVATE (self);

	nm_clear_g_source (&priv->timer);
	nm_clear_g_source (&priv->round2_id);
	g_hash_table_remove_all (priv->addresses);

	priv->state = STATE_INIT;
}

/**
 * nm_arping_manager_destroy:
 * @self: the #NMArpingManager
 *
 * Calls nm_arping_manager_reset() and unrefs @self.
 */
void
nm_arping_manager_destroy (NMArpingManager *self)
{
	g_return_if_fail (NM_IS_ARPING_MANAGER (self));

	nm_arping_manager_reset (self);
	g_object_unref (self);
}

/**
 * nm_arping_manager_check_address:
 * @self: a #NMArpingManager
 * @address: an IP address
 *
 * Check if an IP address is duplicate. @address must have been added with
 * nm_arping_manager_add_address().
 *
 * Returns: %TRUE if the address is not duplicate, %FALSE otherwise
 */
gboolean
nm_arping_manager_check_address (NMArpingManager *self, in_addr_t address)
{
	NMArpingManagerPrivate *priv;
	AddressInfo *info;

	g_return_val_if_fail (NM_IS_ARPING_MANAGER (self), FALSE);
	priv = NM_ARPING_MANAGER_GET_PRIVATE (self);
	g_return_val_if_fail (   priv->state == STATE_INIT
	                      || priv->state == STATE_PROBE_DONE, FALSE);

	info = g_hash_table_lookup (priv->addresses, GUINT_TO_POINTER (address));
	g_return_val_if_fail (info, FALSE);

	return !info->duplicate;
}

static void
send_announcements (NMArpingManager *self, const char *mode_arg)
{
	NMArpingManagerPrivate *priv = NM_ARPING_MANAGER_GET_PRIVATE (self);
	const char *argv[] = { NULL, mode_arg, "-q", "-I", NULL, "-c", "1", NULL, NULL };
	int ip_arg = G_N_ELEMENTS (argv) - 2;
	GError *error = NULL;
	GHashTableIter iter;
	AddressInfo *info;

	argv[4] = nm_platform_link_get_name (NM_PLATFORM_GET, priv->ifindex);
	if (!argv[4]) {
		/* The device was probably just removed. */
		_LOGW ("can't find a name for ifindex %d", priv->ifindex);
		return;
	}

	argv[0] = nm_utils_find_helper ("arping", NULL, NULL);
	if (!argv[0]) {
		_LOGW ("arping could not be found; no ARPs will be sent");
		return;
	}

	g_hash_table_iter_init (&iter, priv->addresses);

	while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &info)) {
		gs_free char *tmp_str = NULL;
		gboolean success;

		if (info->duplicate)
			continue;

		argv[ip_arg] = nm_utils_inet4_ntop (info->address, NULL);
		_LOGD ("run %s", (tmp_str = g_strjoinv (" ", (char **) argv)));

		success = g_spawn_async (NULL, (char **) argv, NULL,
		                         G_SPAWN_STDOUT_TO_DEV_NULL |
		                         G_SPAWN_STDERR_TO_DEV_NULL,
		                         NULL, NULL, NULL, &error);
		if (!success) {
			_LOGW ("could not send ARP for address %s: %s", argv[ip_arg],
			       error->message);
			g_clear_error (&error);
		}
	}
}

static gboolean
arp_announce_round2 (gpointer self)
{
	NMArpingManagerPrivate *priv = NM_ARPING_MANAGER_GET_PRIVATE ((NMArpingManager *) self);

	priv->round2_id = 0;
	send_announcements (self, "-U");
	priv->state = STATE_INIT;
	g_hash_table_remove_all (priv->addresses);

	return G_SOURCE_REMOVE;
}

/**
 * nm_arping_manager_announce_addresses:
 * @self: a #NMArpingManager
 *
 * Start announcing addresses.
 */
void
nm_arping_manager_announce_addresses (NMArpingManager *self)
{
	NMArpingManagerPrivate *priv = NM_ARPING_MANAGER_GET_PRIVATE (self);

	g_return_if_fail (   priv->state == STATE_INIT
	                  || priv->state == STATE_PROBE_DONE);

	send_announcements (self, "-A");
	nm_clear_g_source (&priv->round2_id);
	priv->round2_id = g_timeout_add_seconds (2, arp_announce_round2, self);
	priv->state = STATE_ANNOUNCING;
}

static void
destroy_address_info (gpointer data)
{
	AddressInfo *info = (AddressInfo *) data;

	nm_clear_g_source (&info->watch);

	if (info->pid) {
		nm_utils_kill_child_async (info->pid, SIGTERM, LOGD_IP4, "arping",
		                           1000, NULL, NULL);
	}

	g_slice_free (AddressInfo, info);
}

/*****************************************************************************/

static void
nm_arping_manager_init (NMArpingManager *self)
{
	NMArpingManagerPrivate *priv = NM_ARPING_MANAGER_GET_PRIVATE (self);

	priv->addresses = g_hash_table_new_full (g_direct_hash, g_direct_equal,
	                                         NULL, destroy_address_info);
	priv->state = STATE_INIT;
}

NMArpingManager *
nm_arping_manager_new (int ifindex)
{
	NMArpingManager *self;
	NMArpingManagerPrivate *priv;

	self = g_object_new (NM_TYPE_ARPING_MANAGER, NULL);
	priv = NM_ARPING_MANAGER_GET_PRIVATE (self);
	priv->ifindex = ifindex;
	return self;
}

static void
dispose (GObject *object)
{
	NMArpingManager *self = NM_ARPING_MANAGER (object);
	NMArpingManagerPrivate *priv = NM_ARPING_MANAGER_GET_PRIVATE (self);

	nm_clear_g_source (&priv->timer);
	nm_clear_g_source (&priv->round2_id);
	g_clear_pointer (&priv->addresses, g_hash_table_destroy);

	G_OBJECT_CLASS (nm_arping_manager_parent_class)->dispose (object);
}

static void
nm_arping_manager_class_init (NMArpingManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->dispose = dispose;

	signals[PROBE_TERMINATED] =
	    g_signal_new (NM_ARPING_MANAGER_PROBE_TERMINATED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 0);
}
