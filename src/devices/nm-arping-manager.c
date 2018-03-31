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
 * Copyright (C) 2015-2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-arping-manager.h"

#include <netinet/in.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "platform/nm-platform.h"
#include "nm-utils.h"
#include "NetworkManagerUtils.h"
#include "n-acd/src/n-acd.h"

/*****************************************************************************/

typedef enum {
	STATE_INIT,
	STATE_PROBING,
	STATE_PROBE_DONE,
	STATE_ANNOUNCING,
} State;

typedef struct {
	in_addr_t address;
	gboolean duplicate;
	NMArpingManager *manager;
	NAcd *acd;
	GIOChannel *channel;
	guint event_id;
} AddressInfo;

enum {
	PROBE_TERMINATED,
	LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = { 0 };

typedef struct {
	int            ifindex;
	guint8         hwaddr[ETH_ALEN];
	State          state;
	GHashTable    *addresses;
	guint          completed;
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
        int _ifindex = (self) ? NM_ARPING_MANAGER_GET_PRIVATE (self)->ifindex : 0; \
        \
        nm_log ((level), _NMLOG_DOMAIN, \
                nm_platform_link_get_name (NM_PLATFORM_GET, _ifindex), \
                NULL, \
                "%s%s: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
                _NMLOG_PREFIX_NAME, \
                self ? nm_sprintf_buf (_sbuf, "[%p,%d]", self, _ifindex) : "" \
                _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
    } G_STMT_END

/*****************************************************************************/

static const char *
_acd_event_to_string (unsigned int event)
{
	switch (event) {
	case N_ACD_EVENT_READY:
		return "ready";
	case N_ACD_EVENT_USED:
		return "used";
	case N_ACD_EVENT_DEFENDED:
		return "defended";
	case N_ACD_EVENT_CONFLICT:
		return "conflict";
	case N_ACD_EVENT_DOWN:
		return "down";
	}
	return NULL;
}

#define acd_event_to_string(event) NM_UTILS_LOOKUP_STR (_acd_event_to_string, event)

static const char *
_acd_error_to_string (int error)
{
	if (error < 0)
		return strerror(-error);

	switch (error) {
	case _N_ACD_E_SUCCESS:
		return "success";
	case N_ACD_E_DONE:
		return "no more events (engine running)";
	case N_ACD_E_STOPPED:
		return "no more events (engine stopped)";
	case N_ACD_E_PREEMPTED:
		return "preempted";
	case N_ACD_E_INVALID_ARGUMENT:
		return "invalid argument";
	case N_ACD_E_BUSY:
		return "busy";
	}
	return NULL;
}

#define acd_error_to_string(error) NM_UTILS_LOOKUP_STR (_acd_error_to_string, error)

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

	if (g_hash_table_lookup (priv->addresses, GUINT_TO_POINTER (address)))
		return FALSE;

	info = g_slice_new0 (AddressInfo);
	info->address = address;
	info->manager = self;

	g_hash_table_insert (priv->addresses, GUINT_TO_POINTER (address), info);

	return TRUE;
}

static gboolean
acd_event (GIOChannel *source, GIOCondition condition, gpointer data)
{
	AddressInfo *info = data;
	NMArpingManager *self = info->manager;
	NMArpingManagerPrivate *priv = NM_ARPING_MANAGER_GET_PRIVATE (self);
	NAcdEvent *event;
	char address_str[INET_ADDRSTRLEN];
	gs_free char *hwaddr_str = NULL;
	int r;

	if (   n_acd_dispatch (info->acd)
	    || n_acd_pop_event (info->acd, &event))
		return G_SOURCE_CONTINUE;

	switch (event->event) {
	case N_ACD_EVENT_READY:
		info->duplicate = FALSE;
		if (priv->state == STATE_ANNOUNCING) {
			r = n_acd_announce (info->acd, N_ACD_DEFEND_ONCE);
			if (r) {
				_LOGW ("couldn't announce address %s on interface '%s': %s",
				       nm_utils_inet4_ntop (info->address, address_str),
				       nm_platform_link_get_name (NM_PLATFORM_GET, priv->ifindex),
				       acd_error_to_string (r));
			} else {
				_LOGD ("announcing address %s",
				       nm_utils_inet4_ntop (info->address, address_str));
			}
		}
		break;
	case N_ACD_EVENT_USED:
		info->duplicate = TRUE;
		break;
	case N_ACD_EVENT_DEFENDED:
		_LOGD ("defended address %s from host %s",
		       nm_utils_inet4_ntop (info->address, address_str),
		       (hwaddr_str = nm_utils_hwaddr_ntoa (event->defended.sender,
		                                           event->defended.n_sender)));
		break;
	case N_ACD_EVENT_CONFLICT:
		_LOGW ("conflict for address %s detected with host %s on interface '%s'",
		       nm_utils_inet4_ntop (info->address, address_str),
		       (hwaddr_str = nm_utils_hwaddr_ntoa (event->defended.sender,
		                                           event->defended.n_sender)),
		       nm_platform_link_get_name (NM_PLATFORM_GET, priv->ifindex));
		break;
	default:
		_LOGD ("event '%s' for address %s",
		       acd_event_to_string (event->event),
		       nm_utils_inet4_ntop (info->address, address_str));
		return G_SOURCE_CONTINUE;
	}

	if (   priv->state == STATE_PROBING
	    && ++priv->completed == g_hash_table_size (priv->addresses)) {
		priv->state = STATE_PROBE_DONE;
		g_signal_emit (self, signals[PROBE_TERMINATED], 0);
	}

	return G_SOURCE_CONTINUE;
}

static gboolean
acd_probe_start (NMArpingManager *self,
                 AddressInfo *info,
                 guint64 timeout)
{
	NMArpingManagerPrivate *priv = NM_ARPING_MANAGER_GET_PRIVATE (self);
	NAcdConfig *config;
	int r, fd;

	r = n_acd_new (&info->acd);
	if (r) {
		_LOGW ("could not create ACD for %s on interface '%s': %s",
		       nm_utils_inet4_ntop (info->address, NULL),
		       nm_platform_link_get_name (NM_PLATFORM_GET, priv->ifindex),
		       acd_error_to_string (r));
		return FALSE;
	}

	n_acd_get_fd (info->acd, &fd);
	info->channel = g_io_channel_unix_new (fd);
	info->event_id = g_io_add_watch (info->channel, G_IO_IN, acd_event, info);

	config = &(NAcdConfig) {
		.ifindex = priv->ifindex,
		.mac = priv->hwaddr,
		.n_mac = ETH_ALEN,
		.ip = info->address,
		.timeout_msec = timeout,
		.transport = N_ACD_TRANSPORT_ETHERNET,
	};

	r = n_acd_start (info->acd, config);
	if (r) {
		_LOGW ("could not start probe for %s on interface '%s': %s",
		       nm_utils_inet4_ntop (info->address, NULL),
		       nm_platform_link_get_name (NM_PLATFORM_GET, priv->ifindex),
		       acd_error_to_string (r));
		return FALSE;
	}

	_LOGD ("start probe for %s", nm_utils_inet4_ntop (info->address, NULL));

	return TRUE;
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
 * Returns: %TRUE if at least one probe could be started, %FALSE otherwise
 */
gboolean
nm_arping_manager_start_probe (NMArpingManager *self, guint timeout)
{
	NMArpingManagerPrivate *priv;
	GHashTableIter iter;
	AddressInfo *info;
	gs_free char *timeout_str = NULL;
	gboolean success = FALSE;

	g_return_val_if_fail (NM_IS_ARPING_MANAGER (self), FALSE);
	priv = NM_ARPING_MANAGER_GET_PRIVATE (self);
	g_return_val_if_fail (priv->state == STATE_INIT, FALSE);

	priv->completed = 0;

	g_hash_table_iter_init (&iter, priv->addresses);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &info))
		success |= acd_probe_start (self, info, timeout);

	if (success)
		priv->state = STATE_PROBING;

	return success;
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
	GHashTableIter iter;
	AddressInfo *info;
	int r;

	if (priv->state == STATE_INIT) {
		/* n-acd can't announce without probing, therefore let's
		 * start a fake probe with zero timeout and then perform
		 * the announce. */
		priv->state = STATE_ANNOUNCING;
		g_hash_table_iter_init (&iter, priv->addresses);
		while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &info)) {
			if (!acd_probe_start (self, info, 0)) {
				_LOGW ("couldn't announce address %s on interface '%s'",
				       nm_utils_inet4_ntop (info->address, NULL),
				       nm_platform_link_get_name (NM_PLATFORM_GET, priv->ifindex));
			}
		}
	} else if (priv->state == STATE_PROBE_DONE) {
		priv->state = STATE_ANNOUNCING;
		g_hash_table_iter_init (&iter, priv->addresses);
		while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &info)) {
			if (info->duplicate)
				continue;
			r = n_acd_announce (info->acd, N_ACD_DEFEND_ONCE);
			if (r) {
				_LOGW ("couldn't announce address %s on interface '%s': %s",
				       nm_utils_inet4_ntop (info->address, NULL),
				       nm_platform_link_get_name (NM_PLATFORM_GET, priv->ifindex),
				       acd_error_to_string (r));
			} else
				_LOGD ("announcing address %s", nm_utils_inet4_ntop (info->address, NULL));
		}
	} else
		nm_assert_not_reached ();
}

static void
destroy_address_info (gpointer data)
{
	AddressInfo *info = (AddressInfo *) data;

	g_clear_pointer (&info->channel, g_io_channel_unref);
	g_clear_pointer (&info->acd, n_acd_free);
	nm_clear_g_source (&info->event_id);

	g_slice_free (AddressInfo, info);
}

/*****************************************************************************/

static void
nm_arping_manager_init (NMArpingManager *self)
{
	NMArpingManagerPrivate *priv = NM_ARPING_MANAGER_GET_PRIVATE (self);

	priv->addresses = g_hash_table_new_full (nm_direct_hash, NULL,
	                                         NULL, destroy_address_info);
	priv->state = STATE_INIT;
}

NMArpingManager *
nm_arping_manager_new (int ifindex, const guint8 *hwaddr, size_t hwaddr_len)
{
	NMArpingManager *self;
	NMArpingManagerPrivate *priv;

	g_return_val_if_fail (hwaddr, NULL);
	g_return_val_if_fail (hwaddr_len == ETH_ALEN, NULL);

	self = g_object_new (NM_TYPE_ARPING_MANAGER, NULL);
	priv = NM_ARPING_MANAGER_GET_PRIVATE (self);
	priv->ifindex = ifindex;
	memcpy (priv->hwaddr, hwaddr, ETH_ALEN);

	return self;
}

static void
dispose (GObject *object)
{
	NMArpingManager *self = NM_ARPING_MANAGER (object);
	NMArpingManagerPrivate *priv = NM_ARPING_MANAGER_GET_PRIVATE (self);

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
