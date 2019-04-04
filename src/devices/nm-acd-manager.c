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

#include "nm-acd-manager.h"

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
	NAcdProbe *probe;
} AddressInfo;

struct _NMAcdManager {
	int            ifindex;
	guint8         hwaddr[ETH_ALEN];
	State          state;
	GHashTable    *addresses;
	guint          completed;
	NAcd          *acd;
	GIOChannel    *channel;
	guint          event_id;

	NMAcdCallbacks callbacks;
	gpointer user_data;
};

/*****************************************************************************/

#define _NMLOG_DOMAIN         LOGD_IP4
#define _NMLOG_PREFIX_NAME    "acd"
#define _NMLOG(level, ...) \
    G_STMT_START { \
        char _sbuf[64]; \
        \
        nm_log ((level), _NMLOG_DOMAIN, \
                self && self->ifindex > 0 ? nm_platform_link_get_name (NM_PLATFORM_GET, self->ifindex) : NULL, \
                NULL, \
                "%s%s: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
                _NMLOG_PREFIX_NAME, \
                self ? nm_sprintf_buf (_sbuf, "[%p,%d]", self, self->ifindex) : "" \
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

#define acd_event_to_string_a(event) NM_UTILS_LOOKUP_STR_A (_acd_event_to_string, event)

static const char *
acd_error_to_string (int error)
{
	if (error < 0)
		return nm_strerror_native (-error);

	switch (error) {
	case _N_ACD_E_SUCCESS:
		return "success";
	case N_ACD_E_PREEMPTED:
		return "preempted";
	case N_ACD_E_INVALID_ARGUMENT:
		return "invalid argument";
	}

	g_return_val_if_reached (NULL);
}

static int
acd_error_to_nmerr (int error, gboolean always_fail)
{
	if (error < 0)
		return -nm_errno_native (error);

	if (always_fail) {
		if (NM_IN_SET (error, N_ACD_E_PREEMPTED,
		                      N_ACD_E_INVALID_ARGUMENT))
			return -NME_UNSPEC;
		g_return_val_if_reached (-NME_UNSPEC);
	}

	/* so, @error is either zero (indicating success) or one
	 * of the special status codes like N_ACD_E_*. In both cases,
	 * return the positive value here. */
	if (NM_IN_SET (error, _N_ACD_E_SUCCESS,
	                      N_ACD_E_PREEMPTED,
	                      N_ACD_E_INVALID_ARGUMENT))
		return error;

	g_return_val_if_reached (error);
}

/*****************************************************************************/

/**
 * nm_acd_manager_add_address:
 * @self: a #NMAcdManager
 * @address: an IP address
 *
 * Add @address to the list of IP addresses to probe.

 * Returns: %TRUE on success, %FALSE if the address was already in the list
 */
gboolean
nm_acd_manager_add_address (NMAcdManager *self, in_addr_t address)
{
	AddressInfo *info;

	g_return_val_if_fail (self, FALSE);
	g_return_val_if_fail (self->state == STATE_INIT, FALSE);

	if (g_hash_table_lookup (self->addresses, GUINT_TO_POINTER (address)))
		return FALSE;

	info = g_slice_new0 (AddressInfo);
	info->address = address;

	g_hash_table_insert (self->addresses, GUINT_TO_POINTER (address), info);

	return TRUE;
}

static gboolean
acd_event (GIOChannel *source, GIOCondition condition, gpointer data)
{
	NMAcdManager *self = data;
	NAcdEvent *event;
	AddressInfo *info;
	gboolean emit_probe_terminated = FALSE;
	char address_str[INET_ADDRSTRLEN];
	gs_free char *hwaddr_str = NULL;
	int r;

	if (n_acd_dispatch (self->acd))
		return G_SOURCE_CONTINUE;

	while (   !n_acd_pop_event (self->acd, &event)
	       && event) {
		gboolean check_probing_done = FALSE;

		switch (event->event) {
		case N_ACD_EVENT_READY:
			n_acd_probe_get_userdata (event->ready.probe, (void **) &info);
			info->duplicate = FALSE;
			if (self->state == STATE_ANNOUNCING) {
				/* fake probe ended, start announcing */
				r = n_acd_probe_announce (info->probe, N_ACD_DEFEND_ONCE);
				if (r) {
					_LOGW ("couldn't announce address %s on interface '%s': %s",
					       nm_utils_inet4_ntop (info->address, address_str),
					       nm_platform_link_get_name (NM_PLATFORM_GET, self->ifindex),
					       acd_error_to_string (r));
				} else {
					_LOGD ("announcing address %s",
					       nm_utils_inet4_ntop (info->address, address_str));
				}
			}
			check_probing_done = TRUE;
			break;
		case N_ACD_EVENT_USED:
			n_acd_probe_get_userdata (event->used.probe, (void **) &info);
			info->duplicate = TRUE;
			check_probing_done = TRUE;
			break;
		case N_ACD_EVENT_DEFENDED:
			n_acd_probe_get_userdata (event->defended.probe, (void **) &info);
			_LOGD ("defended address %s from host %s",
			       nm_utils_inet4_ntop (info->address, address_str),
			       (hwaddr_str = nm_utils_hwaddr_ntoa (event->defended.sender,
			                                           event->defended.n_sender)));
			break;
		case N_ACD_EVENT_CONFLICT:
			n_acd_probe_get_userdata (event->conflict.probe, (void **) &info);
			_LOGW ("conflict for address %s detected with host %s on interface '%s'",
			       nm_utils_inet4_ntop (info->address, address_str),
			       (hwaddr_str = nm_utils_hwaddr_ntoa (event->defended.sender,
			                                           event->defended.n_sender)),
			       nm_platform_link_get_name (NM_PLATFORM_GET, self->ifindex));
			break;
		default:
			_LOGD ("unhandled event '%s'", acd_event_to_string_a (event->event));
			break;
		}

		if (   check_probing_done
		    && self->state == STATE_PROBING
		    && ++self->completed == g_hash_table_size (self->addresses)) {
			self->state = STATE_PROBE_DONE;
			emit_probe_terminated = TRUE;
		}
	}

	if (emit_probe_terminated) {
		if (self->callbacks.probe_terminated_callback) {
			self->callbacks.probe_terminated_callback (self,
			                                           self->user_data);
		}
	}

	return G_SOURCE_CONTINUE;
}

static gboolean
acd_probe_add (NMAcdManager *self,
               AddressInfo *info,
               guint64 timeout)
{
	NAcdProbeConfig *probe_config;
	int r;
	char sbuf[NM_UTILS_INET_ADDRSTRLEN];

	r = n_acd_probe_config_new (&probe_config);
	if (r) {
		_LOGW ("could not create probe config for %s on interface '%s': %s",
		       nm_utils_inet4_ntop (info->address, sbuf),
		       nm_platform_link_get_name (NM_PLATFORM_GET, self->ifindex),
		       acd_error_to_string (r));
		return FALSE;
	}

	n_acd_probe_config_set_ip (probe_config, (struct in_addr) { info->address });
	n_acd_probe_config_set_timeout (probe_config, timeout);

	r = n_acd_probe (self->acd, &info->probe, probe_config);
	if (r) {
		_LOGW ("could not start probe for %s on interface '%s': %s",
		       nm_utils_inet4_ntop (info->address, sbuf),
		       nm_platform_link_get_name (NM_PLATFORM_GET, self->ifindex),
		       acd_error_to_string (r));
		n_acd_probe_config_free (probe_config);
		return FALSE;
	}

	n_acd_probe_set_userdata (info->probe, info);
	n_acd_probe_config_free (probe_config);

	return TRUE;
}

static int
acd_init (NMAcdManager *self)
{
	NAcdConfig *config;
	int r;

	if (self->acd)
		return 0;

	r = n_acd_config_new (&config);
	if (r)
		return r;

	n_acd_config_set_ifindex (config, self->ifindex);
	n_acd_config_set_transport (config, N_ACD_TRANSPORT_ETHERNET);
	n_acd_config_set_mac (config, self->hwaddr, ETH_ALEN);

	r = n_acd_new (&self->acd, config);
	n_acd_config_free (config);
	return r;
}

/**
 * nm_acd_manager_start_probe:
 * @self: a #NMAcdManager
 * @timeout: maximum probe duration in milliseconds
 * @error: location to store error, or %NULL
 *
 * Start probing IP addresses for duplicates; when the probe terminates a
 * PROBE_TERMINATED signal is emitted.
 *
 * Returns: 0 on success or a negative NetworkManager error code (NME_*).
 */
int
nm_acd_manager_start_probe (NMAcdManager *self, guint timeout)
{
	GHashTableIter iter;
	AddressInfo *info;
	gboolean success = FALSE;
	int fd, r;

	g_return_val_if_fail (self, FALSE);
	g_return_val_if_fail (self->state == STATE_INIT, FALSE);

	r = acd_init (self);
	if (r) {
		_LOGW ("couldn't init ACD for probing on interface '%s': %s",
		       nm_platform_link_get_name (NM_PLATFORM_GET, self->ifindex),
		       acd_error_to_string (r));
		return acd_error_to_nmerr (r, TRUE);
	}

	self->completed = 0;

	g_hash_table_iter_init (&iter, self->addresses);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &info))
		success |= acd_probe_add (self, info, timeout);

	if (success)
		self->state = STATE_PROBING;

	n_acd_get_fd (self->acd, &fd);
	self->channel = g_io_channel_unix_new (fd);
	self->event_id = g_io_add_watch (self->channel, G_IO_IN, acd_event, self);

	return success ? 0 : -NME_UNSPEC;
}

/**
 * nm_acd_manager_check_address:
 * @self: a #NMAcdManager
 * @address: an IP address
 *
 * Check if an IP address is duplicate. @address must have been added with
 * nm_acd_manager_add_address().
 *
 * Returns: %TRUE if the address is not duplicate, %FALSE otherwise
 */
gboolean
nm_acd_manager_check_address (NMAcdManager *self, in_addr_t address)
{
	AddressInfo *info;

	g_return_val_if_fail (self, FALSE);
	g_return_val_if_fail (NM_IN_SET (self->state, STATE_INIT, STATE_PROBE_DONE), FALSE);

	info = g_hash_table_lookup (self->addresses, GUINT_TO_POINTER (address));
	g_return_val_if_fail (info, FALSE);

	return !info->duplicate;
}

/**
 * nm_acd_manager_announce_addresses:
 * @self: a #NMAcdManager
 *
 * Start announcing addresses.
 *
 * Returns: a negative NetworkManager error number or zero on success.
 */
int
nm_acd_manager_announce_addresses (NMAcdManager *self)
{
	GHashTableIter iter;
	AddressInfo *info;
	int r;
	gboolean success = TRUE;

	r = acd_init (self);
	if (r) {
		_LOGW ("couldn't init ACD for announcing addresses on interface '%s': %s",
		       nm_platform_link_get_name (NM_PLATFORM_GET, self->ifindex),
		       acd_error_to_string (r));
		return acd_error_to_nmerr (r, TRUE);
	}

	if (self->state == STATE_INIT) {
		/* n-acd can't announce without probing, therefore let's
		 * start a fake probe with zero timeout and then perform
		 * the announcement. */
		g_hash_table_iter_init (&iter, self->addresses);
		while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &info)) {
			if (!acd_probe_add (self, info, 0))
				success = FALSE;
		}
		self->state = STATE_ANNOUNCING;
	} else if (self->state == STATE_ANNOUNCING) {
		char sbuf[NM_UTILS_INET_ADDRSTRLEN];

		g_hash_table_iter_init (&iter, self->addresses);
		while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &info)) {
			if (info->duplicate)
				continue;
			r = n_acd_probe_announce (info->probe, N_ACD_DEFEND_ONCE);
			if (r) {
				_LOGW ("couldn't announce address %s on interface '%s': %s",
				       nm_utils_inet4_ntop (info->address, sbuf),
				       nm_platform_link_get_name (NM_PLATFORM_GET, self->ifindex),
				       acd_error_to_string (r));
				success = FALSE;
			} else
				_LOGD ("announcing address %s", nm_utils_inet4_ntop (info->address, sbuf));
		}
	}

	return success ? 0 : -NME_UNSPEC;
}

static void
destroy_address_info (gpointer data)
{
	AddressInfo *info = (AddressInfo *) data;

	n_acd_probe_free (info->probe);

	g_slice_free (AddressInfo, info);
}

/*****************************************************************************/

NMAcdManager *
nm_acd_manager_new (int ifindex,
                    const guint8 *hwaddr,
                    guint hwaddr_len,
                    const NMAcdCallbacks *callbacks,
                    gpointer user_data)
{
	NMAcdManager *self;

	g_return_val_if_fail (ifindex > 0, NULL);
	g_return_val_if_fail (hwaddr, NULL);
	g_return_val_if_fail (hwaddr_len == ETH_ALEN, NULL);

	self = g_slice_new0 (NMAcdManager);

	if (callbacks)
		self->callbacks = *callbacks;
	self->user_data = user_data;

	self->addresses = g_hash_table_new_full (nm_direct_hash, NULL,
	                                         NULL, destroy_address_info);
	self->state = STATE_INIT;
	self->ifindex = ifindex;
	memcpy (self->hwaddr, hwaddr, ETH_ALEN);
	return self;
}

void
nm_acd_manager_free (NMAcdManager *self)
{
	g_return_if_fail (self);

	if (self->callbacks.user_data_destroy)
		self->callbacks.user_data_destroy (self->user_data);

	nm_clear_pointer (&self->addresses, g_hash_table_destroy);
	nm_clear_pointer (&self->channel, g_io_channel_unref);
	nm_clear_g_source (&self->event_id);
	nm_clear_pointer (&self->acd, n_acd_unref);

	g_slice_free (NMAcdManager, self);
}
