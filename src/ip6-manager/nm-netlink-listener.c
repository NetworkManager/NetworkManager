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
 * Copyright (C) 2005 - 2009 Red Hat, Inc.
 * Copyright (C) 2005 - 2008 Novell, Inc.
 * Copyright (C) 2005 Ray Strode
 *
 * Some code borrowed from HAL:
 *
 * Copyright (C) 2003 David Zeuthen, <david@fubar.dk>
 * Copyright (C) 2004 Novell, Inc.
 */

/* FIXME: this should be merged with src/nm-netlink-monitor.c */

#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if.h>
#include <linux/unistd.h>
#include <unistd.h>
#include <stdio.h>

#include <glib.h>
#include <glib/gi18n.h>

#include "NetworkManager.h"
#include "NetworkManagerSystem.h"
#include "nm-netlink-listener.h"
#include "nm-utils.h"
#include "nm-marshal.h"
#include "nm-netlink.h"

#define NM_NETLINK_LISTENER_EVENT_CONDITIONS \
	((GIOCondition) (G_IO_IN | G_IO_PRI))

#define NM_NETLINK_LISTENER_ERROR_CONDITIONS \
	((GIOCondition) (G_IO_ERR | G_IO_NVAL))

#define NM_NETLINK_LISTENER_DISCONNECT_CONDITIONS \
	((GIOCondition) (G_IO_HUP))

#define NM_NETLINK_LISTENER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                            NM_TYPE_NETLINK_LISTENER, \
                                            NMNetlinkListenerPrivate))

typedef struct {
	struct nl_handle *nlh;
	struct nl_cb *    nlh_cb;
	struct nl_cache * nlh_link_cache;

	GIOChannel *	  io_channel;
	guint             event_id;

	guint             request_status_id;
} NMNetlinkListenerPrivate;

static gboolean nm_netlink_listener_event_handler (GIOChannel       *channel,
												   GIOCondition      io_condition,
												   gpointer          user_data);

static gboolean nm_netlink_listener_error_handler (GIOChannel       *channel,
												   GIOCondition      io_condition,
												   NMNetlinkListener *listener);

static gboolean nm_netlink_listener_disconnect_handler (GIOChannel       *channel,
														GIOCondition      io_condition,
														NMNetlinkListener *listener);

static void close_connection (NMNetlinkListener *listener);

enum {
  NOTIFICATION = 0,
  ERROR,

  LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

G_DEFINE_TYPE (NMNetlinkListener, nm_netlink_listener, G_TYPE_OBJECT);

NMNetlinkListener *
nm_netlink_listener_get (void)
{
	static NMNetlinkListener *singleton = NULL;

	if (!singleton)
		singleton = NM_NETLINK_LISTENER (g_object_new (NM_TYPE_NETLINK_LISTENER, NULL));
	else
		g_object_ref (singleton);

	return singleton;
}

static void
nm_netlink_listener_init (NMNetlinkListener *listener)
{
}

static void
finalize (GObject *object)
{
	NMNetlinkListenerPrivate *priv = NM_NETLINK_LISTENER_GET_PRIVATE (object);

	if (priv->request_status_id)
		g_source_remove (priv->request_status_id);

	if (priv->io_channel)
		close_connection (NM_NETLINK_LISTENER (object));

	if (priv->nlh) {
		nl_handle_destroy (priv->nlh);
		priv->nlh = NULL;
	}

	if (priv->nlh_cb) {
		nl_cb_put (priv->nlh_cb);
		priv->nlh_cb = NULL;
	}

	G_OBJECT_CLASS (nm_netlink_listener_parent_class)->finalize (object);
}

static void
nm_netlink_listener_class_init (NMNetlinkListenerClass *listener_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (listener_class);

	g_type_class_add_private (listener_class, sizeof (NMNetlinkListenerPrivate));

	/* Virtual methods */
	object_class->finalize = finalize;

	/* Signals */
	signals[NOTIFICATION] =
		g_signal_new ("notification",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_LAST,
					  G_STRUCT_OFFSET (NMNetlinkListenerClass, notification),
					  NULL, NULL, g_cclosure_marshal_VOID__POINTER,
					  G_TYPE_NONE, 1, G_TYPE_POINTER);

	signals[ERROR] =
		g_signal_new ("error",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_LAST,
					  G_STRUCT_OFFSET (NMNetlinkListenerClass, error),
					  NULL, NULL, _nm_marshal_VOID__POINTER,
					  G_TYPE_NONE, 1, G_TYPE_POINTER);
}

static int
netlink_event_input (struct nl_msg *msg, void *listener)
{
	struct nlmsghdr *hdr = nlmsg_hdr (msg);

	if (hdr->nlmsg_pid != 0)
		return NL_STOP;

	g_signal_emit (listener, signals[NOTIFICATION], 0, msg);

	/* Stop processing messages */
	return NL_STOP;
}

static gboolean
open_connection (NMNetlinkListener *listener, GError **error)
{
	NMNetlinkListenerPrivate *priv = NM_NETLINK_LISTENER_GET_PRIVATE (listener);
	int fd;
	GError *channel_error = NULL;
	GIOFlags channel_flags;

	g_return_val_if_fail (priv->io_channel == NULL, FALSE);

	priv->nlh_cb = nl_cb_alloc (NL_CB_DEFAULT);
	priv->nlh = nl_handle_alloc_cb (priv->nlh_cb);
	if (!priv->nlh) {
		g_set_error (error, NM_NETLINK_LISTENER_ERROR,
		             NM_NETLINK_LISTENER_ERROR_NETLINK_ALLOC_HANDLE,
		             _("unable to allocate netlink handle: %s"),
		             nl_geterror ());
		goto error;
	}

	nl_disable_sequence_check (priv->nlh);
	nl_socket_modify_cb (priv->nlh, NL_CB_VALID, NL_CB_CUSTOM, netlink_event_input, listener);
	if (nl_connect (priv->nlh, NETLINK_ROUTE) < 0) {
		g_set_error (error, NM_NETLINK_LISTENER_ERROR,
		             NM_NETLINK_LISTENER_ERROR_NETLINK_CONNECT,
		             _("unable to connect to netlink: %s"),
		             nl_geterror ());
		goto error;
	}

	fd = nl_socket_get_fd (priv->nlh);
	priv->io_channel = g_io_channel_unix_new (fd);

	g_io_channel_set_encoding (priv->io_channel, NULL, &channel_error);
	/* Encoding is NULL, so no conversion error can possibly occur */
	g_assert (channel_error == NULL);

	g_io_channel_set_close_on_unref (priv->io_channel, TRUE);
	channel_flags = g_io_channel_get_flags (priv->io_channel);
	channel_error = NULL;
	g_io_channel_set_flags (priv->io_channel,
	                        channel_flags | G_IO_FLAG_NONBLOCK,
	                        &channel_error);
	if (channel_error != NULL) {
		g_propagate_error (error, channel_error);
		goto error;
	}

	priv->event_id = g_io_add_watch (priv->io_channel,
	                                 (NM_NETLINK_LISTENER_EVENT_CONDITIONS |
	                                  NM_NETLINK_LISTENER_ERROR_CONDITIONS |
	                                  NM_NETLINK_LISTENER_DISCONNECT_CONDITIONS),
	                                 nm_netlink_listener_event_handler,
	                                 listener);
	return TRUE;

error:
	if (priv->io_channel)
		close_connection (listener);

	if (priv->nlh) {
		nl_handle_destroy (priv->nlh);
		priv->nlh = NULL;
	}

	if (priv->nlh_cb) {
		nl_cb_put (priv->nlh_cb);
		priv->nlh_cb = NULL;
	}
	return FALSE;
}

static void
close_connection (NMNetlinkListener *listener)
{
	NMNetlinkListenerPrivate *priv = NM_NETLINK_LISTENER_GET_PRIVATE (listener);

	g_return_if_fail (priv->io_channel != NULL);

	if (priv->event_id) {
		g_source_remove (priv->event_id);
		priv->event_id = 0;
	}

	g_io_channel_shutdown (priv->io_channel,
						   TRUE /* flush pending data */,
						   NULL);

	g_io_channel_unref (priv->io_channel);
	priv->io_channel = NULL;
}

GQuark
nm_netlink_listener_error_quark (void)
{
	static GQuark error_quark = 0;

	if (error_quark == 0)
		error_quark = g_quark_from_static_string ("nm-netlink-listener-error-quark");

	return error_quark;
}

gboolean
nm_netlink_listener_subscribe (NMNetlinkListener *listener,
							   int group,
							   GError **error)
{
	NMNetlinkListenerPrivate *priv;

	g_return_val_if_fail (NM_IS_NETLINK_LISTENER (listener), FALSE);

	priv = NM_NETLINK_LISTENER_GET_PRIVATE (listener);

	if (!priv->nlh) {
		if (!open_connection (listener, error))
			return FALSE;
	}

	if (nl_socket_add_membership (priv->nlh, group) < 0) {
		g_set_error (error, NM_NETLINK_LISTENER_ERROR,
		             NM_NETLINK_LISTENER_ERROR_NETLINK_JOIN_GROUP,
		             _("unable to join netlink group: %s"),
		             nl_geterror ());
		return FALSE;
	}

	return TRUE;
}

void
nm_netlink_listener_unsubscribe (NMNetlinkListener *listener, int group)
{
	NMNetlinkListenerPrivate *priv;

	g_return_if_fail (NM_IS_NETLINK_LISTENER (listener));

	priv = NM_NETLINK_LISTENER_GET_PRIVATE (listener);
	g_return_if_fail (priv->nlh != NULL);

	nl_socket_drop_membership (priv->nlh, group);
}

static gboolean
nm_netlink_listener_event_handler (GIOChannel       *channel,
								   GIOCondition      io_condition,
								   gpointer          user_data)
{
	NMNetlinkListener *listener = (NMNetlinkListener *) user_data;
	NMNetlinkListenerPrivate *priv;
	GError *error = NULL;

	g_return_val_if_fail (NM_IS_NETLINK_LISTENER (listener), TRUE);

	priv = NM_NETLINK_LISTENER_GET_PRIVATE (listener);
	g_return_val_if_fail (priv->event_id > 0, TRUE);

	if (io_condition & NM_NETLINK_LISTENER_ERROR_CONDITIONS)
		return nm_netlink_listener_error_handler (channel, io_condition, listener);
	else if (io_condition & NM_NETLINK_LISTENER_DISCONNECT_CONDITIONS)
		return nm_netlink_listener_disconnect_handler (channel, io_condition, listener);

	g_return_val_if_fail (!(io_condition & ~(NM_NETLINK_LISTENER_EVENT_CONDITIONS)), FALSE);

	if (nl_recvmsgs_default (priv->nlh) < 0) {
		error = g_error_new (NM_NETLINK_LISTENER_ERROR,
		                     NM_NETLINK_LISTENER_ERROR_PROCESSING_MESSAGE,
		                     _("error processing netlink message: %s"),
		                     nl_geterror ());

		g_signal_emit (G_OBJECT (listener),
		               signals[ERROR],
		               0, error);
		g_error_free (error);
	}

	return TRUE;
}

static gboolean
nm_netlink_listener_error_handler (GIOChannel       *channel,
								   GIOCondition      io_condition,
								   NMNetlinkListener *listener)
{
	GError *socket_error;
	const char *err_msg;
	int err_code;
	socklen_t err_len;

	g_return_val_if_fail (io_condition & NM_NETLINK_LISTENER_ERROR_CONDITIONS, FALSE);

	err_code = 0;
	err_len = sizeof (err_code);
	if (getsockopt (g_io_channel_unix_get_fd (channel),
					SOL_SOCKET, SO_ERROR, (void *) &err_code, &err_len))
		err_msg = strerror (err_code);
	else
		err_msg = _("error occurred while waiting for data on socket");

	socket_error = g_error_new (NM_NETLINK_LISTENER_ERROR,
	                            NM_NETLINK_LISTENER_ERROR_WAITING_FOR_SOCKET_DATA,
	                            "%s",
	                            err_msg);

	g_signal_emit (G_OBJECT (listener),
	               signals[ERROR],
	               0, socket_error);

	g_error_free (socket_error);

	return TRUE;
}

static gboolean
nm_netlink_listener_disconnect_handler (GIOChannel       *channel,
                                       GIOCondition      io_condition,
                                       NMNetlinkListener *listener)
{

	g_return_val_if_fail (!(io_condition & ~(NM_NETLINK_LISTENER_DISCONNECT_CONDITIONS)), FALSE);
	return FALSE;
}

