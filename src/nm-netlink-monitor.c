/* nm-netlink-monitor.c - Monitor netlink socket for interface change 
 *			  events
 *
 * Copyright (C) 2005 Ray Strode
 *
 * Some code borrowed from HAL:  

 * Copyright (C) 2003 David Zeuthen, <david@fubar.dk>
 * Copyright (C) 2004 Novell, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
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
 */
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <linux/unistd.h>
#include <unistd.h>
#include <stdio.h>

#include <glib.h>
#include <glib/gi18n.h>

#include "NetworkManager.h"
#include "NetworkManagerSystem.h"
#include "nm-netlink-monitor.h"
#include "nm-utils.h"
#include "nm-marshal.h"
#include "nm-netlink.h"

#define NM_NETLINK_MONITOR_EVENT_CONDITIONS \
	((GIOCondition) (G_IO_IN | G_IO_PRI))

#define NM_NETLINK_MONITOR_ERROR_CONDITIONS \
	((GIOCondition) (G_IO_ERR | G_IO_NVAL))

#define NM_NETLINK_MONITOR_DISCONNECT_CONDITIONS \
	((GIOCondition) (G_IO_HUP))

#define NM_NETLINK_MONITOR_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                           NM_TYPE_NETLINK_MONITOR, \
                                           NMNetlinkMonitorPrivate))

typedef struct {
	struct nl_handle *nlh;
	struct nl_cb *    nlh_cb;
	struct nl_cache * nlh_link_cache;

	GMainContext *	  context;
	GIOChannel *	  io_channel;
	GSource *		  event_source;

	guint request_status_id;
} NMNetlinkMonitorPrivate;

static gboolean nm_netlink_monitor_event_handler (GIOChannel       *channel,
                                                  GIOCondition      io_condition,
                                                  NMNetlinkMonitor *monitor);

static gboolean nm_netlink_monitor_error_handler (GIOChannel       *channel,
                                                  GIOCondition      io_condition,
                                                  NMNetlinkMonitor *monitor);

static gboolean nm_netlink_monitor_disconnect_handler (GIOChannel       *channel,
                                                       GIOCondition      io_condition,
                                                       NMNetlinkMonitor *monitor);

enum {
  CARRIER_ON = 0,
  CARRIER_OFF,
  ERROR,

  LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

G_DEFINE_TYPE (NMNetlinkMonitor, nm_netlink_monitor, G_TYPE_OBJECT);

NMNetlinkMonitor *
nm_netlink_monitor_get (void)
{
	static NMNetlinkMonitor *singleton = NULL;

	if (!singleton)
		singleton = NM_NETLINK_MONITOR (g_object_new (NM_TYPE_NETLINK_MONITOR, NULL));
	else
		g_object_ref (singleton);

	return singleton;
}

static void
nm_netlink_monitor_init (NMNetlinkMonitor *monitor)
{
}

static void 
finalize (GObject *object)
{
	NMNetlinkMonitorPrivate *priv = NM_NETLINK_MONITOR_GET_PRIVATE (object);

	if (priv->request_status_id)
		g_source_remove (priv->request_status_id);

	if (priv->io_channel)
		nm_netlink_monitor_close_connection (NM_NETLINK_MONITOR (object));

	if (priv->nlh_link_cache) {
		nl_cache_free (priv->nlh_link_cache);
		priv->nlh_link_cache = NULL;
	}

	if (priv->nlh) {
		nl_handle_destroy (priv->nlh);
		priv->nlh = NULL;
	}

	if (priv->nlh_cb) {
		nl_cb_put (priv->nlh_cb);
		priv->nlh_cb = NULL;
	}

	G_OBJECT_CLASS (nm_netlink_monitor_parent_class)->finalize (object);
}

static void
nm_netlink_monitor_class_init (NMNetlinkMonitorClass *monitor_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (monitor_class);

	g_type_class_add_private (monitor_class, sizeof (NMNetlinkMonitorPrivate));

	/* Virtual methods */
	object_class->finalize = finalize;

	/* Signals */
	signals[CARRIER_ON] =
		g_signal_new ("carrier-on",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_LAST,
					  G_STRUCT_OFFSET (NMNetlinkMonitorClass, carrier_on),
					  NULL, NULL, g_cclosure_marshal_VOID__INT,
					  G_TYPE_NONE, 1, G_TYPE_INT);

	signals[CARRIER_OFF] =
		g_signal_new ("carrier-off",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_LAST,
					  G_STRUCT_OFFSET (NMNetlinkMonitorClass, carrier_off),
					  NULL, NULL, g_cclosure_marshal_VOID__INT,
					  G_TYPE_NONE, 1, G_TYPE_INT);

	signals[ERROR] =
		g_signal_new ("error",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_LAST,
					  G_STRUCT_OFFSET (NMNetlinkMonitorClass, error),
					  NULL, NULL, nm_marshal_VOID__POINTER,
					  G_TYPE_NONE, 1, G_TYPE_POINTER);
}

static void
netlink_object_message_handler (struct nl_object *obj, void *arg)
{
	NMNetlinkMonitor *monitor = NM_NETLINK_MONITOR (arg);
	GError *error;
	struct rtnl_link *filter;
	struct rtnl_link *link_obj;
	guint flags;

	filter = rtnl_link_alloc ();
	if (!filter) {
		error = g_error_new (NM_NETLINK_MONITOR_ERROR,
		                     NM_NETLINK_MONITOR_ERROR_BAD_ALLOC,
		                     _("error processing netlink message: %s"),
		                     nl_geterror ());
		g_signal_emit (G_OBJECT (monitor), 
		               signals[ERROR],
		               0, error);
		g_error_free (error);
		return;
	}

	/* Ensure it's a link object */
	if (nl_object_match_filter(obj, OBJ_CAST (filter)) == 0)
		goto out;

	link_obj = (struct rtnl_link *) obj;
	flags = rtnl_link_get_flags (link_obj);
	if (flags & IFF_RUNNING) {
        g_signal_emit (G_OBJECT (monitor), 
                                signals[CARRIER_ON],
                                0, rtnl_link_get_ifindex (link_obj));
	} else {
        g_signal_emit (G_OBJECT (monitor), 
                                signals[CARRIER_OFF],
                                0, rtnl_link_get_ifindex (link_obj));
	}

out:
	rtnl_link_put (filter);
}

static int
netlink_event_input (struct nl_msg *msg, void *arg)
{
	nl_msg_parse (msg, &netlink_object_message_handler, arg);

	/* Stop processing messages */
	return NL_STOP;
}

gboolean
nm_netlink_monitor_open_connection (NMNetlinkMonitor *monitor,
									GError **error)
{
	NMNetlinkMonitorPrivate *priv;
	int fd;
	GError *channel_error = NULL;
	GIOFlags channel_flags;

	g_return_val_if_fail (NM_IS_NETLINK_MONITOR (monitor), FALSE);

	priv = NM_NETLINK_MONITOR_GET_PRIVATE (monitor);
	g_return_val_if_fail (priv->io_channel == NULL, FALSE);

	priv->nlh_cb = nl_cb_alloc (NL_CB_VERBOSE);
	priv->nlh = nl_handle_alloc_cb (priv->nlh_cb);
	if (!priv->nlh) {
		g_set_error (error, NM_NETLINK_MONITOR_ERROR,
		             NM_NETLINK_MONITOR_ERROR_NETLINK_ALLOC_HANDLE,
		             _("unable to allocate netlink handle for monitoring link status: %s"),
		             nl_geterror ());
		goto error;
	}

	nl_disable_sequence_check (priv->nlh);
	nl_socket_modify_cb (priv->nlh, NL_CB_VALID, NL_CB_CUSTOM, netlink_event_input, monitor);
	if (nl_connect (priv->nlh, NETLINK_ROUTE) < 0) {
		g_set_error (error, NM_NETLINK_MONITOR_ERROR,
		             NM_NETLINK_MONITOR_ERROR_NETLINK_CONNECT,
		             _("unable to connect to netlink for monitoring link status: %s"),
		             nl_geterror ());
		goto error;
	}

	if (nl_socket_add_membership (priv->nlh, RTNLGRP_LINK) < 0) {
		g_set_error (error, NM_NETLINK_MONITOR_ERROR,
		             NM_NETLINK_MONITOR_ERROR_NETLINK_JOIN_GROUP,
		             _("unable to join netlink group for monitoring link status: %s"),
		             nl_geterror ());
		goto error;
	}

	if ((priv->nlh_link_cache = rtnl_link_alloc_cache (priv->nlh)) == NULL) {
		g_set_error (error, NM_NETLINK_MONITOR_ERROR,
		             NM_NETLINK_MONITOR_ERROR_NETLINK_ALLOC_LINK_CACHE,
		             _("unable to allocate netlink link cache for monitoring link status: %s"),
		             nl_geterror ());
		goto error;
	}

	nl_cache_mngt_provide (priv->nlh_link_cache);

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

	return TRUE;

error:
	if (priv->io_channel)
		nm_netlink_monitor_close_connection (monitor);

	if (priv->nlh_link_cache) {
		nl_cache_free (priv->nlh_link_cache);
		priv->nlh_link_cache = NULL;
	}

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

void
nm_netlink_monitor_close_connection (NMNetlinkMonitor  *monitor)
{
	NMNetlinkMonitorPrivate *priv;

	g_return_if_fail (NM_IS_NETLINK_MONITOR (monitor));

	priv = NM_NETLINK_MONITOR_GET_PRIVATE (monitor);
	g_return_if_fail (priv->io_channel != NULL);

	if (priv->event_source != NULL)
		nm_netlink_monitor_detach (monitor);

	g_io_channel_shutdown (priv->io_channel,
			       TRUE /* flush pending data */,
			       NULL);

	g_io_channel_unref (priv->io_channel);
	priv->io_channel = NULL;
}

GQuark
nm_netlink_monitor_error_quark (void)
{
	static GQuark error_quark = 0;

	if (error_quark == 0)
		error_quark = g_quark_from_static_string ("nm-netlink-monitor-error-quark");

	return error_quark;
}

static void
nm_netlink_monitor_clear_event_source (NMNetlinkMonitor *monitor)
{
	NM_NETLINK_MONITOR_GET_PRIVATE (monitor)->event_source = NULL;
}

void
nm_netlink_monitor_attach (NMNetlinkMonitor *monitor, 
                           GMainContext     *context)
{
	NMNetlinkMonitorPrivate *priv;
	GSource *event_source;

	g_return_if_fail (NM_IS_NETLINK_MONITOR (monitor));

	priv = NM_NETLINK_MONITOR_GET_PRIVATE (monitor);
	g_return_if_fail (priv->nlh != NULL);

	priv = NM_NETLINK_MONITOR_GET_PRIVATE (monitor);
	g_return_if_fail (priv->context == NULL);

	if (context == NULL)
		context = g_main_context_default ();

	priv->context = g_main_context_ref (context);

	event_source = g_io_create_watch (priv->io_channel,
	                                  NM_NETLINK_MONITOR_EVENT_CONDITIONS |
	                                  NM_NETLINK_MONITOR_ERROR_CONDITIONS |
	                                  NM_NETLINK_MONITOR_DISCONNECT_CONDITIONS);
	g_source_set_callback (event_source, 
	                       (GSourceFunc) nm_netlink_monitor_event_handler,
	                       monitor, 
	                       (GDestroyNotify) nm_netlink_monitor_clear_event_source);
	g_source_attach (event_source, context);
	priv->event_source = event_source;
}

void
nm_netlink_monitor_detach (NMNetlinkMonitor *monitor)
{
	NMNetlinkMonitorPrivate *priv;

	g_return_if_fail (NM_IS_NETLINK_MONITOR (monitor));

	priv = NM_NETLINK_MONITOR_GET_PRIVATE (monitor);
	g_return_if_fail (priv->context != NULL);

	g_source_destroy (priv->event_source);
	priv->event_source = NULL;

	g_main_context_unref (priv->context);
	priv->context = NULL;
}

static gboolean
deferred_emit_carrier_state (gpointer user_data)
{
	NMNetlinkMonitor *monitor = NM_NETLINK_MONITOR (user_data);
	NMNetlinkMonitorPrivate *priv = NM_NETLINK_MONITOR_GET_PRIVATE (monitor);

	priv->request_status_id = 0;

	/* Emit each device's new state */
	nl_cache_foreach_filter (priv->nlh_link_cache, NULL, netlink_object_message_handler, monitor);
	return FALSE;
}

gboolean
nm_netlink_monitor_request_status (NMNetlinkMonitor  *monitor,
                                   GError           **error)
{
	NMNetlinkMonitorPrivate *priv;

	g_return_val_if_fail (NM_IS_NETLINK_MONITOR (monitor), FALSE);

	priv = NM_NETLINK_MONITOR_GET_PRIVATE (monitor);
	g_return_val_if_fail (priv->context != NULL, FALSE);

	/* Update the link cache with latest state */
	if (nl_cache_refill (priv->nlh, priv->nlh_link_cache)) {
		g_set_error (error, NM_NETLINK_MONITOR_ERROR,
		             NM_NETLINK_MONITOR_ERROR_LINK_CACHE_UPDATE,
		             _("error updating link cache: %s"),
		             nl_geterror ());
		return FALSE;
	}

	/* Schedule the carrier state emission */
	if (!priv->request_status_id)
		priv->request_status_id = g_idle_add (deferred_emit_carrier_state, monitor);

	return TRUE;
}

static gboolean
nm_netlink_monitor_event_handler (GIOChannel       *channel,
                                  GIOCondition      io_condition,
                                  NMNetlinkMonitor *monitor)
{
	NMNetlinkMonitorPrivate *priv;
	GError *error = NULL;

	g_return_val_if_fail (NM_IS_NETLINK_MONITOR (monitor), TRUE);

	priv = NM_NETLINK_MONITOR_GET_PRIVATE (monitor);
	g_return_val_if_fail (priv->context != NULL, TRUE);

	if (io_condition & NM_NETLINK_MONITOR_ERROR_CONDITIONS)
		return nm_netlink_monitor_error_handler (channel, io_condition, monitor);
	else if (io_condition & NM_NETLINK_MONITOR_DISCONNECT_CONDITIONS)
		return nm_netlink_monitor_disconnect_handler (channel, io_condition, monitor);

	g_return_val_if_fail (!(io_condition & ~(NM_NETLINK_MONITOR_EVENT_CONDITIONS)), FALSE);

	if (nl_recvmsgs_default (priv->nlh) < 0) {
		error = g_error_new (NM_NETLINK_MONITOR_ERROR,
		                     NM_NETLINK_MONITOR_ERROR_PROCESSING_MESSAGE,
		                     _("error processing netlink message: %s"),
		                     nl_geterror ());

		g_signal_emit (G_OBJECT (monitor), 
		               signals[ERROR],
		               0, error);
		g_error_free (error);
	}

	return TRUE;
}

static gboolean 
nm_netlink_monitor_error_handler (GIOChannel       *channel,
                                  GIOCondition      io_condition,
                                  NMNetlinkMonitor *monitor)
{
	GError *socket_error;
 
	g_return_val_if_fail (io_condition & NM_NETLINK_MONITOR_ERROR_CONDITIONS, FALSE);

	socket_error = g_error_new (NM_NETLINK_MONITOR_ERROR,
	                            NM_NETLINK_MONITOR_ERROR_WAITING_FOR_SOCKET_DATA,
	                            _("error occurred while waiting for data on socket"));

	g_signal_emit (G_OBJECT (monitor), 
	               signals[ERROR],
	               0, socket_error);
	return TRUE;
}

static gboolean 
nm_netlink_monitor_disconnect_handler (GIOChannel       *channel,
                                       GIOCondition      io_condition,
                                       NMNetlinkMonitor *monitor)
{

	g_return_val_if_fail (!(io_condition & ~(NM_NETLINK_MONITOR_DISCONNECT_CONDITIONS)), FALSE);
	return FALSE;
}

