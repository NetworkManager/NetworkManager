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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */
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

#include <glib.h>
#include <glib/gi18n.h>

#include "nm-netlink-monitor.h"
#include "nm-utils.h"

#define NM_NETLINK_MONITOR_EVENT_CONDITIONS \
	((GIOCondition) (G_IO_IN | G_IO_PRI))

#define NM_NETLINK_MONITOR_ERROR_CONDITIONS \
	((GIOCondition) (G_IO_ERR | G_IO_NVAL))

#define NM_NETLINK_MONITOR_DISCONNECT_CONDITIONS \
	((GIOCondition) (G_IO_HUP))

struct _NmNetlinkMonitorPrivate 
{
	GMainContext	*context;
	GIOChannel	*io_channel;
	GSource		*event_source;
};

static void nm_netlink_monitor_finalize (GObject *object);
static void nm_netlink_monitor_class_install_signals (NmNetlinkMonitorClass *service_class);

static gboolean 
nm_netlink_monitor_event_handler (GIOChannel       *channel,
				  GIOCondition      io_condition,
				  NmNetlinkMonitor *monitor);
static gboolean 
nm_netlink_monitor_error_handler (GIOChannel       *channel,
				  GIOCondition      io_condition,
				  NmNetlinkMonitor *monitor);
static gboolean 
nm_netlink_monitor_disconnect_handler (GIOChannel       *channel,
				       GIOCondition      io_condition,
				       NmNetlinkMonitor *monitor);
enum
{
  INTERFACE_CONNECTED = 0,
  INTERFACE_DISCONNECTED,
  ERROR,
  NUMBER_OF_SIGNALS
};

static guint nm_netlink_monitor_signals[NUMBER_OF_SIGNALS];

G_DEFINE_TYPE (NmNetlinkMonitor, nm_netlink_monitor, G_TYPE_OBJECT);

static void
nm_netlink_monitor_class_init (NmNetlinkMonitorClass *monitor_class)
{
	GObjectClass *gobject_class;

	gobject_class = G_OBJECT_CLASS (monitor_class);

	gobject_class->finalize = nm_netlink_monitor_finalize;

	nm_netlink_monitor_class_install_signals (monitor_class);

	g_type_class_add_private (monitor_class, sizeof (NmNetlinkMonitorPrivate));
}

static void
nm_netlink_monitor_class_install_signals (NmNetlinkMonitorClass	*monitor_class)
{
  GObjectClass *object_class;

  object_class = G_OBJECT_CLASS (monitor_class);

  nm_netlink_monitor_signals[INTERFACE_CONNECTED] =
    g_signal_new ("interface-connected",
		  G_OBJECT_CLASS_TYPE (object_class),
		  G_SIGNAL_RUN_LAST,
		  G_STRUCT_OFFSET (NmNetlinkMonitorClass, interface_connected),
		  NULL, NULL, g_cclosure_marshal_VOID__STRING,
		  G_TYPE_NONE, 1, G_TYPE_STRING);
  monitor_class->interface_connected = NULL;

  nm_netlink_monitor_signals[INTERFACE_DISCONNECTED] =
    g_signal_new ("interface-disconnected",
		  G_OBJECT_CLASS_TYPE (object_class),
		  G_SIGNAL_RUN_LAST,
		  G_STRUCT_OFFSET (NmNetlinkMonitorClass, interface_disconnected),
		  NULL, NULL, g_cclosure_marshal_VOID__STRING,
		  G_TYPE_NONE, 1, G_TYPE_STRING);
  monitor_class->interface_disconnected = NULL;

  nm_netlink_monitor_signals[ERROR] =
    g_signal_new ("error",
		  G_OBJECT_CLASS_TYPE (object_class),
		  G_SIGNAL_RUN_LAST,
		  G_STRUCT_OFFSET (NmNetlinkMonitorClass, error),
		  NULL, NULL, g_cclosure_marshal_VOID__POINTER,
		  G_TYPE_NONE, 1, G_TYPE_POINTER);
  monitor_class->error = NULL;
}

gboolean
nm_netlink_monitor_open_connection (NmNetlinkMonitor  *monitor,
				    GError	     **error)
{
	struct sockaddr_nl monitor_address = { 0 };
	int fd, saved_errno;
	GError *channel_error;
	GIOFlags channel_flags;

	g_return_val_if_fail (monitor->priv->io_channel == NULL, FALSE);

	fd = socket (PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

	if (fd < 0) 
	{
		saved_errno = errno;

		g_set_error (error, NM_NETLINK_MONITOR_ERROR,
			     NM_NETLINK_MONITOR_ERROR_OPENING_SOCKET,
			     _("unable to create netlink socket for monitoring "
			       "wired ethernet devices - %s"),
			       g_strerror (saved_errno));
		return FALSE;
	}

	monitor_address.nl_family = AF_NETLINK;
	monitor_address.nl_pid = getpid ();
	monitor_address.nl_groups = RTMGRP_LINK;

	if (bind (fd, 
		  (struct sockaddr *) &monitor_address, 
		  sizeof (monitor_address)) < 0) {

		saved_errno = errno;

		g_set_error (error, NM_NETLINK_MONITOR_ERROR,
			     NM_NETLINK_MONITOR_ERROR_BINDING_TO_SOCKET,
			     _("unable to bind to netlink socket for monitoring "
			       "wired ethernet devices - %s"),
			       g_strerror (saved_errno));
		return FALSE;
	}

	monitor->priv->io_channel = g_io_channel_unix_new (fd);

	channel_error = NULL;
	g_io_channel_set_encoding (monitor->priv->io_channel,
				   NULL	/* encoding */, 
				   &channel_error);

	/* Encoding is NULL, so no conversion error can possibly
	 * occur
	 */
	g_assert (channel_error == NULL);

	g_io_channel_set_close_on_unref (monitor->priv->io_channel,
					 TRUE);

	channel_flags = g_io_channel_get_flags (monitor->priv->io_channel);
	channel_error = NULL;
	g_io_channel_set_flags (monitor->priv->io_channel,
				channel_flags | G_IO_FLAG_NONBLOCK,
				&channel_error);

	if (channel_error != NULL)
	{
		g_propagate_error (error, channel_error);
		return FALSE;
	}

	return TRUE;
}

void
nm_netlink_monitor_close_connection (NmNetlinkMonitor  *monitor)
{
	g_return_if_fail (monitor->priv->io_channel != NULL);

	if (monitor->priv->event_source != NULL)
		nm_netlink_monitor_detach (monitor);

	g_io_channel_shutdown (monitor->priv->io_channel,
			       TRUE /* flush pending data */,
			       NULL);

	g_io_channel_unref (monitor->priv->io_channel);
	monitor->priv->io_channel = NULL;
}

static void
nm_netlink_monitor_init (NmNetlinkMonitor *monitor)
{
	monitor->priv = G_TYPE_INSTANCE_GET_PRIVATE (monitor, 
						     NM_TYPE_NETLINK_MONITOR,
						     NmNetlinkMonitorPrivate);
	monitor->priv->context = NULL;
	monitor->priv->io_channel = NULL;
	monitor->priv->event_source = NULL;
}

static void 
nm_netlink_monitor_finalize (GObject *object)
{
	NmNetlinkMonitor *monitor;
	GObjectClass *gobject_class;

	monitor = NM_NETLINK_MONITOR (object);
	gobject_class = G_OBJECT_CLASS (nm_netlink_monitor_parent_class);

	if (monitor->priv->io_channel != NULL)
		nm_netlink_monitor_close_connection (monitor);

	gobject_class->finalize (object);
}

GQuark
nm_netlink_monitor_error_quark (void)
{
	static GQuark error_quark = 0;

	if (error_quark == 0)
		error_quark = g_quark_from_static_string ("nm-netlink-monitor-error-quark");

	return error_quark;
}

NmNetlinkMonitor *
nm_netlink_monitor_new (void)
{
	GObject *instance;

	instance = g_object_new (NM_TYPE_NETLINK_MONITOR, NULL, NULL);

	return NM_NETLINK_MONITOR (instance);
}

static void
nm_netlink_monitor_clear_event_source (NmNetlinkMonitor *monitor)
{
	monitor->priv->event_source = NULL;
}

void
nm_netlink_monitor_attach (NmNetlinkMonitor *monitor, 
			   GMainContext     *context)
{
	GSource *event_source;

	g_return_if_fail (NM_IS_NETLINK_MONITOR (monitor));
	g_return_if_fail (monitor->priv->context == NULL);

	if (context == NULL)
		context = g_main_context_default ();

	monitor->priv->context = g_main_context_ref (context);

	event_source = g_io_create_watch (monitor->priv->io_channel,
					  NM_NETLINK_MONITOR_EVENT_CONDITIONS |
					  NM_NETLINK_MONITOR_ERROR_CONDITIONS |
					  NM_NETLINK_MONITOR_DISCONNECT_CONDITIONS);
	g_source_set_callback (event_source, 
			       (GSourceFunc) nm_netlink_monitor_event_handler,
			       monitor, 
			       (GDestroyNotify) 
                               nm_netlink_monitor_clear_event_source);
	g_source_attach (event_source, context);
	monitor->priv->event_source = event_source;
}

void
nm_netlink_monitor_detach (NmNetlinkMonitor *monitor)
{
	g_return_if_fail (NM_IS_NETLINK_MONITOR (monitor));
	g_return_if_fail (monitor->priv->context != NULL);

	g_source_destroy (monitor->priv->event_source);
	monitor->priv->event_source = NULL;

	g_main_context_unref (monitor->priv->context);
	monitor->priv->context = NULL;
}

gboolean
nm_netlink_monitor_request_status (NmNetlinkMonitor  *monitor,
				   GError           **error)
{
	typedef struct
	{
		struct nlmsghdr  header;
		struct rtgenmsg  request;
	} NmNetlinkMonitorStatusPacket;
	NmNetlinkMonitorStatusPacket packet = { { 0 } };
	struct sockaddr_nl recipient = { 0 };
	static guint32 sequence_number;
	int fd, saved_errno;
	ssize_t num_bytes_sent;
	size_t num_bytes_to_send, total_bytes_sent;
	gdouble max_wait_period, now;
	const gchar *buffer;
	GError *socket_error;

	fd = g_io_channel_unix_get_fd (monitor->priv->io_channel);

	recipient.nl_family = AF_NETLINK;
	recipient.nl_pid = 0; /* going to kernel */
	recipient.nl_groups = RTMGRP_LINK;

	packet.header.nlmsg_len = NLMSG_LENGTH (sizeof (struct rtgenmsg));
	packet.header.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
	packet.header.nlmsg_type = RTM_GETLINK;
	packet.header.nlmsg_pid = getpid ();
	/* Might be good to generate a unique sequence number and track
	   the response */
	packet.header.nlmsg_seq = sequence_number << 16;
	sequence_number++;

	packet.request.rtgen_family = AF_UNSPEC;

	nm_get_timestamp (&now);

	/* only block for around 1.5 seconds
	 * FIXME: maybe too long? */
	max_wait_period = now + 1.5;
	num_bytes_sent = 0;
	buffer = (const gchar *) &packet;
	num_bytes_to_send = sizeof (packet);
	total_bytes_sent = 0;
	socket_error = NULL;
	do
	{
		num_bytes_sent = sendto (fd, 
					 buffer + total_bytes_sent, 
					 num_bytes_to_send, 
					 MSG_DONTWAIT, 
					 (struct sockaddr *) &recipient,
					 sizeof (recipient));
		if (num_bytes_sent < 0)
		{
			saved_errno = errno;

			if ((saved_errno == EAGAIN) ||
			    (saved_errno == EWOULDBLOCK))
			{
				nm_get_timestamp (&now);
				if ((max_wait_period - now) > G_MINDOUBLE)
				{
					saved_errno = 0;
					continue;
				}
			}

			socket_error = 
				g_error_new (NM_NETLINK_MONITOR_ERROR,
				 	     NM_NETLINK_MONITOR_ERROR_SENDING_TO_SOCKET,
				             "%s", g_strerror (saved_errno));
			break;
		}

		total_bytes_sent += num_bytes_sent;
		num_bytes_to_send -= num_bytes_sent;

		nm_get_timestamp (&now);

		if ((max_wait_period - now) < G_MINDOUBLE)
		{
			socket_error = 
				g_error_new (NM_NETLINK_MONITOR_ERROR,
					     NM_NETLINK_MONITOR_ERROR_SENDING_TO_SOCKET,
					     _("operation took too long"));
			break;
		}
	} while (num_bytes_to_send > 0);

	if (socket_error != NULL)
	{
		if (error != NULL)
			g_propagate_error (error, socket_error);
		else
		{
			g_signal_emit (G_OBJECT (monitor), 
					nm_netlink_monitor_signals[ERROR],
					0, socket_error);
			g_error_free (socket_error);
		}

		return FALSE;
	}

	return TRUE;
}

static gboolean
receive_pending_bytes (GIOChannel  *channel,
		       gchar      **str_return,
		       gsize       *length,
		       GError     **error)
{
	GString *pending_bytes;
	ssize_t num_bytes_read;
	gboolean succeeded;
	struct sockaddr_nl sender = { 0 };
	gchar buffer[4096];
	static const size_t buffer_capacity = (size_t) sizeof (buffer);
	socklen_t sender_size;
	int fd, saved_errno;

	fd = g_io_channel_unix_get_fd (channel);

	pending_bytes = g_string_sized_new (4096);

	sender_size = (socklen_t) sizeof (sender);
	saved_errno = 0;
	succeeded = TRUE;
	do
	{
		num_bytes_read = recvfrom (fd, buffer, buffer_capacity,
					   MSG_DONTWAIT,
					   (struct sockaddr *) &sender,
					   &sender_size);

		if (num_bytes_read < 0)
		{
			saved_errno = errno;

			/* the kernel doesn't send EOF when it's done,
			 * so we just have to wait until it wants to
			 * block and assume that means it's done.
			 */
			if (saved_errno == EAGAIN)
			{
				saved_errno = 0;
				break;
			}
		}
		else if (saved_errno == EINTR)
			saved_errno = 0;

		/* First let's make sure that the sender is actually 
		 * someone legitimate.
		 *
		 * There are a few possibilities:
		 * 	1) The size of the sender is less than the
		 *	   size of a generic sockaddr structure. 
		 *	   This means we got sent completely bogus 
		 *	   data.
		 *      2) The size of the sender is greater than or
		 *         equal to the size of a generic sockaddr
		 *         structure, but the address family the sender
		 *         belongs to is not AF_NETLINK. In this case
		 *	   we were sent some spurious packets that we
		 *	   don't care about.
		 *	3) The address family is AF_NETLINK but the
		 *	   the size of the sender is not equal to the 
		 *	   size of a sockaddr_nl structure. This means
		 *         we can't treat the received data as an 
		 *         instance of sockaddr_nl structure.
		 *
		 * In any of the above cases, we should discard the data.
		 */
		if ((sender_size != (socklen_t) sizeof (sender)) ||
		    ((sender_size == (socklen_t) sizeof (sender)) &&
		     sender.nl_family != AF_NETLINK))
		{
			g_set_error (error, NM_NETLINK_MONITOR_ERROR,
				     NM_NETLINK_MONITOR_ERROR_BAD_SENDER,
				     _("received data from wrong type of sender"));
			succeeded = FALSE;
			goto out;
		}

		/* We only care about messages from the kernel, 
		 * not anywhere else. Only the kernel can have 
		 * nl_pid == 0.
		 */
		if (sender.nl_pid != 0)
		{
			g_set_error (error, NM_NETLINK_MONITOR_ERROR,
				     NM_NETLINK_MONITOR_ERROR_BAD_SENDER,
				     _("received data from unexpected sender"));
			succeeded = FALSE;
			goto out;

		}

		/* Okay, the data has passed basic sanity checks,
		 * let's store it.
		 */
		if (num_bytes_read > 0)
		{
			g_string_append_len (pending_bytes, 
					     buffer, (gssize) num_bytes_read);
			memset (buffer, 0, num_bytes_read);
		}
	}
	while ((num_bytes_read > 0) || (saved_errno == EINTR));

	if (saved_errno != 0)
	{
		g_set_error (error, NM_NETLINK_MONITOR_ERROR,
			     NM_NETLINK_MONITOR_ERROR_READING_FROM_SOCKET,
			     _("%s"), g_strerror (saved_errno));
		succeeded = FALSE;
		goto out;
	}

out:
	if ((pending_bytes->len > 0) && succeeded)
	{
		if (str_return)
			*str_return = pending_bytes->str;

		if (length)
			*length = pending_bytes->len;

		g_string_free (pending_bytes, FALSE);
		pending_bytes = NULL;
	}
	else
	{
		if (str_return)
			*str_return = NULL;

		if (length)
			*length = 0;
	}

	if (pending_bytes != NULL)
		g_string_free (pending_bytes, TRUE);
	return succeeded;
}

static gboolean 
nm_netlink_monitor_event_handler (GIOChannel       *channel,
				  GIOCondition      io_condition,
				  NmNetlinkMonitor *monitor)
{
	GError *error;
	gchar *received_bytes=NULL;
	gboolean processing_is_done;
	gsize num_received_bytes;
	guint num_bytes_to_process;
	struct nlmsghdr *header;

	if (io_condition & NM_NETLINK_MONITOR_ERROR_CONDITIONS)
		return nm_netlink_monitor_error_handler (channel, io_condition, monitor);
	else if (io_condition & NM_NETLINK_MONITOR_DISCONNECT_CONDITIONS)
		return nm_netlink_monitor_disconnect_handler (channel, io_condition, monitor);

	g_return_val_if_fail (!(io_condition &
			        ~(NM_NETLINK_MONITOR_EVENT_CONDITIONS)),
			      FALSE);

	error = NULL;

	/* Unfortunately, the kernel doesn't return EOF when it's
	 * done sending packets, so read_to_end () gets confused.
	 *
	 * This let's us do sockaddr_nl specific sanity checks anyway.
	 */
	//status = g_io_channel_read_to_end (channel, &received_bytes, 
	//			&num_received_bytes,
	//			&error);
	receive_pending_bytes (channel, &received_bytes,
			       &num_received_bytes,
			       &error);
	if (error != NULL) 
	{
		g_signal_emit (G_OBJECT (monitor), 
			       nm_netlink_monitor_signals[ERROR],
			       0, error);
		g_error_free (error);
		return FALSE;
	}

	if (num_received_bytes == 0)
		return TRUE;

	/* Why does NLMSG_* use unsigned ints instead of unsigned longs
	 * or size_t?
	 */
	num_bytes_to_process = (guint) num_received_bytes;

	processing_is_done = FALSE;
	for (header = (struct nlmsghdr *) received_bytes;
	     !processing_is_done &&
	     NLMSG_OK (header, (gint) num_bytes_to_process);
	     header = NLMSG_NEXT (header, num_bytes_to_process)) 
	{
		struct ifinfomsg *interface_info;
		struct rtattr *attribute;
		int num_attribute_bytes_to_process;
		gboolean is_connected;
		gchar *interface_name;

		g_assert (num_bytes_to_process <= num_received_bytes);

		switch (header->nlmsg_type)
		{
			case NLMSG_DONE:
				processing_is_done = TRUE;
				continue;

			case NLMSG_NOOP:
				continue;

			case NLMSG_OVERRUN:
			{
				error = g_error_new (NM_NETLINK_MONITOR_ERROR,
						     NM_NETLINK_MONITOR_ERROR_BAD_SOCKET_DATA,
						     _("too much data was sent "
						       "over socket and some of "
						       "it was lost"));

				g_signal_emit (G_OBJECT (monitor), 
						nm_netlink_monitor_signals[ERROR],
						0, error);
				g_error_free (error);
				error = NULL;
				continue;
			}

			case NLMSG_ERROR:
			{
				struct nlmsgerr *error_message;
				
				error_message = 
					(struct nlmsgerr *) NLMSG_DATA (header);

				error = g_error_new (NM_NETLINK_MONITOR_ERROR,
						     NM_NETLINK_MONITOR_ERROR_BAD_SOCKET_DATA,
						     "%s", g_strerror (error_message->error));

				g_signal_emit (G_OBJECT (monitor), 
						nm_netlink_monitor_signals[ERROR],
						0, error);
				g_error_free (error);
				error = NULL;
				continue;
			}

			default:
				/* we continue above, so we don't have to stuff
				 * everything below here in here */
			break;
		}

		interface_name = NULL;
		interface_info = (struct ifinfomsg *) NLMSG_DATA (header);
		
		/* The !! weirdness is to cannonicalize the value to 0 or 1.
		 */
		is_connected = !!((gboolean) (interface_info->ifi_flags & IFF_RUNNING));

		num_attribute_bytes_to_process = IFLA_PAYLOAD (header);

		for (attribute = IFLA_RTA (interface_info);
		     RTA_OK (attribute, num_attribute_bytes_to_process); 
		     attribute = RTA_NEXT (attribute, num_attribute_bytes_to_process))
		{
			if (attribute->rta_type == IFLA_IFNAME) {
				interface_name = 
					(gchar *) g_strdup (RTA_DATA (attribute));
			}
		}

		if (interface_name != NULL)
		{
			if (is_connected)
				g_signal_emit (G_OBJECT (monitor), 
					       nm_netlink_monitor_signals[INTERFACE_CONNECTED],
					       0, interface_name);
		        else
				g_signal_emit (G_OBJECT (monitor), 
					       nm_netlink_monitor_signals[INTERFACE_DISCONNECTED],
					       0, interface_name);

			g_free (interface_name);
		}
	}
	g_free (received_bytes);

	return TRUE;
}

static gboolean 
nm_netlink_monitor_error_handler (GIOChannel       *channel,
				  GIOCondition      io_condition,
				  NmNetlinkMonitor *monitor)
{
	GError *socket_error;
 
	g_return_val_if_fail (!(io_condition &
			      ~(NM_NETLINK_MONITOR_ERROR_CONDITIONS)),
			      FALSE);

	socket_error = 
	    g_error_new (NM_NETLINK_MONITOR_ERROR,
                         NM_NETLINK_MONITOR_ERROR_WAITING_FOR_SOCKET_DATA,
			 _("error occurred while waiting for data on socket"));

	g_signal_emit (G_OBJECT (monitor), 
		       nm_netlink_monitor_signals[ERROR],
		       0, socket_error);
	return TRUE;
}

static gboolean 
nm_netlink_monitor_disconnect_handler (GIOChannel       *channel,
				       GIOCondition      io_condition,
				       NmNetlinkMonitor *monitor)
{

	g_return_val_if_fail (!(io_condition & 
			      ~(NM_NETLINK_MONITOR_DISCONNECT_CONDITIONS)),
			      FALSE);
	return FALSE;
}
