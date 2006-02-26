/* NetworkManager -- Network link manager
 *
 * Christopher Aillon <caillon@redhat.com>
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2005 Red Hat, Inc.
 */

#include <libnotify/notify.h>
#include "applet-notifications.h"

void
nmwa_send_event_notification (NMWirelessApplet *applet, 
                              NotifyUrgency urgency,
                              const char *summary,
                              const char *message,
                              const char *icon)
{
	NotifyNotification *notification;

	g_return_if_fail (applet != NULL);
	g_return_if_fail (summary != NULL);
	g_return_if_fail (message != NULL);

	if (!notify_is_initted ())
		notify_init ("NetworkManager");

	notification = notify_notification_new (summary, message,
			icon ? icon : GTK_STOCK_NETWORK, GTK_WIDGET (applet));
	notify_notification_set_urgency (notification, urgency);
	notify_notification_show (notification, NULL);
}

