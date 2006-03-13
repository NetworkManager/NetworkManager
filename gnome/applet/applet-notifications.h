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

#ifndef NM_NOTIFICATION_H__
#define NM_NOTIFICATION_H__

#include "config.h"

#ifdef ENABLE_NOTIFY

#include <libnotify/notify.h>
#include "applet.h"

void
nma_send_event_notification (NMApplet *applet, 
                              NotifyUrgency urgency,
                              const char *summary,
                              const char *message,
                              const char *icon);

#endif /* ENABLE_NOTIFY */

#endif /* NM_NOTIFICATION_H__ */
