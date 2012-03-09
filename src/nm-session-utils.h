/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* This program is free software; you can redistribute it and/or modify
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
 * Copyright (C) 2012 Red Hat, Inc.
 * Author: Dan Williams <dcbw@redhat.com>
 */

#ifndef NM_SESSION_UTILS_H
#define NM_SESSION_UTILS_H

#include <glib.h>
#include <glib-object.h>

#define NM_SESSION_MONITOR_ERROR         (nm_session_monitor_error_quark ())
GQuark nm_session_monitor_error_quark    (void) G_GNUC_CONST;
GType  nm_session_monitor_error_get_type (void) G_GNUC_CONST;

typedef enum {
	NM_SESSION_MONITOR_ERROR_IO_ERROR = 0,       /*< nick=IOError >*/
	NM_SESSION_MONITOR_ERROR_MALFORMED_DATABASE, /*< nick=MalformedDatabase >*/
	NM_SESSION_MONITOR_ERROR_UNKNOWN_USER,       /*< nick=UnknownUser >*/
	NM_SESSION_MONITOR_ERROR_NO_DATABASE,        /*< nick=NoDatabase >*/
} NMSessionMonitorError;

gboolean nm_session_uid_to_user (uid_t uid, const char **out_user, GError **error);

gboolean nm_session_user_to_uid (const char *user, uid_t *out_uid, GError **error);

#endif  /* NM_SESSION_UTILS_H */
