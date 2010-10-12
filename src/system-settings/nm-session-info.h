/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager user session tracker -- per-session data
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
 * (C) Copyright 2010 Daniel Gnoutcheff <daniel@gnoutcheff.name>
 */

#ifndef NM_SESSION_INFO_H
#define NM_SESSION_INFO_H

#include <glib-object.h>

G_BEGIN_DECLS

#define NM_TYPE_SESSION_INFO                   (nm_session_info_get_type ())
#define NM_SESSION_INFO(obj)                   (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SESSION_INFO, NMSessionInfo))
#define NM_SESSION_INFO_CLASS(class_struct)    (G_TYPE_CHECK_CLASS_CAST ((class_struct), NM_TYPE_SESSION_INFO, NMSessionInfoClass))
#define NM_IS_SESSION_INFO(obj)                (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SESSION_INFO))
#define NM_IS_SESSION_INFO_CLASS(class_struct) (G_TYPE_CHECK_CLASS_TYPE ((class_struct), NM_TYPE_SESSION_INFO))
#define NM_SESSION_INFO_GET_CLASS(obj)         (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SESSION_INFO, NMSessionInfoClass))

#define NM_SESSION_INFO_ID          "session-id"
#define NM_SESSION_INFO_UNIX_USER   "unix-user"
#define NM_SESSION_INFO_IS_DEFAULT  "is-default"

#define NM_SESSION_INFO_REMOVED     "removed"

#define NM_SESSION_INFO_DEFAULT_ID  "[none]"

typedef struct {
	GObject parent;
} NMSessionInfo;

typedef struct {
	GObjectClass parent_class;
} NMSessionInfoClass;

GType nm_session_info_get_type (void);

char   * nm_session_info_get_id             (NMSessionInfo *self);
char   * nm_session_info_get_unix_user      (NMSessionInfo *self);
gboolean nm_session_info_is_default_session (NMSessionInfo *self);

G_END_DECLS

#endif
