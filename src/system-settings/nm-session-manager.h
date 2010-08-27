/* NetworkManager user session tracker
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

#ifndef NM_SESSION_MANAGER_H
#define NM_SESSION_MANAGER_H

#include <glib-object.h>
#include <dbus/dbus-glib.h>
#include "nm-session-info.h"

G_BEGIN_DECLS

#define NM_SESSION_MANAGER_ERROR                  (nm_session_manager_error_quark())

enum {
	NM_SESSION_MANAGER_ERROR_NOT_FOUND,
	NM_SESSION_MANAGER_ERROR_INFO_GATHERING_FAILED,
	NM_SESSION_MANAGER_ERROR_DISPOSED
} NMSessionManagerError;

#define NM_TYPE_SESSION_MANAGER                   (nm_session_manager_get_type ())
#define NM_SESSION_MANAGER(obj)                   (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SESSION_MANAGER, NMSessionManager))
#define NM_SESSION_MANAGER_CLASS(class_struct)    (G_TYPE_CHECK_CLASS_CAST ((class_struct), NM_TYPE_SESSION_MANAGER, NMSessionManagerClass))
#define NM_IS_SESSION_MANAGER(obj)                (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SESSION_MANAGER))
#define NM_IS_SESSION_MANAGER_CLASS(class_struct) (G_TYPE_CHECK_CLASS_TYPE ((class_struct), NM_TYPE_SESSION_MANAGER))
#define NM_SESSION_MANAGER_GET_CLASS(obj)         (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SESSION_MANAGER, NMSessionManagerClass))

#define NM_SESSION_MANAGER_SESSION_ADDED "session-added"
#define NM_SESSION_MANAGER_INIT_DONE     "init-done"

typedef struct {
	GObject parent;
} NMSessionManager;

typedef struct {
	GObjectClass parent_class;
} NMSessionManagerClass;

typedef void (*NMSessionFunc) (NMSessionInfo *session, 
                               GError *error,
                               gpointer user_data);

NMSessionManager * nm_session_manager_get                   (void);

gboolean           nm_session_manager_is_initialized        (NMSessionManager *manager);

GSList           * nm_session_manager_get_sessions          (NMSessionManager *manager);

void               nm_session_manager_get_session           (NMSessionManager *manager, 
                                                             char *session_id,
                                                             NMSessionFunc callback, 
                                                             gpointer user_data);

void               nm_session_manager_get_session_of_caller (NMSessionManager *manager, 
                                                             DBusGMethodInvocation  *method_call,
                                                             NMSessionFunc callback, 
                                                             gpointer user_data);

GType              nm_session_manager_get_type              (void);

GQuark             nm_session_manager_error_quark           (void);

G_END_DECLS

#endif
