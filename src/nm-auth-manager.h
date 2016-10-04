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
 * Copyright (C) 2014 Red Hat, Inc.
 */

#ifndef NM_AUTH_MANAGER_H
#define NM_AUTH_MANAGER_H

#include "nm-auth-subject.h"

#define NM_TYPE_AUTH_MANAGER            (nm_auth_manager_get_type ())
#define NM_AUTH_MANAGER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_AUTH_MANAGER, NMAuthManager))
#define NM_AUTH_MANAGER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_AUTH_MANAGER, NMAuthManagerClass))
#define NM_IS_AUTH_MANAGER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_AUTH_MANAGER))
#define NM_IS_AUTH_MANAGER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_AUTH_MANAGER))
#define NM_AUTH_MANAGER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_AUTH_MANAGER, NMAuthManagerClass))

#define NM_AUTH_MANAGER_POLKIT_ENABLED "polkit-enabled"

#define NM_AUTH_MANAGER_SIGNAL_CHANGED "changed"

typedef struct _NMAuthManager NMAuthManager;
typedef struct _NMAuthManagerClass NMAuthManagerClass;

GType nm_auth_manager_get_type (void);

NMAuthManager *nm_auth_manager_setup (gboolean polkit_enabled);
NMAuthManager *nm_auth_manager_get (void);

gboolean nm_auth_manager_get_polkit_enabled (NMAuthManager *self);

#if WITH_POLKIT

void nm_auth_manager_polkit_authority_check_authorization (NMAuthManager *self,
                                                           NMAuthSubject *subject,
                                                           const char *action_id,
                                                           gboolean allow_user_interaction,
                                                           GCancellable *cancellable,
                                                           GAsyncReadyCallback callback,
                                                           gpointer user_data);
gboolean nm_auth_manager_polkit_authority_check_authorization_finish (NMAuthManager *self,
                                                                      GAsyncResult *res,
                                                                      gboolean *out_is_authorized,
                                                                      gboolean *out_is_challenge,
                                                                      GError **error);

#endif

#endif /* NM_AUTH_MANAGER_H */
