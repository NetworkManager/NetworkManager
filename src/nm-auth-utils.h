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
 * Copyright (C) 2010 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_MANAGER_AUTH_H__
#define __NETWORKMANAGER_MANAGER_AUTH_H__

#include "nm-connection.h"

#include "nm-auth-manager.h"

/*****************************************************************************/

typedef struct NMAuthChain NMAuthChain;

typedef void (*NMAuthChainResultFunc) (NMAuthChain *chain,
                                       GDBusMethodInvocation *context,
                                       gpointer user_data);

NMAuthChain *nm_auth_chain_new_context (GDBusMethodInvocation *context,
                                        NMAuthChainResultFunc done_func,
                                        gpointer user_data);

NMAuthChain *nm_auth_chain_new_subject (NMAuthSubject *subject,
                                        GDBusMethodInvocation *context,
                                        NMAuthChainResultFunc done_func,
                                        gpointer user_data);

gpointer nm_auth_chain_get_data (NMAuthChain *chain, const char *tag);

gpointer nm_auth_chain_steal_data (NMAuthChain *chain, const char *tag);

void nm_auth_chain_set_data_unsafe (NMAuthChain *chain,
                                    const char *tag,
                                    gpointer data,
                                    GDestroyNotify data_destroy);

#define nm_auth_chain_set_data(chain, tag, data, data_destroy) \
	nm_auth_chain_set_data_unsafe ((chain), ""tag"", (data), (data_destroy))

NMAuthCallResult nm_auth_chain_get_result (NMAuthChain *chain,
                                           const char *permission);

void nm_auth_chain_add_call_unsafe (NMAuthChain *chain,
                                    const char *permission,
                                    gboolean allow_interaction);

#define nm_auth_chain_add_call(chain, permission, allow_interaction) \
	nm_auth_chain_add_call_unsafe ((chain), ""permission"", (allow_interaction))

void nm_auth_chain_destroy (NMAuthChain *chain);

NMAuthSubject *nm_auth_chain_get_subject (NMAuthChain *self);

/*****************************************************************************/

struct CList;

static inline NMAuthChain *
nm_auth_chain_parent_lst_entry (struct CList *parent_lst_self)
{
	return (NMAuthChain *) ((void *) parent_lst_self);
}

static inline struct CList *
nm_auth_chain_parent_lst_list (NMAuthChain *self)
{
	return (struct CList *) ((void *) self);
}

/*****************************************************************************/


/* Caller must free returned error description */
gboolean nm_auth_is_subject_in_acl (NMConnection *connection,
                                    NMAuthSubject *subect,
                                    char **out_error_desc);

gboolean nm_auth_is_subject_in_acl_set_error (NMConnection *connection,
                                              NMAuthSubject *subject,
                                              GQuark err_domain,
                                              int err_code,
                                              GError **error);

#endif /* __NETWORKMANAGER_MANAGER_AUTH_H__ */

