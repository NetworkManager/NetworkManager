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
 * Copyright (C) 2010 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_MANAGER_AUTH_H__
#define __NETWORKMANAGER_MANAGER_AUTH_H__

#include "nm-connection.h"

typedef struct NMAuthChain NMAuthChain;

typedef enum {
	NM_AUTH_CALL_RESULT_UNKNOWN,
	NM_AUTH_CALL_RESULT_YES,
	NM_AUTH_CALL_RESULT_AUTH,
	NM_AUTH_CALL_RESULT_NO,
} NMAuthCallResult;

typedef void (*NMAuthChainResultFunc) (NMAuthChain *chain,
                                       GError *error,
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

void nm_auth_chain_set_data (NMAuthChain *chain,
                             const char *tag,
                             gpointer data,
                             GDestroyNotify data_destroy);

void nm_auth_chain_set_data_ulong (NMAuthChain *chain,
                                   const char *tag,
                                   gulong data);

gulong nm_auth_chain_get_data_ulong (NMAuthChain *chain, const char *tag);

NMAuthCallResult nm_auth_chain_get_result (NMAuthChain *chain,
                                           const char *permission);

void nm_auth_chain_add_call (NMAuthChain *chain,
                             const char *permission,
                             gboolean allow_interaction);

void nm_auth_chain_unref (NMAuthChain *chain);

/* Caller must free returned error description */
gboolean nm_auth_is_subject_in_acl (NMConnection *connection,
                                    NMAuthSubject *subect,
                                    char **out_error_desc);

NMAuthSubject *nm_auth_chain_get_subject (NMAuthChain *self);

#endif /* __NETWORKMANAGER_MANAGER_AUTH_H__ */

