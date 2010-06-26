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
 * Copyright (C) 2004 - 2010 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#ifndef NM_POLICY_HOSTNAME_H
#define NM_POLICY_HOSTNAME_H

#include <glib.h>

gboolean nm_policy_set_system_hostname (const char *new_hostname,
                                        const char *ip4_addr,
                                        const char *ip6_addr,
                                        const char *msg);


typedef struct HostnameThread HostnameThread;

typedef void (*HostnameThreadCallback) (HostnameThread *ht,
                                        int error,
                                        const char *hostname,
                                        gpointer user_data);

HostnameThread * hostname4_thread_new (guint32 ip4_addr,
                                       HostnameThreadCallback callback,
                                       gpointer user_data);

HostnameThread * hostname6_thread_new (const struct in6_addr *ip6_addr,
                                       HostnameThreadCallback callback,
                                       gpointer user_data);

void             hostname_thread_free (HostnameThread *ht);

gboolean         hostname_thread_is_dead (HostnameThread *ht);

void             hostname_thread_kill (HostnameThread *ht);

#endif /* NM_POLICY_HOSTNAME_H */
