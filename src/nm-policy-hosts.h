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
 */

#ifndef NM_POLICY_HOSTS_H
#define NM_POLICT_HOSTS_H

#include <glib.h>

gboolean nm_policy_hosts_update_etc_hosts (const char *hostname,
                                           const char *fallback_hostname4,
                                           const char *fallback_hostname6,
                                           const char *ip4_addr,
                                           const char *ip6_addr,
                                           gboolean *out_changed);

/* Only for testcases; don't use outside of nm-policy-hosts.c */
gboolean nm_policy_hosts_find_token (const char *line, const char *token);

GString *nm_policy_get_etc_hosts (const char **lines,
                                  gsize existing_len,
                                  const char *hostname,
                                  const char *fallback_hostname4,
                                  const char *fallback_hostname6,
                                  const char *ip4_addr,
                                  const char *ip6_addr,
                                  GError **error);

#endif /* NM_POLICY_HOSTS_H */

