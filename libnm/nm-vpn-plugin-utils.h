/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2011 Red Hat, Inc.
 */

#ifndef NM_VPN_PLUGIN_UTILS_H
#define NM_VPN_PLUGIN_UTILS_H

#include <glib.h>
#include <nm-setting.h>

G_BEGIN_DECLS

gboolean nm_vpn_plugin_utils_read_vpn_details (int fd,
                                               GHashTable **out_data,
                                               GHashTable **out_secrets);

gboolean nm_vpn_plugin_utils_get_secret_flags (GHashTable *data,
                                               const char *secret_name,
                                               NMSettingSecretFlags *out_flags);

G_END_DECLS

#endif /* NM_VPN_PLUGIN_UTILS_H */
