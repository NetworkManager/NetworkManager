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
 * Copyright 2014 Red Hat, Inc.
 */

#ifndef __NM_CONNECTION_PRIVATE_H__
#define __NM_CONNECTION_PRIVATE_H__

#if !((NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_WITH_LIBNM_CORE_PRIVATE)
#error Cannot use this header.
#endif

#include "nm-setting.h"
#include "nm-connection.h"

NMSetting  *_nm_connection_find_base_type_setting         (NMConnection *connection);

const char *_nm_connection_detect_slave_type              (NMConnection *connection,
                                                           NMSetting **out_s_port);

const char *_nm_connection_detect_bluetooth_type (NMConnection *self);

gboolean    _nm_connection_verify_required_interface_name (NMConnection *connection,
                                                           GError **error);

int _nm_setting_ovs_interface_verify_interface_type (NMSettingOvsInterface *self,
                                                     NMConnection *connection,
                                                     gboolean normalize,
                                                     gboolean *out_modified,
                                                     GError **error);

#endif  /* __NM_CONNECTION_PRIVATE_H__ */
